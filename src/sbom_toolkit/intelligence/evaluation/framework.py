"""
Refactored core testing framework for comparing KG-enhanced RAG vs standalone LLM performance.

This module provides reproducible testing to validate the hypothesis that
knowledge graph enhancement improves LLM performance on software supply chain analysis.
"""

import hashlib
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from ...cli.output import CLIOutputManager
from ...shared.models import PerformanceComparison, TestCase
from ...shared.output import OutputManager
from .context_builder import SBOMContextBuilder
from .metrics import AdvancedEvaluator
from .reporting import PerformanceReporter
from .test_cache import TestResultCache
from .test_runner import SystemTestRunner


class SimpleProgressTracker:
    """Simple text-based progress tracking for verbose mode to avoid Rich conflicts."""

    def __init__(self, total, console):
        self.total = total
        self.completed = 0
        self.console = console
        self.tasks = {}
        self.task_counter = 0
        self.last_progress_message = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def add_task(self, description: str, total: int | None = None) -> int:
        task_id = self.task_counter
        self.tasks[task_id] = {
            "description": description,
            "completed": 0,
            "total": total or self.total,
        }
        self.task_counter += 1
        return task_id

    def update(self, task_id: int, advance: int = 1, description: str | None = None):
        if task_id in self.tasks:
            self.tasks[task_id]["completed"] += advance
            if description:
                self.tasks[task_id]["description"] = description
            self.completed += advance

            # Simple progress output - only show if there's meaningful progress
            task = self.tasks[task_id]
            progress_pct = (self.completed / self.total) * 100 if self.total > 0 else 0
            progress_message = f"Progress: {progress_pct:.0f}% ({self.completed}/{self.total})"

            # Only print if progress percentage changed significantly or description changed
            if progress_message != self.last_progress_message or (
                description and description != task.get("last_description")
            ):
                print(f"  {progress_message} - {task['description']}")
                self.last_progress_message = progress_message
                task["last_description"] = task["description"]


class PerformanceTestFramework:
    """Framework for conducting reproducible performance tests."""

    def __init__(
        self,
        output_manager: OutputManager,
        cli_output: CLIOutputManager | None = None,
        save_detailed: bool = False,
        cache_enabled: bool = True,
        model_override: str | None = None,
        verbose: bool = False,
        mock_mode: bool = False,
    ):
        self.output_manager = output_manager
        self.cli_output = cli_output
        self.save_detailed = save_detailed
        self.cache_enabled = cache_enabled
        self.model_override = model_override
        self.verbose = verbose
        self.mock_mode = mock_mode

        # Initialize components
        if self.cache_enabled:
            cache_dir = output_manager.base_dir / "cache" / "performance_tests"
        else:
            cache_dir = None

        self.cache = TestResultCache(cache_dir, cache_enabled)

        self.evaluator = AdvancedEvaluator()  # Regular evaluator for sequential mode
        self.quiet_evaluator = AdvancedEvaluator(quiet_mode=not verbose)  # Quiet unless verbose
        # Pass model override and verbose flag to test runner
        self.test_runner = SystemTestRunner(
            self.evaluator, save_detailed, model_override, verbose, mock_mode
        )
        self.quiet_test_runner = SystemTestRunner(
            self.quiet_evaluator, save_detailed, model_override, verbose, mock_mode
        )
        self.context_builder = SBOMContextBuilder()
        self.reporter = PerformanceReporter(output_manager)

        # RAG system attributes
        self.rag_system = None
        self.rag_system_initialized = False
        self.rag_embedding_thread = None
        self.rag_embedding_complete = False
        self.rag_embedding_error = None

        # Thread management for clean shutdown
        self.shutdown_event = threading.Event()
        self.active_threads = []
        self.active_executors = []  # Track active ThreadPoolExecutors
        self.exit_timer = None  # Initialize exit timer for timeout handling

    def set_signal_handlers(self):
        """Set up signal handlers for graceful termination."""

        def signal_handler(sig, frame):
            if self.cli_output:
                self.cli_output.interrupt_info("\n\nTest interrupted by user (Ctrl+C)")
                self.cli_output.interrupt_info("🛑 Initiating graceful shutdown...")
            else:
                print("\n\n⚠️  Test interrupted by user (Ctrl+C)")
                print("🛑 Initiating graceful shutdown...")

            # Signal all threads to shutdown
            self.shutdown_event.set()
            self._cleanup_threads_and_exit()

        signal.signal(signal.SIGINT, signal_handler)

    def _cleanup_threads_and_exit(self):
        """Clean up threads and executors, then exit gracefully."""
        if self.cli_output:
            self.cli_output.status("Shutting down active threads...")
        else:
            print("📋 Shutting down active threads...")

        # Shutdown active ThreadPoolExecutors
        for executor in self.active_executors:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

        # Join threads with timeout
        for thread in self.active_threads:
            try:
                thread.join(timeout=1.0)  # 1 second timeout per thread
            except Exception:
                pass

        sys.exit(1)

    def _start_background_embedding_generation(self, kg_data: dict[str, Any]):
        """Start background thread to generate embeddings for legacy RAG."""
        if self.rag_embedding_thread is not None:
            return  # Already started

        # Mock mode: instant completion
        if self.mock_mode:
            if self.verbose:
                print("🎭 Mock embeddings: Instant completion")
            self._create_mock_rag_system()
            self.rag_embedding_complete = True
            return

        # Use concurrent.futures for better thread management with free-threading
        from concurrent.futures import ThreadPoolExecutor

        def generate_embeddings():
            try:
                # Small delay to let initial test streaming start before heavy embedding API calls
                import time

                time.sleep(3.0)

                # Check for shutdown signal
                if self.shutdown_event.is_set():
                    return

                from ..retrieval.legacy.rag import RAGSystem

                # Create RAG system with embedding cache
                rag_system = RAGSystem(
                    require_openai=True, embedding_cache=self.cache.embedding_cache
                )

                # Check for shutdown signal
                if self.shutdown_event.is_set():
                    return

                # Override model if specified
                if self.model_override:
                    rag_system.chat_model = self.model_override

                # Load knowledge graph and generate embeddings
                # Always suppress noisy output during background generation to avoid spam
                import contextlib
                import io

                with contextlib.redirect_stdout(io.StringIO()):
                    rag_system.load_knowledge_graph(kg_data)

                # Check for shutdown signal after KG loading
                if self.shutdown_event.is_set():
                    return

                # Generate embeddings if not already cached
                if not rag_system.embeddings:
                    # Always suppress embedding generation progress spam
                    with contextlib.redirect_stdout(io.StringIO()):
                        rag_system.generate_embeddings(kg_data)

                self.rag_system = rag_system
                self.rag_system_initialized = True
                self.rag_embedding_complete = True

            except TimeoutError as e:
                self.rag_embedding_error = f"Initialization timeout: {str(e)}"
                self.rag_embedding_complete = True
            except Exception as e:
                self.rag_embedding_error = str(e)
                self.rag_embedding_complete = True

        # Use ThreadPoolExecutor for better thread management with free-threading
        if not hasattr(self, "_executor"):
            self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="embedding-gen")

        # Submit the task to the executor
        future = self._executor.submit(generate_embeddings)

        # Store the future for better management
        self.rag_embedding_future = future

        # Create a thread-like wrapper for compatibility
        class FutureThread:
            def __init__(self, future):
                self.future = future
                self.daemon = True

            def start(self):
                pass  # Already started by executor

            def is_alive(self):
                return not self.future.done()

            def join(self, timeout=None):
                try:
                    self.future.result(timeout=timeout)
                except Exception:
                    pass  # Errors handled in the task itself

        self.rag_embedding_thread = FutureThread(future)
        self.active_threads.append(self.rag_embedding_thread)

    def _create_mock_rag_system(self):
        """Create a mock RAG system for testing without API calls."""

        class MockRAGSystem:
            def __init__(self):
                self.embeddings = ["mock_embedding"] * 100  # Simulate embeddings
                self.chat_model = "mock-model"

            def load_knowledge_graph(self, kg_data):
                pass  # No-op in mock mode

            def generate_embeddings(self, kg_data):
                pass  # No-op in mock mode

            def query(self, question, top_k=5, sbom_context="", stream=False, verbose=False):
                # Return a realistic mock response in the expected format
                return {
                    "answer": f"Mock response for: {question[:50]}... (using context: {len(sbom_context)} chars)",
                    "sources": ["mock_source_1", "mock_source_2"],
                }

        self.rag_system = MockRAGSystem()
        self.rag_system_initialized = True

    def _wait_for_embeddings(self):
        """Wait for embeddings to be ready."""
        if not self.rag_embedding_complete:
            if self.verbose:
                if self.cli_output:
                    self.cli_output.progress_info(
                        "Waiting for Legacy RAG embeddings to complete..."
                    )
                else:
                    print("⏳ Waiting for Legacy RAG embeddings to complete...")

            # Add timeout to prevent infinite waiting - reduced from 5 minutes to 2 minutes
            start_time = time.time()
            timeout = 120  # 2 minutes max wait time
            check_interval = 0.1  # Check more frequently (100ms instead of 500ms)

            while not self.rag_embedding_complete and not self.shutdown_event.is_set():
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    if self.verbose:
                        if self.cli_output:
                            self.cli_output.warning(
                                "Legacy RAG embedding generation timed out after 2 minutes"
                            )
                        else:
                            print("⚠️  Legacy RAG embedding generation timed out after 2 minutes")

                    # Force terminate the background thread if it's still alive
                    if self.rag_embedding_thread and self.rag_embedding_thread.is_alive():
                        if self.verbose:
                            print("🔄 Attempting to terminate hanging embedding thread...")
                        # Set error state to prevent further waiting
                        self.rag_embedding_error = (
                            f"Embedding generation timed out after {timeout}s"
                        )
                        self.rag_embedding_complete = True
                        # The daemon thread will be cleaned up when the main process exits
                    else:
                        self.rag_embedding_error = "Embedding generation timed out"
                        self.rag_embedding_complete = True
                    break

                # Show progress every 10 seconds in verbose mode
                if self.verbose and int(elapsed) % 10 == 0 and elapsed > 0:
                    print(f"⏳ Still waiting for embeddings... ({int(elapsed)}s elapsed)")

                time.sleep(check_interval)

        if self.rag_embedding_error:
            if self.verbose:
                if self.cli_output:
                    self.cli_output.warning(
                        f"Legacy RAG initialization failed: {self.rag_embedding_error}"
                    )
                else:
                    print(f"⚠️  Legacy RAG initialization failed: {self.rag_embedding_error}")
        elif not self.rag_system_initialized:
            if self.verbose:
                if self.cli_output:
                    self.cli_output.warning("Legacy RAG system not available")
                else:
                    print("⚠️  Legacy RAG system not available")

    def generate_test_cases(self, repository_url: str, sbom_data: dict[str, Any]) -> list[TestCase]:
        """Load citation-focused test cases for evaluating accuracy and consistency across systems."""
        from .test_cases import (
            get_baseline_test_cases,
            load_citation_focused_test_cases,
        )

        # Load the main citation-focused test cases
        test_cases = load_citation_focused_test_cases(repository_url, sbom_data)

        # Add baseline system validation tests
        test_cases.extend(get_baseline_test_cases(repository_url))

        return test_cases

    def run_performance_comparison(
        self,
        repository_url: str,
        sbom_data: dict[str, Any],
        kg_data: dict[str, Any],
        max_tests: int | None = None,
    ) -> PerformanceComparison:
        """Run complete performance comparison between MCP-RAG, Legacy RAG, and Standalone LLM systems."""
        # Compute SBOM hash for caching
        sbom_hash = self.cache._compute_sbom_hash(sbom_data)

        # Create test configuration for cache key (include model override)
        test_config = {
            "max_tests": max_tests,
            "save_detailed": self.save_detailed,
            "model_override": self.model_override,
        }

        # Check for cached comparison
        cached_comparison = self.cache.get_cached_comparison(repository_url, sbom_hash, test_config)
        if cached_comparison is not None:
            if self.cache_enabled:
                if self.cli_output:
                    self.cli_output.success(
                        f"Using cached performance comparison (session: {cached_comparison.test_session_id})"
                    )
                    self.cli_output.info(
                        f"  Completed tests: {len(cached_comparison.kg_enhanced_results)}"
                    )
                else:
                    print(
                        f"✓ Using cached performance comparison (session: {cached_comparison.test_session_id})"
                    )
                    print(f"  Completed tests: {len(cached_comparison.kg_enhanced_results)}")
            return cached_comparison

        test_session_id = f"test_{int(time.time())}"

        if self.cli_output:
            self.cli_output.test_info(f"Starting 3-way performance test session: {test_session_id}")
            self.cli_output.info("📊 Systems: MCP-Enhanced RAG vs Legacy RAG vs Standalone LLM")
            if self.model_override:
                self.cli_output.info(f"🎯 Using model override: {self.model_override}")
            if self.cache_enabled:
                self.cli_output.debug(f"📦 SBOM hash: {sbom_hash} (for cache key)")
        else:
            print(f"🧪 Starting 3-way performance test session: {test_session_id}")
            print("📊 Systems: MCP-Enhanced RAG vs Legacy RAG vs Standalone LLM")
            if self.model_override:
                print(f"🎯 Using model override: {self.model_override}")
            if self.cache_enabled:
                print(f"📦 SBOM hash: {sbom_hash} (for cache key)")

        # Start background embedding generation immediately
        if self.cli_output:
            self.cli_output.system_info(
                "Starting background embedding generation for Legacy RAG..."
            )
        else:
            print("🚀 Starting background embedding generation for Legacy RAG...")
        self._start_background_embedding_generation(kg_data)

        # Generate test cases
        test_cases = self.generate_test_cases(repository_url, sbom_data)

        # Limit test cases if max_tests is specified
        if max_tests is not None and max_tests < len(test_cases):
            test_cases = test_cases[:max_tests]
            if self.cli_output:
                self.cli_output.status(
                    f"Generated {len(test_cases)} test cases (limited by --tests flag)"
                )
            else:
                print(f"📋 Generated {len(test_cases)} test cases (limited by --tests flag)")
        else:
            if self.cli_output:
                self.cli_output.status(f"Generated {len(test_cases)} test cases")
            else:
                print(f"📋 Generated {len(test_cases)} test cases")

        # Prepare SBOM context for all systems
        sbom_context = self.context_builder.create_sbom_context(sbom_data, kg_data)
        print(
            f"📄 Shared SBOM context: {len(sbom_context):,} characters ({len(sbom_context.split()):,} words)"
        )

        kg_results = []
        legacy_rag_results = []
        standalone_results = []

        # Set up signal handling for graceful abort
        self.set_signal_handlers()

        try:
            for i, test_case in enumerate(test_cases):
                if self.shutdown_event.is_set():
                    break

                print(f"\n🔍 Test {i + 1}/{len(test_cases)}: {test_case.category}")
                print(f"Question: {test_case.question[:100]}...")

                # Test MCP-enhanced system
                print("  Testing MCP-enhanced system...")
                cached_result = self.cache.get_cached_test_result(
                    test_case, sbom_hash, "kg_enhanced"
                )
                if cached_result is not None:
                    if self.cache_enabled:
                        print(
                            f"    ✓ Using cached result (saved {cached_result.response_time:.1f}s)"
                        )
                    kg_result = cached_result
                else:
                    kg_result = self.test_runner.test_mcp_system(test_case, kg_data, sbom_context)
                    self.cache.save_test_result_to_cache(
                        kg_result, test_case, sbom_hash, "kg_enhanced"
                    )

                kg_results.append(kg_result)
                print(
                    f"    P: {kg_result.precision:.1%} | R: {kg_result.recall:.1%} | F1.5: {kg_result.f1_5_score:.1%}, Time: {kg_result.response_time:.2f}s"
                )

                if self.shutdown_event.is_set():
                    break

                # Test legacy RAG system
                print("  Testing legacy RAG system...")
                # Wait for embeddings to be ready
                self._wait_for_embeddings()

                cached_result = self.cache.get_cached_test_result(
                    test_case, sbom_hash, "legacy_rag"
                )
                if cached_result is not None:
                    if self.cache_enabled:
                        print(
                            f"    ✓ Using cached result (saved {cached_result.response_time:.1f}s)"
                        )
                    legacy_rag_result = cached_result
                else:
                    legacy_rag_result = self.test_runner.test_legacy_rag_system(
                        test_case, kg_data, sbom_context, self.rag_system
                    )
                    self.cache.save_test_result_to_cache(
                        legacy_rag_result, test_case, sbom_hash, "legacy_rag"
                    )

                legacy_rag_results.append(legacy_rag_result)
                print(
                    f"    P: {legacy_rag_result.precision:.1%} | R: {legacy_rag_result.recall:.1%} | F1.5: {legacy_rag_result.f1_5_score:.1%}, Time: {legacy_rag_result.response_time:.2f}s"
                )

                if self.shutdown_event.is_set():
                    break

                # Test standalone LLM system
                print("  Testing standalone LLM system...")
                cached_result = self.cache.get_cached_test_result(
                    test_case, sbom_hash, "standalone"
                )
                if cached_result is not None:
                    if self.cache_enabled:
                        print(
                            f"    ✓ Using cached result (saved {cached_result.response_time:.1f}s)"
                        )
                    standalone_result = cached_result
                else:
                    standalone_result = self.test_runner.test_standalone_system(
                        test_case, kg_data, sbom_context
                    )
                    self.cache.save_test_result_to_cache(
                        standalone_result, test_case, sbom_hash, "standalone"
                    )

                standalone_results.append(standalone_result)
                print(
                    f"    P: {standalone_result.precision:.1%} | R: {standalone_result.recall:.1%} | F1.5: {standalone_result.f1_5_score:.1%}, Time: {standalone_result.response_time:.2f}s"
                )

        except KeyboardInterrupt:
            print("\n⚠️  Test interrupted, saving partial results...")
            self.shutdown_event.set()

        finally:
            # Clean up exit timer
            if self.exit_timer and self.exit_timer.is_alive():
                self.exit_timer.cancel()

        # Calculate summary statistics
        summary_stats = self._calculate_summary_stats(
            kg_results, legacy_rag_results, standalone_results
        )

        # Create comparison object
        comparison = PerformanceComparison(
            repository_url=repository_url,
            test_session_id=test_session_id,
            timestamp=datetime.now().isoformat(),
            total_test_cases=len(test_cases),
            kg_enhanced_results=kg_results,
            legacy_rag_results=legacy_rag_results,
            standalone_results=standalone_results,
            summary_stats=summary_stats,
        )

        # Cache the comparison for future use
        if self.cache_enabled and not self.shutdown_event.is_set():
            self.cache.save_comparison_to_cache(comparison, repository_url, sbom_hash, test_config)
        elif self.shutdown_event.is_set():
            print("⚠️  Partial results - caching disabled due to interruption")

        return comparison

    def run_performance_comparison_grouped_parallel(
        self,
        repository_url: str,
        sbom_data: dict[str, Any],
        kg_data: dict[str, Any],
        max_tests: int | None = None,
    ) -> PerformanceComparison:
        """Run optimal parallel comparison using Python 3.13 free-threading.

        This approach maximizes parallelism by:
        1. Starting embedding generation in background immediately
        2. Running Standalone and MCP tests in parallel while embeddings generate
        3. Only waiting for embeddings when RAG tests are ready to run

        Args:
            repository_url: URL of the repository being tested
            sbom_data: SBOM data dictionary
            kg_data: Knowledge graph data
            max_tests: Optional limit on number of tests

        Returns:
            PerformanceComparison object with results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from rich.console import Console

        # Check if free-threading is available
        is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
        if callable(is_gil_enabled):
            if is_gil_enabled():
                if self.verbose:
                    print("⚠️  GIL enabled, falling back to sequential processing")
                return self.run_performance_comparison_grouped_sequential(
                    repository_url, sbom_data, kg_data, max_tests
                )
        elif self.verbose:
            print(
                "sys._is_gil_enabled() not available; assuming GIL is enabled and falling back to sequential processing"
            )
            return self.run_performance_comparison_grouped_sequential(
                repository_url, sbom_data, kg_data, max_tests
            )

        if self.verbose:
            print("🚀 Using free-threaded parallel test execution")

        # Generate test session ID
        import uuid

        test_session_id = str(uuid.uuid4())[:8]

        # Always start background embedding generation for better performance
        # In verbose mode, we'll start it right before Phase 1 & 2 to avoid early API contention
        if not self.verbose:
            # Start background embedding generation IMMEDIATELY for non-verbose mode
            if self.rag_embedding_thread is None:
                self._start_background_embedding_generation(kg_data)
                # Don't sleep - let it run in background
        # Note: For verbose mode, we'll start background generation at the right time in Phase 1 & 2

        # Get or generate test cases
        sbom_hash = hashlib.md5(str(sbom_data).encode()).hexdigest()
        test_cases = self.generate_test_cases(repository_url, sbom_data)

        if max_tests is not None and max_tests < len(test_cases):
            test_cases = test_cases[:max_tests]
            if self.verbose:
                print(f"📋 Generated {len(test_cases)} test cases (limited by --tests flag)")
        else:
            if self.verbose:
                print(f"📋 Generated {len(test_cases)} test cases")

        # Prepare SBOM context for all systems
        sbom_context = self.context_builder.create_sbom_context(sbom_data, kg_data)
        if self.verbose:
            print(
                f"📄 Shared SBOM context: {len(sbom_context):,} characters ({len(sbom_context.split()):,} words)"
            )

        # Initialize result lists
        kg_results = []
        legacy_rag_results = []
        standalone_results = []

        # Set up signal handling
        self.set_signal_handlers()
        console = Console()

        # Calculate optimal worker count for free-threading
        import os

        max_workers = min(32, (os.cpu_count() or 1) + 4)

        try:
            # Phase 1 & 2: Run Standalone and MCP tests in parallel (no embedding dependency)
            console.print(
                "\n[bold blue]🚀 Phase 1 & 2: Running Standalone and MCP tests in parallel[/bold blue]"
            )

            progress_tracker = None
            task_id = None
            if self.verbose:
                progress_tracker = SimpleProgressTracker(len(test_cases) * 2, console)
                task_id = progress_tracker.add_task("Running parallel tests", len(test_cases) * 2)

            # In verbose mode, run sequentially to preserve streaming output
            if self.verbose:
                # Run tests sequentially to preserve streaming
                for i, test_case in enumerate(test_cases):
                    if self.shutdown_event.is_set():
                        break

                    print(f"\n🔍 Test {i + 1}/{len(test_cases)}: {test_case.category}")

                    # Run Standalone test with streaming
                    standalone_result = self._test_single_system_cached(
                        test_case, sbom_hash, "standalone", kg_data, sbom_context
                    )
                    standalone_results.append(standalone_result)
                    print(
                        f"  ✓ Standalone Test {i + 1}: P:{standalone_result.precision:.0%}|R:{standalone_result.recall:.0%}|F1.5:{standalone_result.f1_5_score:.0%}"
                    )

                    # Run MCP test with streaming
                    mcp_result = self._test_single_system_cached(
                        test_case, sbom_hash, "kg_enhanced", kg_data, sbom_context
                    )
                    kg_results.append(mcp_result)
                    print(
                        f"  ✓ MCP Test {i + 1}: P:{mcp_result.precision:.0%}|R:{mcp_result.recall:.0%}|F1.5:{mcp_result.f1_5_score:.0%}"
                    )

                    # Note: RAG embedding generation is started earlier at the CLI level
                    # to ensure embeddings are ready by Phase 3
                    if i == 0 and self.rag_embedding_thread is not None:
                        print("🚀 RAG embeddings running in background while tests continue...")

                    if progress_tracker is not None and task_id is not None:
                        progress_tracker.update(
                            task_id,
                            advance=2,
                            description=f"Completed {(i + 1) * 2}/{len(test_cases) * 2} tests",
                        )
            else:
                # In non-verbose mode, run in parallel for speed
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all standalone and MCP tests
                    future_to_info = {}

                    for i, test_case in enumerate(test_cases):
                        if self.shutdown_event.is_set():
                            break

                        # Submit standalone test
                        future_standalone = executor.submit(
                            self._test_single_system_cached,
                            test_case,
                            sbom_hash,
                            "standalone",
                            kg_data,
                            sbom_context,
                        )
                        future_to_info[future_standalone] = ("standalone", i, test_case)

                        # Submit MCP test
                        future_mcp = executor.submit(
                            self._test_single_system_cached,
                            test_case,
                            sbom_hash,
                            "kg_enhanced",
                            kg_data,
                            sbom_context,
                        )
                        future_to_info[future_mcp] = ("kg_enhanced", i, test_case)

                    # Process results as they complete
                    completed_count = 0
                    for future in as_completed(future_to_info):
                        if self.shutdown_event.is_set():
                            break

                        system_type, test_idx, test_case = future_to_info[future]

                        try:
                            result = future.result()
                            completed_count += 1

                            if system_type == "standalone":
                                standalone_results.append((test_idx, result))
                            else:  # kg_enhanced
                                kg_results.append((test_idx, result))

                        except Exception as e:
                            if self.verbose:
                                print(f"  ❌ {system_type} Test {test_idx + 1} failed: {e}")

                    # Sort results by original test case order
                    standalone_results.sort(key=lambda x: x[0])
                    kg_results.sort(key=lambda x: x[0])
                    standalone_results = [result for _, result in standalone_results]
                    kg_results = [result for _, result in kg_results]

            # Phase 3: Run RAG tests (wait for embeddings if needed)
            console.print("\n[bold blue]🧠 Phase 3: Testing Legacy RAG System[/bold blue]")

            # Check if we need to initialize RAG system (verbose mode or failed background)
            # First, check if background thread completed without us noticing
            if (
                hasattr(self, "rag_embedding_future")
                and self.rag_embedding_future.done()
                and not self.rag_embedding_complete
            ):
                try:
                    # Future completed - check if it succeeded
                    self.rag_embedding_future.result()  # This will raise exception if failed
                    if hasattr(self, "rag_system") and self.rag_system_initialized:
                        self.rag_embedding_complete = True
                        if self.verbose:
                            console.print("✓ Background embeddings completed successfully")
                except Exception as e:
                    self.rag_embedding_error = str(e)
                    self.rag_embedding_complete = True

            if not self.rag_embedding_complete:
                if self.rag_embedding_thread is None:
                    # No background thread was started, initialize synchronously
                    console.print("🔄 Initializing Legacy RAG system with embeddings...")
                    try:
                        from ..retrieval.legacy.rag import RAGSystem

                        # Create RAG system with embedding cache
                        rag_system = RAGSystem(
                            require_openai=True, embedding_cache=self.cache.embedding_cache
                        )

                        # Override model if specified
                        if self.model_override:
                            rag_system.chat_model = self.model_override

                        # Load knowledge graph and generate embeddings
                        rag_system.load_knowledge_graph(kg_data)

                        # Generate embeddings if not already cached
                        if not rag_system.embeddings:
                            rag_system.generate_embeddings(kg_data)

                        self.rag_system = rag_system
                        self.rag_system_initialized = True
                        self.rag_embedding_complete = True
                        console.print("✓ Legacy RAG embeddings generated successfully")

                    except Exception as e:
                        console.print(f"[red]❌ Failed to initialize Legacy RAG system: {e}[/red]")
                        self.rag_embedding_error = str(e)
                        self.rag_embedding_complete = True
                else:
                    # Background thread was started, wait for it to complete
                    console.print("⏳ Finalizing embeddings (this may take a moment)...")
                    self._wait_for_embeddings()

                    # After waiting, check if background completed successfully
                    if not self.rag_embedding_complete or not self.rag_system_initialized:
                        console.print("🔄 Initializing Legacy RAG system with embeddings...")
                        try:
                            from ..retrieval.legacy.rag import RAGSystem

                            # Create RAG system with embedding cache
                            rag_system = RAGSystem(
                                require_openai=True, embedding_cache=self.cache.embedding_cache
                            )

                            # Override model if specified
                            if self.model_override:
                                rag_system.chat_model = self.model_override

                            # Load knowledge graph and generate embeddings
                            rag_system.load_knowledge_graph(kg_data)

                            # Generate embeddings if not already cached
                            if not rag_system.embeddings:
                                rag_system.generate_embeddings(kg_data)

                            self.rag_system = rag_system
                            self.rag_system_initialized = True
                            self.rag_embedding_complete = True
                            console.print("✓ Legacy RAG embeddings generated successfully")

                        except Exception as e:
                            console.print(
                                f"[red]❌ Failed to initialize Legacy RAG system: {e}[/red]"
                            )
                            self.rag_embedding_error = str(e)
                            self.rag_embedding_complete = True
            else:
                # Background embeddings completed successfully
                if self.verbose:
                    console.print("✓ Background embeddings already completed")

            if self.rag_embedding_error:
                console.print(f"[red]❌ RAG system unavailable: {self.rag_embedding_error}[/red]")
                # Create empty results for failed RAG tests
                from ...shared.models import TestResult

                for test_case in test_cases:
                    error_result = TestResult(
                        test_case=test_case,
                        system_name="legacy_rag",
                        response=f"ERROR: {self.rag_embedding_error}",
                        response_time=0.0,
                        tokens_used=0,
                        precision=0.0,
                        recall=0.0,
                        f1_score=0.0,
                        f1_5_score=0.0,
                        errors=[self.rag_embedding_error],
                    )
                    legacy_rag_results.append(error_result)
            else:
                console.print("✓ RAG embeddings ready")

                rag_progress_tracker = None
                rag_task_id = None
                if self.verbose:
                    rag_progress_tracker = SimpleProgressTracker(len(test_cases), console)
                    rag_task_id = rag_progress_tracker.add_task(
                        "Running RAG tests", len(test_cases)
                    )

                for i, test_case in enumerate(test_cases):
                    if self.shutdown_event.is_set():
                        break

                    result = self._test_single_system_cached(
                        test_case, sbom_hash, "legacy_rag", kg_data, sbom_context
                    )
                    legacy_rag_results.append(result)

                    if self.verbose:
                        print(
                            f"  ✓ RAG Test {i + 1}: P:{result.precision:.0%}|R:{result.recall:.0%}|F1.5:{result.f1_5_score:.0%}"
                        )
                        if rag_progress_tracker is not None and rag_task_id is not None:
                            rag_progress_tracker.update(
                                rag_task_id,
                                advance=1,
                                description=f"Completed {i + 1}/{len(test_cases)} RAG tests",
                            )

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️  Test interrupted[/yellow]")
            self.shutdown_event.set()

        # Show final summary
        console.print("\n[bold green]✓ Parallel testing complete![/bold green]")
        console.print(f"  Standalone: {len(standalone_results)} tests")
        console.print(f"  MCP-Enhanced: {len(kg_results)} tests")
        console.print(f"  Legacy RAG: {len(legacy_rag_results)} tests")

        # Calculate summary statistics
        all_results = kg_results + legacy_rag_results + standalone_results

        # Calculate averages
        precisions = [r.precision for r in all_results if r.precision is not None]
        recalls = [r.recall for r in all_results if r.recall is not None]
        f1_scores = [r.f1_score for r in all_results if r.f1_score is not None]
        f1_5_scores = [r.f1_5_score for r in all_results if r.f1_5_score is not None]
        times = [r.response_time for r in all_results if r.response_time is not None]

        summary_stats = {
            "avg_precision": sum(precisions) / len(precisions) if precisions else 0,
            "avg_recall": sum(recalls) / len(recalls) if recalls else 0,
            "avg_f1_score": sum(f1_scores) / len(f1_scores) if f1_scores else 0,
            "avg_f1_5_score": sum(f1_5_scores) / len(f1_5_scores) if f1_5_scores else 0,
            "avg_accuracy": sum(f1_5_scores) / len(f1_5_scores)
            if f1_5_scores
            else 0,  # Backward compatibility
            "avg_response_time": sum(times) / len(times) if times else 0,
            "success_rate": len([r for r in all_results if not r.response.startswith("ERROR")])
            / len(all_results)
            if all_results
            else 0,
        }

        # Create performance comparison results
        comparison = PerformanceComparison(
            test_session_id=test_session_id,
            timestamp=datetime.now().isoformat(),
            repository_url=repository_url,
            total_test_cases=len(test_cases),
            kg_enhanced_results=kg_results,
            legacy_rag_results=legacy_rag_results,
            standalone_results=standalone_results,
            summary_stats=summary_stats,
            test_metadata={
                "sbom_component_count": len(sbom_data.get("components", [])),
                "kg_node_count": len(kg_data.get("nodes", [])),
                "kg_edge_count": len(kg_data.get("edges", [])),
                "model_override": self.model_override,
                "execution_mode": "optimized_parallel_freethreading",
            },
        )

        # Optionally save results
        if self.save_detailed:
            self.reporter.save_detailed_logs(test_session_id, self.quiet_test_runner.detailed_logs)

        return comparison

    def run_performance_comparison_grouped_sequential(
        self,
        repository_url: str,
        sbom_data: dict[str, Any],
        kg_data: dict[str, Any],
        max_tests: int | None = None,
    ) -> PerformanceComparison:
        """Run grouped sequential performance comparison - all Standalone, then MCP, then RAG.

        Fallback version for systems without free-threading.
        """
        # Generate test session ID
        test_session_id = f"test_{int(time.time())}"

        if self.cli_output:
            self.cli_output.test_info(
                f"Starting grouped 3-way performance test session: {test_session_id}"
            )
            self.cli_output.info(
                "📊 Systems: Standalone → MCP-Enhanced → Legacy RAG (grouped execution)"
            )
            if self.model_override:
                self.cli_output.info(f"🎯 Using model override: {self.model_override}")
        else:
            print(f"🧪 Starting grouped 3-way performance test session: {test_session_id}")
            print("📊 Systems: Standalone → MCP-Enhanced → Legacy RAG (grouped execution)")
            if self.model_override:
                print(f"🎯 Using model override: {self.model_override}")

        # Start background embedding generation if not already started
        if self.rag_embedding_thread is None:
            if self.cli_output:
                self.cli_output.system_info(
                    "Starting background embedding generation for Legacy RAG..."
                )
            else:
                print("🚀 Starting background embedding generation for Legacy RAG...")
            self._start_background_embedding_generation(kg_data)
        else:
            if self.cli_output:
                self.cli_output.system_info("RAG embedding generation already in progress...")
            else:
                print("⏳ RAG embedding generation already in progress...")

        # Generate test cases
        test_cases = self.generate_test_cases(repository_url, sbom_data)

        # Limit test cases if max_tests is specified
        if max_tests is not None and max_tests < len(test_cases):
            test_cases = test_cases[:max_tests]

        # Prepare SBOM context for all systems
        sbom_context = self.context_builder.create_sbom_context(sbom_data, kg_data)

        # Compute SBOM hash for caching
        sbom_hash = self.cache._compute_sbom_hash(sbom_data)

        kg_results = []
        legacy_rag_results = []
        standalone_results = []

        # Set up signal handling for graceful abort
        self.set_signal_handlers()

        try:
            # Phase 1: Run all Standalone tests
            print(f"\n{'=' * 60}")
            print("📊 Phase 1: Testing Standalone LLM System")
            print(f"{'=' * 60}")
            for i, test_case in enumerate(test_cases):
                if self.shutdown_event.is_set():
                    break

                print(f"  Test {i + 1}/{len(test_cases)}: {test_case.category}")
                result = self._test_single_system_cached(
                    test_case, sbom_hash, "standalone", kg_data, sbom_context
                )
                standalone_results.append(result)
                print(
                    f"    P: {result.precision:.1%} | R: {result.recall:.1%} | F1.5: {result.f1_5_score:.1%}, Time: {result.response_time:.2f}s"
                )

            # Phase 2: Run all MCP tests
            print(f"\n{'=' * 60}")
            print("🤖 Phase 2: Testing MCP-Enhanced System")
            print(f"{'=' * 60}")
            for i, test_case in enumerate(test_cases):
                if self.shutdown_event.is_set():
                    break

                print(f"  Test {i + 1}/{len(test_cases)}: {test_case.category}")
                result = self._test_single_system_cached(
                    test_case, sbom_hash, "kg_enhanced", kg_data, sbom_context
                )
                kg_results.append(result)
                print(
                    f"    P: {result.precision:.1%} | R: {result.recall:.1%} | F1.5: {result.f1_5_score:.1%}, Time: {result.response_time:.2f}s"
                )

            # Phase 3: Run all RAG tests (embeddings should be ready by now)
            print(f"\n{'=' * 60}")
            print("🧠 Phase 3: Testing Legacy RAG System")
            print(f"{'=' * 60}")
            # Check embedding status before starting RAG tests
            if not self.rag_embedding_complete:
                print("⏳ Finalizing embeddings (this may take a moment)...")
                self._wait_for_embeddings()

            if self.rag_embedding_error:
                print(f"❌ RAG system unavailable: {self.rag_embedding_error}")
            elif self.rag_system_initialized:
                print("✓ RAG embeddings ready")

            for i, test_case in enumerate(test_cases):
                if self.shutdown_event.is_set():
                    break

                print(f"  Test {i + 1}/{len(test_cases)}: {test_case.category}")
                result = self._test_single_system_cached(
                    test_case, sbom_hash, "legacy_rag", kg_data, sbom_context
                )
                legacy_rag_results.append(result)
                print(
                    f"    P: {result.precision:.1%} | R: {result.recall:.1%} | F1.5: {result.f1_5_score:.1%}, Time: {result.response_time:.2f}s"
                )

        except KeyboardInterrupt:
            print("\n⚠️  Test interrupted, saving partial results...")
            self.shutdown_event.set()

        finally:
            # Clean up exit timer
            if self.exit_timer and self.exit_timer.is_alive():
                self.exit_timer.cancel()

        # Calculate summary statistics
        summary_stats = self._calculate_summary_stats(
            kg_results, legacy_rag_results, standalone_results
        )

        # Create comparison object
        comparison = PerformanceComparison(
            repository_url=repository_url,
            test_session_id=test_session_id,
            timestamp=datetime.now().isoformat(),
            total_test_cases=len(test_cases),
            kg_enhanced_results=kg_results,
            legacy_rag_results=legacy_rag_results,
            standalone_results=standalone_results,
            summary_stats=summary_stats,
        )

        return comparison

    def _test_single_system_cached(
        self, test_case, sbom_hash: str, system_type: str, kg_data, sbom_context
    ):
        """Test a single system with caching support."""
        # Check cache first
        cached_result = self.cache.get_cached_test_result(test_case, sbom_hash, system_type)
        if cached_result is not None:
            if self.cache_enabled and self.verbose:
                print(f"    ✓ Using cached result (saved {cached_result.response_time:.1f}s)")
            return cached_result

        # Use appropriate test runner based on verbose setting
        test_runner = self.test_runner if self.verbose else self.quiet_test_runner

        # Run actual test based on system type
        if system_type == "kg_enhanced":
            result = test_runner.test_mcp_system(test_case, kg_data, sbom_context)
        elif system_type == "legacy_rag":
            result = test_runner.test_legacy_rag_system(
                test_case, kg_data, sbom_context, self.rag_system
            )
        else:  # standalone
            result = test_runner.test_standalone_system(test_case, kg_data, sbom_context)

        # Cache the result
        self.cache.save_test_result_to_cache(result, test_case, sbom_hash, system_type)
        return result

    def run_performance_comparison_parallel(
        self,
        repository_url: str,
        sbom_data: dict[str, Any],
        kg_data: dict[str, Any],
        max_tests: int | None = None,
    ) -> PerformanceComparison:
        """Run parallel performance comparison using Python 3.13 free-threading.

        This method tests all three systems (MCP, Legacy RAG, Standalone) in parallel
        for each test case, providing significant speedup.

        Args:
            repository_url: URL of the repository being tested
            sbom_data: SBOM data dictionary
            kg_data: Knowledge graph data
            max_tests: Optional limit on number of tests

        Returns:
            PerformanceComparison object with results
        """
        from rich.console import Console
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TaskID,
            TextColumn,
            TimeElapsedColumn,
        )

        # Check if free-threading is available
        is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
        if callable(is_gil_enabled):
            if is_gil_enabled():
                if self.verbose:
                    print("⚠️  GIL enabled, falling back to sequential processing")
                return self.run_performance_comparison(
                    repository_url, sbom_data, kg_data, max_tests
                )
        elif self.verbose:
            print(
                "sys._is_gil_enabled() not available; assuming GIL is enabled and falling back to sequential processing"
            )
            return self.run_performance_comparison(repository_url, sbom_data, kg_data, max_tests)

        if self.verbose:
            print("🚀 Using parallel test execution with free-threading")

        # Generate test session ID
        import uuid

        test_session_id = str(uuid.uuid4())[:8]

        # Initialize legacy RAG system in parallel mode (but suppress output unless verbose)
        if self.verbose:
            if self.cli_output:
                self.cli_output.system_info(
                    "Starting background embedding generation for Legacy RAG..."
                )
            else:
                print("🚀 Starting background embedding generation for Legacy RAG...")
        self._start_background_embedding_generation(kg_data)

        # Get or generate test cases
        sbom_hash = hashlib.md5(str(sbom_data).encode()).hexdigest()
        test_cases = self.generate_test_cases(repository_url, sbom_data)

        if max_tests is not None and max_tests < len(test_cases):
            test_cases = test_cases[:max_tests]
            if self.verbose:
                if self.cli_output:
                    self.cli_output.status(
                        f"Generated {len(test_cases)} test cases (limited by --tests flag)"
                    )
                else:
                    print(f"📋 Generated {len(test_cases)} test cases (limited by --tests flag)")
        else:
            if self.verbose:
                if self.cli_output:
                    self.cli_output.status(f"Generated {len(test_cases)} test cases")
                else:
                    print(f"📋 Generated {len(test_cases)} test cases")

        # Prepare SBOM context for all systems
        sbom_context = self.context_builder.create_sbom_context(sbom_data, kg_data)
        if self.verbose:
            print(
                f"📄 Shared SBOM context: {len(sbom_context):,} characters ({len(sbom_context.split()):,} words)"
            )

        kg_results = []
        legacy_rag_results = []
        standalone_results = []

        # Set up signal handling for graceful abort
        self.set_signal_handlers()

        console = Console()

        # Calculate total work (3 systems × number of test cases)
        total_tests = len(test_cases) * 3  # MCP + Legacy RAG + Standalone
        completed_tests = 0

        def test_single_system(test_case, system_type):
            """Test a single system with robust error handling and retry logic."""
            nonlocal completed_tests
            import time
            import traceback

            from ...shared.models import TestResult

            # Check for abort signal early
            if self.shutdown_event.is_set():
                return system_type, TestResult(
                    test_case=test_case,
                    system_name=system_type,
                    response="ERROR: Test aborted by user",
                    response_time=0.0,
                    tokens_used=0,
                    precision=0.0,
                    recall=0.0,
                    f1_score=0.0,
                    f1_5_score=0.0,
                    passed=False,
                    errors=["Test aborted by user"],
                )

            # Check cache first (outside retry loop)
            cached_result = self.cache.get_cached_test_result(test_case, sbom_hash, system_type)
            if cached_result is not None and self.cache_enabled:
                return system_type, cached_result

            # Define transient error types that warrant retry
            transient_errors = (
                ConnectionError,
                TimeoutError,
                OSError,  # Network issues
                KeyError,  # Occasional data access issues
            )

            last_error = None
            error_details = []
            max_retries = 2  # Retry up to 2 times for transient failures

            for attempt in range(max_retries + 1):
                try:
                    # Check abort signal before each attempt
                    if self.shutdown_event.is_set():
                        break

                    # Add small delay for retries
                    if attempt > 0:
                        time.sleep(min(2.0 * attempt, 5.0))  # Exponential backoff, max 5s
                        if self.verbose:
                            print(f"    🔄 Retry {attempt}/{max_retries} for {system_type}")

                    # Run actual test based on system type
                    if system_type == "kg_enhanced":
                        result = self.quiet_test_runner.test_mcp_system(
                            test_case, kg_data, sbom_context
                        )
                    elif system_type == "legacy_rag":
                        # Wait for embeddings to be ready (but suppress output unless verbose)
                        if not self.verbose:
                            # Show a simple waiting message even in non-verbose mode during embedding generation
                            if not self.rag_embedding_complete:
                                print("⏳ Generating embeddings for first test (30s delay)...")
                        else:
                            if self.cli_output:
                                self.cli_output.progress_info(
                                    "Waiting for Legacy RAG embeddings to complete..."
                                )
                            else:
                                print("⏳ Waiting for Legacy RAG embeddings to complete...")
                        self._wait_for_embeddings()
                        result = self.quiet_test_runner.test_legacy_rag_system(
                            test_case, kg_data, sbom_context, self.rag_system
                        )
                    else:  # standalone
                        result = self.quiet_test_runner.test_standalone_system(
                            test_case, kg_data, sbom_context
                        )

                    # Cache the successful result
                    self.cache.save_test_result_to_cache(result, test_case, sbom_hash, system_type)
                    return system_type, result

                except transient_errors as e:
                    last_error = e
                    error_msg = f"Attempt {attempt + 1}: {type(e).__name__}: {str(e)}"
                    error_details.append(error_msg)

                    if attempt < max_retries:
                        if self.verbose:
                            print(f"    ⚠️ Transient error in {system_type}: {error_msg}")
                        continue  # Retry for transient errors
                    else:
                        # Final attempt failed
                        break

                except Exception as e:
                    # Non-transient errors - don't retry
                    last_error = e
                    error_msg = f"Fatal error: {type(e).__name__}: {str(e)}"
                    error_details.append(error_msg)

                    # Log full traceback for debugging fatal errors
                    if self.verbose:
                        print(f"    ❌ Fatal error in {system_type}: {error_msg}")
                        print(f"    Traceback: {traceback.format_exc()}")
                    break  # Don't retry for fatal errors

            # All attempts failed - return error result
            error_summary = f"Failed after {max_retries + 1} attempts: {str(last_error)}"
            return system_type, TestResult(
                test_case=test_case,
                system_name=system_type,
                response=f"ERROR: {error_summary}",
                response_time=0.0,
                tokens_used=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                f1_5_score=0.0,
                passed=False,
                errors=error_details,
            )

        # Inform user about potential initial delay
        if not self.rag_embedding_complete and not self.verbose:
            console.print(
                "ℹ️  [blue]First test may take ~30s while embeddings generate in background[/blue]"
            )

        # Use Rich progress bars only in non-verbose mode to avoid streaming conflicts
        if self.verbose:
            # In verbose mode, use simple text progress to avoid Rich conflicts with streaming
            class VerboseProgressContext:
                def __init__(self, total_tests, console):
                    self.total_tests = total_tests
                    self.console = console
                    self.tracker = None

                def __enter__(self):
                    self.tracker = SimpleProgressTracker(self.total_tests, self.console)
                    return self.tracker

                def __exit__(self, exc_type, exc_val, exc_tb):
                    # Clean up any remaining progress state
                    if self.tracker and hasattr(self.tracker, "completed"):
                        if self.tracker.completed < self.tracker.total:
                            print(
                                f"  Final Progress: 100% ({self.tracker.total}/{self.tracker.total}) - Tests completed"
                            )

            progress_context = VerboseProgressContext(total_tests, console)
        else:
            # In non-verbose mode, use Rich progress bars with better error handling
            from rich.progress import (
                BarColumn,
                Progress,
                SpinnerColumn,
                TaskID,
                TextColumn,
                TimeElapsedColumn,
            )

            progress_context = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeElapsedColumn(),
                console=console,
                transient=True,  # Auto-cleanup on exit to prevent hanging
                refresh_per_second=2,  # Reduce refresh rate to avoid conflicts
            )

        # Run tests with single overall progress bar
        with progress_context as progress:
            # Create single overall task
            overall_task: TaskID = progress.add_task("Testing systems", total=total_tests)  # type: ignore[assignment]

            try:
                for i, test_case in enumerate(test_cases):
                    if self.shutdown_event.is_set():
                        break

                    if self.verbose:
                        console.print(
                            f"\n[bold blue]🔍 Test {i + 1}/{len(test_cases)}: {test_case.category}[/bold blue]"
                        )

                    # Test all three systems in parallel for this test case
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        # Track executor for graceful shutdown
                        self.active_executors.append(executor)
                        # Submit all three system tests
                        futures = {
                            executor.submit(
                                test_single_system, test_case, "kg_enhanced"
                            ): "kg_enhanced",
                            executor.submit(
                                test_single_system, test_case, "legacy_rag"
                            ): "legacy_rag",
                            executor.submit(
                                test_single_system, test_case, "standalone"
                            ): "standalone",
                        }

                        # Collect results as they complete
                        for future in as_completed(futures):
                            try:
                                system_type, result = future.result()
                                completed_tests += 1

                                # Update progress
                                system_name = {
                                    "kg_enhanced": "MCP-Enhanced",
                                    "legacy_rag": "Legacy RAG",
                                    "standalone": "Standalone",
                                }[system_type]

                                f1_5_score = result.f1_5_score
                                progress.update(
                                    overall_task,
                                    advance=1,
                                    description=f"✓ {system_name}: P:{result.precision:.0%}|R:{result.recall:.0%}|F1.5:{f1_5_score:.0%}",
                                )

                                # Store result in appropriate list
                                if system_type == "kg_enhanced":
                                    kg_results.append(result)
                                elif system_type == "legacy_rag":
                                    legacy_rag_results.append(result)
                                else:
                                    standalone_results.append(result)

                            except Exception as e:
                                completed_tests += 1
                                progress.update(overall_task, advance=1, description="✗ Error")
                                if self.verbose:
                                    console.print(f"  [red]✗ Failed to get result: {e}[/red]")

            except KeyboardInterrupt:
                if not self.verbose:
                    console.print("\n[yellow]⚠️  Test interrupted[/yellow]")
                else:
                    console.print(
                        "\n[yellow]⚠️  Test interrupted, saving partial results gracefully...[/yellow]"
                    )
                self.shutdown_event.set()

            finally:
                # Mark cleanup as completed for signal handler
                pass  # Cleanup tracking no longer needed

                # Clean up exit timer
                if self.exit_timer and self.exit_timer.is_alive():
                    self.exit_timer.cancel()

                # Clean up executor tracking
                self.active_executors.clear()

        # Show final summary
        if not self.verbose:
            console.print("\n✓ Testing complete")
        else:
            console.print("\n[bold green]✓ Testing complete![/bold green]")
            console.print(f"  MCP-Enhanced: {len(kg_results)} tests")
            console.print(f"  Legacy RAG: {len(legacy_rag_results)} tests")
            console.print(f"  Standalone: {len(standalone_results)} tests")

        # Calculate summary statistics
        summary_stats = self._calculate_summary_stats(
            kg_results, legacy_rag_results, standalone_results
        )

        # Create comparison object
        comparison = PerformanceComparison(
            repository_url=repository_url,
            test_session_id=test_session_id,
            timestamp=datetime.now().isoformat(),
            total_test_cases=len(test_cases),
            kg_enhanced_results=kg_results,
            legacy_rag_results=legacy_rag_results,
            standalone_results=standalone_results,
            summary_stats=summary_stats,
            test_metadata={
                "sbom_component_count": len(sbom_data.get("components", [])),
                "kg_node_count": len(kg_data.get("nodes", [])),
                "kg_edge_count": len(kg_data.get("edges", [])),
                "model_override": self.model_override,
                "execution_mode": "parallel_freethreading",
            },
        )

        # Optionally save results
        if self.save_detailed:
            self.reporter.save_detailed_logs(test_session_id, self.quiet_test_runner.detailed_logs)

        return comparison

    def _calculate_summary_stats(
        self, kg_results, legacy_rag_results, standalone_results
    ) -> dict[str, Any]:
        """Calculate summary statistics for all three systems."""

        def calc_system_stats(results, system_name):
            if not results:
                return {
                    "avg_precision": 0,
                    "avg_recall": 0,
                    "avg_f1_score": 0,
                    "avg_f1_5_score": 0,
                    "avg_accuracy": 0,  # Keep for backward compatibility (=avg_f1_5_score)
                    "avg_response_time": 0,
                    "success_rate": 0,
                    "tests_completed": 0,
                }

            # Collect individual metrics for micro-averaging
            precisions = [r.precision for r in results if r.precision >= 0]
            recalls = [r.recall for r in results if r.recall >= 0]
            f1_scores = [r.f1_score for r in results if r.f1_score >= 0]
            f1_5_scores = [r.f1_5_score for r in results if r.f1_5_score >= 0]
            times = [r.response_time for r in results if r.response_time > 0]

            stats = {
                "avg_precision": sum(precisions) / len(precisions) if precisions else 0,
                "avg_recall": sum(recalls) / len(recalls) if recalls else 0,
                "avg_f1_score": sum(f1_scores) / len(f1_scores) if f1_scores else 0,
                "avg_f1_5_score": sum(f1_5_scores) / len(f1_5_scores) if f1_5_scores else 0,
                "avg_accuracy": sum(f1_5_scores) / len(f1_5_scores)
                if f1_5_scores
                else 0,  # Backward compatibility
                "avg_response_time": sum(times) / len(times) if times else 0,
                "success_rate": len([r for r in results if not r.response.startswith("ERROR")])
                / len(results),
                "tests_completed": len(results),
            }

            if system_name == "mcp_enhanced":
                # Count function calls for MCP system
                stats["total_function_calls"] = 0  # TODO: Track this in test runner

            return stats

        return {
            "mcp_enhanced": calc_system_stats(kg_results, "mcp_enhanced"),
            "legacy_rag": calc_system_stats(legacy_rag_results, "legacy_rag"),
            "standalone": calc_system_stats(standalone_results, "standalone"),
        }

    def save_results(self, comparison: PerformanceComparison):
        """Save results using the reporter."""
        return self.reporter.save_results(comparison)

    def generate_report(self, comparison: PerformanceComparison) -> str:
        """Generate human-readable report using the reporter."""
        return self.reporter.generate_report(comparison)

    def save_detailed_logs(self, test_session_id: str, comparison: PerformanceComparison):
        """Save detailed logs from test runner."""
        return self.reporter.save_detailed_logs(test_session_id, self.test_runner.detailed_logs)

    def generate_summary_text(self, comparison: PerformanceComparison) -> str:
        """Generate summary text using the reporter."""
        return self.reporter.generate_summary_text(comparison)
