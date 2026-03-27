"""
Test runner module for executing individual system tests.

This module contains the core test execution logic for MCP-enhanced,
Legacy RAG, and Standalone LLM systems.
"""

import time
from datetime import datetime
from typing import Any

from ...shared.models import TestCase, TestResult
from ..prompts import get_standalone_system_prompt, get_standalone_user_prompt


class SystemTestRunner:
    """Handles execution of individual system tests."""

    def __init__(
        self,
        evaluator: Any,
        save_detailed: bool = False,
        model_override: str | None = None,
        verbose: bool = False,
        mock_mode: bool = False,
    ):
        self.evaluator = evaluator
        self.save_detailed = save_detailed
        self.detailed_logs: list[dict[str, Any]] = []
        self.model_override = model_override  # Allow model override
        self.verbose = verbose  # Store verbose flag
        self.mock_mode = mock_mode
        self.quiet_mode = getattr(
            evaluator, "quiet_mode", False
        )  # Inherit quiet mode from evaluator

        # Determine streaming behavior: verbose=True always enables, quiet=True disables (unless verbose=True)
        self.enable_streaming = self.verbose or not self.quiet_mode

    def test_mcp_system(
        self,
        test_case: TestCase,
        kg_data: dict[str, Any],
        sbom_context: str,
    ) -> TestResult:
        """Test the KG-enhanced MCP system on a test case."""
        try:
            start_time = time.time()

            # Mock mode: return simulated response
            if self.mock_mode:
                response_time = 0.5  # Simulate fast response
                response = f"🎭 Mock MCP response for '{test_case.question}': Found 3 vulnerabilities in components X, Y, Z with CVE-2023-12345, CVE-2023-67890, CVE-2024-11111."

                evaluation_result = self.evaluator.evaluate_response(
                    test_case, response, kg_data, "kg_enhanced"
                )

                return TestResult(
                    test_case=test_case,
                    system_name="kg_enhanced",
                    response=response,
                    response_time=response_time,
                    tokens_used=100,  # Mock token usage
                    precision=evaluation_result.get("precision", 0.85),  # Mock metrics
                    recall=evaluation_result.get("recall", 0.90),
                    f1_score=evaluation_result.get("f1_score", 0.87),
                    f1_5_score=evaluation_result.get("f1_5_score", 0.89),
                    passed=True,
                )

            # Real mode: actual MCP system
            from ..retrieval.mcp_system_refactored import MCPSystemRefactored

            # Add model validation
            model_to_use = self.model_override or "gpt-4o"

            try:
                mcp_system = MCPSystemRefactored(require_openai=True)
                # Override model if specified
                if self.model_override:
                    mcp_system.chat_model = self.model_override
                    if not self.quiet_mode:
                        print(f"🎯 Using model override: {self.model_override}")

                mcp_system.load_knowledge_graph(kg_data)

                function_calls_made = []
                function_call_results = []
                original_execute = mcp_system.execute_kg_function

                def track_execute(function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
                    result = original_execute(function_name, arguments)
                    function_calls_made.append(f"{function_name}({arguments})")
                    function_call_results.append(
                        {
                            "function": function_name,
                            "arguments": arguments,
                            "result": result,
                        }
                    )
                    return result

                mcp_system.execute_kg_function = track_execute  # type: ignore[method-assign]

                try:
                    response = mcp_system.chat_with_kg_access(
                        test_case.question, context=sbom_context, stream=self.enable_streaming
                    )
                except Exception:
                    # If chat fails, try without streaming
                    if self.enable_streaming:
                        print(
                            f"⚠️  MCP streaming failed with {model_to_use}, trying without streaming..."
                        )
                    response = mcp_system.chat_with_kg_access(
                        test_case.question, context=sbom_context, stream=False
                    )

                response_time = time.time() - start_time

                evaluation_result = self.evaluator.evaluate_response(
                    test_case, response, kg_data, "kg_enhanced"
                )

            except Exception as mcp_error:
                # MCP system failed, but return a valid result
                response = f"MCP system error with {model_to_use}: {str(mcp_error)}"
                response_time = time.time() - start_time
                evaluation_result = {
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                    "f1_5_score": 0.0,
                    "citation_metrics": {},
                }
                function_calls_made = []
                function_call_results = []

                if self.enable_streaming:
                    print(f"❌ MCP system failed: {str(mcp_error)[:100]}...")

            if self.save_detailed:
                log_entry = {
                    "test_case_id": test_case.id,
                    "system_type": "kg_enhanced",
                    "question": test_case.question,
                    "category": test_case.category,
                    "difficulty": test_case.difficulty,
                    "expected_elements": test_case.expected_elements,
                    "function_calls": function_calls_made.copy(),
                    "function_call_results": function_call_results.copy(),
                    "response": response,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat(),
                    "evaluation_result": evaluation_result,
                    "model_used": model_to_use,
                }
                self.detailed_logs.append(log_entry)

            evaluation_result_map: dict[str, Any] = (
                evaluation_result if isinstance(evaluation_result, dict) else {}
            )
            citation_metrics_raw = evaluation_result_map.get("citation_metrics", {})
            citation_metrics = (
                citation_metrics_raw if isinstance(citation_metrics_raw, dict) else {}
            )

            precision_raw = evaluation_result_map.get("precision", 0.0)
            recall_raw = evaluation_result_map.get("recall", 0.0)
            f1_raw = evaluation_result_map.get("f1_score", 0.0)
            f1_5_raw = evaluation_result_map.get("f1_5_score", 0.0)

            precision = float(precision_raw) if isinstance(precision_raw, int | float) else 0.0
            recall = float(recall_raw) if isinstance(recall_raw, int | float) else 0.0
            f1_score = float(f1_raw) if isinstance(f1_raw, int | float) else 0.0
            f1_5_score = float(f1_5_raw) if isinstance(f1_5_raw, int | float) else 0.0

            result = TestResult(
                test_case=test_case,
                system_name="kg_enhanced",
                response=response,
                response_time=response_time,
                tokens_used=0,  # TODO: Track actual tokens used
                citation_metrics=citation_metrics,
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                f1_5_score=f1_5_score,
                passed=f1_5_score > 0.5,  # Use F-1.5 as primary metric
            )

            return result
        except Exception as e:
            return TestResult(
                test_case=test_case,
                system_name="kg_enhanced",
                response=f"ERROR: {str(e)}",
                response_time=0.0,
                tokens_used=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                f1_5_score=0.0,
                passed=False,
                errors=[str(e)],
            )

    def test_legacy_rag_system(
        self,
        test_case: TestCase,
        kg_data: dict[str, Any],
        sbom_context: str,
        rag_system: Any,
    ) -> TestResult:
        """Test the legacy RAG system on a test case."""
        try:
            start_time = time.time()

            # Mock mode: return simulated response
            if self.mock_mode:
                response_time = 0.3  # Simulate fast response
                response = f"🎭 Mock RAG response for '{test_case.question}': Based on vector similarity search, found relevant vulnerabilities in components A, B with CVE-2023-99999."

                evaluation_result = self.evaluator.evaluate_response(
                    test_case, response, kg_data, "legacy_rag"
                )

                return TestResult(
                    test_case=test_case,
                    system_name="legacy_rag",
                    response=response,
                    response_time=response_time,
                    tokens_used=80,  # Mock token usage
                    precision=evaluation_result.get("precision", 0.75),  # Mock metrics
                    recall=evaluation_result.get("recall", 0.65),
                    f1_score=evaluation_result.get("f1_score", 0.70),
                    f1_5_score=evaluation_result.get("f1_5_score", 0.68),
                    passed=True,
                )

            # Real mode: actual RAG system
            # Override model if specified
            if self.model_override:
                rag_system.chat_model = self.model_override

            result = rag_system.query(
                test_case.question,
                top_k=5,
                sbom_context=sbom_context,
                stream=self.enable_streaming,
                verbose=self.enable_streaming,
            )
            response = result.get("answer", "No response generated")
            response_time = time.time() - start_time

            evaluation_result = self.evaluator.evaluate_response(
                test_case, response, kg_data, "legacy_rag"
            )

            if self.save_detailed:
                log_entry = {
                    "test_case_id": test_case.id,
                    "system_type": "legacy_rag",
                    "question": test_case.question,
                    "category": test_case.category,
                    "difficulty": test_case.difficulty,
                    "expected_elements": test_case.expected_elements,
                    "function_calls": [],  # Legacy RAG doesn't use function calls
                    "function_call_results": [],
                    "response": response,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat(),
                    "evaluation_result": evaluation_result,
                    "retrieved_documents": result.get("retrieved_documents", []),
                    "similarities": result.get("similarities", []),
                    "model_used": self.model_override or "gpt-4o",  # Track which model was used
                }
                self.detailed_logs.append(log_entry)

            result = TestResult(
                test_case=test_case,
                system_name="legacy_rag",
                response=response,
                response_time=response_time,
                tokens_used=0,  # TODO: Track actual tokens used
                citation_metrics=evaluation_result.get("citation_metrics", {}),
                precision=evaluation_result.get("precision", 0.0),
                recall=evaluation_result.get("recall", 0.0),
                f1_score=evaluation_result.get("f1_score", 0.0),
                f1_5_score=evaluation_result.get("f1_5_score", 0.0),
                passed=evaluation_result.get("f1_5_score", 0.0)
                > 0.5,  # Use F-1.5 as primary metric
            )

            return result
        except Exception as e:
            return TestResult(
                test_case=test_case,
                system_name="legacy_rag",
                response=f"ERROR: {str(e)}",
                response_time=0.0,
                tokens_used=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                f1_5_score=0.0,
                passed=False,
                errors=[str(e)],
            )

    def test_standalone_system(
        self,
        test_case: TestCase,
        kg_data: dict[str, Any],
        sbom_context: str,
    ) -> TestResult:
        """Test standalone LLM system on a test case."""
        try:
            start_time = time.time()

            # Mock mode: return simulated response
            if self.mock_mode:
                response_time = 0.8  # Simulate slower response (no KG help)
                response = f"🎭 Mock Standalone response for '{test_case.question}': Based on SBOM analysis, identified potential security concerns in components without specific CVE citations."

                evaluation_result = self.evaluator.evaluate_response(
                    test_case, response, kg_data, "standalone"
                )

                return TestResult(
                    test_case=test_case,
                    system_name="standalone",
                    response=response,
                    response_time=response_time,
                    tokens_used=120,  # Mock token usage (higher due to less efficient prompting)
                    precision=evaluation_result.get(
                        "precision", 0.60
                    ),  # Mock metrics (lower than KG-enhanced)
                    recall=evaluation_result.get("recall", 0.45),
                    f1_score=evaluation_result.get("f1_score", 0.52),
                    f1_5_score=evaluation_result.get("f1_5_score", 0.49),
                    passed=True,
                )

            # Real mode: actual OpenAI API call
            import os

            from openai import OpenAI

            from ...shared.streaming import stream_openai_response

            # Use model override if specified, otherwise default to gpt-4o
            model_to_use = self.model_override or "gpt-4o"

            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

            system_prompt = get_standalone_system_prompt()
            user_prompt = get_standalone_user_prompt(sbom_context, test_case.question)

            try:
                # Try streaming first
                completion_params = {
                    "model": model_to_use,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": True,
                }

                # Some models like o3-mini don't support certain parameters
                if not model_to_use.startswith("o3"):
                    completion_params["temperature"] = 0.7
                    completion_params["max_tokens"] = 1000

                response_stream = client.chat.completions.create(**completion_params)
                response_text = stream_openai_response(
                    response_stream, "🤖", enable_streaming=self.enable_streaming
                )

                # Check if we got a valid response
                if not response_text or response_text.startswith("Error:"):
                    raise Exception("Streaming failed or returned error")

            except Exception:
                # Fallback to non-streaming
                if self.enable_streaming:
                    print(f"⚠️  Streaming failed with {model_to_use}, trying non-streaming...")

                try:
                    completion_params = {
                        "model": model_to_use,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "stream": False,
                    }

                    # Some models like o3-mini don't support certain parameters
                    if not model_to_use.startswith("o3"):
                        completion_params["temperature"] = 0.7
                        completion_params["max_tokens"] = 1000

                    response = client.chat.completions.create(**completion_params)
                    response_text = response.choices[0].message.content or "No response generated."
                except Exception as non_stream_error:
                    # Model might not be compatible at all
                    response_text = (
                        f"Model {model_to_use} compatibility error: {str(non_stream_error)}"
                    )
                    if self.enable_streaming:
                        print(
                            f"❌ Model {model_to_use} failed completely: {str(non_stream_error)[:100]}..."
                        )

            response_time = time.time() - start_time

            evaluation_result = self.evaluator.evaluate_response(
                test_case, response_text, kg_data, "standalone"
            )

            if self.save_detailed:
                log_entry = {
                    "test_case_id": test_case.id,
                    "system_type": "standalone",
                    "question": test_case.question,
                    "category": test_case.category,
                    "difficulty": test_case.difficulty,
                    "expected_elements": test_case.expected_elements,
                    "response": response_text,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat(),
                    "evaluation_result": evaluation_result,
                    "model_used": model_to_use,
                }
                self.detailed_logs.append(log_entry)

            return TestResult(
                test_case=test_case,
                system_name="standalone",
                response=response_text,
                response_time=response_time,
                tokens_used=0,  # TODO: Track actual tokens used
                citation_metrics=evaluation_result.get("citation_metrics", {}),
                precision=evaluation_result.get("precision", 0.0),
                recall=evaluation_result.get("recall", 0.0),
                f1_score=evaluation_result.get("f1_score", 0.0),
                f1_5_score=evaluation_result.get("f1_5_score", 0.0),
                passed=evaluation_result.get("f1_5_score", 0.0)
                > 0.5,  # Use F-1.5 as primary metric
            )
        except Exception as e:
            # Even if everything fails, return a proper TestResult
            error_msg = (
                f"Standalone system test failed with {self.model_override or 'gpt-4o'}: {str(e)}"
            )
            if self.enable_streaming:
                print(f"❌ {error_msg}")

            return TestResult(
                test_case=test_case,
                system_name="standalone",
                response=error_msg,
                response_time=0.0,
                tokens_used=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                f1_5_score=0.0,
                passed=False,
                errors=[str(e)],
            )
