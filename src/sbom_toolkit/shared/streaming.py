"""
Unified streaming utilities for LLM responses across different systems.

This module provides consistent streaming behavior for MCP, RAG, and standalone LLM systems
used in the performance testing framework.
"""

import json
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

try:
    from ..cli.output import CLIOutputManager
except ImportError:
    CLIOutputManager = None  # type: ignore


class ProgressManager:
    """Manages dual progress bars without interrupting streaming output."""

    def __init__(self, cli_output: Any = None):
        """Initialize the progress manager."""
        self.cli_output = cli_output
        self.is_streaming = False
        self.queued_updates = []
        self.overall_progress = None
        self.current_task = None
        self.lock = threading.Lock()
        self.last_display_time = 0

    def start_streaming(self):
        """Signal that streaming output has started."""
        with self.lock:
            self.is_streaming = True

    def end_streaming(self):
        """Signal that streaming output has ended and show any queued updates."""
        with self.lock:
            self.is_streaming = False
            self._flush_queued_updates()

    def _flush_queued_updates(self):
        """Show all queued progress updates."""
        if self.queued_updates:
            for update in self.queued_updates:
                if self.cli_output and not self.cli_output.is_quiet:
                    self.cli_output.print_raw(update)
                else:
                    print(update)
            self.queued_updates.clear()

    def _should_display_update(self) -> bool:
        """Check if enough time has passed to display an update (0.5 second throttle)."""
        current_time = time.time()
        if current_time - self.last_display_time >= 0.5:
            self.last_display_time = current_time
            return True
        return False

    def _format_progress_bar(self, current: int, total: int, width: int = 10) -> str:
        """Format a progress bar with the given width."""
        if total <= 0:
            return "[" + "?" * width + "]"

        filled = int((current / total) * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}]"

    def _display_dual_progress(self, force: bool = False):
        """Display both progress bars if appropriate."""
        if not force and not self._should_display_update():
            return

        if not self.overall_progress and not self.current_task:
            return

        lines = []

        if self.overall_progress:
            overall = self.overall_progress
            bar = self._format_progress_bar(overall["current"], overall["total"])
            percentage = (
                (overall["current"] / overall["total"]) * 100 if overall["total"] > 0 else 0
            )
            line = f"Overall Progress: {bar} {overall['current']}/{overall['total']} {overall['item_name']} ({percentage:.1f}%)"
            lines.append(line)

        if self.current_task:
            task = self.current_task
            bar = self._format_progress_bar(task["current"], task["total"])
            percentage = (task["current"] / task["total"]) * 100 if task["total"] > 0 else 0
            line = f"Current Task:     {bar} {task['current']}/{task['total']} {task['item_name']} ({percentage:.1f}%) - {task['name']}"
            lines.append(line)

        if lines:
            message = "\n".join(lines)
            if self.is_streaming:
                self.queued_updates.append(message)
            else:
                if self.cli_output and not self.cli_output.is_quiet:
                    self.cli_output.print_raw(message)
                else:
                    print(message)

    def set_overall_progress(self, operation_name: str, total: int, item_name: str = "items"):
        """Set the overall progress tracking.

        Args:
            operation_name: Name of the overall operation
            total: Total number of items to process
            item_name: Name of items being processed
        """
        with self.lock:
            self.overall_progress = {
                "name": operation_name,
                "total": total,
                "current": 0,
                "item_name": item_name,
            }
            self._display_dual_progress(force=True)

    def set_current_task(self, task_name: str, total: int, item_name: str = "items"):
        """Set the current task progress tracking.

        Args:
            task_name: Name of the current task
            total: Total number of items to process in this task
            item_name: Name of items being processed
        """
        with self.lock:
            self.current_task = {
                "name": task_name,
                "total": total,
                "current": 0,
                "item_name": item_name,
            }
            self._display_dual_progress(force=True)

    def increment_overall_progress(self, amount: int = 1):
        """Increment overall progress counter."""
        with self.lock:
            if not self.overall_progress:
                return

            self.overall_progress["current"] += amount
            self._display_dual_progress()

    def increment_current_task(self, amount: int = 1):
        """Increment current task progress counter."""
        with self.lock:
            if not self.current_task:
                return

            self.current_task["current"] += amount
            self._display_dual_progress()

    def complete_current_task(self, final_message: str | None = None):
        """Complete the current task.

        Args:
            final_message: Optional final message to show
        """
        with self.lock:
            if self.current_task:
                # Set to completed state
                self.current_task["current"] = self.current_task["total"]
                self._display_dual_progress(force=True)

            if final_message:
                if self.is_streaming:
                    self.queued_updates.append(final_message)
                else:
                    # Release lock before printing to avoid blocking other threads
                    self.lock.release()
                    try:
                        if self.cli_output and not self.cli_output.is_quiet:
                            self.cli_output.print_raw(final_message)
                        else:
                            print(final_message)
                    finally:
                        self.lock.acquire()

            self.current_task = None

    def complete_overall_progress(self, final_message: str | None = None):
        """Complete the overall progress.

        Args:
            final_message: Optional final message to show
        """
        with self.lock:
            if self.overall_progress:
                # Set to completed state
                self.overall_progress["current"] = self.overall_progress["total"]
                self._display_dual_progress(force=True)

            if final_message:
                if self.is_streaming:
                    self.queued_updates.append(final_message)
                else:
                    # Release lock before printing to avoid blocking other threads
                    self.lock.release()
                    try:
                        if self.cli_output and not self.cli_output.is_quiet:
                            self.cli_output.print_raw(final_message)
                        else:
                            print(final_message)
                    finally:
                        self.lock.acquire()

            self.overall_progress = None
            self.current_task = None

    def update_progress(self, message: str, force_immediate: bool = False):
        """Update progress with a custom message.

        Args:
            message: Progress message to show
            force_immediate: If True, show immediately even during streaming
        """
        with self.lock:
            if force_immediate or not self.is_streaming:
                if self.cli_output and not self.cli_output.is_quiet:
                    self.cli_output.print_raw(message)
                else:
                    print(message)
            else:
                self.queued_updates.append(message)

    def background_progress(self, message: str):
        """Simple progress update for background threads that bypasses streaming checks."""
        if self.cli_output and not self.cli_output.is_quiet:
            self.cli_output.print_raw(message)
        else:
            print(message)

    # Legacy methods for backward compatibility
    def set_operation(self, operation_name: str, total: int):
        """Legacy method - redirects to set_current_task."""
        self.set_current_task(operation_name, total)

    def increment_progress(
        self, amount: int = 1, item_name: str = "items", background: bool = False
    ):
        """Legacy method - redirects to increment_current_task."""
        self.increment_current_task(amount)

    def complete_operation(self, final_message: str | None = None, background: bool = False):
        """Legacy method - redirects to complete_current_task."""
        self.complete_current_task(final_message)


# Global progress manager instance
progress_manager = ProgressManager()


class StreamingHandler:
    """Handles streaming output for LLM responses with consistent formatting."""

    def __init__(
        self,
        system_name: str = "🤖",
        enable_streaming: bool = True,
        cli_output: Any = None,
    ):
        """
        Initialize the streaming handler.

        Args:
            system_name: Prefix to show before streaming (default: "🤖")
            enable_streaming: Whether to enable streaming output
        """
        self.system_name = system_name
        self.enable_streaming = enable_streaming
        self.cli_output = cli_output
        self.collected_content = ""

    def start_stream(self) -> None:
        """Start streaming by printing the system prefix."""
        if self.enable_streaming:
            progress_manager.start_streaming()

            if self.cli_output and not self.cli_output.is_quiet:
                self.cli_output.print_raw(f"{self.system_name} ", end="", flush=True)
            else:
                # Use consistent output method
                prefix = f"{self.system_name} "
                sys.stdout.write(prefix)
                sys.stdout.flush()

    def stream_chunk(self, content: str) -> None:
        """
        Stream a chunk of content.

        Args:
            content: Text content to stream
        """
        if content:
            self.collected_content += content
            if self.enable_streaming:
                if self.cli_output and not self.cli_output.is_quiet:
                    self.cli_output.print_raw(content, end="", flush=True)
                else:
                    # Use consistent output method
                    if content:
                        sys.stdout.write(content)
                        sys.stdout.flush()

    def end_stream(self) -> None:
        """End streaming by adding a newline."""
        if self.enable_streaming and self.collected_content:
            if self.cli_output and not self.cli_output.is_quiet:
                self.cli_output.print_raw("")  # Add newline after streaming
            else:
                # Use consistent output method
                sys.stdout.write("\n")
                sys.stdout.flush()
        progress_manager.end_streaming()

    def get_collected_content(self) -> str:
        """Get the complete collected content."""
        return self.collected_content

    def reset(self) -> None:
        """Reset the collected content for reuse."""
        self.collected_content = ""


def stream_openai_response(
    response_stream: Iterator[Any],
    system_name: str = "🤖",
    enable_streaming: bool = True,
) -> str:
    """
    Stream an OpenAI response with consistent formatting.
    Enhanced compatibility for different model types including o3-mini.

    Args:
        response_stream: OpenAI streaming response iterator
        system_name: Prefix to show before streaming
        enable_streaming: Whether to enable streaming output

    Returns:
        Complete response text
    """
    handler = StreamingHandler(system_name, enable_streaming)
    handler.start_stream()

    try:
        for chunk in response_stream:
            if chunk.choices and len(chunk.choices) > 0:
                choice = chunk.choices[0]
                # Enhanced compatibility for different model streaming formats
                if hasattr(choice, "delta") and choice.delta:
                    content = None
                    # Try different attribute paths for content
                    if hasattr(choice.delta, "content") and choice.delta.content:
                        content = choice.delta.content
                    elif hasattr(choice.delta, "text") and choice.delta.text:
                        content = choice.delta.text

                    if content:
                        # Filter out excessive newlines that some models produce
                        if content != "\n" or handler.collected_content:
                            handler.stream_chunk(content)
                # Fallback for non-streaming models or different formats
                elif (
                    hasattr(choice, "message")
                    and choice.message
                    and hasattr(choice.message, "content")
                ):
                    content = choice.message.content
                    if content:
                        handler.stream_chunk(content)
                        break  # Complete message received
    except Exception as e:
        # Better error handling with fallback
        if enable_streaming:
            sys.stdout.write(f"\n⚠️  Streaming error: {str(e)[:100]}...")
            sys.stdout.flush()
        # Try to get any accumulated content
        if not handler.get_collected_content():
            # Final fallback for streaming errors
            handler.stream_chunk("Error: Unable to process model response")

    handler.end_stream()
    return handler.get_collected_content()


def stream_openai_response_with_tools(
    response_stream: Iterator[Any],
    system_name: str = "🤖",
    enable_streaming: bool = True,
) -> tuple[str, list[dict[str, Any]] | None]:
    """
    Stream an OpenAI response that may include tool calls.

    Args:
        response_stream: OpenAI streaming response iterator
        system_name: Prefix to show before streaming
        enable_streaming: Whether to enable streaming output

    Returns:
        Tuple of (complete_response_text, tool_calls_list)
    """
    handler = StreamingHandler(system_name, enable_streaming)
    handler.start_stream()

    accumulated_tool_calls = {}

    try:
        for chunk in response_stream:
            if chunk.choices and len(chunk.choices) > 0:
                choice = chunk.choices[0]

                # Handle tool calls (these come in deltas and need to be accumulated)
                if hasattr(choice, "delta") and choice.delta and choice.delta.tool_calls:
                    for tool_call_delta in choice.delta.tool_calls:
                        tool_call_id = getattr(tool_call_delta, "id", None)
                        if tool_call_id:
                            # Initialize if not exists
                            if tool_call_id not in accumulated_tool_calls:
                                accumulated_tool_calls[tool_call_id] = {
                                    "id": tool_call_id,
                                    "type": getattr(tool_call_delta, "type", "function"),
                                    "function": {"name": "", "arguments": ""},
                                }

                            # Accumulate function name and arguments
                            if hasattr(tool_call_delta, "function"):
                                if (
                                    hasattr(tool_call_delta.function, "name")
                                    and tool_call_delta.function.name
                                ):
                                    accumulated_tool_calls[tool_call_id]["function"]["name"] += (
                                        tool_call_delta.function.name
                                    )
                                if (
                                    hasattr(tool_call_delta.function, "arguments")
                                    and tool_call_delta.function.arguments
                                ):
                                    accumulated_tool_calls[tool_call_id]["function"][
                                        "arguments"
                                    ] += tool_call_delta.function.arguments

                # Handle content streaming
                if hasattr(choice, "delta") and choice.delta and choice.delta.content:
                    handler.stream_chunk(choice.delta.content)
    except Exception:
        # Silently handle stream errors
        pass

    handler.end_stream()

    # Convert accumulated tool calls to proper format
    final_tool_calls = None
    if accumulated_tool_calls:
        final_tool_calls = []
        for tool_id, tool_data in accumulated_tool_calls.items():
            func_name = tool_data["function"]["name"]
            func_args = tool_data["function"]["arguments"]

            # Skip if function name is empty
            if not func_name:
                continue

            # Ensure arguments are valid JSON
            if not func_args or not func_args.strip():
                func_args = "{}"
            else:
                try:
                    json.loads(func_args)
                except (json.JSONDecodeError, TypeError):
                    func_args = "{}"

            final_tool_calls.append(
                {
                    "id": tool_id,
                    "type": "function",
                    "function": {"name": func_name, "arguments": func_args},
                }
            )

    return handler.get_collected_content(), final_tool_calls


def stream_non_openai_response(
    response_text: str,
    system_name: str = "🤖",
    enable_streaming: bool = True,
    chunk_size: int = 1,
) -> str:
    """
    Simulate streaming for non-streaming responses (like standalone LLM).

    Args:
        response_text: Complete response text to stream
        system_name: Prefix to show before streaming
        enable_streaming: Whether to enable streaming output
        chunk_size: Size of chunks to simulate streaming

    Returns:
        The same response text
    """
    if not enable_streaming:
        return response_text

    handler = StreamingHandler(system_name, enable_streaming)
    handler.start_stream()

    # Stream the response in chunks
    for i in range(0, len(response_text), chunk_size):
        chunk = response_text[i : i + chunk_size]
        handler.stream_chunk(chunk)
        # Small delay to simulate realistic streaming
        import time

        time.sleep(0.01)

    handler.end_stream()
    return response_text
