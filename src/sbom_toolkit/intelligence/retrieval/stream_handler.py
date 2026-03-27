import json
import sys
from typing import Any


class StreamHandler:
    """
    Handles streaming responses from OpenAI API, including processing tool calls
    and real-time content display.
    """

    def __init__(self):
        """Initialize the stream handler."""
        pass

    def handle_streaming_response(self, stream, stream_enabled: bool = True):
        """Handle streaming response from OpenAI API."""

        # Create mock classes that are compatible with OpenAI message format
        class MockMessage:
            def __init__(self, content: str, tool_calls=None):
                self.content = content
                self.tool_calls = tool_calls if tool_calls else None
                self.role = "assistant"

        class MockChoice:
            def __init__(self, content: str, tool_calls=None):
                self.message = MockMessage(content, tool_calls)

        class MockResponse:
            def __init__(self, content: str, tool_calls=None):
                self.choices = [MockChoice(content, tool_calls)]

        collected_content = ""
        accumulated_tool_calls = {}

        # Import the global progress manager to coordinate with streaming
        progress_manager: Any | None = None
        try:
            from ...shared.streaming import progress_manager as _progress_manager

            if stream_enabled:
                _progress_manager.start_streaming()
            progress_manager = _progress_manager
        except ImportError:
            progress_manager = None

        # Process stream in real-time
        try:
            for chunk in stream:
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
                                        accumulated_tool_calls[tool_call_id]["function"][
                                            "name"
                                        ] += tool_call_delta.function.name
                                    if (
                                        hasattr(tool_call_delta.function, "arguments")
                                        and tool_call_delta.function.arguments
                                    ):
                                        accumulated_tool_calls[tool_call_id]["function"][
                                            "arguments"
                                        ] += tool_call_delta.function.arguments

                    # Handle content streaming (print immediately for real-time effect)
                    if hasattr(choice, "delta") and choice.delta and choice.delta.content:
                        content = choice.delta.content
                        collected_content += content
                        if stream_enabled:
                            sys.stdout.write(content)
                            sys.stdout.flush()
        except Exception:
            # Silently handle stream errors
            pass

        # Signal end of streaming
        try:
            if stream_enabled and progress_manager:
                progress_manager.end_streaming()
        except Exception as e:
            print(f"Error in stream handler: {e}")
            raise e

        if stream_enabled and collected_content:
            sys.stdout.write("\n")  # Add newline after streaming content
            sys.stdout.flush()

        # Convert accumulated tool calls to proper format
        final_tool_calls = None
        if accumulated_tool_calls:
            # Create mock tool call objects
            class MockFunction:
                def __init__(self, name, arguments):
                    self.name = name
                    self.arguments = arguments

            class MockToolCall:
                def __init__(self, tool_id, function):
                    self.id = tool_id
                    self.function = function
                    self.type = "function"

            final_tool_calls = []
            for tool_id, tool_data in accumulated_tool_calls.items():
                # Only include tool calls with valid function names and arguments
                func_name = tool_data["function"]["name"]
                func_args = tool_data["function"]["arguments"]

                # Skip if function name is empty
                if not func_name:
                    continue

                # Ensure arguments are valid JSON, default to empty object if not
                if not func_args or not func_args.strip():
                    func_args = "{}"
                else:
                    # Validate that arguments are valid JSON
                    try:
                        json.loads(func_args)
                    except (json.JSONDecodeError, TypeError):
                        # If invalid JSON, try to fix common issues or default to empty
                        func_args = "{}"

                mock_function = MockFunction(func_name, func_args)
                mock_tool_call = MockToolCall(tool_id, mock_function)
                final_tool_calls.append(mock_tool_call)

        # Return a properly formatted response object
        return MockResponse(collected_content, final_tool_calls)
