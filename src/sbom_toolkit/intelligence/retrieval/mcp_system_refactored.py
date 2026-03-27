import json
import os
import sys
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from openai import OpenAI

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None  # type: ignore[misc,assignment]

from ..prompts import get_mcp_system_prompt
from .component_analyzer import ComponentAnalyzer
from .knowledge_graph_manager import KnowledgeGraphManager
from .mcp_tools import MCPTools
from .query_engine import QueryEngine
from .security_analyzer import SecurityAnalyzer
from .stream_handler import StreamHandler


class MCPSystemRefactored:
    """
    MCP (Model Context Protocol) system that gives the LLM direct access to query the knowledge graph
    through function calling, enabling structured interaction with security data and conversation memory.

    This is a refactored version that separates concerns into focused modules.
    """

    def __init__(self, api_key: str | None = None, require_openai: bool = True):
        """Initialize the MCP system with OpenAI client and modular components"""
        self.chat_model = "gpt-4o"
        self.client: Any | None = None
        self.chat_history: list[dict[str, Any]] = []  # Store conversation history

        # Initialize modular components
        self.kg_manager = KnowledgeGraphManager()
        self.security_analyzer = SecurityAnalyzer(self.kg_manager)
        self.component_analyzer = ComponentAnalyzer(self.kg_manager)
        self.query_engine = QueryEngine(self.kg_manager)
        self.stream_handler = StreamHandler()
        self.mcp_tools = MCPTools(
            self.kg_manager, self.security_analyzer, self.component_analyzer, self.query_engine
        )

        if not OPENAI_AVAILABLE:
            if require_openai:
                raise Exception("OpenAI package not installed. Install with: pip install openai")
            else:
                print("Warning: OpenAI not available. MCP system requires OpenAI.")
                return

        try:
            provided_key = api_key or os.getenv("OPENAI_API_KEY")
            if provided_key and OpenAI is not None:
                self.client = OpenAI(api_key=provided_key)
            elif require_openai:
                raise Exception("OpenAI API key required but not provided")
        except Exception as e:
            if require_openai:
                print(f"Error initializing MCP system: {e}")
                raise
            else:
                print(f"Warning: OpenAI client not initialized: {e}")

    def load_knowledge_graph(self, graph_data: dict[str, Any]):
        """Load a knowledge graph into the system.

        Args:
            graph_data: Dictionary containing 'nodes' and 'edges' of the knowledge graph
        """
        self.kg_manager.load_knowledge_graph(graph_data)

    def get_kg_tools(self) -> list[dict[str, Any]]:
        """Get function definitions for the LLM."""
        return self.mcp_tools.get_kg_tools()

    def execute_kg_function(self, function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a knowledge graph function call."""
        return self.mcp_tools.execute_kg_function(function_name, arguments)

    def chat_with_kg_access(
        self,
        user_question: str | None,
        context: str | None = None,
        stream: bool = True,
    ) -> str:
        """Chat with the user, giving the LLM direct access to query the knowledge graph.

        Args:
            user_question: The user's question
            context: Optional SBOM summary/context to provide as additional user context
            stream: Whether to stream the response tokens in real-time

        Returns:
            The LLM's response after potentially querying the knowledge graph
        """
        if self.client is None:
            return "OpenAI client not available. Cannot process question."

        # Track tool calls for this exchange
        tool_calls_made = []

        # Loop protection variables
        MAX_TOOL_ITERATIONS = 5
        tool_iteration_count = 0
        duplicate_call_tracker = set()
        successful_calls = set()  # Track only successful calls for duplicate detection

        # Get system prompt from centralized management
        system_prompt = get_mcp_system_prompt()
        messages = [{"role": "system", "content": system_prompt}]

        # Include recent chat history so the LLM has context about the ongoing conversation
        if self.chat_history:
            history_limit = 10  # keep the prompt size reasonable
            recent_exchanges = self.chat_history[-history_limit:]
            for past_exchange in recent_exchanges:
                # Reconstruct the dialogue turns
                user_q = past_exchange.get("user_question", "")
                assistant_resp = past_exchange.get("assistant_response", "")
                if user_q:
                    messages.append({"role": "user", "content": user_q})

                # Include tool call outputs from this exchange so the model can reuse them without re-querying
                if past_exchange.get("tool_calls"):
                    for call in past_exchange["tool_calls"]:
                        # Replay the tool result as plain assistant content (avoids needing original tool_call_id)
                        result = call.get("result", {}) if isinstance(call, dict) else {}
                        messages.append({"role": "assistant", "content": json.dumps(result)})

                if assistant_resp:
                    messages.append({"role": "assistant", "content": assistant_resp})

        # Provide static SBOM or other context as a system message so the LLM treats it as reference material
        if context is not None:
            messages.append(
                {
                    "role": "system",
                    "content": f"SBOM context for reference:\n{str(context)}",
                }
            )
        if user_question is None:
            user_question = ""
        messages.append({"role": "user", "content": str(user_question)})
        tools = self.get_kg_tools()

        try:
            # Initial LLM call with tool access
            if stream:
                sys.stdout.write("🤖 ")
                sys.stdout.flush()

            completion_params = {
                "model": self.chat_model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "stream": True,
            }

            # Some models like o3-mini don't support max_tokens parameter
            # Note: We don't add max_tokens for tool calling as it can interfere with function execution

            response_stream = self.client.chat.completions.create(**completion_params)
            response = self.stream_handler.handle_streaming_response(response_stream, stream)

            # Process tool calls with loop protection
            while (
                response
                and response.choices
                and len(response.choices) > 0
                and response.choices[0].message
                and response.choices[0].message.tool_calls
                and tool_iteration_count < MAX_TOOL_ITERATIONS
            ):
                tool_iteration_count += 1

                # Check for duplicate calls - but only prevent duplicates of successful calls
                current_calls = []
                should_break = False
                for tool_call in response.choices[0].message.tool_calls:
                    try:
                        function_name = tool_call.function.name
                        arguments_str = (
                            tool_call.function.arguments.strip()
                            if tool_call.function.arguments
                            else "{}"
                        )
                        call_signature = f"{function_name}({arguments_str})"
                        current_calls.append(call_signature)

                        # Only prevent duplicates if this exact call was previously successful
                        if call_signature in successful_calls:
                            print(f"\n⚠️  Duplicate successful call detected: {call_signature}")
                            print("   Breaking loop to prevent infinite recursion")
                            should_break = True
                            break

                        # Track all calls (including failed ones) to detect true infinite loops
                        if call_signature in duplicate_call_tracker:
                            duplicate_count = list(duplicate_call_tracker).count(call_signature)
                            if duplicate_count >= 3:  # Allow up to 3 attempts for error recovery
                                print(f"\n⚠️  Too many attempts for: {call_signature}")
                                print("   Breaking loop after 3 failed attempts")
                                should_break = True
                                break

                        duplicate_call_tracker.add(call_signature)
                    except Exception:
                        pass  # Continue with processing even if signature creation fails

                if should_break:
                    break
                else:
                    # Only execute tools if no duplicates were found (else clause of for loop)

                    # Add assistant message to conversation in proper format
                    # Convert tool calls to proper dictionary format for OpenAI API
                    tool_calls_dict = []
                    if response.choices[0].message.tool_calls:
                        for tool_call in response.choices[0].message.tool_calls:
                            tool_calls_dict.append(
                                {
                                    "id": tool_call.id,
                                    "type": "function",
                                    "function": {
                                        "name": tool_call.function.name,
                                        "arguments": tool_call.function.arguments,
                                    },
                                }
                            )

                    message_dict = {
                        "role": "assistant",
                        "content": response.choices[0].message.content,
                        "tool_calls": tool_calls_dict,
                    }
                    messages.append(message_dict)

                    # Execute each tool call
                    for tool_call in response.choices[0].message.tool_calls:
                        try:
                            function_name = tool_call.function.name
                            arguments_str = tool_call.function.arguments

                            # Handle empty or incomplete arguments
                            if not arguments_str or not arguments_str.strip():
                                arguments = {}
                                # Only show warning for functions that typically need parameters
                                if function_name in [
                                    "get_cve_details",
                                    "analyze_component",
                                    "get_cwe_details",
                                    "get_capec_details",
                                ]:
                                    print(
                                        f"\n🔍 LLM is calling: {function_name}({arguments}) [⚠️  API provided no arguments - attempting auto-correction]"
                                    )
                                else:
                                    print(f"\n🔍 LLM is calling: {function_name}({arguments})")
                            else:
                                arguments = json.loads(arguments_str)
                                print(f"\n🔍 LLM is calling: {function_name}({arguments})")

                        except Exception as e:
                            print(f"\n❌ Error processing tool call: {e}")
                            print(f"Function name: {getattr(tool_call.function, 'name', 'N/A')}")
                            print(f"Arguments: '{getattr(tool_call.function, 'arguments', 'N/A')}'")

                            # Add error result to continue the conversation
                            result = {"error": f"Failed to parse tool call: {e}"}
                            tool_calls_made.append(
                                {
                                    "tool_call_id": tool_call.id,
                                    "function_name": getattr(tool_call.function, "name", "unknown"),
                                    "arguments": {},
                                    "result": result,
                                }
                            )

                            # Add tool result to conversation
                            tool_result_msg = {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(result),
                            }
                            messages.append(tool_result_msg)
                            continue

                        # Execute the function
                        result = self.execute_kg_function(function_name, arguments)

                        # Print result summary and track successful calls
                        call_signature = f"{function_name}({json.dumps(arguments, sort_keys=True)})"
                        if "error" in result:
                            print(f"   ❌ {result['error']}")
                        else:
                            print("   ✓ Tool executed successfully")
                            # Track this as a successful call to prevent future duplicates
                            successful_calls.add(call_signature)
                            # Show summary of results
                            if "vulnerable_components" in result:
                                print(
                                    f"     Found {len(result['vulnerable_components'])} vulnerable components"
                                )
                            if "cves" in result:
                                print(f"     Found {len(result['cves'])} CVEs")
                            if "cwes" in result:
                                print(f"     Found {len(result['cwes'])} CWEs")

                        # Track this tool call
                        tool_calls_made.append(
                            {
                                "tool_call_id": tool_call.id,
                                "function_name": function_name,
                                "arguments": arguments,
                                "result": result,
                            }
                        )

                        # Add tool result to conversation
                        result_content = json.dumps(result)

                        # WORKAROUND: Truncate very large tool results to prevent LLM overload
                        MAX_TOOL_RESULT_CHARS = 20000  # Reasonable limit for model context
                        if len(result_content) > MAX_TOOL_RESULT_CHARS:
                            # Keep the structure by taking first part and a summary
                            truncated_result = {
                                **{
                                    k: v
                                    for k, v in result.items()
                                    if k
                                    not in [
                                        "citations",
                                        "cve_details",
                                        "cwe_details",
                                        "capec_details",
                                    ]
                                },
                                "truncated": True,
                                "original_size": len(result_content),
                                "note": "Large detailed data truncated for LLM processing",
                            }
                            result_content = json.dumps(truncated_result)

                        tool_result_msg = {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result_content,
                        }
                        messages.append(tool_result_msg)

                    # Get next LLM response with streaming
                    if stream:
                        sys.stdout.write("🤖 ")
                        sys.stdout.flush()

                    try:
                        response_stream = self.client.chat.completions.create(**completion_params)
                        response = self.stream_handler.handle_streaming_response(
                            response_stream, stream
                        )
                    except Exception as e:
                        print(f"\n❌ Error in follow-up LLM call: {e}")
                        break

                    continue  # Continue the while loop

                # If we hit the duplicate call break, exit the while loop
                break

            # Check if we hit the iteration limit
            if tool_iteration_count >= MAX_TOOL_ITERATIONS:
                print(f"\n⚠️  Reached maximum tool call iterations ({MAX_TOOL_ITERATIONS})")
                print("   Proceeding with available data to prevent infinite loops")

            final_response = (
                response.choices[0].message.content
                if response
                and response.choices
                and len(response.choices) > 0
                and response.choices[0].message
                else ""
            )

            # Store this exchange in chat history
            exchange = {
                "user_question": user_question,
                "assistant_response": final_response,
                "timestamp": datetime.now().isoformat(),
                "tool_calls": tool_calls_made,
                "context_provided": context is not None,
                "tool_iterations": tool_iteration_count,
            }
            self.chat_history.append(exchange)

            # Keep only the last 50 exchanges to prevent memory bloat
            if len(self.chat_history) > 50:
                self.chat_history = self.chat_history[-50:]

            return final_response
        except Exception as e:
            # Still track failed exchanges for debugging
            exchange = {
                "user_question": user_question,
                "assistant_response": f"Error: {str(e)}",
                "timestamp": datetime.now().isoformat(),
                "tool_calls": tool_calls_made,
                "context_provided": context is not None,
                "error": True,
            }
            self.chat_history.append(exchange)
            return f"Error processing question: {str(e)}"

    # Convenience methods that delegate to appropriate analyzers
    def analyze_security_comprehensive(self, focus: str = "comprehensive") -> dict[str, Any]:
        """Comprehensive security analysis."""
        return self.security_analyzer.analyze_security_comprehensive(focus)

    def get_vulnerable_components(
        self, min_severity_score: float = 0.0, limit: int = 10, include_paths: bool = True
    ) -> dict[str, Any]:
        """Get vulnerable components with filtering."""
        return self.query_engine.get_vulnerable_components(min_severity_score, limit, include_paths)

    def analyze_component(self, component_name: str) -> dict[str, Any]:
        """Analyze a specific component in detail."""
        return self.component_analyzer.analyze_component(component_name)

    def get_cve_details(self, cve_id: str) -> dict[str, Any]:
        """Get detailed information about a specific CVE."""
        return self.component_analyzer.get_cve_details(cve_id)

    def get_sbom_overview(self) -> dict[str, Any]:
        """Get a high-level overview of the SBOM."""
        return self.query_engine.get_sbom_overview()

    def debug_kg_structure(self, show_sample_data: bool = True) -> dict[str, Any]:
        """Debug function to inspect the knowledge graph structure."""
        return self.kg_manager.debug_kg_structure(show_sample_data)

    def get_chat_history(self, limit: int = 5, include_tool_calls: bool = True) -> dict[str, Any]:
        """Retrieve previous conversation history."""
        if not self.chat_history:
            return {
                "chat_history": [],
                "total_exchanges": 0,
                "message": "No previous conversation history available",
            }

        # Get the most recent exchanges up to the limit
        recent_history = (
            self.chat_history[-limit:] if len(self.chat_history) > limit else self.chat_history
        )

        formatted_history = []
        for past_exchange in recent_history:
            formatted_exchange: dict[str, Any] = {
                "user_question": past_exchange.get("user_question", ""),
                "assistant_response": past_exchange.get("assistant_response", ""),
                "timestamp": past_exchange.get("timestamp", ""),
            }

            if include_tool_calls and past_exchange.get("tool_calls"):
                formatted_exchange["tool_calls"] = past_exchange.get("tool_calls", [])

            formatted_history.append(formatted_exchange)

        return {
            "chat_history": formatted_history,
            "total_exchanges": len(self.chat_history),
            "retrieved_exchanges": len(formatted_history),
            "include_tool_calls": include_tool_calls,
        }
