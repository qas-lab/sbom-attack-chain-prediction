import json
import os
import sys

import click

from sbom_toolkit.intelligence.retrieval.mcp_system_refactored import MCPSystemRefactored


@click.command(name="mcp-chat")
@click.option(
    "--kg-file",
    "-k",
    type=str,
    required=True,
    help="Path to the pre-built knowledge graph JSON file.",
)
@click.option(
    "--no-stream",
    is_flag=True,
    help="Disable streaming output (show complete response at once)",
)
def mcp_chat_command(kg_file: str, no_stream: bool) -> None:
    """
    MCP-powered interactive chat interface with direct knowledge graph access and chat history.

    This command uses the MCP (Model Context Protocol) system that gives the LLM direct access to query
    the knowledge graph through function calls and maintains conversation history.
    The LLM can use its previous responses as context for follow-up questions.

    By default, responses stream in real-time to show tokens as they're generated.
    Use --no-stream to disable streaming and show complete responses at once.

    Example questions:
    - "What vulnerabilities are in flask?"
    - "Show me an overview of this SBOM"
    - "Based on our previous discussion, what are the most critical issues?"
    - "Can you elaborate on the attack chains we identified earlier?"
    """
    print("\nStarting MCP Chat with Memory...")

    if no_stream:
        print("🔧 Streaming disabled - responses will appear all at once")
    else:
        print("⚡ Streaming enabled - you'll see tokens appear in real-time")

    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable not set.")
        print(
            "The mcp-chat command requires an OpenAI API key to provide conversational AI analysis."
        )
        print("Please set your OpenAI API key:")
        print("  export OPENAI_API_KEY='your-api-key-here'")
        return

    # Load knowledge graph
    kg_path = os.path.abspath(kg_file)
    if not os.path.exists(kg_path):
        print(f"Error: Knowledge graph file not found at {kg_path}")
        return

    try:
        with open(kg_path) as f:
            kg_data = json.load(f)
        print(f"Loaded knowledge graph from {kg_path}")
    except Exception as e:
        print(f"Error loading knowledge graph from {kg_path}: {e}")
        return

    # Initialize MCP system and load KG
    mcp_system = MCPSystemRefactored()
    mcp_system.load_knowledge_graph(kg_data)

    print("✅ MCP system ready with knowledge graph + AI analysis + chat history")
    print("🧠 The LLM can now access previous conversation context and build upon earlier analysis")
    print(
        "💡 Try asking: 'What vulnerabilities are in this SBOM?' followed by 'What did we find earlier?'"
    )
    print("🔚 Type 'quit', 'exit', or press Ctrl+C to exit\n")

    # Check if input is piped
    is_piped = not sys.stdin.isatty()

    while True:
        try:
            if is_piped:
                # Read from pipe
                question = sys.stdin.readline()
                if not question.strip():
                    break
                question = question.strip()
                print(f"🔍 Processing: {question}")
            else:
                question = input("\nYour question: ").strip()

            if question.lower() in ["quit", "exit", "q"]:
                break

            if not question:
                print("Please enter a question or type 'quit' to exit.")
                continue

        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        try:
            # Use MCP system with streaming support
            stream_enabled = not no_stream
            response = mcp_system.chat_with_kg_access(question, stream=stream_enabled)

            # Only print the response if streaming was disabled (since streaming prints as it goes)
            if no_stream:
                print(f"\n🤖 {response}")

        except Exception as e:
            print(f"An error occurred during query processing: {e}")
            import traceback

            traceback.print_exc()
