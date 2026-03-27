from .mcp_system_refactored import MCPSystemRefactored

# Export only the refactored system - legacy system deprecated
__all__ = ["MCPSystemRefactored"]

# For backward compatibility, alias to the old name
MCPSystem = MCPSystemRefactored
