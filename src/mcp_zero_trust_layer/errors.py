"""Shared exceptions."""


class MCPZTError(Exception):
    """Base exception for MCP Zero Trust Layer."""


class ConfigError(MCPZTError):
    """Raised when configuration cannot be loaded or validated."""


class PolicyError(MCPZTError):
    """Raised when policy evaluation fails."""

