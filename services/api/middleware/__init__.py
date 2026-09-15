"""FastMCP middleware hooks on the MCP message path, for the API service.

Anything that owes an HTTP status (e.g. header/body validation, which must
return a real 400) belongs in `services/api/asgi/` instead: a FastMCP
middleware hook cannot set one (see that module's docstring).
"""
