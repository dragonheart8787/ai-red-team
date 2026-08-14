"""FastAPI routers (engagement, task, approval, report).

This is the ONLY surface agents may call, and it exposes state/task operations
only -- never tools, shell, network, or Registry writes (§2)."""
