"""Control Plane: deterministic code only. Orchestrator, resolvers, policy,
capability broker, tool gateway and audit all live in one FastAPI modular
monolith and talk via in-process function calls (ARCHITECTURE.md §2)."""
