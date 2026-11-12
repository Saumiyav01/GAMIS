# ADR-0002: Standard-library-only P0; dependencies added per phase
Status: Accepted
Context: P0 needs only deterministic data, doubles, and a harness. Pydantic, SQLAlchemy, FastAPI are required later.
Decision: P0 core has zero runtime dependencies; each framework is added in the phase that first needs it (Pydantic P1,
SQLAlchemy/PostgreSQL P2, FastAPI P11). Tests use `unittest.TestCase` so they run with or without pytest.
Consequences: P0 runs anywhere with Python 3.12. P1 schemas will be Pydantic v2 as specified.
