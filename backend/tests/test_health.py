import os

from fastapi.testclient import TestClient

os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///./test.db",
)
os.environ.setdefault(
    "NEO4J_URI",
    "bolt://localhost:7687",
)
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault(
    "NEO4J_PASSWORD",
    "test-password",
)

from app.main import app


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
