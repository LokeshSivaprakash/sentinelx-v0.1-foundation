import os

os.environ.setdefault(
    "NEO4J_URI",
    "bolt://localhost:7687",
)
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault(
    "NEO4J_PASSWORD",
    "test-password",
)

from app.models.events import SecurityEvent
from app.services.neo4j_service import create_security_graph


def create_test_graph() -> None:
    event = SecurityEvent(
        event_id="11111111-1111-1111-1111-111111111111",
        schema_version="0.1",
        source="manual-test",
        event_type="vulnerability",
        severity="high",
        timestamp="2026-08-11T22:00:00Z",
        tenant_id="local",
        resource={
            "type": "container_image",
            "id": "sentinelx-test:1.0",
            "name": "sentinelx-test",
        },
        finding={
            "id": "CVE-TEST-0001",
            "package": "example-package",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
            "cvss": 8.5,
            "metadata": {},
        },
        evidence=[],
        relationships=[],
        metadata={
            "test": True,
        },
    )
    create_security_graph(event)
    print("SentinelX security graph created.")


if __name__ == "__main__":
    create_test_graph()