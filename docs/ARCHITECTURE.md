# Architecture v0.1
Start with a modular MVP: FastAPI + PostgreSQL + Neo4j + connector SDK.
Keep an event boundary so Kafka can be introduced without changing the public event model.
Security intelligence is the core; scanners remain external integrations.
