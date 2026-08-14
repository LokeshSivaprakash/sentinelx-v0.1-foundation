import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# Project root:
# sentinelx-v0.1-foundation/
PROJECT_ROOT = Path(__file__).resolve().parents[3]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


NEO4J_URI = os.getenv("NEO4J_URI")

NEO4J_USER = os.getenv("NEO4J_USER")

NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


if not NEO4J_URI:
    raise RuntimeError(
        f"NEO4J_URI environment variable is required. "
        f"Expected .env at: {ENV_FILE}"
    )

if not NEO4J_USER:
    raise RuntimeError(
        "NEO4J_USER environment variable is required"
    )

if not NEO4J_PASSWORD:
    raise RuntimeError(
        "NEO4J_PASSWORD environment variable is required"
    )


driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(
        NEO4J_USER,
        NEO4J_PASSWORD,
    ),
)


def verify_connection() -> bool:
    try:
        driver.verify_connectivity()
        return True
    except Exception:
        return False