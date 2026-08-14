import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# Project root:
# sentinelx-v0.1-foundation/
PROJECT_ROOT = Path(__file__).resolve().parents[3]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        f"DATABASE_URL environment variable is required. "
        f"Expected .env at: {ENV_FILE}"
    )


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def init_db() -> None:
    # Import models so SQLAlchemy registers their tables
    from app.models.db_models import (
        SecurityEventRecord,
        SecurityIncidentRecord,
        SecurityDetectionRecord,
        SecurityAutomationActionRecord,
    )

    Base.metadata.create_all(
        bind=engine
    )