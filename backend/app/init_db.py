import app.models.db_models  # noqa: F401
from app.db.postgres import Base, engine


def init_database():
    Base.metadata.create_all(bind=engine)
    print("SentinelX database initialized.")


if __name__ == "__main__":
    init_database()