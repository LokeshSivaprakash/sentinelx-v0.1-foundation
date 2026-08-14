from app.db.postgres import Base, engine
from app.models.db_models import SecurityEventRecord, SecurityIncidentRecord


def init_database():
    Base.metadata.create_all(bind=engine)
    print("SentinelX database initialized.")


if __name__ == "__main__":
    init_database()