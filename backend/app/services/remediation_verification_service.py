from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import SecurityIncidentRecord


def verify_remediation(
    db: Session,
    incident_id: UUID,
    package: str,
    previous_version: str,
    remediated_version: str,
    verification_methods: list[str],
) -> dict:
    """
    Record remediation verification for an incident.

    This does not automatically mark the incident as resolved.
    Verification must be explicitly recorded before closure.
    """

    statement = select(
        SecurityIncidentRecord
    ).where(
        SecurityIncidentRecord.incident_id
        == incident_id
    )

    incident = (
        db.execute(statement)
        .scalars()
        .first()
    )

    if not incident:
        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    metadata = (
        dict(incident.incident_metadata or {})
    )

    verification = {
        "status": "verified",
        "package": package,
        "previous_version": previous_version,
        "remediated_version": remediated_version,
        "verification_methods": verification_methods,
        "verified_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    metadata["remediation_verification"] = (
        verification
    )

    incident.incident_metadata = metadata

    db.commit()
    db.refresh(incident)

    return {
        "incident_id": str(
            incident.incident_id
        ),
        "resource_id": incident.resource_id,
        "verification": verification,
        "incident_status": incident.status,
    }