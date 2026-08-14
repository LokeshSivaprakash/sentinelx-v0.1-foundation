from sqlalchemy.orm import Session

from app.models.db_models import (
    SecurityEventRecord,
    SecurityIncidentRecord,
)
from app.models.events import SecurityEvent
from app.services.detection_service import (
    detect_event,
)
from app.services.incident_service import (
    correlate_detections_to_incident,
)
from app.services.neo4j_service import (
    create_security_graph,
)
from app.services.soc_automation_service import (
    run_soc_playbook,
)


def save_event(
    db: Session,
    event: SecurityEvent,
) -> tuple[SecurityEventRecord, bool]:
    """
    Persist a security event and trigger the SentinelX
    detection → incident → SOC automation pipeline.

    Returns:
        (SecurityEventRecord, created)
    """

    # =========================================================
    # Idempotency check
    # =========================================================

    existing_record = (
        db.query(SecurityEventRecord)
        .filter(
            SecurityEventRecord.event_id
            == event.event_id
        )
        .first()
    )

    if existing_record:
        return existing_record, False

    # =========================================================
    # Create database event record
    # =========================================================

    record = SecurityEventRecord(
        event_id=event.event_id,
        schema_version=event.schema_version,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        timestamp=event.timestamp,
        tenant_id=event.tenant_id,
        resource=event.resource.model_dump(),
        finding=(
            event.finding.model_dump()
            if event.finding
            else None
        ),
        evidence=event.evidence,
        relationships=event.relationships,
        event_metadata=event.metadata,
        raw_reference=event.raw_reference,
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    # =========================================================
    # Build / update Neo4j security graph
    # =========================================================

    create_security_graph(event)

    # =========================================================
    # Detection engine
    # =========================================================

    detection_result = detect_event(
        event,
        db,
    )

    # =========================================================
    # Detection → Incident → SOC automation
    # =========================================================

    if detection_result.detection_count > 0:

        incident = (
            correlate_detections_to_incident(
                db,
                event.resource.id,
            )
        )

        # -----------------------------------------------------
        # Retrieve the database incident record
        # -----------------------------------------------------

        incident_record = (
            db.query(
                SecurityIncidentRecord
            )
            .filter(
                SecurityIncidentRecord.incident_id
                == incident.incident_id
            )
            .first()
        )

        # -----------------------------------------------------
        # Trigger SOC playbook
        # -----------------------------------------------------

        if incident_record:
            run_soc_playbook(
                db,
                incident_record,
            )

    return record, True