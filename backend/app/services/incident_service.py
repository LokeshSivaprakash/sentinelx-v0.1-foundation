from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import (
    SecurityDetectionRecord,
    SecurityEventRecord,
    SecurityIncidentRecord,
)
from app.models.incidents import (
    CorrelatedEvent,
    IncidentUpdate,
    SecurityIncident,
)
from app.services.incident_enrichment_service import (
    enrich_incident_from_cve,
)

# ============================================================
# EVENT → INCIDENT CORRELATION
# ============================================================

def correlate_resource_events(
    db: Session,
    resource_id: str,
    window_minutes: int = 60,
) -> SecurityIncident:
    """
    Correlate security events for the same resource
    within a time window.
    """

    cutoff = (
        datetime.now(UTC)
        - timedelta(minutes=window_minutes)
    )

    statement = (
        select(SecurityEventRecord)
        .where(
            SecurityEventRecord.timestamp >= cutoff,
            SecurityEventRecord.resource["id"].as_string()
            == resource_id,
        )
        .order_by(
            SecurityEventRecord.timestamp.asc()
        )
    )

    records = (
        db.execute(statement)
        .scalars()
        .all()
    )

    if not records:
        raise ValueError(
            f"No security events found for resource: "
            f"{resource_id}"
        )

    events = [
        CorrelatedEvent(
            event_id=record.event_id,
            event_type=record.event_type,
            severity=record.severity,
            timestamp=record.timestamp,
            source=record.source,
        )
        for record in records
    ]

    # ---------------------------------------------------------
    # Determine incident severity
    # ---------------------------------------------------------

    severities = {
        event.severity
        for event in events
    }

    if "critical" in severities:
        incident_severity = "critical"

    elif "high" in severities:
        incident_severity = "high"

    elif "medium" in severities:
        incident_severity = "medium"

    elif "low" in severities:
        incident_severity = "low"

    else:
        incident_severity = "informational"

    # ---------------------------------------------------------
    # Serialize events
    # ---------------------------------------------------------

    event_payload = [
        event.model_dump(mode="json")
        for event in events
    ]

    # ---------------------------------------------------------
    # Incident metadata
    # ---------------------------------------------------------

    incident_metadata = {
        "correlation_rule": "same_resource",
        "window_minutes": window_minutes,
    }

    # ---------------------------------------------------------
    # Find existing unresolved incident
    # ---------------------------------------------------------

    existing_statement = (
        select(SecurityIncidentRecord)
        .where(
            SecurityIncidentRecord.resource_id
            == resource_id,
            SecurityIncidentRecord.status
            != "resolved",
        )
        .order_by(
            SecurityIncidentRecord.created_at.desc()
        )
    )

    existing_incident = (
        db.execute(existing_statement)
        .scalars()
        .first()
    )

    # ---------------------------------------------------------
    # Update existing incident
    # ---------------------------------------------------------

    if existing_incident:

        existing_incident.severity = (
            incident_severity
        )

        existing_incident.event_count = (
            len(events)
        )

        existing_incident.events = (
            event_payload
        )

        existing_incident.incident_metadata = (
            incident_metadata
        )

        db.commit()
        db.refresh(existing_incident)

        return SecurityIncident(
            incident_id=(
                existing_incident.incident_id
            ),
            severity=(
                existing_incident.severity
            ),
            status=(
                existing_incident.status
            ),
            resource_id=(
                existing_incident.resource_id
            ),
            resource_type=(
                existing_incident.resource_type
            ),
            event_count=(
                existing_incident.event_count
            ),
            events=events,
            metadata=(
                existing_incident.incident_metadata
            ),
        )

    # ---------------------------------------------------------
    # Create new incident
    # ---------------------------------------------------------

    incident = SecurityIncidentRecord(
        incident_id=uuid4(),
        severity=incident_severity,
        status="open",
        resource_id=resource_id,
        resource_type="container_image",
        event_count=len(events),
        events=event_payload,
        incident_metadata=incident_metadata,
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return SecurityIncident(
        incident_id=incident.incident_id,
        severity=incident.severity,
        status=incident.status,
        resource_id=incident.resource_id,
        resource_type=incident.resource_type,
        event_count=incident.event_count,
        events=events,
        metadata=incident.incident_metadata,
    )


# ============================================================
# DETECTION → INCIDENT CORRELATION
# ============================================================

def correlate_detections_to_incident(
    db: Session,
    resource_id: str,
) -> SecurityIncident:
    """
    Correlate persisted detections for a resource
    into an incident.

    The incident is enriched with Neo4j intelligence
    using CVEs extracted from detection evidence.
    """

    detection_statement = (
        select(SecurityDetectionRecord)
        .where(
            SecurityDetectionRecord.resource_id
            == resource_id
        )
        .order_by(
            SecurityDetectionRecord.created_at.asc()
        )
    )

    detections = (
        db.execute(detection_statement)
        .scalars()
        .all()
    )

    if not detections:
        raise ValueError(
            f"No detections found for resource: "
            f"{resource_id}"
        )

    # ---------------------------------------------------------
    # Determine incident severity
    # ---------------------------------------------------------

    severities = {
        detection.severity
        for detection in detections
    }

    if "critical" in severities:
        incident_severity = "critical"

    elif "high" in severities:
        incident_severity = "high"

    elif "medium" in severities:
        incident_severity = "medium"

    elif "low" in severities:
        incident_severity = "low"

    else:
        incident_severity = "informational"

    # ---------------------------------------------------------
    # Calculate aggregate risk
    # ---------------------------------------------------------

    risk_scores = [
        detection.risk_score
        for detection in detections
        if detection.risk_score is not None
    ]

    max_risk_score = (
        max(risk_scores)
        if risk_scores
        else 0
    )

    average_risk_score = (
        round(
            sum(risk_scores)
            / len(risk_scores),
            2,
        )
        if risk_scores
        else 0
    )

    # ---------------------------------------------------------
    # Extract CVEs from detection evidence
    # ---------------------------------------------------------

    cves: set[str] = set()

    for detection in detections:

        evidence = (
            detection.evidence
            or {}
        )

        cve = evidence.get("cve")

        if cve:
            cves.add(cve)

    # ---------------------------------------------------------
    # Neo4j intelligence enrichment
    # ---------------------------------------------------------

    intelligence: dict[str, dict] = {}

    for cve in cves:

        try:
            intelligence[cve] = (
                enrich_incident_from_cve(cve)
            )

        except Exception as exc:  # noqa: BLE001

            # Graph intelligence must never
            # prevent incident creation.

            intelligence[cve] = {
                "error": str(exc),
                "attack_path_count": 0,
                "blast_radius": {
                    "affected_assets": 0,
                    "affected_services": 0,
                    "affected_images": 0,
                },
                "attack_path": [],
                "blast_radius_results": [],
            }

    # ---------------------------------------------------------
    # Build detection payload
    # ---------------------------------------------------------

    detection_payload = [
        {
            "detection_id": (
                detection.detection_id
            ),
            "event_id": str(
                detection.event_id
            ),
            "rule_name": (
                detection.rule_name
            ),
            "severity": (
                detection.severity
            ),
            "resource_id": (
                detection.resource_id
            ),
            "resource_type": (
                detection.resource_type
            ),
            "risk_score": (
                detection.risk_score
            ),
            "description": (
                detection.description
            ),
            "evidence": (
                detection.evidence
            ),
            "recommended_action": (
                detection.recommended_action
            ),
            "created_at": (
                detection.created_at.isoformat()
                if detection.created_at
                else None
            ),
        }
        for detection in detections
    ]

    # ---------------------------------------------------------
    # Incident metadata
    # ---------------------------------------------------------

    incident_metadata = {
        "correlation_rule": (
            "same_resource_detections"
        ),
        "detection_count": (
            len(detections)
        ),
        "max_risk_score": (
            max_risk_score
        ),
        "average_risk_score": (
            average_risk_score
        ),
        "intelligence": intelligence,
    }

    # ---------------------------------------------------------
    # Find existing unresolved incident
    # ---------------------------------------------------------

    existing_statement = (
        select(SecurityIncidentRecord)
        .where(
            SecurityIncidentRecord.resource_id
            == resource_id,
            SecurityIncidentRecord.status
            != "resolved",
        )
        .order_by(
            SecurityIncidentRecord.created_at.desc()
        )
    )

    existing_incident = (
        db.execute(existing_statement)
        .scalars()
        .first()
    )

    # ---------------------------------------------------------
    # Update existing incident
    # ---------------------------------------------------------

    if existing_incident:

        existing_incident.severity = (
            incident_severity
        )

        existing_incident.event_count = (
            len(detections)
        )

        existing_incident.events = (
            detection_payload
        )

        existing_incident.incident_metadata = (
            incident_metadata
        )

        db.commit()
        db.refresh(existing_incident)

        return SecurityIncident(
            incident_id=(
                existing_incident.incident_id
            ),
            severity=(
                existing_incident.severity
            ),
            status=(
                existing_incident.status
            ),
            resource_id=(
                existing_incident.resource_id
            ),
            resource_type=(
                existing_incident.resource_type
            ),
            event_count=(
                existing_incident.event_count
            ),
            # Detection payloads are NOT
            # CorrelatedEvent objects.
            events=[],
            metadata=(
                existing_incident.incident_metadata
            ),
        )

    # ---------------------------------------------------------
    # Create new incident
    # ---------------------------------------------------------

    incident = SecurityIncidentRecord(
        incident_id=uuid4(),
        severity=incident_severity,
        status="open",
        resource_id=resource_id,
        resource_type="container_image",
        event_count=len(detections),
        events=detection_payload,
        incident_metadata=incident_metadata,
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return SecurityIncident(
        incident_id=incident.incident_id,
        severity=incident.severity,
        status=incident.status,
        resource_id=incident.resource_id,
        resource_type=incident.resource_type,
        event_count=incident.event_count,
        events=[],
        metadata=incident.incident_metadata,
    )


# ============================================================
# INCIDENT UPDATE
# ============================================================

def update_incident(
    db: Session,
    incident_id: UUID,
    update: IncidentUpdate,
) -> SecurityIncident:
    """
    Update an incident while enforcing:

    1. Valid incident status transitions.
    2. Remediation verification before resolution.
    3. Resolution text only when resolved.
    """

    # =========================================================
    # Find incident
    # =========================================================

    statement = (
        select(SecurityIncidentRecord)
        .where(
            SecurityIncidentRecord.incident_id
            == incident_id
        )
    )

    incident = (
        db.execute(statement)
        .scalars()
        .first()
    )

    if not incident:
        raise ValueError(
            f"Incident not found: "
            f"{incident_id}"
        )

    # =========================================================
    # Current/requested status
    # =========================================================

    current_status = incident.status
    requested_status = update.status

    # =========================================================
    # Allowed transitions
    # =========================================================

    allowed_transitions = {
        "open": {
            "open",
            "investigating",
        },
        "investigating": {
            "investigating",
            "contained",
        },
        "contained": {
            "contained",
            "resolved",
        },
        "resolved": {
            "resolved",
        },
    }

    # =========================================================
    # Validate status transition
    # =========================================================

    if requested_status is not None:

        allowed_statuses = (
            allowed_transitions.get(
                current_status,
                set(),
            )
        )

        if (
            requested_status
            not in allowed_statuses
        ):
            raise ValueError(
                "Invalid incident status "
                "transition: "
                f"{current_status} -> "
                f"{requested_status}"
            )

        # =====================================================
        # Remediation verification gate
        # =====================================================

        if (
            requested_status == "resolved"
            and current_status != "resolved"
        ):

            metadata = (
                incident.incident_metadata
                or {}
            )

            verification = (
                metadata.get(
                    "remediation_verification"
                )
                or {}
            )

            if (
                verification.get("status")
                != "verified"
            ):
                raise ValueError(
                    "Incident cannot be resolved "
                    "until remediation is verified."
                )

        incident.status = requested_status

    # =========================================================
    # Analyst notes
    # =========================================================

    if update.analyst_notes is not None:

        incident.analyst_notes = (
            update.analyst_notes
        )

    # =========================================================
    # Resolution
    # =========================================================

    if update.resolution is not None:

        if incident.status != "resolved":
            raise ValueError(
                "Resolution can only be provided "
                "when the incident is resolved."
            )

        incident.resolution = (
            update.resolution
        )

    # =========================================================
    # Commit changes
    # =========================================================

    db.commit()
    db.refresh(incident)

    # =========================================================
    # Return API model
    #
    # Detection-driven incidents store detection
    # payloads in the events JSON field.
    #
    # Those are NOT CorrelatedEvent objects.
    # The investigation endpoint retrieves the
    # underlying SecurityEventRecord objects separately.
    # =========================================================

    return SecurityIncident(
        incident_id=incident.incident_id,
        severity=incident.severity,
        status=incident.status,
        resource_id=incident.resource_id,
        resource_type=incident.resource_type,
        event_count=incident.event_count,
        events=[],
        metadata=(
            incident.incident_metadata
            or {}
        ),
    )