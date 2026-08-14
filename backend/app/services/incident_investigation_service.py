from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import (
    SecurityDetectionRecord,
    SecurityEventRecord,
    SecurityIncidentRecord,
)


def get_incident_investigation(
    db: Session,
    incident_id: UUID,
) -> dict:
    # =========================================================
    # Get incident
    # =========================================================

    incident_statement = (
        select(SecurityIncidentRecord)
        .where(
            SecurityIncidentRecord.incident_id
            == incident_id
        )
    )

    incident = (
        db.execute(incident_statement)
        .scalars()
        .first()
    )

    if not incident:
        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    # =========================================================
    # Get detections
    # =========================================================

    detection_statement = (
        select(SecurityDetectionRecord)
        .where(
            SecurityDetectionRecord.resource_id
            == incident.resource_id
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

    # =========================================================
    # Get security events
    # =========================================================

    event_statement = (
        select(SecurityEventRecord)
        .where(
            SecurityEventRecord.resource["id"].as_string()
            == incident.resource_id
        )
        .order_by(
            SecurityEventRecord.timestamp.asc()
        )
    )

    events = (
        db.execute(event_statement)
        .scalars()
        .all()
    )

    # =========================================================
    # Calculate risk
    # =========================================================

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

    # =========================================================
    # Detection summary
    # =========================================================

    detection_summary = {
        "count": len(detections),

        "critical": sum(
            1
            for detection in detections
            if detection.severity == "critical"
        ),

        "high": sum(
            1
            for detection in detections
            if detection.severity == "high"
        ),

        "medium": sum(
            1
            for detection in detections
            if detection.severity == "medium"
        ),

        "low": sum(
            1
            for detection in detections
            if detection.severity == "low"
        ),

        "max_risk_score": max_risk_score,

        "average_risk_score": (
            average_risk_score
        ),
    }

    # =========================================================
    # Serialize detections
    # =========================================================

    detection_results = [
        {
            "detection_id": detection.detection_id,

            "event_id": str(
                detection.event_id
            ),

            "rule_name": detection.rule_name,

            "severity": detection.severity,

            "resource_id": detection.resource_id,

            "resource_type": detection.resource_type,

            "risk_score": detection.risk_score,

            "description": detection.description,

            "evidence": detection.evidence,

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

    # =========================================================
    # Serialize security events
    # =========================================================

    event_results = [
        {
            "event_id": str(
                event.event_id
            ),

            "schema_version": (
                event.schema_version
            ),

            "source": event.source,

            "event_type": event.event_type,

            "severity": event.severity,

            "timestamp": (
                event.timestamp.isoformat()
                if event.timestamp
                else None
            ),

            "tenant_id": event.tenant_id,

            "resource": event.resource,

            "finding": event.finding,

            "evidence": event.evidence,

            "relationships": (
                event.relationships
            ),

            "metadata": event.event_metadata,

            "raw_reference": (
                event.raw_reference
            ),
        }
        for event in events
    ]

    # =========================================================
    # Get Neo4j intelligence
    # =========================================================

    incident_metadata = (
        incident.incident_metadata
        or {}
    )

    intelligence = incident_metadata.get(
        "intelligence",
        {},
    )

    # =========================================================
    # Build analyst summary
    # =========================================================

    primary_cve = None

    internet_exposed = False

    exploit_available = False

    patch_available = False

    affected_assets = 0

    affected_services = 0

    affected_images = 0

    for cve_data in intelligence.values():

        if not primary_cve:
            primary_cve = cve_data.get(
                "cve"
            )

        # -----------------------------------------------------
        # Blast radius counts
        # -----------------------------------------------------

        blast_radius = cve_data.get(
            "blast_radius",
            {},
        )

        affected_assets += blast_radius.get(
            "affected_assets",
            0,
        )

        affected_services += blast_radius.get(
            "affected_services",
            0,
        )

        affected_images += blast_radius.get(
            "affected_images",
            0,
        )

        # -----------------------------------------------------
        # Attack path exposure
        # -----------------------------------------------------

        for path in cve_data.get(
            "attack_path",
            [],
        ):

            internet_exposed = (
                internet_exposed
                or bool(
                    path.get(
                        "internet_exposed",
                        False,
                    )
                )
            )

            exploit_available = (
                exploit_available
                or bool(
                    path.get(
                        "exploit_available",
                        False,
                    )
                )
            )

            patch_available = (
                patch_available
                or bool(
                    path.get(
                        "patch_available",
                        False,
                    )
                )
            )

    # =========================================================
    # Recommended actions
    # =========================================================

    recommended_actions = []

    for detection in detections:

        action = (
            detection.recommended_action
        )

        if (
            action
            and action
            not in recommended_actions
        ):
            recommended_actions.append(
                action
            )

    # =========================================================
    # Analyst summary
    # =========================================================

    summary = {
        "risk_level": incident.severity,

        "risk_score": max_risk_score,

        "primary_cve": primary_cve,

        "internet_exposed": (
            internet_exposed
        ),

        "exploit_available": (
            exploit_available
        ),

        "patch_available": (
            patch_available
        ),

        "affected_assets": (
            affected_assets
        ),

        "affected_services": (
            affected_services
        ),

        "affected_images": (
            affected_images
        ),
    }

    # =========================================================
    # Final investigation response
    # =========================================================

    return {
        "summary": summary,

        "incident": {
            "incident_id": str(
                incident.incident_id
            ),

            "severity": incident.severity,

            "status": incident.status,

            "resource_id": (
                incident.resource_id
            ),

            "resource_type": (
                incident.resource_type
            ),

            "event_count": (
                incident.event_count
            ),

            "analyst_notes": (
                incident.analyst_notes
            ),

            "resolution": (
                incident.resolution
            ),

            "created_at": (
                incident.created_at.isoformat()
                if incident.created_at
                else None
            ),

            "updated_at": (
                incident.updated_at.isoformat()
                if incident.updated_at
                else None
            ),
        },

        "risk": {
            "max_risk_score": (
                max_risk_score
            ),

            "average_risk_score": (
                average_risk_score
            ),
        },

        "detection_summary": (
            detection_summary
        ),

        "detections": (
            detection_results
        ),

        "events": (
            event_results
        ),

        "intelligence": (
            intelligence
        ),

        "recommended_actions": (
            recommended_actions
        ),
    }