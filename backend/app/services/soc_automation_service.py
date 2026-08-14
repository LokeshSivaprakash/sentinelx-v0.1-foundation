from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import (
    SecurityAutomationActionRecord,
    SecurityDetectionRecord,
    SecurityIncidentRecord,
)


def _determine_priority(
    detections: list[SecurityDetectionRecord],
) -> tuple[str, int]:
    if not detections:
        return "P3", 0

    risk_scores = [
        detection.risk_score
        for detection in detections
        if detection.risk_score is not None
    ]

    max_risk = max(risk_scores) if risk_scores else 0

    if max_risk >= 97:
        return "P0", max_risk

    if max_risk >= 85:
        return "P1", max_risk

    if max_risk >= 65:
        return "P2", max_risk

    return "P3", max_risk


def run_soc_playbook(
    db: Session,
    incident: SecurityIncidentRecord,
) -> list[SecurityAutomationActionRecord]:
    """
    Evaluate a controlled SOC playbook for an incident.

    This creates auditable response actions.
    It does not directly execute destructive infrastructure actions.
    """

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

    priority, max_risk = _determine_priority(
        detections
    )

    actions: list[
        SecurityAutomationActionRecord
    ] = []

    # ---------------------------------------------------------
    # Critical vulnerability playbook
    # ---------------------------------------------------------

    has_critical_detection = any(
        detection.severity == "critical"
        for detection in detections
    )

    if has_critical_detection:

        action_definitions = [
            (
                "create_incident",
                "Create or update a critical security incident.",
            ),
            (
                "assign_analyst",
                "Assign the incident to the SOC analyst queue.",
            ),
            (
                "request_containment",
                "Request containment review for the affected resource.",
            ),
            (
                "request_patch",
                "Request remediation of the vulnerable package.",
            ),
        ]

        for action_name, reason in action_definitions:

            action = SecurityAutomationActionRecord(
                action_id=uuid4(),
                incident_id=incident.incident_id,
                resource_id=incident.resource_id,
                playbook=(
                    "critical-vulnerability-response"
                ),
                action=action_name,
                priority=priority,
                status="pending",
                reason=reason,
                metadata={
                    "max_risk_score": max_risk,
                    "detection_count": len(
                        detections
                    ),
                    "automatic_execution": False,
                },
            )

            db.add(action)
            actions.append(action)

    # ---------------------------------------------------------
    # High-risk suspicious activity playbook
    # ---------------------------------------------------------

    suspicious_activity = any(
        detection.rule_name
        == "suspicious-activity"
        for detection in detections
    )

    if suspicious_activity:

        action = SecurityAutomationActionRecord(
            action_id=uuid4(),
            incident_id=incident.incident_id,
            resource_id=incident.resource_id,
            playbook="suspicious-activity-response",
            action="investigate_activity",
            priority=priority,
            status="pending",
            reason=(
                "Investigate suspicious activity "
                "associated with the affected resource."
            ),
            metadata={
                "max_risk_score": max_risk,
                "automatic_execution": False,
            },
        )

        db.add(action)
        actions.append(action)

    db.commit()

    for action in actions:
        db.refresh(action)

    return actions