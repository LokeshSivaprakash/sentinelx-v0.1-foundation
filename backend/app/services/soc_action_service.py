from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import (
    SecurityAutomationActionRecord,
    SecurityIncidentRecord,
)
from app.models.incidents import (
    AutomationActionResponse,
)

ALLOWED_ACTION_TRANSITIONS = {
    "pending": {
        "pending",
        "approved",
        "rejected",
    },
    "approved": {
        "approved",
        "running",
        "rejected",
    },
    "running": {
        "running",
        "completed",
        "failed",
    },
    "completed": {
        "completed",
    },
    "rejected": {
        "rejected",
    },
    "failed": {
        "failed",
        "pending",
    },
}


def update_soc_action(
    db: Session,
    action_id: UUID,
    status: str,
    result: str | None = None,
) -> dict:
    # =========================================================
    # Find automation action
    # =========================================================

    statement = select(
        SecurityAutomationActionRecord
    ).where(
        SecurityAutomationActionRecord.action_id
        == action_id
    )

    action = (
        db.execute(statement)
        .scalars()
        .first()
    )

    if not action:
        raise ValueError(
            f"Automation action not found: {action_id}"
        )

    # =========================================================
    # Validate action transition
    # =========================================================

    current_status = action.status

    allowed_statuses = (
        ALLOWED_ACTION_TRANSITIONS.get(
            current_status,
            set(),
        )
    )

    if status not in allowed_statuses:
        raise ValueError(
            "Invalid automation action transition: "
            f"{current_status} -> {status}"
        )

    # =========================================================
    # Update action status
    # =========================================================

    action.status = status

    # =========================================================
    # Update action metadata
    # =========================================================

    action_metadata = dict(
        action.action_metadata or {}
    )

    if result is not None:
        action_metadata["result"] = result

    if status == "completed":
        action_metadata[
            "execution_completed"
        ] = True

    if status == "failed":
        action_metadata[
            "execution_failed"
        ] = True

    action.action_metadata = action_metadata

    # =========================================================
    # Update linked incident when action completes
    # =========================================================

    if status == "completed":

        incident_statement = select(
            SecurityIncidentRecord
        ).where(
            SecurityIncidentRecord.incident_id
            == action.incident_id
        )

        incident = (
            db.execute(
                incident_statement
            )
            .scalars()
            .first()
        )

        if incident:

            incident_metadata = dict(
                incident.incident_metadata or {}
            )

            automation_metadata = dict(
                incident_metadata.get(
                    "automation",
                    {},
                )
            )

            automation_metadata[
                "last_completed_action"
            ] = action.action

            automation_metadata[
                "automation_status"
            ] = "completed"

            automation_metadata[
                "completed_action_id"
            ] = str(action.action_id)

            incident_metadata[
                "automation"
            ] = automation_metadata

            incident.incident_metadata = (
                incident_metadata
            )

    # =========================================================
    # Commit
    # =========================================================

    db.commit()
    db.refresh(action)

    # =========================================================
    # Return response
    # =========================================================

    return AutomationActionResponse(
    action_id=action.action_id,
    incident_id=action.incident_id,
    resource_id=action.resource_id,
    playbook=action.playbook,
    action=action.action,
    priority=action.priority,
    status=action.status,
    reason=action.reason,
    metadata=action.action_metadata or {},
    created_at=action.created_at,
    updated_at=action.updated_at,
)