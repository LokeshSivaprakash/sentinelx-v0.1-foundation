from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal, init_db
from app.models.db_models import (
    SecurityAutomationActionRecord,
    SecurityDetectionRecord,
    SecurityIncidentRecord,
)
from app.models.events import SecurityEvent
from app.models.incidents import (
    AutomationActionUpdate,
    IncidentUpdate,
    RemediationVerificationRequest,
)
from app.services.correlation_service import (
    find_related_vulnerabilities,
)
from app.services.detection_service import (
    detect_event,
)
from app.services.event_service import (
    save_event,
)
from app.services.incident_investigation_service import (
    get_incident_investigation,
)
from app.services.incident_service import (
    correlate_detections_to_incident,
    update_incident,
)
from app.services.intelligence_service import (
    get_critical_vulnerabilities,
)
from app.services.neo4j_service import (
    get_attack_path,
    get_blast_radius,
)
from app.services.remediation_service import (
    get_remediation_for_cve,
)
from app.services.remediation_verification_service import (
    verify_remediation,
)
from app.services.risk_service import (
    get_prioritized_vulnerabilities,
)
from app.services.soc_action_service import (
    update_soc_action,
)

# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="SentinelX API",
    version="0.1.0",
    description=(
        "Open-source Security Intelligence Platform"
    ),
)


# ============================================================
# DATABASE
# ============================================================

@app.on_event("startup")
def startup():
    init_db()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "sentinelx-api",
        "version": "0.1.0",
    }


# ============================================================
# EVENT INGESTION
# ============================================================

@app.post(
    "/v1/events",
    status_code=202,
)
def ingest_event(
    event: SecurityEvent,
    db: Session = Depends(get_db),
):
    record, created = save_event(
        db,
        event,
    )

    return {
        "accepted": True,
        "event_id": str(record.event_id),
        "schema_version": record.schema_version,
        "status": (
            "created"
            if created
            else "already_exists"
        ),
    }


# ============================================================
# DETECTION
# ============================================================

@app.post("/v1/detections/evaluate")
def evaluate_detection(
    event: SecurityEvent,
):
    return detect_event(
        event
    ).model_dump(
        mode="json"
    )


@app.get("/v1/detections")
def get_detections(
    db: Session = Depends(get_db),
):
    statement = (
        select(
            SecurityDetectionRecord
        )
        .order_by(
            SecurityDetectionRecord.created_at.desc()
        )
    )

    records = (
        db.execute(statement)
        .scalars()
        .all()
    )

    return [
        {
            "detection_id": record.detection_id,
            "event_id": str(
                record.event_id
            ),
            "rule_name": record.rule_name,
            "severity": record.severity,
            "resource_id": record.resource_id,
            "resource_type": record.resource_type,
            "risk_score": record.risk_score,
            "description": record.description,
            "evidence": record.evidence,
            "recommended_action": (
                record.recommended_action
            ),
            "created_at": record.created_at,
        }
        for record in records
    ]


@app.get(
    "/v1/detections/{resource_id}"
)
def get_resource_detections(
    resource_id: str,
    db: Session = Depends(get_db),
):
    statement = (
        select(
            SecurityDetectionRecord
        )
        .where(
            SecurityDetectionRecord.resource_id
            == resource_id
        )
        .order_by(
            SecurityDetectionRecord.created_at.desc()
        )
    )

    records = (
        db.execute(statement)
        .scalars()
        .all()
    )

    return {
        "resource_id": resource_id,
        "detection_count": len(records),
        "detections": [
            {
                "detection_id": (
                    record.detection_id
                ),
                "event_id": str(
                    record.event_id
                ),
                "rule_name": (
                    record.rule_name
                ),
                "severity": (
                    record.severity
                ),
                "resource_id": (
                    record.resource_id
                ),
                "resource_type": (
                    record.resource_type
                ),
                "risk_score": (
                    record.risk_score
                ),
                "description": (
                    record.description
                ),
                "evidence": (
                    record.evidence
                ),
                "recommended_action": (
                    record.recommended_action
                ),
                "created_at": (
                    record.created_at
                ),
            }
            for record in records
        ],
    }


# ============================================================
# INCIDENT CORRELATION
# ============================================================

@app.post(
    "/v1/incidents/correlate/{resource_id}"
)
def correlate_detections(
    resource_id: str,
    db: Session = Depends(get_db),
):
    try:
        incident = (
            correlate_detections_to_incident(
                db,
                resource_id,
            )
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    return incident.model_dump(
        mode="json"
    )


# ============================================================
# INCIDENT INVESTIGATION
# ============================================================

@app.get(
    "/v1/incidents/{incident_id}/investigation"
)
def incident_investigation(
    incident_id: UUID,
    db: Session = Depends(get_db),
):
    try:
        return get_incident_investigation(
            db,
            incident_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


# ============================================================
# GET INCIDENT BY RESOURCE
# ============================================================

@app.get(
    "/v1/incidents/{resource_id}"
)
def get_incident(
    resource_id: str,
    db: Session = Depends(get_db),
):
    statement = (
        select(
            SecurityIncidentRecord
        )
        .where(
            SecurityIncidentRecord.resource_id
            == resource_id
        )
        .order_by(
            SecurityIncidentRecord.created_at.desc()
        )
    )

    incident = (
        db.execute(statement)
        .scalars()
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail=(
                "No incident found for "
                f"resource: {resource_id}"
            ),
        )

    return {
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
        "events": incident.events,
        "metadata": (
            incident.incident_metadata
        ),
        "analyst_notes": (
            incident.analyst_notes
        ),
        "resolution": (
            incident.resolution
        ),
        "created_at": (
            incident.created_at
        ),
        "updated_at": (
            incident.updated_at
        ),
    }


# ============================================================
# UPDATE INCIDENT
# ============================================================

@app.patch(
    "/v1/incidents/{incident_id}"
)
def patch_incident(
    incident_id: UUID,
    update: IncidentUpdate,
    db: Session = Depends(get_db),
):
    try:
        incident = update_incident(
            db,
            incident_id,
            update,
        )

    except ValueError as exc:

        message = str(exc)

        # -----------------------------------------------------
        # Incident does not exist
        # -----------------------------------------------------

        if message.startswith(
            "Incident not found:"
        ):
            raise HTTPException(
                status_code=404,
                detail=message,
            )

        # -----------------------------------------------------
        # Invalid lifecycle transition
        # -----------------------------------------------------

        if message.startswith(
            "Invalid incident status transition:"
        ):
            raise HTTPException(
                status_code=400,
                detail=message,
            )

        # -----------------------------------------------------
        # Resolution validation
        # -----------------------------------------------------

        if message.startswith(
            "Resolution can only be provided"
        ):
            raise HTTPException(
                status_code=400,
                detail=message,
            )

        # -----------------------------------------------------
        # Other known validation errors
        # -----------------------------------------------------

        raise HTTPException(
            status_code=400,
            detail=message,
        )

    return incident.model_dump(
        mode="json"
    )

@app.post(
    "/v1/incidents/{incident_id}/verify-remediation"
)
def verify_incident_remediation(
    incident_id: UUID,
    request: RemediationVerificationRequest,
    db: Session = Depends(get_db),
):
    try:
        return verify_remediation(
            db=db,
            incident_id=incident_id,
            package=request.package,
            previous_version=request.previous_version,
            remediated_version=request.remediated_version,
            verification_methods=(
                request.verification_methods
            ),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )
# ============================================================
# INTELLIGENCE
# ============================================================

@app.get(
    "/v1/intelligence/critical-vulnerabilities"
)
def critical_vulnerabilities():
    results = (
        get_critical_vulnerabilities()
    )

    return {
        "count": len(results),
        "results": results,
    }


@app.get(
    "/v1/intelligence/risk-prioritized"
)
def risk_prioritized():
    results = (
        get_prioritized_vulnerabilities()
    )

    return {
        "count": len(results),
        "results": results,
    }


@app.get(
    "/v1/intelligence/correlate/{cve}"
)
def correlate_vulnerability(
    cve: str,
):
    results = (
        find_related_vulnerabilities(
            cve
        )
    )

    return {
        "cve": cve,
        "count": len(results),
        "related_context": results,
    }


@app.get(
    "/v1/intelligence/attack-path/{cve}"
)
def attack_path(
    cve: str,
):
    results = get_attack_path(
        cve
    )

    return {
        "cve": cve,
        "count": len(results),
        "results": results,
    }


@app.get(
    "/v1/intelligence/blast-radius/{cve}"
)
def blast_radius(
    cve: str,
):
    results = get_blast_radius(
        cve
    )

    return {
        "cve": cve,
        "affected_assets": len(
            {
                result["asset_id"]
                for result in results
            }
        ),
        "affected_services": len(
            {
                result["service_id"]
                for result in results
            }
        ),
        "affected_images": len(
            {
                result["image_id"]
                for result in results
            }
        ),
        "results": results,
    }

@app.get(
    "/v1/intelligence/remediation/{cve}"
)
def remediation(cve: str):
    try:
        return get_remediation_for_cve(cve)

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

@app.get("/v1/soc/queue")
def get_soc_queue(
    db: Session = Depends(get_db),
):
    statement = (
        select(SecurityAutomationActionRecord)
        .where(
            SecurityAutomationActionRecord.status == "pending"
        )
        .order_by(
            SecurityAutomationActionRecord.created_at.asc()
        )
    )

    actions = (
        db.execute(statement)
        .scalars()
        .all()
    )

    return {
        "count": len(actions),
        "queue": [
            {
                "action_id": str(action.action_id),
                "incident_id": str(action.incident_id),
                "resource_id": action.resource_id,
                "playbook": action.playbook,
                "action": action.action,
                "priority": action.priority,
                "status": action.status,
                "reason": action.reason,
                "metadata": action.action_metadata,
                "created_at": action.created_at,
            }
            for action in actions
        ],
    }


@app.get("/v1/soc/actions/{incident_id}")
def get_soc_actions(
    incident_id: UUID,
    db: Session = Depends(get_db),
):
    statement = (
        select(SecurityAutomationActionRecord)
        .where(
            SecurityAutomationActionRecord.incident_id
            == incident_id
        )
        .order_by(
            SecurityAutomationActionRecord.created_at.asc()
        )
    )

    actions = (
        db.execute(statement)
        .scalars()
        .all()
    )

    return {
        "incident_id": str(incident_id),
        "count": len(actions),
        "actions": [
            {
                "action_id": str(action.action_id),
                "playbook": action.playbook,
                "action": action.action,
                "priority": action.priority,
                "status": action.status,
                "reason": action.reason,
                "metadata": action.action_metadata,
                "created_at": action.created_at,
            }
            for action in actions
        ],
    }
@app.patch(
    "/v1/soc/actions/{action_id}"
)
def patch_soc_action(
    action_id: UUID,
    update: AutomationActionUpdate,
    db: Session = Depends(get_db),
):
    try:
        return update_soc_action(
            db=db,
            action_id=action_id,
            status=update.status,
            result=update.result,
        )

    except ValueError as exc:
        message = str(exc)

        if message.startswith(
            "Automation action not found:"
        ):
            raise HTTPException(
                status_code=404,
                detail=message,
            )

        raise HTTPException(
            status_code=400,
            detail=message,
        )