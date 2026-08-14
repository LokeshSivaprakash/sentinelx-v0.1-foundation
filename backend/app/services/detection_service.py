from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db_models import SecurityDetectionRecord
from app.models.detections import (
    DetectionResponse,
    DetectionResult,
)
from app.models.events import SecurityEvent


def _persist_detection(
    db: Session,
    detection: DetectionResult,
) -> None:
    """
    Persist a detection.

    The database ID combines the event ID and detection rule ID
    so the same detection rule can fire for many different events.
    """

    database_detection_id = (
        f"{detection.event_id}:{detection.detection_id}"
    )

    statement = select(SecurityDetectionRecord).where(
        SecurityDetectionRecord.detection_id
        == database_detection_id
    )

    existing = db.execute(statement).scalars().first()

    if existing:
        existing.rule_name = detection.rule_name
        existing.severity = detection.severity
        existing.resource_id = detection.resource_id
        existing.resource_type = detection.resource_type
        existing.risk_score = detection.risk_score
        existing.description = detection.description
        existing.evidence = detection.evidence
        existing.recommended_action = (
            detection.recommended_action
        )
        return

    record = SecurityDetectionRecord(
        detection_id=database_detection_id,
        event_id=detection.event_id,
        rule_name=detection.rule_name,
        severity=detection.severity,
        resource_id=detection.resource_id,
        resource_type=detection.resource_type,
        risk_score=detection.risk_score,
        description=detection.description,
        evidence=detection.evidence,
        recommended_action=detection.recommended_action,
    )

    db.add(record)


def detect_event(
    event: SecurityEvent,
    db: Session | None = None,
) -> DetectionResponse:
    detections: list[DetectionResult] = []

    metadata = event.metadata
    finding = event.finding

    # ---------------------------------------------------------
    # Rule 1: Critical vulnerability + internet exposure
    # ---------------------------------------------------------

    if (
        finding
        and event.severity == "critical"
        and metadata.get("internet_exposed") is True
    ):
        detections.append(
            DetectionResult(
                detection_id="DET-001",
                rule_name="critical-internet-exposed-vulnerability",
                severity="critical",
                description=(
                    "A critical vulnerability exists on an "
                    "internet-exposed resource."
                ),
                event_id=event.event_id,
                resource_id=event.resource.id,
                resource_type=event.resource.type,
                risk_score=95,
                evidence={
                    "cve": finding.id,
                    "cvss": finding.cvss,
                    "internet_exposed": True,
                    "environment": metadata.get(
                        "environment"
                    ),
                },
                recommended_action=(
                    "Prioritize remediation and evaluate "
                    "immediate containment."
                ),
            )
        )

    # ---------------------------------------------------------
    # Rule 2: Critical vulnerability + exploit available
    # ---------------------------------------------------------

    if (
        finding
        and event.severity == "critical"
        and metadata.get("exploit_available") is True
    ):
        detections.append(
            DetectionResult(
                detection_id="DET-002",
                rule_name="critical-exploitable-vulnerability",
                severity="critical",
                description=(
                    "A critical vulnerability has an "
                    "available exploit."
                ),
                event_id=event.event_id,
                resource_id=event.resource.id,
                resource_type=event.resource.type,
                risk_score=100,
                evidence={
                    "cve": finding.id,
                    "cvss": finding.cvss,
                    "exploit_available": True,
                },
                recommended_action=(
                    "Immediately prioritize remediation "
                    "and investigate potential exploitation."
                ),
            )
        )

    # ---------------------------------------------------------
    # Rule 3: Critical asset + vulnerable package
    # ---------------------------------------------------------

    if (
        finding
        and metadata.get("asset_criticality") == "critical"
        and finding.id
    ):
        detections.append(
            DetectionResult(
                detection_id="DET-003",
                rule_name="critical-asset-vulnerability",
                severity="high",
                description=(
                    "A vulnerable package was identified on "
                    "a critical asset."
                ),
                event_id=event.event_id,
                resource_id=event.resource.id,
                resource_type=event.resource.type,
                risk_score=90,
                evidence={
                    "cve": finding.id,
                    "package": finding.package,
                    "installed_version": (
                        finding.installed_version
                    ),
                    "asset_criticality": "critical",
                },
                recommended_action=(
                    "Prioritize patching and validate "
                    "the asset's exposure."
                ),
            )
        )

    # ---------------------------------------------------------
    # Rule 4: Exploitable vulnerability with patch available
    # ---------------------------------------------------------

    if (
        finding
        and metadata.get("exploit_available") is True
        and metadata.get("patch_available") is True
    ):
        detections.append(
            DetectionResult(
                detection_id="DET-004",
                rule_name="exploitable-vulnerability-with-patch",
                severity="high",
                description=(
                    "An exploitable vulnerability has "
                    "a known patch available."
                ),
                event_id=event.event_id,
                resource_id=event.resource.id,
                resource_type=event.resource.type,
                risk_score=85,
                evidence={
                    "cve": finding.id,
                    "exploit_available": True,
                    "patch_available": True,
                    "fixed_version": (
                        finding.fixed_version
                    ),
                },
                recommended_action=(
                    "Apply the available security patch "
                    "and verify remediation."
                ),
            )
        )

    # ---------------------------------------------------------
    # Persist detections
    # ---------------------------------------------------------

    if db is not None and detections:
        for detection in detections:
            _persist_detection(db, detection)

        db.commit()

    return DetectionResponse(
        resource_id=event.resource.id,
        detection_count=len(detections),
        detections=detections,
    )