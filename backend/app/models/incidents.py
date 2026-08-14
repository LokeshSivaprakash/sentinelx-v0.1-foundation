from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

# ============================================================
# INCIDENT STATUS
# ============================================================

IncidentStatus = Literal[
    "open",
    "investigating",
    "contained",
    "resolved",
]


# ============================================================
# REMEDIATION VERIFICATION
# ============================================================

VerificationMethod = Literal[
    "package_version_check",
    "vulnerability_rescan",
    "deployment_verification",
    "configuration_check",
    "manual_validation",
]


class CorrelatedEvent(BaseModel):
    event_id: UUID
    event_type: str
    severity: str
    timestamp: datetime
    source: str


class SecurityIncident(BaseModel):
    incident_id: UUID
    severity: str
    status: IncidentStatus = "open"
    resource_id: str
    resource_type: str
    event_count: int
    events: list[CorrelatedEvent] = Field(
        default_factory=list
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    analyst_notes: str | None = None
    resolution: str | None = None


class RemediationVerificationRequest(BaseModel):
    package: str = Field(
        min_length=1,
        max_length=150,
    )

    previous_version: str = Field(
        min_length=1,
        max_length=100,
    )

    remediated_version: str = Field(
        min_length=1,
        max_length=100,
    )

    verification_methods: list[
        VerificationMethod
    ] = Field(
        min_length=1,
        max_length=10,
    )

AutomationActionStatus = Literal[
    "pending",
    "approved",
    "running",
    "completed",
    "rejected",
    "failed",
]


class AutomationActionUpdate(BaseModel):
    status: AutomationActionStatus
    result: str | None = None

class AutomationActionResponse(BaseModel):
    action_id: UUID
    incident_id: UUID
    resource_id: str
    playbook: str
    action: str
    priority: str
    status: AutomationActionStatus
    reason: str
    metadata: dict[str, Any] = Field(
        default_factory=dict
    )
    created_at: datetime
    updated_at: datetime