from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

DetectionSeverity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]


class DetectionResult(BaseModel):
    detection_id: str
    rule_name: str
    severity: DetectionSeverity

    description: str

    event_id: UUID
    resource_id: str
    resource_type: str

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    recommended_action: str


class DetectionResponse(BaseModel):
    resource_id: str
    detection_count: int

    detections: list[DetectionResult] = Field(
        default_factory=list
    )