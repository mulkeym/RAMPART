from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class EvaluationRequest(BaseModel):
    request: dict[str, Any]


class Violation(BaseModel):
    policy_id: str
    severity: str
    category: str
    message: str
    source: Literal["deterministic", "llm"] = "deterministic"
    path: Optional[str] = None


class EvaluationResponse(BaseModel):
    decision: Literal["accept", "fail"]
    violations: list[Violation] = Field(default_factory=list)
    sanitized_request: Optional[dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str = "rampart"
