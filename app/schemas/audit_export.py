from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class AuditExportCreate(BaseModel):
    audience: Literal["internal_audit", "legal", "rd_lead"]
    occurred_from: str | None = None
    occurred_to: str | None = None
    project_code: str | None = Field(default=None, max_length=100)
    actions: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("occurred_from", "occurred_to")
    @classmethod
    def check_datetime(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            datetime.fromisoformat(value.strip())
        except ValueError as exc:
            raise ValueError("时间必须使用 ISO 8601 格式") from exc
        return value.strip()

    @field_validator("actions")
    @classmethod
    def check_actions(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item and item.strip()]


class RuleVersionCreate(BaseModel):
    version: str = Field(min_length=3, max_length=80)
    definition: dict[str, Any]
    activate: bool = True


class DownloadVerifyRequest(BaseModel):
    document_sha256: str = Field(min_length=64, max_length=64)
