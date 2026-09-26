from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AuditExportCreate(BaseModel):
    profile: Literal["internal_audit", "legal", "research_lead"]
    events_from: str | None = Field(default=None, max_length=40)
    events_to: str | None = Field(default=None, max_length=40)
    project_codes: list[str] | None = Field(default=None, max_length=200)
    event_types: list[str] | None = Field(default=None, max_length=200)

    def criteria_payload(self) -> dict:
        return self.model_dump(exclude={"profile"}, exclude_none=True)
