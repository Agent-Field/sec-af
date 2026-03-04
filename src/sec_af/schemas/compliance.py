"""Compliance framework data models. See DESIGN.md section 10."""

from pydantic import BaseModel


class ComplianceMapping(BaseModel):
    framework: str
    control_id: str
    control_name: str


class ComplianceGap(BaseModel):
    framework: str
    control_id: str
    control_name: str
    finding_count: int
    max_severity: str
    cwe_ids: list[str]
