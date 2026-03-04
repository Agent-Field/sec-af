"""Compliance schemas.

See DESIGN.md §7.1, §7.3, and §10 for compliance mapping output.
"""

from pydantic import BaseModel

from .hunt import Severity


class ComplianceMapping(BaseModel):
    """DESIGN.md §7.1 framework control mapping for a finding."""

    framework: str
    control_id: str
    control_name: str


class ComplianceGap(BaseModel):
    """DESIGN.md §7.3 and §10.2 summarized control-level gap."""

    framework: str
    control_id: str
    control_name: str
    finding_count: int
    severity: Severity
