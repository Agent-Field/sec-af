"""Phase-boundary view models for context-specific data passing.

These provide minimal projections of complex schemas for specific consumers,
following the Composite Intelligence principle of contextual fidelity.
"""

from pydantic import BaseModel, Field


class FindingForVerifier(BaseModel):
    """What the verifier pipeline needs from a RawFinding."""

    id: str
    title: str
    description: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    cwe_id: str
    function_name: str | None = None
    data_flow_summary: str = Field(default="", description="Flattened data flow path")


class FindingForDedup(BaseModel):
    """What the deduplicator needs. 8 fields."""

    id: str
    fingerprint: str
    title: str
    file_path: str
    start_line: int
    cwe_id: str
    finding_type: str
    estimated_severity: str


class FindingForReachability(BaseModel):
    """What the reachability gate needs. 5 fields."""

    title: str
    description: str
    cwe_id: str
    file_path: str
    start_line: int
    verdict: str
