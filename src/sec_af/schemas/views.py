from pydantic import BaseModel


class FindingForVerifier(BaseModel):
    id: str
    title: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    cwe_id: str
    function_name: str | None = None
    data_flow_summary: str


class FindingForDedup(BaseModel):
    id: str
    fingerprint: str
    title: str
    file_path: str
    start_line: int
    cwe_id: str
    finding_type: str
    estimated_severity: str


class FindingForReachability(BaseModel):
    title: str
    description: str
    cwe_id: str
    file_path: str
    start_line: int
