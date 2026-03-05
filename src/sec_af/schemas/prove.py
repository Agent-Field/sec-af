"""PROVE phase schemas.

These are complex `.harness()` schemas from DESIGN.md §6.3-§6.4 and §7.1.
"""

from enum import Enum, IntEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from .compliance import ComplianceMapping
from .hunt import FindingType, Severity


class Verdict(str, Enum):
    """DESIGN.md §6.3 exploitability verdict semantics."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"
    NOT_EXPLOITABLE = "not_exploitable"


class EvidenceLevel(IntEnum):
    """DESIGN.md §6.3 six-level evidence strength hierarchy."""

    STATIC_MATCH = 1
    FLOW_IDENTIFIED = 2
    REACHABILITY_CONFIRMED = 3
    SANITIZATION_BYPASSABLE = 4
    EXPLOIT_SCENARIO_VALIDATED = 5
    FULL_EXPLOIT = 6


class DataFlowTrace(BaseModel):
    """Flat schema for data flow tracing sub-agent. 4 fields."""

    source: str = Field(description="Where tainted input enters (e.g. 'request.params.id')")
    sink: str = Field(description="Security-sensitive operation reached (e.g. 'sql.execute(query)')")
    steps: list[str] = Field(description="Ordered list of file:line descriptions showing flow path")
    sink_reached: bool = Field(description="Whether tainted data actually reaches the sink")


class SanitizationResult(BaseModel):
    """Flat schema for sanitization analysis sub-agent. 4 fields."""

    found: bool = Field(description="Whether any sanitization/validation was found on the path")
    type: str | None = Field(
        default=None,
        description="Type of sanitization (e.g. 'parameterized query', 'html encoding')",
    )
    sufficient: bool | None = Field(
        default=None,
        description="Whether sanitization is sufficient to prevent exploit",
    )
    bypass_method: str | None = Field(default=None, description="How sanitization could be bypassed, if applicable")


class ExploitHypothesis(BaseModel):
    """Flat schema for exploit construction sub-agent. 3 fields."""

    hypothesis: str = Field(description="Natural language description of exploit scenario")
    payload: str | None = Field(default=None, description="Concrete exploit payload or input")
    expected_outcome: str = Field(description="What would happen if exploit succeeds")


class VerdictDecision(BaseModel):
    """Flat schema for verdict sub-agent. Uses .ai() not .harness(). 4 fields."""

    verdict: str = Field(description='One of: "confirmed", "likely", "inconclusive", "not_exploitable"')
    evidence_level: int = Field(description="1-6 scale: 1=STATIC_MATCH to 6=FULL_EXPLOIT")
    rationale: str
    confidence: str = Field(description='One of: "high", "medium", "low"')


class RemediationSuggestion(BaseModel):
    """Flat schema for AI-generated remediation suggestion. 3 fields."""

    fix_description: str = Field(description="Natural language description of the recommended fix")
    patch_diff: str = Field(description="Unified diff format patch showing the code changes needed")
    confidence: str = Field(description='Confidence in the fix: "high", "medium", or "low"')


class DataFlowStep(BaseModel):
    """DESIGN.md §6.4 one step in source-to-sink proof trace."""

    file: str
    line: int
    description: str
    tainted: bool


class DataFlowEvidence(BaseModel):
    """DESIGN.md §6.4 grouped data flow evidence artifact."""

    steps: list[DataFlowStep] = Field(default_factory=list)
    source: str | None = None
    sink: str | None = None
    sink_reached: bool = False


class SanitizationAnalysis(BaseModel):
    """DESIGN.md §6.4 sanitization effectiveness analysis."""

    sanitization_found: bool
    sanitization_type: str | None = None
    sanitization_sufficient: bool | None = None
    bypass_possible: bool | None = None
    bypass_method: str | None = None


class HttpEvidence(BaseModel):
    """DESIGN.md §6.4 HTTP request/response evidence artifact."""

    method: str | None = None
    url: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    highlighted_segment: str | None = None


class ReachabilityEvidence(BaseModel):
    """DESIGN.md §6.4 reachability evidence for dependency findings."""

    vulnerable_function: str
    call_chain: list[str] = Field(default_factory=list)
    reachable: bool
    direct_dependency: bool


class ChainStep(BaseModel):
    """DESIGN.md §6.4 chain evidence link across findings."""

    step_number: int
    finding_id: str
    description: str
    enables: str


class Proof(BaseModel):
    """DESIGN.md §6.4 evidence artifact supporting final verdict."""

    exploit_hypothesis: str
    verification_method: str
    evidence_level: EvidenceLevel
    data_flow_trace: list[DataFlowStep] | None = None
    data_flow_evidence: DataFlowEvidence | None = None
    sanitization_analysis: SanitizationAnalysis | None = None
    vulnerable_code: str | None = None
    exploit_payload: str | None = None
    expected_outcome: str | None = None
    poc_code: str | None = None
    poc_execution_output: str | None = None
    http_request: HttpEvidence | None = None
    http_response: HttpEvidence | None = None
    reachability: ReachabilityEvidence | None = None
    chain_steps: list[ChainStep] | None = None


class ProverSignal(BaseModel):
    """DESIGN.md §6.6 depth-first expansion signal from a prover."""

    expand: bool = False
    expansion_reason: str | None = None
    expansion_strategy: str | None = None
    expansion_target: str | None = None


class Location(BaseModel):
    """DESIGN.md §7.1 source location metadata for verified findings."""

    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    function_name: str | None = None
    code_snippet: str | None = None


class CvssV4Score(BaseModel):
    """DESIGN.md §7.1 CVSS v4 scoring details."""

    vector: str
    base_score: float
    severity: str
    automatable: bool
    subsequent_impact: bool


class EpssScore(BaseModel):
    """DESIGN.md §7.1 EPSS probability details."""

    score: float
    percentile: float
    date: str


class ReproductionStep(BaseModel):
    """DESIGN.md §7.1 reproduction instructions for analysts."""

    step: int
    description: str
    command: str | None = None
    expected_output: str | None = None


class VerifiedFinding(BaseModel):
    """DESIGN.md §7.1 finding fully assessed by PROVE phase."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    fingerprint: str
    title: str
    description: str
    finding_type: FindingType
    cwe_id: str
    cwe_name: str
    owasp_category: str | None = None
    tags: list[str] = Field(default_factory=list)
    verdict: Verdict
    evidence_level: EvidenceLevel
    rationale: str
    severity: Severity
    cvss_v4: CvssV4Score | None = None
    epss: EpssScore | None = None
    exploitability_score: float
    proof: Proof | None = None
    location: Location
    related_locations: list[Location] = Field(default_factory=list)
    chain_id: str | None = None
    chain_step: int | None = None
    enables: list[str] | None = None
    compliance: list[ComplianceMapping] = Field(default_factory=list)
    reproduction_steps: list[ReproductionStep] = Field(default_factory=list)
    remediation: RemediationSuggestion | None = None
    sarif_rule_id: str
    sarif_security_severity: float
    drop_reason: str | None = None
