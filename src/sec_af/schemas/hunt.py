"""HUNT phase schemas.

These are complex `.harness()` schemas from DESIGN.md §5.4-§5.5.
"""

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from .recon import DataFlowStep


class FindingType(str, Enum):
    """DESIGN.md §5.4 finding type taxonomy."""

    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    CONFIG = "config"
    LOGIC = "logic"
    API = "api"


class Severity(str, Enum):
    """DESIGN.md §5.4 and §7 severity scale."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """DESIGN.md §5.4 confidence for provisional findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HuntStrategy(str, Enum):
    """DESIGN.md §5.2 and §5.3 strategy catalog for hunters."""

    INJECTION = "injection"
    AUTH = "auth"
    CRYPTO = "crypto"
    LOGIC_BUGS = "logic_bugs"
    DATA_EXPOSURE = "data_exposure"
    SUPPLY_CHAIN = "supply_chain"
    CONFIG_SECRETS = "config_secrets"
    API_SECURITY = "api_security"
    PYTHON_SPECIFIC = "python_specific"
    JAVASCRIPT_SPECIFIC = "javascript_specific"


class RawFinding(BaseModel):
    """DESIGN.md §5.4 potential vulnerability from a hunter."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    hunter_strategy: str
    title: str
    description: str
    finding_type: FindingType
    cwe_id: str
    cwe_name: str
    owasp_category: str | None = None
    file_path: str
    start_line: int
    end_line: int
    function_name: str | None = None
    code_snippet: str
    estimated_severity: Severity
    confidence: Confidence
    data_flow: list[DataFlowStep] | None = None
    related_files: list[str] = Field(default_factory=list)
    fingerprint: str = Field(default_factory=lambda: str(uuid4()))


class PotentialChain(BaseModel):
    """DESIGN.md §5.5 potential multi-step attack chain before proof."""

    chain_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    combined_impact: str
    estimated_severity: Severity


class HuntResult(BaseModel):
    """DESIGN.md §5.5 deduplicated and correlated hunt output."""

    findings: list[RawFinding] = Field(default_factory=list)
    chains: list[PotentialChain] = Field(default_factory=list)
    total_raw: int = 0
    deduplicated_count: int = 0
    chain_count: int = 0
    strategies_run: list[str] = Field(default_factory=list)
    hunt_duration_seconds: float = 0.0


class DeduplicatedResult(BaseModel):
    """DESIGN.md §5.5 dedup lane output before PROVE prioritization."""

    findings: list[RawFinding] = Field(default_factory=list)
    chains: list[PotentialChain] = Field(default_factory=list)
    dropped_duplicates: int = 0
    kept_findings: int = 0
