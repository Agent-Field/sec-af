"""REST API input schema for SEC-AF audits.

See DESIGN.md §8.2 for input contract details.
"""

from pydantic import BaseModel, Field


class AuditInput(BaseModel):
    """DESIGN.md §8.2 input for `sec-af.audit` execution."""

    repo_url: str = Field(..., description="Git repository URL to audit")
    branch: str = Field(default="main", description="Branch to audit")
    commit_sha: str | None = Field(default=None, description="Commit SHA to audit")
    base_commit_sha: str | None = Field(
        default=None,
        description="Base commit SHA for diff-aware PR scanning",
    )
    depth: str = Field(
        default="standard",
        description="Scan depth profile: quick|standard|thorough",
    )
    severity_threshold: str = Field(
        default="low",
        description="Minimum severity to report: critical|high|medium|low|info",
    )
    scan_types: list[str] = Field(
        default_factory=lambda: ["sast", "sca", "secrets", "config"],
    )
    output_formats: list[str] = Field(default_factory=lambda: ["json"])
    compliance_frameworks: list[str] = Field(default_factory=list)
    max_cost_usd: float | None = Field(default=None, description="Budget cap in USD")
    max_provers: int | None = Field(default=None, description="Max parallel provers")
    max_duration_seconds: int | None = Field(
        default=None,
        description="Maximum execution time",
    )
    include_paths: list[str] | None = Field(
        default=None,
        description="Only scan these repository paths",
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["tests/", "vendor/", "node_modules/", ".git/"],
    )
    is_pr: bool = Field(default=False, description="Whether scan is for a pull request")
    pr_id: str | None = Field(default=None, description="Pull request identifier")
    post_pr_comments: bool = Field(default=False, description="Post findings as PR comments")
    fail_on_findings: bool = Field(
        default=False,
        description="Return non-zero status for CI gating",
    )
    dast_enabled: bool = Field(
        default=False,
        description="Enable DAST-like runtime exploit verification (requires sandbox)",
    )
    repo_urls: list[str] = Field(
        default_factory=list,
        description="Additional repository URLs for cross-service analysis",
    )
