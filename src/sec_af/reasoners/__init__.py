# pyright: reportMissingImports=false, reportImportCycles=false
from agentfield import AgentRouter

router = AgentRouter(tags=["security", "audit", "red-team"])

from . import recon  # noqa: E402,F401
from . import hunt  # noqa: E402,F401
from . import prove  # noqa: E402,F401
from . import phases  # noqa: E402,F401

__all__ = ["router"]
