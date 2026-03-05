from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field


class OrchestrationSignal(BaseModel):
    signal_type: str
    source_phase: str
    source_agent: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.monotonic)


class AdaptationDecision(BaseModel):
    rule: str
    trigger: str
    action: str
    signal: OrchestrationSignal | None = None
