from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

ReasonerFunc = TypeVar("ReasonerFunc", bound=Callable[..., Awaitable[Any]])

class AgentRouter:
    def __init__(self, tags: list[str] | None = ...) -> None: ...
    def reasoner(self) -> Callable[[ReasonerFunc], ReasonerFunc]: ...

class Agent:
    def __init__(
        self,
        node_id: str,
        version: str,
        description: str,
        agentfield_server: str,
        api_key: str | None = ...,
    ) -> None: ...
    def include_router(self, router: AgentRouter) -> None: ...
    def run(self, port: int, host: str) -> None: ...
