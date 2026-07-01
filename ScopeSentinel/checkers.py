from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol

from .types import SentinelDecision, SentinelTaskContext


@dataclass(frozen=True)
class CheckContext:
    """
    Read-only snapshot passed to a custom checker.

    A checker should inspect this context and either:

    - return SentinelDecision(...) to short-circuit the normal pipeline
    - return None to allow ScopeSentinel to continue its built-in checks

    This object is intentionally frozen to discourage custom checkers from
    mutating ScopeSentinel runtime state directly.
    """

    task_context: SentinelTaskContext

    action: str
    element_text: str = ""
    value_text: str = ""

    html_text: str = ""
    context_text: str = ""
    pruned_html: str = ""
    screenshot_text: str = ""

    current_url: str = ""
    current_app: str = "browser"
    step_id: Optional[int] = None

    action_level: Optional[str] = None
    value_sensitivity: str = "S0"

    recent_type_value: str = ""
    recent_type_sensitivity: str = "S0"

    metadata: Dict[str, Any] = field(default_factory=dict)


class CheckerFunction(Protocol):
    """
    Function signature accepted by FunctionChecker.
    """

    def __call__(self, ctx: CheckContext) -> Optional[SentinelDecision]:
        ...


class SentinelChecker(ABC):
    """
    Base class for custom ScopeSentinel checkers.

    Lower priority values run earlier.

    Example:
        class BlockAdminChecker(SentinelChecker):
            name = "block_admin"
            priority = 10

            def check(self, ctx: CheckContext) -> Optional[SentinelDecision]:
                if "/admin" in ctx.current_url:
                    return SentinelDecision(
                        allowed=False,
                        risk_type="TASK_DEVIATION",
                        reason="Admin pages are blocked by deployment policy.",
                        recommended_response="BLOCK",
                    )
                return None
    """

    name: str = "checker"
    priority: int = 100

    @abstractmethod
    def check(self, ctx: CheckContext) -> Optional[SentinelDecision]:
        """
        Return SentinelDecision to stop the pipeline, or None to continue.
        """
        raise NotImplementedError

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SentinelChecker):
            return NotImplemented
        return (self.priority, self.name) < (other.priority, other.name)


@dataclass
class FunctionChecker(SentinelChecker):
    """
    Wrap a normal function as a SentinelChecker.

    This is convenient when users do not want to define a class.

    Example:
        def block_downloads(ctx: CheckContext):
            if ctx.action.lower() == "download":
                return SentinelDecision(
                    allowed=False,
                    risk_type="DESTRUCTIVE_ACTION",
                    reason="Downloads are disabled in this environment.",
                    recommended_response="BLOCK",
                )
            return None

        checker = FunctionChecker(block_downloads, name="block_downloads", priority=20)
    """

    fn: CheckerFunction
    name: str = "function_checker"
    priority: int = 100

    def check(self, ctx: CheckContext) -> Optional[SentinelDecision]:
        result = self.fn(ctx)

        if result is None:
            return None

        if not isinstance(result, SentinelDecision):
            raise TypeError(
                f"Checker '{self.name}' must return SentinelDecision or None, "
                f"got {type(result).__name__}."
            )

        return result


def normalize_checker(checker: SentinelChecker | CheckerFunction) -> SentinelChecker:
    """
    Convert a checker-like object into a SentinelChecker.

    Accepted inputs:
    - SentinelChecker instance
    - function taking CheckContext and returning Optional[SentinelDecision]
    """
    if isinstance(checker, SentinelChecker):
        return checker

    if callable(checker):
        checker_name = getattr(checker, "__name__", "function_checker")
        return FunctionChecker(fn=checker, name=checker_name)

    raise TypeError(
        "checker must be a SentinelChecker instance or a callable "
        "with signature check(ctx) -> Optional[SentinelDecision]."
    )


def sort_checkers(
    checkers: Optional[list[SentinelChecker | CheckerFunction]],
) -> list[SentinelChecker]:
    """
    Normalize and sort checkers by priority.

    Lower priority values run earlier.
    """
    if not checkers:
        return []

    normalized = [normalize_checker(checker) for checker in checkers]
    return sorted(normalized, key=lambda c: (c.priority, c.name))


def make_allow_decision(
    reason: str,
    *,
    risk_type: str = "NONE",
    evidence: Optional[Dict[str, Any]] = None,
) -> SentinelDecision:
    """
    Convenience helper for custom checkers.

    Returning an allow decision short-circuits the built-in pipeline, so use it
    carefully. In most cases, custom checkers should return blocking decisions
    or None.
    """
    return SentinelDecision(
        allowed=True,
        risk_type=risk_type,
        reason=reason,
        recommended_response="ALLOW",
        evidence=evidence or {},
    )


def make_block_decision(
    reason: str,
    *,
    risk_type: str = "CUSTOM_CHECKER_BLOCK",
    recommended_response: str = "BLOCK",
    evidence: Optional[Dict[str, Any]] = None,
) -> SentinelDecision:
    """
    Convenience helper for blocking inside custom checkers.
    """
    return SentinelDecision(
        allowed=False,
        risk_type=risk_type,
        reason=reason,
        recommended_response=recommended_response,
        evidence=evidence or {},
    )