from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SentinelTaskContext:
    """
    Task-level security context inferred from the user's original task.

    This object describes what the current task permits.
    It should not be confused with SentinelConfig, which describes
    instance-level global limits.
    """

    user_task: str = ""
    background: str = ""
    attack_family_hint: str = ""

    allowed_domains: List[str] = field(default_factory=list)
    allowed_apps: List[str] = field(default_factory=lambda: ["browser"])
    allowed_data_sources: List[str] = field(default_factory=lambda: ["current_website"])

    permissions_level: str = "Level0"   # Level0 / Level1 / Level2
    info_sensitivity: str = "S0"        # S0 / S1 / S2

    task_summary: str = ""
    task_constraints: List[str] = field(default_factory=list)

    dataset_name: str = ""
    guard_hints: Dict[str, Any] = field(default_factory=dict)

    # High-level policy augmentations from dataset-specific policies.
    policy_instructions: List[str] = field(default_factory=list)
    protected_entities: List[str] = field(default_factory=list)
    protected_resources: List[str] = field(default_factory=list)

    # Runtime/package-level metadata.
    # This is intentionally generic so core.py, tests, and downstream users can
    # attach non-critical bookkeeping data without changing the public schema.
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SentinelRuntimeState:
    """
    Runtime state observed from the browser or computer-use environment.
    """

    current_url: str = ""
    current_app: str = "browser"
    html: str = ""
    screenshot_text: str = ""
    step_id: Optional[int] = None

    # Optional structured metadata for future integrations.
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SentinelCandidateAction:
    """
    Canonical candidate action proposed by the worker/agent.

    ScopeSentinel should receive actions in this normalized format.
    """

    action: str
    element: Any = None
    value: Any = None

    # Optional metadata from the worker, browser driver, evaluator, or benchmark.
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SentinelDecision:
    """
    Final or intermediate safety decision.

    allowed:
        Whether the candidate action is allowed.

    risk_type:
        High-level risk label.

    reason:
        Human-readable explanation.

    recommended_response:
        Suggested intervention type.
        Common values:
        - ALLOW
        - BLOCK
        - CLOSE_PAGE
        - TERMINATE

    evidence:
        Structured evidence useful for debugging, audit logs, and tests.
    """

    allowed: bool
    risk_type: str = "NONE"
    reason: str = ""
    recommended_response: str = "ALLOW"
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyAugment:
    """
    Additional policy information produced by a dataset-specific or domain-specific policy.
    """

    policy_instructions: List[str] = field(default_factory=list)
    protected_entities: List[str] = field(default_factory=list)
    protected_resources: List[str] = field(default_factory=list)