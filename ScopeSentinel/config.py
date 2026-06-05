from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal


@dataclass
class SentinelConfig:
    """
    Declarative configuration for ScopeSentinel.
    """
    model: str = "gpt-4o"
    audit_log_dir: str = "scope_sentinel_logs"

    """
    Action permission ceiling
    Hard upper bound on permitted action level, regardless of what the LLM infers.

    - Level0: navigation and clicks only (hover, scroll, goto, click, …)
    - Level1: + download and authorize
    - Level2: + type (any keyboard input)
    """
    max_action_level: Literal["Level0", "Level1", "Level2"] = "Level2"

    """
    Domain policy
    When True, only domains inferred from the task are permitted.
    Navigation to any other domain is blocked immediately.
    """
    strict_domain_enforcement: bool = False
    """
    Domains that are always permitted, merged into the task context after
    initialize(). Supports wildcard prefix, e.g. "*.example.com".
    """
    extra_allowed_domains: List[str] = field(default_factory=list)
    

    """
    Sensitivity ceilings
    Hard ceiling on input value sensitivity that will be passed through.
    Values classified above this level are blocked before LLM checks.

    - S0: generic public text
    - S1: basic personal / identifying information
    - S2: credentials, payment data, secrets
    """
    max_allowed_input_sensitivity: Literal["S0", "S1", "S2"] = "S2"

   