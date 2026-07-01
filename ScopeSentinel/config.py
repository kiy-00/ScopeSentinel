from dataclasses import dataclass, field
from typing import List, Optional


_ACTION_LEVEL_ORDER = {
    "Level0": 0,
    "Level1": 1,
    "Level2": 2,
}

_SENSITIVITY_ORDER = {
    "S0": 0,
    "S1": 1,
    "S2": 2,
}


@dataclass
class SentinelConfig:
    """
    Global configuration for a ScopeSentinel instance.

    This class controls instance-level security behavior. It is different from
    SentinelTaskContext:

    - SentinelTaskContext describes what the current user task permits.
    - SentinelConfig describes the maximum behavior this ScopeSentinel instance
      is willing to allow.

    Typical examples:
    - A task may require typing, but max_action_level can still cap execution at Level0.
    - A task may include personal data, but max_allowed_disclosure_sensitivity can
      still prevent disclosure above S0.
    - strict_mode can turn uncertain LLM/tool failures into conservative blocks.
    """

    # -----------------------------
    # Action permission controls
    # -----------------------------

    max_action_level: str = "Level2"
    """
    Hard upper bound for candidate action level.

    Level0: low-risk browser/navigation actions.
    Level1: medium-risk actions such as download/authorize.
    Level2: typing or data-entry actions.

    Even if a task context allows Level2, this config can cap the system at
    Level0 or Level1.
    """

    # -----------------------------
    # Domain controls
    # -----------------------------

    strict_domain_enforcement: bool = False
    """
    If True, ScopeSentinel should enforce allowed domain rules more strictly.

    Intended behavior:
    - URLs matching task_context.allowed_domains are allowed.
    - URLs matching extra_allowed_domains are also allowed.
    - Unknown external URLs should be treated as suspicious unless clearly justified.
    """

    extra_allowed_domains: List[str] = field(default_factory=list)
    """
    Additional domains allowed by the package user.

    Examples:
    - "example.com"
    - "*.example.org"

    These should supplement, not replace, domains inferred from the task.
    """

    # -----------------------------
    # Sensitivity controls
    # -----------------------------

    max_allowed_input_sensitivity: str = "S2"
    """
    Hard upper bound for candidate typed value sensitivity.

    S0: public/non-sensitive text.
    S1: basic personal/contact/identity-like information.
    S2: highly sensitive data such as credentials, secrets, payment data,
        or identity-critical information.
    """

    max_allowed_disclosure_sensitivity: str = "S2"
    """
    Hard upper bound for what this ScopeSentinel instance may disclose.

    This is an instance-level cap. The actual task-level allowed disclosure is
    still inferred into task_context / allowed_disclosure_sensitivity.
    """

    # -----------------------------
    # Feature switches
    # -----------------------------

    enable_visual_check: bool = True
    """
    Whether to enable visual legitimacy / hidden-element checks.

    This is useful for VPI-style or DOM/visual mismatch attacks.
    """

    enable_url_scan: bool = False
    """
    Whether to enable external URL validation/scanning.

    This should replace any module-level global switch such as external_validate.
    """

    enable_llm_url_check: bool = True
    """
    Whether to allow LLM-based URL safety judgment.

    If False, URL checks should rely only on structural/domain/tool checks.
    """

    # -----------------------------
    # Failure behavior
    # -----------------------------

    strict_mode: bool = False
    """
    Controls fail-open vs fail-closed behavior when an internal checker fails.

    False:
        Prefer availability. If an LLM/tool check fails, allow fallback behavior
        that is less likely to block normal tasks.

    True:
        Prefer safety. If an LLM/tool check fails and the risk cannot be judged,
        block conservatively.
    """

    # -----------------------------
    # Thresholds
    # -----------------------------

    visual_risk_score_threshold: float = 0.55
    """
    Threshold for visual risk score.

    If a visual legitimacy checker returns a score greater than or equal to this
    value, the action should usually be treated as suspicious.
    """

    repeated_block_terminate_count: int = 3
    """
    Number of repeated blocks of the same risk/action signature before returning
    TERMINATE instead of BLOCK.

    This generalizes the previously hardcoded repeated-block behavior.
    """

    # -----------------------------
    # Logging
    # -----------------------------

    audit_log_dir: str = "scope_sentinel_logs"
    """
    Base directory for audit logs.

    core.py may append task_id/session-specific subdirectories under this path.
    """

    # -----------------------------
    # Validation
    # -----------------------------

    def __post_init__(self) -> None:
        self.max_action_level = self._validate_action_level(
            self.max_action_level,
            field_name="max_action_level",
        )
        self.max_allowed_input_sensitivity = self._validate_sensitivity(
            self.max_allowed_input_sensitivity,
            field_name="max_allowed_input_sensitivity",
        )
        self.max_allowed_disclosure_sensitivity = self._validate_sensitivity(
            self.max_allowed_disclosure_sensitivity,
            field_name="max_allowed_disclosure_sensitivity",
        )

        if not isinstance(self.extra_allowed_domains, list):
            raise TypeError("extra_allowed_domains must be a list of domain rules.")

        self.extra_allowed_domains = [
            str(domain).strip().lower()
            for domain in self.extra_allowed_domains
            if str(domain).strip()
        ]

        if not 0.0 <= float(self.visual_risk_score_threshold) <= 1.0:
            raise ValueError("visual_risk_score_threshold must be between 0.0 and 1.0.")

        if int(self.repeated_block_terminate_count) < 1:
            raise ValueError("repeated_block_terminate_count must be >= 1.")

        self.visual_risk_score_threshold = float(self.visual_risk_score_threshold)
        self.repeated_block_terminate_count = int(self.repeated_block_terminate_count)

    @staticmethod
    def _validate_action_level(value: str, field_name: str) -> str:
        value = str(value).strip()
        if value not in _ACTION_LEVEL_ORDER:
            allowed = ", ".join(_ACTION_LEVEL_ORDER.keys())
            raise ValueError(f"{field_name} must be one of: {allowed}.")
        return value

    @staticmethod
    def _validate_sensitivity(value: str, field_name: str) -> str:
        value = str(value).strip().upper()
        if value not in _SENSITIVITY_ORDER:
            allowed = ", ".join(_SENSITIVITY_ORDER.keys())
            raise ValueError(f"{field_name} must be one of: {allowed}.")
        return value

    # -----------------------------
    # Comparison helpers
    # -----------------------------

    def allows_action_level(self, action_level: Optional[str]) -> bool:
        """
        Return whether the given action level is within max_action_level.
        """
        if action_level is None:
            return False

        action_level = str(action_level).strip()
        if action_level not in _ACTION_LEVEL_ORDER:
            return False

        return _ACTION_LEVEL_ORDER[action_level] <= _ACTION_LEVEL_ORDER[self.max_action_level]

    def allows_input_sensitivity(self, sensitivity: Optional[str]) -> bool:
        """
        Return whether the given input sensitivity is within the configured cap.
        """
        if sensitivity is None:
            return False

        sensitivity = str(sensitivity).strip().upper()
        if sensitivity not in _SENSITIVITY_ORDER:
            return False

        return (
            _SENSITIVITY_ORDER[sensitivity]
            <= _SENSITIVITY_ORDER[self.max_allowed_input_sensitivity]
        )

    def allows_disclosure_sensitivity(self, sensitivity: Optional[str]) -> bool:
        """
        Return whether the given disclosure sensitivity is within the configured cap.
        """
        if sensitivity is None:
            return False

        sensitivity = str(sensitivity).strip().upper()
        if sensitivity not in _SENSITIVITY_ORDER:
            return False

        return (
            _SENSITIVITY_ORDER[sensitivity]
            <= _SENSITIVITY_ORDER[self.max_allowed_disclosure_sensitivity]
        )

    def all_allowed_domains(self, task_allowed_domains: Optional[List[str]] = None) -> List[str]:
        """
        Merge task-level allowed domains and instance-level extra allowed domains.

        Duplicates are removed while preserving order.
        """
        merged: List[str] = []

        for domain in task_allowed_domains or []:
            d = str(domain).strip().lower()
            if d and d not in merged:
                merged.append(d)

        for domain in self.extra_allowed_domains:
            d = str(domain).strip().lower()
            if d and d not in merged:
                merged.append(d)

        return merged