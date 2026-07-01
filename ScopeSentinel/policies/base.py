from typing import Optional

from ..types import PolicyAugment, SentinelDecision, SentinelTaskContext


class BasePolicy:
    name = "base"

    def should_enable(self, ctx: SentinelTaskContext) -> bool:
        return False

    def build_policy_augment(self, ctx: SentinelTaskContext) -> PolicyAugment:
        return PolicyAugment()

    def pre_action_check(
        self,
        ctx: SentinelTaskContext,
        action: str,
        element_text: str,
        value_text: str,
        html_text: str,
        current_url: str,
        current_app: str,
        screenshot_text: str,
    ) -> Optional[SentinelDecision]:
        return None