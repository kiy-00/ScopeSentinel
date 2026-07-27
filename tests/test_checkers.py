from scopesentinel import (
    FunctionChecker,
    SentinelDecision,
    SentinelChecker,
)
from scopesentinel.checkers import CheckContext
from scopesentinel.types import SentinelTaskContext


def make_context(
    action="click",
):
    """
    Create a minimal checker context.
    """

    return CheckContext(
        task_context=SentinelTaskContext(
            user_task="mock task",
        ),
        action=action,
        element_text="mock element",
        value_text="mock value",
    )


class BlockDownloadChecker(SentinelChecker):
    """
    Example custom checker.
    """

    name = "block_download"

    priority = 10

    def check(
        self,
        ctx: CheckContext,
    ):
        if ctx.action == "download":
            return SentinelDecision(
                allowed=False,
                risk_type="CUSTOM_POLICY",
                reason="Downloads are blocked.",
                recommended_response="BLOCK",
            )

        return None


def test_checker_returns_decision():
    """
    Checker should be able to return SentinelDecision.
    """

    checker = BlockDownloadChecker()

    ctx = make_context(
        action="download"
    )

    result = checker.check(ctx)

    assert isinstance(
        result,
        SentinelDecision,
    )

    assert result.allowed is False

    assert result.risk_type == "CUSTOM_POLICY"


def test_checker_allows_unmatched_action():
    """
    Checker should return None when it does not apply.
    """

    checker = BlockDownloadChecker()

    ctx = make_context(
        action="click"
    )

    result = checker.check(ctx)

    assert result is None


def test_checker_priority_order():
    """
    Lower priority number should execute first.
    """

    execution_order = []


    class FirstChecker(SentinelChecker):

        name = "first"

        priority = 10

        def check(self, ctx):

            execution_order.append(
                self.name
            )

            return None


    class SecondChecker(SentinelChecker):

        name = "second"

        priority = 20

        def check(self, ctx):

            execution_order.append(
                self.name
            )

            return None


    checkers = [
        SecondChecker(),
        FirstChecker(),
    ]

    ordered = sorted(checkers)

    for checker in ordered:
        checker.check(
            make_context()
        )


    assert execution_order == [
        "first",
        "second",
    ]


def test_checker_short_circuit():

    execution_order = []


    class BlockingChecker(SentinelChecker):

        name = "blocking"

        priority = 10

        def check(self, ctx):

            execution_order.append(
                self.name
            )

            return SentinelDecision(
                allowed=False,
                risk_type="BLOCK",
                reason="blocked",
                recommended_response="BLOCK",
            )


    class ShouldNotRunChecker(SentinelChecker):

        name = "should_not_run"

        priority = 20

        def check(self, ctx):

            execution_order.append(
                self.name
            )

            return None


    checkers = [
        BlockingChecker(),
        ShouldNotRunChecker(),
    ]


    decision = None

    for checker in sorted(checkers):

        decision = checker.check(
            make_context()
        )

        if decision is not None:
            break


    assert decision is not None

    assert decision.allowed is False

    assert execution_order == [
        "blocking"
    ]


def test_function_checker():

    def custom_rule(ctx):

        if ctx.action == "authorize":
            return SentinelDecision(
                allowed=False,
                risk_type="CUSTOM_POLICY",
                reason="Authorization blocked.",
                recommended_response="BLOCK",
            )

        return None


    checker = FunctionChecker(
        fn=custom_rule,
        name="authorization_rule",
        priority=5,
    )


    result = checker.check(
        make_context(
            action="authorize"
        )
    )


    assert isinstance(
        result,
        SentinelDecision,
    )

    assert result.allowed is False


def test_function_checker_allow():

    def allow_rule(ctx):
        return None


    checker = FunctionChecker(
        fn=allow_rule
    )


    result = checker.check(
        make_context()
    )


    assert result is None