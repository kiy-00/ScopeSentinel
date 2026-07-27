from scopesentinel.types import SentinelTaskContext

from scopesentinel.policies import (
    AgentBaitPolicy,
    EIAPolicy,
    VPIPolicy,
)


def build_context(
    dataset_name="",
    attack_family_hint="",
):
    return SentinelTaskContext(
        user_task="test task",
        background="",
        attack_family_hint=attack_family_hint,
        dataset_name=dataset_name,
    )


# ============================================================
# AgentBait
# ============================================================


def test_agentbait_policy_enable():

    policy = AgentBaitPolicy()

    ctx = build_context(
        dataset_name="AgentBait"
    )

    assert (
        policy.should_enable(ctx)
        is True
    )


def test_agentbait_policy_disable_other_dataset():

    policy = AgentBaitPolicy()

    ctx = build_context(
        dataset_name="VPI"
    )

    assert (
        policy.should_enable(ctx)
        is False
    )


def test_agentbait_policy_build_augment():

    policy = AgentBaitPolicy()

    ctx = build_context(
        dataset_name="AgentBait"
    )

    augment = policy.build_policy_augment(
        ctx
    )

    assert augment is not None

    assert isinstance(
        augment.policy_instructions,
        list,
    )

    assert len(
        augment.policy_instructions
    ) > 0


    joined = "\n".join(
        augment.policy_instructions
    )


    assert (
        "personal"
        in joined.lower()
    )



# ============================================================
# EIA
# ============================================================


def test_eia_policy_enable():

    policy = EIAPolicy()

    ctx = build_context(
        dataset_name="EIA"
    )

    assert (
        policy.should_enable(ctx)
        is True
    )


def test_eia_policy_disable_other_dataset():

    policy = EIAPolicy()

    ctx = build_context(
        dataset_name="AgentBait"
    )

    assert (
        policy.should_enable(ctx)
        is False
    )


def test_eia_policy_build_augment():

    policy = EIAPolicy()

    ctx = build_context(
        dataset_name="EIA"
    )

    augment = policy.build_policy_augment(
        ctx
    )

    assert augment is not None


    assert isinstance(
        augment.policy_instructions,
        list,
    )


    assert len(
        augment.policy_instructions
    ) > 0


    joined = "\n".join(
        augment.policy_instructions
    )


    assert (
        "injected"
        in joined.lower()
    )


# ============================================================
# VPI
# ============================================================


def test_vpi_policy_enable():

    policy = VPIPolicy()

    ctx = build_context(
        dataset_name="VPI"
    )

    assert (
        policy.should_enable(ctx)
        is True
    )


def test_vpi_policy_disable_other_dataset():

    policy = VPIPolicy()

    ctx = build_context(
        dataset_name="EIA"
    )

    assert (
        policy.should_enable(ctx)
        is False
    )


def test_vpi_policy_build_augment():

    policy = VPIPolicy()

    ctx = build_context(
        dataset_name="VPI"
    )

    augment = policy.build_policy_augment(
        ctx
    )

    assert augment is not None


    assert isinstance(
        augment.policy_instructions,
        list,
    )


    assert len(
        augment.policy_instructions
    ) > 0


    joined = "\n".join(
        augment.policy_instructions
    )


    assert (
        "attacker"
        in joined.lower()
    )


# ============================================================
# Common interface
# ============================================================


def test_all_policies_have_required_interface():

    policies = [
        AgentBaitPolicy(),
        EIAPolicy(),
        VPIPolicy(),
    ]

    for policy in policies:

        assert hasattr(
            policy,
            "name",
        )

        assert hasattr(
            policy,
            "should_enable",
        )

        assert hasattr(
            policy,
            "build_policy_augment",
        )