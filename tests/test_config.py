from scopesentinel import SentinelConfig


def test_default_config_values():
    """
    Default configuration should be usable.
    """

    config = SentinelConfig()

    assert config.max_action_level == "Level2"

    assert config.max_allowed_input_sensitivity == "S2"

    assert config.max_allowed_disclosure_sensitivity == "S2"

    assert config.enable_visual_check is True

    assert config.enable_url_scan is False

    assert config.strict_mode is False

    assert config.repeated_block_terminate_count == 3


def test_action_level_limit():
    """
    max_action_level should restrict higher-risk actions.
    """

    config = SentinelConfig(
        max_action_level="Level0"
    )

    assert config.allows_action_level(
        "Level0"
    )

    assert not config.allows_action_level(
        "Level1"
    )

    assert not config.allows_action_level(
        "Level2"
    )


def test_input_sensitivity_limit():
    """
    Input sensitivity should respect configured maximum.
    """

    config = SentinelConfig(
        max_allowed_input_sensitivity="S1"
    )

    assert config.allows_input_sensitivity(
        "S0"
    )

    assert config.allows_input_sensitivity(
        "S1"
    )

    assert not config.allows_input_sensitivity(
        "S2"
    )


def test_disclosure_sensitivity_limit():
    """
    Disclosure sensitivity should respect configured maximum.
    """

    config = SentinelConfig(
        max_allowed_disclosure_sensitivity="S0"
    )

    assert config.allows_disclosure_sensitivity(
        "S0"
    )

    assert not config.allows_disclosure_sensitivity(
        "S1"
    )

    assert not config.allows_disclosure_sensitivity(
        "S2"
    )


def test_extra_allowed_domains_merge():

    config = SentinelConfig(
        extra_allowed_domains=[
            "example.com"
        ]
    )

    domains = config.all_allowed_domains(
        [
            "google.com",
            "example.com",
        ]
    )

    assert domains == [
        "google.com",
        "example.com",
    ]


def test_invalid_action_level():

    try:
        SentinelConfig(
            max_action_level="Level3"
        )
    except ValueError:
        return

    assert False, "Invalid action level should raise ValueError"


def test_invalid_sensitivity():

    try:
        SentinelConfig(
            max_allowed_input_sensitivity="S3"
        )
    except ValueError:
        return

    assert False, "Invalid sensitivity should raise ValueError"


def test_strict_mode_setting():

    config = SentinelConfig(
        strict_mode=True
    )

    assert config.strict_mode is True


def test_visual_check_switch():

    config = SentinelConfig(
        enable_visual_check=False
    )

    assert config.enable_visual_check is False