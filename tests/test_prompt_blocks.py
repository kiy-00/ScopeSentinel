from scopesentinel import PromptBlock, PromptOverrides


def test_prompt_override_basic_storage():
    """
    PromptOverrides should store custom prompt blocks.
    """

    overrides = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Never allow payment actions."
        }
    )

    assert (
        overrides.get(
            PromptBlock.ACTION_EXTRA_CONTEXT
        )
        == "Never allow payment actions."
    )


def test_prompt_override_string_key():
    """
    String keys should also work.
    """

    overrides = PromptOverrides(
        blocks={
            "ACTION_EXTRA_CONTEXT":
                "Extra rule"
        }
    )

    assert (
        overrides.get(
            PromptBlock.ACTION_EXTRA_CONTEXT
        )
        == "Extra rule"
    )


def test_prompt_override_format_for_prompt():
    """
    format_for_prompt should generate LLM prompt text.
    """

    overrides = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Never allow payment actions."
        }
    )

    text = overrides.format_for_prompt(
        PromptBlock.ACTION_EXTRA_CONTEXT
    )

    assert (
        "Never allow payment actions."
        in text
    )

    assert (
        "Additional user-defined rules"
        in text
    )


def test_prompt_override_empty_block():

    overrides = PromptOverrides()

    text = overrides.format_for_prompt(
        PromptBlock.ACTION_EXTRA_CONTEXT
    )

    assert text == ""


def test_prompt_override_merge_task_priority():
    """
    Task-level override should replace instance-level override.
    """

    base = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Base rule"
        }
    )

    task = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Task rule"
        }
    )

    merged = base.merge(
        task,
        other_precedence=True,
    )

    assert (
        merged.get(
            PromptBlock.ACTION_EXTRA_CONTEXT
        )
        == "Task rule"
    )


def test_prompt_override_merge_keep_base():

    base = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Base rule"
        }
    )

    task = PromptOverrides(
        blocks={
            PromptBlock.FIELD_EXTRA_DEFINITIONS:
                "Field rule"
        }
    )

    merged = base.merge(
        task,
        other_precedence=True,
    )

    assert (
        merged.get(
            PromptBlock.ACTION_EXTRA_CONTEXT
        )
        == "Base rule"
    )

    assert (
        merged.get(
            PromptBlock.FIELD_EXTRA_DEFINITIONS
        )
        == "Field rule"
    )


def test_prompt_override_invalid_block():

    try:
        PromptOverrides(
            blocks={
                "UNKNOWN_BLOCK":
                    "invalid"
            }
        )
    except ValueError:
        return

    assert False, (
        "Unknown prompt block should raise ValueError"
    )