from scopesentinel import (
    FunctionChecker,
    PromptBlock,
    PromptOverrides,
    SentinelConfig,
    SentinelDecision,
)


def collect_prompts(mock_client):
    return [
        call["messages"][-1]["content"]
        for call in mock_client.chat.completions.calls
    ]


def test_core_basic_allow(
    make_sentinel,
    mock_llm_allow,
):
    sentinel = make_sentinel(
        mock_client=mock_llm_allow
    )

    decision = sentinel.pre_action_check(
        action="click",
        element="Search button",
        value="",
        html="<button>Search</button>",
    )

    assert isinstance(
        decision,
        SentinelDecision,
    )

    assert decision.allowed is True
    assert decision.risk_type == "NONE"


def test_core_custom_checker_blocks(
    make_sentinel,
    mock_llm_allow,
):

    def block_download(ctx):

        if ctx.action == "download":
            return SentinelDecision(
                allowed=False,
                risk_type="CUSTOM_POLICY",
                reason="Download blocked by checker.",
                recommended_response="BLOCK",
            )

        return None


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        checkers=[
            FunctionChecker(
                fn=block_download,
                name="block_download",
            )
        ],
    )


    decision = sentinel.pre_action_check(
        action="download",
        element="Download button",
        value="",
        html="<button>Download</button>",
    )


    assert decision.allowed is False
    assert decision.risk_type == "CUSTOM_POLICY"

    assert (
        decision.evidence["custom_checker"]
        == "block_download"
    )


def test_core_action_level_config_blocks(
    make_sentinel,
    mock_llm_allow,
):

    config = SentinelConfig(
        max_action_level="Level0"
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        config=config,
    )


    decision = sentinel.pre_action_check(
        action="type",
        element="Search input",
        value="hello",
        html="<input>",
    )


    assert decision.allowed is False
    assert decision.risk_type == "TASK_DEVIATION"



def test_core_prompt_override_reaches_llm(
    make_sentinel,
    mock_llm_allow,
):

    overrides = PromptOverrides(
        blocks={
            PromptBlock.SENSITIVITY_EXTRA_RULES:
                "Never allow payment actions."
        }
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        prompt_overrides=overrides,
    )


    sentinel._llm_estimate_input_sensitivity(
        "hello"
    )


    prompts = collect_prompts(
        mock_llm_allow
    )


    matched = [
        p
        for p in prompts
        if "Never allow payment actions."
        in p
    ]


    assert len(matched) > 0



def test_core_block_counter_terminates(
    make_sentinel,
):

    sentinel = make_sentinel()


    decision1 = sentinel._finalize_decision(
        "click",
        "bad button",
        "",
        SentinelDecision(
            allowed=False,
            risk_type="TASK_DEVIATION",
            reason="blocked",
            recommended_response="BLOCK",
        ),
    )


    decision2 = sentinel._finalize_decision(
        "click",
        "bad button",
        "",
        SentinelDecision(
            allowed=False,
            risk_type="TASK_DEVIATION",
            reason="blocked",
            recommended_response="BLOCK",
        ),
    )


    decision3 = sentinel._finalize_decision(
        "click",
        "bad button",
        "",
        SentinelDecision(
            allowed=False,
            risk_type="TASK_DEVIATION",
            reason="blocked",
            recommended_response="BLOCK",
        ),
    )


    assert decision1.recommended_response == "BLOCK"
    assert decision2.recommended_response == "BLOCK"
    assert decision3.recommended_response == "TERMINATE"



def test_core_recent_state_reset_after_navigation(
    make_sentinel,
):

    sentinel = make_sentinel()


    sentinel._recent_type_context = {
        "value": "hello",
        "value_sensitivity": "S0",
        "element": "Input",
        "current_url": "",
        "step_id": None,
    }


    sentinel.pre_action_check(
        action="goto",
        element="",
        value="",
        html="",
    )


    assert (
        sentinel._recent_type_context["value"]
        == ""
    )



def test_action_extra_context_reaches_action_judge(
    make_sentinel,
    mock_llm_allow,
):

    overrides = PromptOverrides(
        blocks={
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "Do not click payment-related buttons."
        }
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        prompt_overrides=overrides,
    )


    sentinel._llm_check_action_alignment(
        action="click",
        element_text="Product details",
        value_text="",
        current_url="",
        current_app="browser",
        context_text="shopping page",
    )


    prompts = collect_prompts(
        mock_llm_allow
    )


    assert any(
        "Do not click payment-related buttons."
        in p
        for p in prompts
    )



def test_sensitivity_extra_rules_reaches_sensitivity_judge(
    make_sentinel,
    mock_llm_allow,
):

    overrides = PromptOverrides(
        blocks={
            PromptBlock.SENSITIVITY_EXTRA_RULES:
                "Treat internal employee IDs as S1."
        }
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        prompt_overrides=overrides,
    )


    sentinel._llm_estimate_input_sensitivity(
        "employee123"
    )


    prompts = collect_prompts(
        mock_llm_allow
    )


    assert any(
        "Treat internal employee IDs as S1."
        in p
        for p in prompts
    )



def test_disclosure_extra_rules_reaches_disclosure_judge(
    make_sentinel,
    mock_llm_allow,
):

    overrides = PromptOverrides(
        blocks={
            PromptBlock.DISCLOSURE_EXTRA_RULES:
                "Phone numbers require explicit task justification."
        }
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        prompt_overrides=overrides,
    )


    sentinel._llm_check_sensitive_disclosure_necessity(
        element_text="Phone number field",
        value_text="13800138000",
        current_url="",
        current_app="browser",
        context_text="contact form",
        value_sensitivity="S1",
        protected_match=False,
    )


    prompts = collect_prompts(
        mock_llm_allow
    )


    assert any(
        "Phone numbers require explicit task justification."
        in p
        for p in prompts
    )



def test_field_extra_definitions_reaches_input_target_judge(
    make_sentinel,
    mock_llm_allow,
):

    overrides = PromptOverrides(
        blocks={
            PromptBlock.FIELD_EXTRA_DEFINITIONS:
                "Employee ID fields are considered low-risk identifiers."
        }
    )


    sentinel = make_sentinel(
        mock_client=mock_llm_allow,
        prompt_overrides=overrides,
    )


    sentinel._llm_check_input_target(
        element_text="Employee ID field",
        value_text="employee123",
        context_text="employee form",
        value_sensitivity="S1",
    )


    prompts = collect_prompts(
        mock_llm_allow
    )


    assert any(
        "Employee ID fields are considered low-risk identifiers."
        in p
        for p in prompts
    )