import json
from types import SimpleNamespace
from typing import Any

import pytest

from scopesentinel import ScopeSentinel, SentinelConfig, config


class MockCompletionResponse:
    """
    Mimic OpenAI chat completion response.
    """

    def __init__(self, content: str):
        self.choices = [
            SimpleNamespace(
                message=SimpleNamespace(
                    content=content
                )
            )
        ]


class MockChatCompletion:
    """
    Mock:
        client.chat.completions.create()
    """

    def __init__(self, response_factory):
        self.response_factory = response_factory
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        content = self.response_factory(kwargs)

        return MockCompletionResponse(content)


class MockChat:
    def __init__(self, response_factory):
        self.completions = MockChatCompletion(response_factory)


class MockOpenAI:
    """
    Fake OpenAI client.
    """

    def __init__(self, response_factory):
        self.chat = MockChat(response_factory)


def _default_task_scope_response():
    """
    Mock response for _llm_parse_task_scope.
    """

    return json.dumps(
        {
            "permissions_level": "Level2",
            "observed_prompt_sensitivity": "S0",
            "allowed_disclosure_sensitivity": "S0",
            "allowed_domains": [],
            "allowed_apps": [
                "browser"
            ],
            "allowed_data_sources": [
                "current_website"
            ],
            "task_summary": "mock task",
            "task_constraints": [],
        }
    )


@pytest.fixture
def mock_llm_allow():
    """
    Mock all LLM decisions as ALLOW.
    """

    def factory(kwargs):

        prompt = kwargs["messages"][-1]["content"]
        prompt_lower = prompt.lower()

        if "minimum safe execution scope" in prompt_lower:
            return _default_task_scope_response()

        if "classify the sensitivity" in prompt_lower:
            return "S0"

        return json.dumps(
            {
                "allowed": True,
                "risk_type": "NONE",
                "reason": "mock allow",
                "field_role": "UNKNOWN",
                "form_region_aligned": True,
                "low_risk_slot_group": False,
            }
        )

    return MockOpenAI(factory)


@pytest.fixture
def mock_llm_block():
    """
    Mock all LLM decisions as BLOCK.
    """

    def factory(kwargs):

        prompt = kwargs["messages"][-1]["content"]
        prompt_lower = prompt.lower()

        if "classify the sensitivity" in prompt_lower:
            return "S2"

        if "minimum safe execution scope" in prompt_lower:
            return json.dumps(
                {
                    "permissions_level": "Level2",
                    "observed_prompt_sensitivity": "S2",
                    "allowed_disclosure_sensitivity": "S0",
                    "allowed_domains": [],
                    "allowed_apps": [
                        "browser"
                    ],
                    "allowed_data_sources": [
                        "current_website"
                    ],
                    "task_summary": "mock task",
                    "task_constraints": [],
                }
            )

        return json.dumps(
            {
                "allowed": False,
                "risk_type": "TASK_DEVIATION",
                "reason": "mock block",
                "field_role": "UNKNOWN",
                "form_region_aligned": False,
                "low_risk_slot_group": False,
            }
        )

    return MockOpenAI(factory)


@pytest.fixture
def make_sentinel():
    """
    Factory fixture for creating ScopeSentinel instances.
    """

    def factory(
        mock_client=None,
        **kwargs: Any,
    ):

        config = kwargs.pop(
            "config",
            SentinelConfig()
        )

        sentinel = ScopeSentinel(
            openai_api_key="test-key",
            config=config,
            **kwargs,
        )

        if mock_client is not None:
            sentinel.client = mock_client

        return sentinel

    return factory