# ScopeSentinel

Runtime scope enforcement and attack defense for autonomous web agents.

## Overview

ScopeSentinel is a lightweight runtime layer for LLM-driven web agents (browser automation, computer-use agents). It sits between the agent's planning step and the browser execution step, and checks every candidate action — click, type, goto, download, authorize — against the agent's original task before that action reaches the page.

Web agents observe untrusted content by design: page text, DOM structure, and screenshots all flow into the model's context on every step. That gives an attacker room to plant instructions inside a page (a fake "verify your identity" banner, a hidden form field, a manipulated screenshot) and steer the agent away from the user's actual goal. ScopeSentinel treats this as an execution-time problem: the question it asks is not "does this page contain something suspicious," but "does this specific action still serve the task the user asked for."

## Core mechanisms

**Action risk tiers.** Candidate actions are classified into three levels — Level0 (read-only/navigation: click, scroll, observe), Level1 (download, authorize), Level2 (typing/data entry). A task's maximum allowed level is derived at initialization and enforced as a hard ceiling.

**Information sensitivity tiers.** Typed content is scored S0 (public text — search terms, filters), S1 (basic personal data — name, phone, address), S2 (credentials, payment data, tokens). ScopeSentinel separately tracks what appeared in the task prompt versus what the task actually needs disclosed — a phone number mentioned in the prompt does not automatically become fair game for every form field on the page.

**Layered checks.** Structural/rule-based checkers run first (cheap, deterministic). Anything unresolved goes to an LLM-based judge that evaluates action-task alignment, click-target legitimacy, and background consistency. Repeated blocks on the same action signature escalate the response from BLOCK to TERMINATE, so the agent doesn't loop against a wall.

**Attack-family policies.** Three pluggable policies cover the main threat classes studied in current web-agent security research:
- `AgentBaitPolicy` — resists prompts that plant sensitive-looking bait data (SSNs, card numbers) to test whether the agent types them into random forms.
- `EIAPolicy` — resists environmental injection: hidden fields, disguised forms styled to match the legitimate page.
- `VPIPolicy` — resists visual prompt injection: attacker-controlled files, off-task resources, screenshots manipulated to influence action selection.

Each policy only activates when the task context signals its attack family, and augments the check pipeline with policy-specific instructions and protected-entity lists rather than replacing the core logic.

## Installation

```bash
pip install scopesentinel
# or, from source
git clone https://github.com/kiy-00/ScopeSentinel.git
cd ScopeSentinel
pip install -e .
```

Requires Python ≥ 3.10 and an OpenAI API key (`OPENAI_API_KEY` env var, or passed explicitly).

## Usage

### Basic setup

```python
from ScopeSentinel import ScopeSentinel

sentinel = ScopeSentinel(
    model="gpt-4o",
    openai_api_key="sk-...",       # or leave unset to read from env
    audit_log_dir="./logs",
    task_id="task-001",
)

sentinel.initialize(
    user_prompt="Find the cheapest flight from Shanghai to Tokyo and book it.",
    background="User is a returning customer on a travel booking site.",
)
```

### Checking an action before execution

Call this right before your agent submits an action to the browser:

```python
allowed, reason = sentinel.check_safety(
    action="type",
    element="input#promo-code-and-ssn",
    value="123-45-6789",
    html=current_page_html,
    current_url="https://example-travel.com/checkout",
)

if not allowed:
    print(f"Blocked: {reason}")
    # skip execution, or trigger sentinel.should_close_page() / should_terminate_task()
else:
    execute_action(action, element, value)
```

### Integrating with an agent loop

```python
for step in agent.run_steps():
    candidate = step.propose_action()
    allowed, reason = sentinel.check_safety(
        action=candidate.action,
        element=candidate.element,
        value=candidate.value,
        html=step.page_html,
        current_url=step.url,
        step_id=step.index,
    )
    if allowed:
        step.execute(candidate)
    elif sentinel.should_terminate_task():
        agent.abort(reason)
        break
    else:
        step.skip(reason)
```

### Configuration

```python
from ScopeSentinel import SentinelConfig

config = SentinelConfig(
    max_action_level="Level1",              # cap this instance below Level2 regardless of task
    max_allowed_input_sensitivity="S1",     # never allow S2 disclosure
    enable_visual_check=True,               # catch hidden/off-screen input targets
    repeated_block_terminate_count=3,
)
sentinel = ScopeSentinel(model="gpt-4o", config=config)
```

Custom checkers can be added for cheap, task-specific gates that run before the LLM judge — see `ScopeSentinel.checkers.FunctionChecker`.

## Extending with a new attack policy

```python
from ScopeSentinel.policies.base import BasePolicy
from ScopeSentinel.types import PolicyAugment

class MyPolicy(BasePolicy):
    name = "my_policy"

    def should_enable(self, ctx):
        return ctx.attack_family_hint == "my_policy"

    def build_policy_augment(self, ctx):
        return PolicyAugment(policy_instructions=["Flag any action targeting /admin/*."])
```

## Evaluation

ScopeSentinel has been evaluated against Task-Specific, Safety-Prompt, Supervisor, and AGrail baselines on a BrowserUse + GPT-4o setup, using AgentBait, EIA, and VPI-Bench attack sets plus a benign-task set for usability. Defense success rates of 90.0% (AgentBait), 86.0% (EIA), and 90.0% (VPI) were reported, alongside an 80.0% completion rate on normal tasks — the highest among the compared methods.

## Status

Research prototype. API surface may change. Contributions and issue reports welcome.

## License

MIT
