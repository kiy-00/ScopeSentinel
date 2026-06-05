from __future__ import annotations

from enum import Enum


class ActionLevel(str, Enum):
    """
    Permitted action level for a web agent task.
    """

    # Navigation and clicks only: hover, scroll, goto, click, new tab, close tab, select.
    CLICK_ONLY = "Level0"

    # Level0 + download and authorize.
    STANDARD = "Level1"

    # Level1 + keyboard input (type).
    FULL = "Level2"


class SensitivityLevel(str, Enum):
    """
    Information sensitivity classification.
    """

    # Generic public or non-sensitive text.
    PUBLIC = "S0"

    # Basic personal or identifying information (name, email, phone, membership number).
    PERSONAL = "S1"

    # Credentials, payment data, secrets, or identity-critical information.
    CONFIDENTIAL = "S2"
