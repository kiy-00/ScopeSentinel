from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Mapping, Optional


class PromptBlock(str, Enum):
    """
    Named extension points for ScopeSentinel LLM prompts.

    Each block corresponds to one or more internal LLM judgment stages.
    Users can attach additional instructions without modifying core.py.
    """

    SCOPE_EXTRA_CONSTRAINTS = "SCOPE_EXTRA_CONSTRAINTS"
    SENSITIVITY_EXTRA_RULES = "SENSITIVITY_EXTRA_RULES"
    DISCLOSURE_EXTRA_RULES = "DISCLOSURE_EXTRA_RULES"
    ACTION_EXTRA_CONTEXT = "ACTION_EXTRA_CONTEXT"
    FIELD_EXTRA_DEFINITIONS = "FIELD_EXTRA_DEFINITIONS"


@dataclass
class PromptOverrides:
    """
    User-defined prompt extensions for ScopeSentinel.

    This class supports named prompt blocks. Each block stores additional text
    that will be appended to a specific internal LLM prompt.

    Design principle:
    - PromptOverrides should not replace ScopeSentinel's built-in safety prompt.
    - It should only add task-specific, domain-specific, or deployment-specific
      rules on top of the default behavior.

    Example:
        overrides = PromptOverrides({
            PromptBlock.ACTION_EXTRA_CONTEXT:
                "For banking websites, transfer or withdrawal actions require explicit user authorization."
        })
    """

    blocks: Dict[PromptBlock, str] = field(default_factory=dict)

    def __init__(
        self,
        blocks: Optional[Mapping[PromptBlock | str, str]] = None,
        **kwargs: str,
    ) -> None:
        """
        Create PromptOverrides from either a mapping or keyword arguments.

        Accepted forms:

            PromptOverrides({
                PromptBlock.ACTION_EXTRA_CONTEXT: "extra rule"
            })

            PromptOverrides({
                "ACTION_EXTRA_CONTEXT": "extra rule"
            })

            PromptOverrides(
                ACTION_EXTRA_CONTEXT="extra rule"
            )

        Mapping values and keyword values are merged.
        Keyword values override mapping values if the same block appears twice.
        """
        merged: Dict[PromptBlock, str] = {}

        if blocks:
            for key, value in blocks.items():
                block = self._coerce_block(key)
                text = self._normalize_text(value)
                if text:
                    merged[block] = text

        for key, value in kwargs.items():
            block = self._coerce_block(key)
            text = self._normalize_text(value)
            if text:
                merged[block] = text

        self.blocks = merged

    @staticmethod
    def _coerce_block(value: PromptBlock | str) -> PromptBlock:
        """
        Convert a PromptBlock or string into PromptBlock.

        Supports:
        - PromptBlock.ACTION_EXTRA_CONTEXT
        - "ACTION_EXTRA_CONTEXT"
        - "PromptBlock.ACTION_EXTRA_CONTEXT" is intentionally not supported,
          because users should pass clean enum names or enum values.
        """
        if isinstance(value, PromptBlock):
            return value

        if not isinstance(value, str):
            raise TypeError("Prompt block key must be a PromptBlock or string.")

        raw = value.strip()
        if not raw:
            raise ValueError("Prompt block key cannot be empty.")

        try:
            return PromptBlock(raw)
        except ValueError:
            pass

        try:
            return PromptBlock[raw]
        except KeyError:
            allowed = ", ".join(block.name for block in PromptBlock)
            raise ValueError(f"Unknown prompt block '{value}'. Allowed blocks: {allowed}.")

    @staticmethod
    def _normalize_text(value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def get(self, block: PromptBlock | str, default: str = "") -> str:
        """
        Return the override text for a block.
        """
        block = self._coerce_block(block)
        return self.blocks.get(block, default)

    def set(self, block: PromptBlock | str, text: str) -> None:
        """
        Set or replace override text for a block.
        """
        block = self._coerce_block(block)
        normalized = self._normalize_text(text)
        if normalized:
            self.blocks[block] = normalized
        else:
            self.blocks.pop(block, None)

    def add(self, block: PromptBlock | str, text: str, separator: str = "\n") -> None:
        """
        Append text to an existing block.

        If the block does not exist, this behaves like set().
        """
        block = self._coerce_block(block)
        normalized = self._normalize_text(text)

        if not normalized:
            return

        existing = self.blocks.get(block, "")
        if existing:
            self.blocks[block] = existing + separator + normalized
        else:
            self.blocks[block] = normalized

    def remove(self, block: PromptBlock | str) -> None:
        """
        Remove a block override.
        """
        block = self._coerce_block(block)
        self.blocks.pop(block, None)

    def has(self, block: PromptBlock | str) -> bool:
        """
        Return whether a block has non-empty override text.
        """
        block = self._coerce_block(block)
        return bool(self.blocks.get(block, "").strip())

    def is_empty(self) -> bool:
        """
        Return whether no prompt overrides are defined.
        """
        return not any(text.strip() for text in self.blocks.values())

    def merge(
        self,
        other: Optional["PromptOverrides"],
        *,
        other_precedence: bool = True,
    ) -> "PromptOverrides":
        """
        Merge two PromptOverrides objects and return a new object.

        This is mainly used to combine:
        - instance-level overrides from ScopeSentinel(...)
        - task-level overrides from initialize(...)

        If other_precedence=True:
            other overrides replace self overrides when both define the same block.

        If other_precedence=False:
            self overrides keep priority.
        """
        if other is None:
            return PromptOverrides(self.blocks)

        merged: Dict[PromptBlock, str] = {}

        if other_precedence:
            merged.update(self.blocks)
            merged.update(other.blocks)
        else:
            merged.update(other.blocks)
            merged.update(self.blocks)

        return PromptOverrides(merged)

    def to_dict(self) -> Dict[str, str]:
        """
        Convert overrides to a JSON-serializable dictionary.
        """
        return {block.name: text for block, text in self.blocks.items() if text.strip()}

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, str]]) -> "PromptOverrides":
        """
        Create PromptOverrides from a JSON-like dictionary.
        """
        if not data:
            return cls()
        return cls(data)

    def format_for_prompt(
        self,
        block: PromptBlock | str,
        *,
        title: str = "Additional user-defined rules",
    ) -> str:
        """
        Format one block for insertion into an LLM prompt.

        Returns an empty string if the block is undefined.

        Example output:

            Additional user-defined rules:
            \"\"\"
            ...
            \"\"\"
        """
        text = self.get(block, "").strip()
        if not text:
            return ""

        title = str(title).strip() or "Additional user-defined rules"

        return f"""
{title}:
\"\"\"
{text}
\"\"\"
""".strip()

    def __bool__(self) -> bool:
        return not self.is_empty()