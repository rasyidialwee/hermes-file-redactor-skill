"""In-memory placeholder identity mapping for one sanitization run."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlaceholderSession:
    """Maps exact string values to stable typed placeholders within one run.

    The reverse map must never be serialized into LLM context or logs.
    Discard the session when the process exits.
    """

    _counters: dict[str, int] = field(default_factory=dict)
    _value_to_placeholder: dict[tuple[str, str], str] = field(default_factory=dict)

    def placeholder_for(self, category: str, value: str) -> str:
        key = (category, value)
        existing = self._value_to_placeholder.get(key)
        if existing is not None:
            return existing
        n = self._counters.get(category, 0) + 1
        self._counters[category] = n
        token = f"[{category}_{n:03d}]"
        self._value_to_placeholder[key] = token
        return token

    def clear(self) -> None:
        self._counters.clear()
        self._value_to_placeholder.clear()
