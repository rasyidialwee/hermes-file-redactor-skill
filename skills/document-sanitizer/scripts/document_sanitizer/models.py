"""Public result types. Never include original sensitive values."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Detection:
    """A redaction hit without storing the original value."""

    category: str
    start: int
    end: int
    confidence: float
    placeholder: str


@dataclass
class SanitizationResult:
    """Outcome of sanitizing a file or text blob."""

    content: str
    detections: list[Detection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sanitized: bool = True
    mode: str = "pii"
    file_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @property
    def categories(self) -> list[str]:
        return sorted({d.category for d in self.detections})
