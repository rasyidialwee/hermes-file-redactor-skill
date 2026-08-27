"""Fixture-driven improve loop — report leaks and false positives."""

from __future__ import annotations

from dataclasses import dataclass, field

from .api import sanitize_text
from .config import SanitizerConfig


@dataclass(frozen=True)
class DocumentFixture:
    name: str
    text: str
    must_redact: list[str]
    safe_to_keep: list[str] = field(default_factory=list)
    mode: str = "pii"
    description: str = ""


@dataclass
class FixtureReport:
    name: str
    leaks: list[str]
    false_positives: list[str]
    detection_count: int
    categories: list[str]

    @property
    def ok(self) -> bool:
        return not self.leaks and not self.false_positives


def evaluate_fixture(
    fixture: DocumentFixture,
    *,
    config: SanitizerConfig | None = None,
) -> FixtureReport:
    cfg = config if config is not None else SanitizerConfig(mode=fixture.mode)
    result = sanitize_text(fixture.text, config=cfg)
    content = result.content
    leaks = [s for s in fixture.must_redact if s and s in content]
    false_positives = [s for s in fixture.safe_to_keep if s and s not in content]
    return FixtureReport(
        name=fixture.name,
        leaks=leaks,
        false_positives=false_positives,
        detection_count=result.detection_count,
        categories=list(result.categories),
    )


def run_improve(
    fixtures: list[DocumentFixture],
    *,
    cycles: int = 1,
    verbose: bool = False,
) -> tuple[list[FixtureReport], bool]:
    """Run fixtures for N cycles. Returns (last-cycle reports, all_clean)."""
    cycles = max(1, cycles)
    last: list[FixtureReport] = []
    for cycle in range(1, cycles + 1):
        last = [evaluate_fixture(f) for f in fixtures]
        dirty = [r for r in last if not r.ok]
        if verbose or dirty:
            print(f"=== improve cycle {cycle}/{cycles} ===")
            for r in last:
                if r.ok:
                    if verbose:
                        print(f"  OK  {r.name} detections={r.detection_count}")
                    continue
                print(f"  FAIL {r.name}")
                for leak in r.leaks:
                    print(f"    LEAK: {leak!r}")
                for fp in r.false_positives:
                    print(f"    FP:   {fp!r} (safe_to_keep removed)")
        if not dirty:
            print(f"Layer clean after cycle {cycle} — add new fixtures to raise the floor.")
            return last, True
    print(f"Still dirty after {cycles} cycle(s): {sum(1 for r in last if not r.ok)} fixture(s).")
    return last, False
