#!/usr/bin/env python3
"""strix-personal: lifecycle rollup for the repo (the /strix-status surface).

Shows where every action point sits on DETECTED → … → VERIFIED, plus coverage.
Read-only. Zero-install (vendored core).

    python3 scripts/strix_status.py --root . [--include-ai] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))

import action_scanner  # noqa: E402  (vendored)
import signals  # noqa: E402  (vendored)
from lifecycle import (  # noqa: E402  (vendored)
    _PROGRESSION,
    MAX_STATIC_STATE,
    ActionState,
    ScanReport,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lifecycle status for the repository.")
    p.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p.add_argument("--include-ai", action="store_true", help="Include AI surfaces.")
    p.add_argument("--json", action="store_true", help="Emit JSON.")
    p.add_argument(
        "--no-signals",
        action="store_true",
        help="Show the static scan only, ignoring recorded runtime signals.",
    )
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    candidates = action_scanner.scan(root, include_ai=args.include_ai)
    report = ScanReport.from_candidates(candidates)

    # Replay recorded runtime signals. This is the ONLY way a state past
    # WRAPPED appears — the scan above cannot produce one, and every signal is
    # re-checked against the tree that was just scanned before it may move
    # anything. An expired signal is dropped and reported, never applied
    # quietly.
    outcome = signals.ApplyOutcome()
    if not args.no_signals:
        journal = signals.SignalJournal.for_root(root)
        outcome = signals.apply_signals(report, journal.current(), candidates=candidates)

    states = report.by_state()

    if args.json:
        print(json.dumps({
            "schema": "strix_personal.status/v1",
            "total": report.total,
            "coverage": report.coverage(),
            "governed": report.governed_count(),
            "by_state": states,
            "signals": {
                "applied": len(outcome.applied),
                "advanced": outcome.advanced,
                "dropped": [
                    {
                        "kind": d.record.kind,
                        "capability_id": d.record.capability_id,
                        "file": d.record.file,
                        "line": d.record.line,
                        "reason": d.reason,
                    }
                    for d in outcome.dropped
                ],
                "max_static_state": MAX_STATIC_STATE.value,
            },
        }, indent=2))
        return 0

    print("\U0001f512 Strix Personal — lifecycle status")
    print(report.headline())
    print("")
    ordered = [*_PROGRESSION, ActionState.SUPPRESSED]
    width = max((len(s.value) for s in ordered), default=10)
    for s in ordered:
        n = states.get(s.value, 0)
        bar = "█" * n
        print(f"  {s.value.ljust(width)}  {str(n).rjust(3)}  {bar}")
    print("")

    # Where the states above WRAPPED came from — and where they did not.
    if args.no_signals:
        print("Runtime signals ignored (--no-signals): static scan only.")
    else:
        print(outcome.summary())
        for d in outcome.dropped:
            where = f"{d.record.file}:{d.record.line}" if d.record.file else d.record.capability_id
            print(f"  dropped  {d.record.kind:<9}{where:<38}{d.reason}")
        above = sum(
            n for s, n in states.items()
            if s in ("tested", "enforced", "verified")
        )
        if not above:
            print(
                f"  Nothing is past `{MAX_STATIC_STATE.value}` — a scan cannot put it there. "
                "Produce a signal:"
            )
            for kind, producer in signals.PRODUCER_FOR_KIND.items():
                print(f"    {signals.STATE_FOR_KIND[kind].value:<10}{producer}")
    print("")

    if report.coverage() >= 0.999 and report.total:
        print("All detected actions are governed locally.")
        print("Upgrade to hosted approvals + public proof links: strixgov.com (Connected Mode).")
    else:
        print("Next: /strix-apply to wrap the open action points.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
