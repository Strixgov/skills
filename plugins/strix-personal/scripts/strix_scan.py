#!/usr/bin/env python3
"""strix-personal: scan a repo for consequential actions and report lifecycle.

Zero-install: imports the vendored core from ``_vendor/`` — no ``pip install``
required. Run by the ``/strix-scan`` command, or standalone:

    python3 scripts/strix_scan.py --root . [--include-ai] [--json]

Output is the DETECTED → … inventory with coverage. It NEVER wraps or executes
anything — scanning is read-only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))

import action_scanner  # noqa: E402  (vendored)
from lifecycle import (  # noqa: E402  (vendored)
    CONFIDENCE_MEANING,
    FAST_PATH_COMMAND,
    MEASUREMENT_DISCLAIMER,
    PIPELINE,
    SEVERITY_MEANING,
    STATE_MEANING,
    ScanReport,
)

# Compatibility coverage for the public Wire happy-path fixture. The canonical
# catalog historically described pathlib unlink but omitted its regex, so a
# normal ``target = Path(...); target.unlink()`` action was invisible. Keep the
# scope deliberately narrow: a named Python receiver followed by ``.unlink()``.
_PATHLIB_UNLINK_PATTERN = (
    r"\b[A-Za-z_][A-Za-z0-9_]*\.unlink\s*\(",
    "mutation",
    "file-delete",
    "filesystem.delete",
    "medium",
    frozenset({".py"}),
)
if _PATHLIB_UNLINK_PATTERN not in action_scanner.MUTATION_PATTERNS:
    action_scanner.MUTATION_PATTERNS.insert(0, _PATHLIB_UNLINK_PATTERN)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan for consequential (governable) actions.")
    p.add_argument("--root", default=".", help="Repository root to scan (default: cwd).")
    p.add_argument("--include-ai", action="store_true", help="Also surface AI call sites.")
    p.add_argument("--only-ai", action="store_true", help="Only AI surfaces.")
    p.add_argument("--include-deps", action="store_true", help="Scan dependency manifests too.")
    p.add_argument("--limit", type=int, default=50, help="Max candidates (default 50).")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of the human report.")
    p.add_argument(
        "--no-legend",
        action="store_true",
        help="Omit the 'how to read this' block from the text report. The measurement "
        "boundary is printed either way.",
    )
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 3

    candidates = action_scanner.scan(
        root,
        limit=args.limit,
        include_mutations=not args.only_ai,
        include_ai=args.include_ai or args.only_ai,
        include_deps=args.include_deps,
    )
    report = ScanReport.from_candidates(candidates)

    if args.json:
        payload = {
            "schema": "strix_personal.scan_report/v1",
            "headline": report.headline(),
            "total": report.total,
            "coverage": report.coverage(),
            "by_state": report.by_state(),
            "by_severity": report.by_severity(),
            "measurement": MEASUREMENT_DISCLAIMER,
            "legend": {
                "severity": SEVERITY_MEANING,
                "confidence": CONFIDENCE_MEANING,
                "state": STATE_MEANING,
                "coverage": "(governed + suppressed) / total",
                "blocking": "ungoverned AND unsuppressed AND severity == error",
            },
            "pipeline": [
                {"command": c, "verb": v, "effect": e, "does": d} for c, v, e, d in PIPELINE
            ],
            "fast_path": {
                "command": FAST_PATH_COMMAND,
                "in_pipeline": False,
                "executes_wrapped_action": True,
                "note": "one-shot: scans, wraps, and RUNS the action once to mint evidence",
            },
            "entries": [
                {
                    "state": e.state.value,
                    "capability_id": e.capability_id,
                    "file": e.candidate.file,
                    "line": e.candidate.line,
                    "severity": e.candidate.severity,
                    "confidence": e.candidate.confidence,
                    "snippet": e.candidate.snippet.strip(),
                    "governed": e.candidate.governed,
                }
                for e in report.entries
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(report.render(legend=not args.no_legend))

    return 0


if __name__ == "__main__":
    sys.exit(main())
