#!/usr/bin/env python3
"""strix-personal: record what a runtime check actually observed.

This is the ``/strix-test`` write surface — the only way a fact that a static
scan cannot see (a deny scenario passed; a real signed record was produced)
reaches ``/strix-status``. Without it those outcomes lived only in a chat
transcript and the next command reset everything to WRAPPED.

    # a deny/approval scenario passed against one wrapped call site
    python3 scripts/strix_signal.py record --root . \
        --kind test --file src/billing.py --line 47 --passed

    # the wrapped call produced a real signed record
    python3 scripts/strix_signal.py record --root . \
        --kind evidence --file src/billing.py --line 47 --evidence-id evt_123

    # what has been recorded, and what still applies
    python3 scripts/strix_signal.py list --root . [--json]

What this does NOT do: it does not verify anything. It records what a check
reported. The record is unsigned, local, and re-checked against the tree on
every read — a signal whose call site changed is dropped, not trusted. The
signed record named by ``--evidence-id`` is the artifact a third party
verifies (``npx @strixgov/verifier@latest <id>``); this file just remembers
which call site produced it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))

import action_scanner  # noqa: E402  (vendored)
import signals  # noqa: E402  (vendored)
from lifecycle import ScanReport  # noqa: E402  (vendored)


def _find(candidates, file: str, line: int):
    """Resolve the call site a signal is about.

    Exact match first; then the same file, since a line number drifts with
    edits above it and a signal keyed to a stale line would silently attach to
    whatever now occupies it. Ambiguity is refused rather than guessed.
    """
    exact = [c for c in candidates if c.file == file and c.line == line]
    if exact:
        return exact[0], None
    in_file = [c for c in candidates if c.file == file]
    if len(in_file) == 1:
        return in_file[0], f"line {line} not found; matched the one call site in {file}"
    if not in_file:
        return None, f"no scanned call site in {file}"
    lines = ", ".join(str(c.line) for c in in_file)
    return None, f"{file} has several call sites (lines {lines}) — pass the exact --line"


def _cmd_record(args) -> int:
    root = Path(args.root).resolve()
    candidates = action_scanner.scan(root, include_ai=True, include_deps=False)

    if args.kind == "bypass":
        # Repo-scoped, and it has a real producer already: the check runs
        # inside /strix-apply, against the post-wrap tree. Recording one by
        # hand here would assert a repo-wide property nobody checked.
        print(
            "refusing: 'bypass' is recorded by /strix-apply, which actually runs the "
            "repo-wide check. Re-run the wrap to refresh it.",
            file=sys.stderr,
        )
        return 2

    target, why = _find(candidates, args.file, args.line)
    if target is None:
        print(f"refusing: {why}", file=sys.stderr)
        return 2
    if why:
        print(f"note: {why}")

    if not target.governed:
        # TESTED and VERIFIED both sit above WRAPPED. Recording against an
        # unwrapped call would produce a signal that can never apply — better
        # to say so now than to let it sit in the journal looking effective.
        print(
            f"refusing: {target.file}:{target.line} is not wrapped yet. "
            f"{args.kind} sits above WRAPPED — run /strix-apply first.",
            file=sys.stderr,
        )
        return 2

    try:
        rec = signals.record_site(
            kind=args.kind,
            candidate=target,
            passed=args.passed,
            evidence_id=args.evidence_id,
            source=args.source,
            detail=args.detail,
        )
        signals.SignalJournal.for_root(root).append(rec)
    except signals.SignalError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        return 2

    verdict = "PASS" if args.passed else "FAIL"
    print(f"recorded {args.kind} {verdict} for {target.file}:{target.line} [{target.capability_id}]")
    if args.evidence_id:
        print(f"  evidence: {args.evidence_id}")
        print(f"  verify independently: npx @strixgov/verifier@latest {args.evidence_id}")
    if not args.passed:
        print("  a failing signal revokes any earlier pass for this call site.")
    print("Next: /strix-status")
    return 0


def _cmd_list(args) -> int:
    root = Path(args.root).resolve()
    journal = signals.SignalJournal.for_root(root)
    current = journal.current()
    candidates = action_scanner.scan(root, include_ai=True, include_deps=False)
    report = ScanReport.from_candidates(candidates)
    outcome = signals.apply_signals(report, current, candidates=candidates)

    if args.json:
        print(
            json.dumps(
                {
                    "schema": "strix_personal.signals/v1",
                    "journal": str(journal.path),
                    "recorded": len(current),
                    "applied": len(outcome.applied),
                    "dropped": [
                        {"kind": d.record.kind, "capability_id": d.record.capability_id,
                         "file": d.record.file, "line": d.record.line, "reason": d.reason}
                        for d in outcome.dropped
                    ],
                    "measurement": signals_disclaimer(),
                },
                indent=2,
            )
        )
        return 0

    print(f"Signal journal: {journal.path}")
    if not current:
        print("No runtime signals recorded yet.")
        print("")
        for kind, producer in signals.PRODUCER_FOR_KIND.items():
            print(f"  {kind:<10}produced by {producer}")
        return 0
    print(outcome.summary())
    print("")
    for entry, rec in outcome.applied:
        ev = f"  evidence={rec.evidence_id}" if rec.evidence_id else ""
        # The state THIS signal unlocked, not the entry's final state — three
        # signals on one call site would otherwise all read "→ verified" and
        # imply each one got it there.
        unlocked = signals.STATE_FOR_KIND[rec.kind].value
        print(f"  applied  {rec.kind:<9}{entry.location:<34}→ {unlocked:<10}{ev}")
    for d in outcome.dropped:
        where = f"{d.record.file}:{d.record.line}" if d.record.file else d.record.capability_id
        print(f"  dropped  {d.record.kind:<9}{where:<40}{d.reason}")
    print("")
    print(f"{signals_disclaimer()}.")
    return 0


def signals_disclaimer() -> str:
    from lifecycle import MEASUREMENT_DISCLAIMER  # noqa: PLC0415  (vendored, lazy)

    return MEASUREMENT_DISCLAIMER


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Record and inspect runtime governance signals.")
    sub = p.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("record", help="Record what a runtime check observed.")
    rec.add_argument("--root", default=".", help="Repository root (default: cwd).")
    rec.add_argument("--kind", required=True, choices=sorted(signals.STATE_FOR_KIND),
                     help="test → TESTED · evidence → VERIFIED · bypass is /strix-apply's.")
    rec.add_argument("--file", required=True, help="Repo-relative path of the wrapped call site.")
    rec.add_argument("--line", type=int, required=True, help="Line of the wrapped call site.")
    rec.add_argument("--passed", action="store_true", default=False,
                     help="The check passed. Omit to record a FAILURE, which revokes any earlier pass.")
    rec.add_argument("--evidence-id", default=None,
                     help="Required for a passing --kind evidence: the signed record's id.")
    rec.add_argument("--source", default="/strix-test", help="What produced this observation.")
    rec.add_argument("--detail", default="", help="Free-text note carried on the record.")
    rec.set_defaults(func=_cmd_record)

    lst = sub.add_parser("list", help="Show recorded signals and whether they still apply.")
    lst.add_argument("--root", default=".", help="Repository root (default: cwd).")
    lst.add_argument("--json", action="store_true", help="Emit JSON.")
    lst.set_defaults(func=_cmd_list)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
