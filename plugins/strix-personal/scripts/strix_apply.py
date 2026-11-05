#!/usr/bin/env python3
"""strix-personal: plan and (optionally) apply a rollback-safe governance wrap.

Zero-install: imports the vendored core from ``_vendor/``. Run by the
``/strix-apply`` command, or standalone:

    # Dry-run: show the wrap plan + diff for one call site (default).
    python3 scripts/strix_apply.py --root . --file src/billing.py --line 47

    # Apply it (backs the file up first; prints the bypass check).
    python3 scripts/strix_apply.py --root . --file src/billing.py --line 47 --apply

By default this is a DRY RUN — nothing is written. ``--apply`` writes, after
backing the file up; ``--rollback`` restores from the most recent backup.
Multi-line / ambiguous call sites are refused (wrap them by hand under review).
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))

import action_scanner  # noqa: E402  (vendored)
import patcher  # noqa: E402  (vendored)
import signals  # noqa: E402  (vendored)


def _find_candidate(root: Path, file: str, line: int):
    for c in action_scanner.scan(root, include_ai=True, include_deps=False):
        if c.file == file and c.line == line:
            return c
    # Fall back to first match in the file if the exact line shifted.
    for c in action_scanner.scan(root, include_ai=True):
        if c.file == file:
            return c
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Plan/apply a rollback-safe governance wrap.")
    p.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p.add_argument("--file", required=True, help="Path (relative to root) of the call site.")
    p.add_argument("--line", type=int, required=True, help="1-based line of the call site.")
    p.add_argument("--apply", action="store_true", help="Write the change (default: dry run).")
    p.add_argument("--rollback", action="store_true", help="Restore the file from its backup.")
    p.add_argument(
        "--py-import",
        default=patcher._DEFAULT_PY_IMPORT,
        help="Python import line for the helper.",
    )
    p.add_argument(
        "--ts-import",
        default=patcher._DEFAULT_TS_IMPORT,
        help="TypeScript import line for the helper.",
    )
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    target = root / args.file

    if args.rollback:
        try:
            patcher.restore_file(target)
        except patcher.PatchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"rolled back {args.file} from backup.")
        return 0

    cand = _find_candidate(root, args.file, args.line)
    if cand is None:
        print(f"error: no governable action point found at {args.file}:{args.line}", file=sys.stderr)
        return 2

    plan = patcher.plan_wrap(root, cand, py_import=args.py_import, ts_import=args.ts_import)
    print(f"capability: {plan.capability_id}   language: {plan.language}")

    if not plan.is_applicable:
        print(f"NOT auto-wrappable: {plan.skipped_reason}")
        print("→ wrap this call by hand under review; it stays WRAPPABLE.")
        return 1

    before = target.read_text(encoding="utf-8")
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        plan.new_text.splitlines(keepends=True),
        fromfile=f"a/{args.file}",
        tofile=f"b/{args.file}",
    )
    print("".join(diff))

    if not args.apply:
        print("\n(dry run — re-run with --apply to write. The file is backed up first.)")
        return 0

    res = patcher.apply_wrap(root, plan)

    # The bypass check is REPO-WIDE, not file-local. ENFORCED means "no
    # sibling unwrapped call site bypasses the boundary" — a claim about the
    # whole tree. Reading only the edited file would PASS while an ungoverned
    # call to the same capability sat in another module, which is exactly the
    # case the state exists to rule out.
    after = action_scanner.scan(root, include_ai=True, include_deps=False)
    same_cap = [c for c in after if c.capability_id == plan.capability_id]
    bypasses = [c for c in same_cap if not c.governed and not c.suppressed]
    routed = bool(same_cap) and not bypasses and any(c.governed for c in same_cap)

    print(f"\napplied. backup: {res.backup_path.name}")
    print(
        f"bypass check: {'PASS — all calls routed through the boundary' if routed else 'OPEN'}"
        f"  ({len(same_cap)} call site(s) to {plan.capability_id} repo-wide)"
    )
    if bypasses:
        print(f"  {len(bypasses)} ungoverned call(s) to {plan.capability_id} remain:")
        for b in bypasses:
            print(f"    {b.file}:{b.line}  {b.snippet.strip()}")
        print("  → wrap these too before this capability can reach ENFORCED.")

    # Record the result so it survives to /strix-status. This is the ENFORCED
    # signal: a static scan cannot produce it, and until now nothing persisted
    # it — it was printed here and lost. A failing check is recorded too, so a
    # reintroduced bypass demotes the capability instead of leaving a stale
    # PASS standing.
    try:
        rec = signals.record_bypass(
            capability_id=plan.capability_id,
            candidates=after,
            passed=routed,
            source="/strix-apply",
        )
        signals.SignalJournal.for_root(root).append(rec)
        print(f"  signal recorded: bypass {'PASS' if routed else 'OPEN'} → /strix-status")
    except signals.SignalError as exc:
        # Never fail the wrap because the journal is unwritable — the code
        # change already succeeded and reporting it is the lesser concern.
        print(f"  (bypass signal not recorded: {exc})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
