#!/usr/bin/env python3
"""strix-wire preflight guard — fail-closed detection of repos that must NOT be
auto-wired.

strix-wire is a *quickstart* for codebases with NO governance: it wraps ONE
irreversible call and RUNS it once. Two kinds of repo make that a mistake, and
this guard exists so the skill refuses by construction instead of relying on a
human noticing:

  1. ALREADY-GOVERNED — the repo already ships a first-party Strix governance
     layer (governedProcedure / Canonical Proof Flow / signed evidence). Wiring
     the quickstart helper here adds a lesser, unsigned, redundant path.

  2. PRODUCTION — the repo shows live-system markers (live Stripe keys,
     .env.production, real deploy domains). strix-wire's final step fires a real
     irreversible mutation; that must never happen on a live system without
     explicit sign-off.

Contract (pinned by tests/test_strix_wire_preflight.py):
  - stdlib only, standalone (no solo_builder import) so it is byte-identical as
    the loose skill file AND vendored into the strix-personal plugin.
  - verdict "STOP" when governed OR production markers are found; "OK" otherwise.
  - exit code 3 on STOP, 0 on OK, 2 on bad invocation. Fail CLOSED: an
    unreadable root or a scan error resolves to STOP, never a silent OK.

Usage:
    python3 preflight.py [--root .] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Directories never worth scanning (and huge on real repos).
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "out", "coverage",
    "venv", ".venv", "env", "__pycache__", ".solo", ".well-known", ".turbo",
    ".cache", "vendor", "target", ".pytest_cache", ".mypy_cache",
}
# Extensions / name prefixes worth reading.
_TEXT_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".json", ".sql",
    ".prisma", ".md", ".yml", ".yaml", ".toml",
}
_MAX_BYTES = 512 * 1024      # skip files larger than this
_MAX_FILES = 6000            # bound the walk on very large repos
_MAX_MARKERS = 12            # collect enough to be convincing, then stop

# --- Marker patterns ---------------------------------------------------------
# Each entry: (compiled regex, human label, kind: "governed" | "production").
_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # already-governed (first-party Strix)
    (re.compile(r"governedProcedure\s*\("), "governedProcedure() call site", "governed"),
    (re.compile(r"\bgovernedAction\s*\(|\bgoverned_action\s*\("), "governedAction() already wired", "governed"),
    (re.compile(r"evidence_outbox|governance_evidence\b"), "governance evidence tables", "governed"),
    (re.compile(r"CanonicalProofFlow|Canonical Proof Flow|_proof\b.*evidenceId"), "Canonical Proof Flow", "governed"),
    (re.compile(r"@strixgov/"), "@strixgov/* dependency", "governed"),
    (re.compile(r"execution control system for AI agents"), "Strix governance CLAUDE.md", "governed"),
    # production / live-system
    (re.compile(r"sk_live_[A-Za-z0-9]"), "live Stripe secret key (sk_live_)", "production"),
    (re.compile(r"\b(academytn\.com|strixgov\.com|velarisgroup\.app)\b"), "production deploy domain", "production"),
    (re.compile(r"(NODE_ENV|VERCEL_ENV|NEXT_PUBLIC_APP_ENV)\s*[=:]\s*[\"']?production"), "NODE_ENV=production", "production"),
]
# Filenames that are themselves markers (no content read needed).
_FILENAME_MARKERS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^strix-capabilities(\.test)?\.ts$"), "strix-capabilities registry", "governed"),
    (re.compile(r"governed-procedure\.ts$"), "governed-procedure.ts", "governed"),
    (re.compile(r"^\.env(\..+)?\.production$|^\.env\.production$"), "production env file", "production"),
]


def _is_env_file(name: str) -> bool:
    return name.startswith(".env")


def _normalized_realpath(path: Path | str) -> str:
    """Fully resolved, normalized, case-folded-where-the-OS-is path.

    `normcase` matters on Windows, where `C:\\Repo\\Src` and `c:\\repo\\src`
    are the same location: a case-sensitive comparison would let a differently
    cased path escape containment. It is a no-op on POSIX, where case IS
    significant, so the same code is correct on both.
    """
    return os.path.normcase(os.path.normpath(os.path.realpath(path)))


def _contained(path: Path | str, root_real: str) -> bool:
    """True if `path`'s RESOLVED target lies inside `root_real`.

    Resolution is the whole point: `Path.is_symlink()` is not sufficient
    because a Windows directory junction is a reparse point that reports
    False, while `realpath` collapses junctions, symlinks and `..` alike.

    `commonpath` rather than a `startswith` prefix test: prefix comparison
    states the invariant only indirectly and gets sibling names wrong —
    `C:\\repo-escape` shares a prefix with `C:\\repo`. (The `+ os.sep` guard
    happens to cover that one case, but `commonpath` expresses "is inside"
    directly instead of relying on a separator trick.) It also raises on
    cross-drive comparison, which is exactly the not-contained answer.

    Any path that cannot be resolved or compared is NOT contained — an
    unresolvable entry is precisely the one not to touch.
    """
    try:
        target = _normalized_realpath(path)
        return os.path.commonpath([root_real, target]) == root_real
    except (OSError, ValueError):
        # ValueError covers commonpath across different drives / mixed
        # absolute-relative, both of which mean "outside".
        return False


def scan(root: Path) -> dict:
    """Walk the repo (bounded) and collect governance/production markers.

    Fail closed: any structural problem resolves to STOP.
    """
    markers: list[dict] = []
    seen: set[tuple[str, str]] = set()
    files_scanned = 0
    truncated = False
    # Subtrees and files deliberately NOT read because they resolve outside the
    # disclosed root. Recorded, never silently dropped (Gate E).
    unscanned: list[dict] = []
    unscanned_seen: set[str] = set()
    # Content that EXISTS inside the root but could not be read. Distinct from
    # `unscanned` (deliberately excluded because it resolves outside): this is
    # coverage we wanted and did not get (Gate E).
    unreadable: list[dict] = []
    unreadable_seen: set[str] = set()

    def add_unreadable(entry: Path, reason: str) -> None:
        try:
            rel = str(entry.relative_to(root))
        except ValueError:
            rel = str(entry)
        if rel in unreadable_seen:
            return
        unreadable_seen.add(rel)
        unreadable.append({"path": rel, "reason": reason})

    def add(marker: str, kind: str, path: str) -> None:
        key = (marker, kind)
        if key in seen:
            return
        seen.add(key)
        markers.append({"marker": marker, "kind": kind, "path": path})

    def add_unscanned(entry: Path, reason: str) -> None:
        try:
            rel = str(entry.relative_to(root))
        except ValueError:
            rel = str(entry)
        if rel in unscanned_seen:
            return
        unscanned_seen.add(rel)
        unscanned.append({"path": rel, "reason": reason})

    try:
        # Same normalization the containment check uses, so a mixed-case or
        # symlinked root compares correctly against its own children.
        root_real = _normalized_realpath(root)
        # Guard against a cycle *within* the root: the same resolved directory
        # reached twice is walked once. Containment already excludes anything
        # outside, so this only bounds self-referential links.
        visited_dirs: set[str] = set()
        stack = [root]
        while stack:
            cur = stack.pop()
            try:
                entries = list(cur.iterdir())
            except (PermissionError, OSError) as exc:
                # An unreadable directory is a whole subtree we did not see.
                add_unreadable(cur, f"directory not listable: {type(exc).__name__}")
                continue
            for entry in entries:
                # CONTAINMENT FIRST — before is_dir()/is_file(), which follow
                # symlinks and reparse points and therefore stat the TARGET.
                # Establishing containment first means we never touch metadata
                # outside the disclosed root, not merely never read contents.
                if not _contained(entry, root_real):
                    add_unscanned(entry, "resolves outside the disclosed root")
                    continue

                try:
                    is_dir = entry.is_dir()
                    is_file = entry.is_file()
                except OSError as exc:
                    add_unreadable(entry, f"type check failed: {type(exc).__name__}")
                    continue

                if is_dir:
                    # Name-based skip stays a DIRECTORY-only rule, as before —
                    # a file that happens to be called "build" or "target" is
                    # still scanned.
                    if entry.name in _SKIP_DIRS:
                        continue
                    real = _normalized_realpath(entry)
                    if real in visited_dirs:
                        continue
                    visited_dirs.add(real)
                    stack.append(entry)
                    continue
                if not is_file:
                    continue
                name = entry.name
                # filename markers (cheap, no read)
                for rx, label, kind in _FILENAME_MARKERS:
                    if rx.search(name):
                        add(label, kind, str(entry.relative_to(root)))
                # decide whether to read contents
                if entry.suffix.lower() not in _TEXT_EXTS and not _is_env_file(name):
                    continue
                try:
                    if entry.stat().st_size > _MAX_BYTES:
                        continue
                except OSError as exc:
                    add_unreadable(entry, f"stat failed: {type(exc).__name__}")
                    continue
                files_scanned += 1
                if files_scanned > _MAX_FILES:
                    truncated = True
                    break
                try:
                    text = entry.read_text(encoding="utf-8", errors="ignore")
                except (OSError, ValueError) as exc:
                    # THE case this guard exists for: a live key or a
                    # governedProcedure() call could be sitting in here.
                    add_unreadable(entry, f"unreadable: {type(exc).__name__}")
                    continue
                for rx, label, kind in _PATTERNS:
                    if rx.search(text):
                        add(label, kind, str(entry.relative_to(root)))
                if len(markers) >= _MAX_MARKERS:
                    truncated = True
                    break
            if truncated:
                break
    except Exception as exc:  # fail closed
        return {
            "verdict": "STOP",
            "governed": True,
            "production": True,
            "markers": [{"marker": f"preflight scan error: {exc}", "kind": "error", "path": ""}],
            "reason": "preflight could not complete; failing closed",
            "filesScanned": files_scanned,
            "truncated": truncated,
            "unscannedSubtrees": unscanned,
            "unreadable": unreadable,
            "complete": False,
        }

    governed = any(m["kind"] == "governed" for m in markers)
    production = any(m["kind"] == "production" for m in markers)
    # Coverage the guard did not get: paths excluded for resolving outside the
    # root, content it could not read, or a walk that hit its ceiling. Any of
    # these means "I could not look", which is a different answer from "I
    # looked and found nothing" and must never render as a clean OK.
    complete = not (unscanned or unreadable or truncated)
    # An escape / unreadable file is COVERAGE LOSS, not a governance finding:
    # the guard stops, but `governed`/`production` stay false so an operator is
    # never told a marker was found when none was.
    stop = governed or production or not complete
    return {
        "verdict": "STOP" if stop else "OK",
        "governed": governed,
        "production": production,
        "markers": markers,
        "reason": _reason(governed, production, unscanned, unreadable, truncated),
        "filesScanned": files_scanned,
        "truncated": truncated,
        "unscannedSubtrees": unscanned,
        "unreadable": unreadable,
        "complete": complete,
    }


def _reason(
    governed: bool,
    production: bool,
    unscanned: list[dict] | None = None,
    unreadable: list[dict] | None = None,
    truncated: bool = False,
) -> str:
    if governed and production:
        return ("This repo already has first-party Strix governance AND shows "
                "production markers. strix-wire is a quickstart for ungoverned "
                "repos; do NOT auto-wire here.")
    if governed:
        return ("This repo already ships a first-party Strix governance layer. "
                "strix-wire would add a lesser, redundant, unsigned path.")
    if production:
        return ("This repo shows live-production markers. strix-wire's final "
                "step runs a real irreversible mutation; do NOT run it here.")
    parts: list[str] = []
    if unscanned:
        first = unscanned[0]["path"]
        more = f" (and {len(unscanned) - 1} more)" if len(unscanned) > 1 else ""
        parts.append(
            f"{len(unscanned)} path(s) resolve outside the disclosed root and were "
            f"NOT examined — first: {first}{more}"
        )
    if unreadable:
        first = unreadable[0]["path"]
        more = f" (and {len(unreadable) - 1} more)" if len(unreadable) > 1 else ""
        parts.append(
            f"{len(unreadable)} path(s) inside the root could not be read — "
            f"first: {first} ({unreadable[0].get('reason', 'unreadable')}){more}"
        )
    if truncated:
        parts.append("the scan hit its file/marker ceiling before finishing")
    if parts:
        return (
            "; ".join(parts)
            + ". The guard cannot certify a repository it did not fully examine, so "
            "it fails closed. No governance or production marker was found in what "
            "it COULD read — that is not the same as there being none."
        )
    return "No governance or production markers found; safe to proceed."


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="strix-wire preflight guard (fail-closed).")
    p.add_argument("--root", default=".", help="Repository root to check (default: cwd).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        # fail closed
        result = {
            "verdict": "STOP",
            "governed": True,
            "production": True,
            "markers": [{"marker": f"root not a directory: {root}", "kind": "error", "path": ""}],
            "reason": "preflight root is not a readable directory; failing closed",
        }
    else:
        result = scan(root)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result['verdict']}")
        print(f"reason:  {result['reason']}")
        for m in result["markers"]:
            loc = f" ({m['path']})" if m.get("path") else ""
            print(f"  - [{m['kind']}] {m['marker']}{loc}")

    return 3 if result["verdict"] == "STOP" else 0


if __name__ == "__main__":
    sys.exit(main())
