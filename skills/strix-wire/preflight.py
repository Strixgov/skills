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


def scan(root: Path) -> dict:
    """Walk the repo (bounded) and collect governance/production markers.

    Fail closed: any structural problem resolves to STOP.
    """
    markers: list[dict] = []
    seen: set[tuple[str, str]] = set()
    files_scanned = 0
    truncated = False

    def add(marker: str, kind: str, path: str) -> None:
        key = (marker, kind)
        if key in seen:
            return
        seen.add(key)
        markers.append({"marker": marker, "kind": kind, "path": path})

    try:
        stack = [root]
        while stack:
            cur = stack.pop()
            try:
                entries = list(cur.iterdir())
            except (PermissionError, OSError):
                continue
            for entry in entries:
                if entry.is_dir():
                    if entry.name in _SKIP_DIRS:
                        continue
                    stack.append(entry)
                    continue
                if not entry.is_file():
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
                except OSError:
                    continue
                files_scanned += 1
                if files_scanned > _MAX_FILES:
                    truncated = True
                    break
                try:
                    text = entry.read_text(encoding="utf-8", errors="ignore")
                except (OSError, ValueError):
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
        }

    governed = any(m["kind"] == "governed" for m in markers)
    production = any(m["kind"] == "production" for m in markers)
    stop = governed or production
    return {
        "verdict": "STOP" if stop else "OK",
        "governed": governed,
        "production": production,
        "markers": markers,
        "reason": _reason(governed, production),
        "filesScanned": files_scanned,
        "truncated": truncated,
    }


def _reason(governed: bool, production: bool) -> str:
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
