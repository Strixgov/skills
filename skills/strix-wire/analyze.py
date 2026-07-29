#!/usr/bin/env python3
"""strix-wire analyze — the single scoped, read-only repository analysis.

WIRE-CONSENT-1 (consolidated consent architecture):

  Collapse mechanical permissions, not governance decisions.

This script exists so that the entire read-only analysis phase of
/strix-wire — previously eight to ten separate tool invocations, each
raising its own permission prompt — is ONE command, covered by ONE user
authorization. In a single process it performs, in order:

  1. scope guard          — pin the disclosed analysis root; nothing outside
                            it is ever read (the skill's own bundled files
                            are the only exception, and they are ours). The
                            CLI additionally refuses a --root outside the
                            current working directory unless
                            --allow-external-root is passed explicitly, so
                            the approved command cannot quietly point at an
                            arbitrary directory.
  2. repository check     — is this a code repository at all (stat-only; a
                            non-repository directory is refused before any
                            file content is read).
  3. preflight            — the fail-closed already-governed / production
                            guard (vendored ``preflight.py``, run
                            in-process). A truncated or partially-unreadable
                            scan STOPs instead of passing: "we didn't finish
                            looking" is never reported as "clean".
  4. runtime detection    — Python version, project language markers, and a
                            PATH probe for the toolchain the run step would
                            need. Missing toolchain produces exactly ONE
                            remediation entry, never a retry loop.
  5. scanner              — the consequential-action scanner (vendored
                            ``scanner.py``, run in-process).
  6. candidate analysis   — ranking, temporary-path exclusion (automatic),
                            recommended wrap target, and the coverage map.
  7. helper integrity     — SHA-256 of every bundled helper, compared against
                            any copy already present in the repository.

What this script must NEVER do — enforced by construction and pinned by
``tests/test_consent_boundary.py``:

  - write, create, delete, move, or chmod any file (its only output is
    stdout/stderr);
  - spawn a subprocess or execute repository code;
  - open a socket or make any network request;
  - read file CONTENT outside the analysis root (bundled skill files and
    the Python runtime's own imports excepted);
  - install anything.

The analysis authorization is single-run and single-root: the emitted
report pins ``consent.scope_root`` and ``consent.expires = "end-of-run"``.
A new run, or a different ``--root``, requires a fresh authorization —
this consent is not a reusable grant, and it never authorizes the two
governance decisions that follow it (source modification; execution).

Exit codes:
    0 — analysis completed read-only (verdict OK or NO_CANDIDATES)
    2 — bad invocation
    3 — preflight STOP (fail closed; analysis halted before scanning)
    4 — remediation required (not a recognized repository / toolchain gap
        that blocks even analysis)

Usage:
    python3 analyze.py [--root .] [--json] [--limit N]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path

CONTRACT = "WIRE-CONSENT-1"
ANALYZER_VERSION = "0.3.0"

SKILL_DIR = Path(__file__).resolve().parent

# The six affirmative grants and six refusals shown on the ANALYSIS REQUEST
# card in SKILL.md. Keep the two lists in lockstep with the card text —
# tests/test_consent_contract.py pins both sides.
CONSENT_COVERS = [
    "Read source files in this repository",
    "Detect installed language runtimes",
    "Run the Strix preflight",
    "Run the repository scanner",
    "Analyze consequential-action candidates",
    "Compare bundled helper files for integrity",
]
CONSENT_DOES_NOT_AUTHORIZE = [
    "Modify source files",
    "Install packages",
    "Access files outside this repository",
    "Use credentials",
    "Contact external services",
    "Execute a consequential action",
]

# Path segments treated as temporary/disposable — candidates under these are
# excluded from the analysis automatically (the old flow's manual
# "exclude temporary paths and refine" step, now built in).
TEMP_SEGMENTS = frozenset(
    {
        "tmp",
        "temp",
        ".tmp",
        ".temp",
        "tmpdir",
        "temporary",
        "scratch",
        ".scratch",
    }
)

# Bundled helper files whose integrity the analysis attests, and the names
# a copy may have been given inside a customer repository (4a in SKILL.md
# renames the Python helpers on copy).
BUNDLED_HELPERS = (
    "helpers/governed_action.py",
    "helpers/governedAction.ts",
    "helpers/governed_action_local.py",
    "helpers/governedAction.local.ts",
)
COPY_NAME_TO_BUNDLED = {
    "governed_action.py": "helpers/governed_action.py",
    "strix_wire.py": "helpers/governed_action.py",
    "governedAction.ts": "helpers/governedAction.ts",
    "governed_action_local.py": "helpers/governed_action_local.py",
    "strix_wire_local.py": "helpers/governed_action_local.py",
    "governedAction.local.ts": "helpers/governedAction.local.ts",
}


_MODULE_CACHE: dict[str, object] = {}


def _load_bundled_module(name: str):
    """Import a sibling script by explicit file path (never via sys.path,
    so a customer repo's own ``scanner.py``/``preflight.py`` can't shadow
    the vendored ones). Cached per process."""
    if name in _MODULE_CACHE:
        return _MODULE_CACHE[name]
    path = SKILL_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"strix_wire_{name}", path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"cannot load bundled module: {path}")
    module = importlib.util.module_from_spec(spec)
    # Register before exec: dataclasses (used by scanner.py) resolves the
    # defining module through sys.modules at class-creation time.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _MODULE_CACHE[name] = module
    return module


def _which(cmd: str) -> str | None:
    """Minimal PATH probe (stat only — no content reads, no execution)."""
    exts = ["", ".exe", ".cmd", ".bat"] if os.name == "nt" else [""]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for ext in exts:
            candidate = os.path.join(d, cmd + ext)
            if os.path.isfile(candidate):
                return candidate
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_temp_path(rel_path: str) -> bool:
    segments = rel_path.replace("\\", "/").lower().split("/")
    return any(seg in TEMP_SEGMENTS for seg in segments[:-1])


def _consent_block(root: Path) -> dict:
    return {
        "contract": CONTRACT,
        "scope_root": str(root),
        "covers": list(CONSENT_COVERS),
        "does_not_authorize": list(CONSENT_DOES_NOT_AUTHORIZE),
        "expires": "end-of-run",
        "rescope": (
            "a new analysis run, or any change to the analysis root, "
            "requires a fresh ANALYSIS REQUEST authorization"
        ),
        "not_upgradeable": (
            "this authorization covers read-only analysis only; applying a "
            "source change and executing a governed action each require "
            "their own separate, explicit approval"
        ),
    }


def _repo_markers(root: Path) -> list[str]:
    """Stat-only repository markers — reads no file content, so it is safe
    to run before the preflight content scan."""
    markers = [
        name
        for name in (
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "setup.py",
            "go.mod",
            "Cargo.toml",
        )
        if (root / name).is_file()
    ]
    if (root / ".git").exists():
        markers.append(".git")
    return markers


def _unreadable_subtrees(root: Path, skip: frozenset) -> list[str]:
    """Directories under root the walk cannot enter. Preflight silently
    skips these, which would fail OPEN — so the analyzer sweeps for them
    first and fails CLOSED if any exist outside the skip set."""
    bad: list[str] = []

    def onerror(err: OSError) -> None:
        bad.append(getattr(err, "filename", None) or str(err))

    for _dirpath, dirnames, _filenames in os.walk(root, onerror=onerror):
        dirnames[:] = [d for d in dirnames if d not in skip]
    return bad


def detect_runtime(root: Path, source_files: list[Path], markers: list[str]) -> dict:
    """Language/runtime detection — Step 1 of the old flow, in-process."""
    ext_counts: dict[str, int] = {}
    for f in source_files:
        ext_counts[f.suffix.lower()] = ext_counts.get(f.suffix.lower(), 0) + 1

    ts_files = ext_counts.get(".ts", 0) + ext_counts.get(".tsx", 0)
    js_files = (
        ext_counts.get(".js", 0)
        + ext_counts.get(".jsx", 0)
        + ext_counts.get(".mjs", 0)
    )
    py_files = ext_counts.get(".py", 0)

    language = None
    helper = None
    if "package.json" in markers and ts_files > 0:
        language, helper = "typescript", "helpers/governedAction.ts"
    elif "package.json" in markers:
        language, helper = "javascript", "helpers/governedAction.ts"
    if any(m in markers for m in ("pyproject.toml", "requirements.txt", "setup.py")):
        # Multiple ecosystems: pick the one with more source files.
        if language is None or py_files > ts_files + js_files:
            language, helper = "python", "helpers/governed_action.py"

    node_path = _which("node") if language in ("typescript", "javascript") else None
    return {
        "python": platform.python_version(),
        "language": language,
        "helper": helper,
        "markers": [m for m in markers if m != ".git"],
        "source_file_counts": {
            "python": py_files,
            "typescript": ts_files,
            "javascript": js_files,
        },
        "node_found": (
            None if language not in ("typescript", "javascript") else bool(node_path)
        ),
    }


def helper_integrity(root: Path, source_files: list[Path]) -> dict:
    bundled = []
    bundle_hashes: dict[str, str] = {}
    for rel in BUNDLED_HELPERS:
        path = SKILL_DIR / rel
        digest = _sha256(path) if path.is_file() else None
        bundled.append({"name": rel, "sha256": digest, "present": digest is not None})
        if digest:
            bundle_hashes[rel] = digest

    copies = []
    for f in source_files:
        counterpart = COPY_NAME_TO_BUNDLED.get(f.name)
        if counterpart is None or counterpart not in bundle_hashes:
            continue
        try:
            identical = _sha256(f) == bundle_hashes[counterpart]
        except OSError:
            identical = False
        copies.append(
            {
                "path": str(f.relative_to(root)),
                "bundled_name": counterpart,
                "identical": identical,
            }
        )
    return {"bundled": bundled, "copies_in_repo": copies}


def run_analysis(root: Path, limit: int = 20) -> tuple[dict, int]:
    """Run every read-only analysis phase in this one process.

    Returns (report, exit_code). Never writes; only reads under ``root``
    plus this skill's own bundle directory.
    """
    root = root.resolve()
    report: dict = {
        "tool": "strix-wire analyze",
        "contract": CONTRACT,
        "version": ANALYZER_VERSION,
        "read_only": True,
        "consent": _consent_block(root),
        "phases_completed": [],
        "remediation": [],
    }
    phases = report["phases_completed"]

    if not root.is_dir():
        report["verdict"] = "ERROR"
        report["error"] = f"analysis root is not a readable directory: {root}"
        return report, 2
    phases.append("scope")

    # Phase: repository check FIRST (stat-only, no content reads) — an
    # arbitrary non-repository directory is refused before anything reads
    # file content, so the analysis grant cannot be repurposed as a generic
    # directory reader.
    markers = _repo_markers(root)
    repository = {
        "root": str(root),
        "is_repository": bool(markers),
        "markers_found": markers,
    }
    report["repository"] = repository
    phases.append("repository")
    if not repository["is_repository"]:
        report["remediation"].append(
            {
                "issue": "not a recognized code repository",
                "fix": (
                    "run this from a project root containing package.json, "
                    "pyproject.toml, requirements.txt, setup.py, go.mod, "
                    "Cargo.toml, or a .git directory"
                ),
            }
        )
        report["verdict"] = "REMEDIATION_REQUIRED"
        return report, 4

    # Phase: preflight (fail closed — a STOP halts analysis before scanning).
    preflight = _load_bundled_module("preflight")
    scanner = _load_bundled_module("scanner")

    # Fail-closed sweep: preflight silently skips subtrees it cannot read,
    # which would turn "no markers found" into a false OK. Refuse instead.
    skip = frozenset(preflight._SKIP_DIRS) | frozenset(scanner.SKIP_DIRS)
    unreadable = _unreadable_subtrees(root, skip)
    if unreadable:
        report["verdict"] = "STOP"
        report["reason"] = (
            f"{len(unreadable)} directorie(s) under the analysis root could "
            f"not be read (first: {unreadable[0]}); the preflight guard "
            "cannot certify a repo it cannot fully see — failing closed"
        )
        phases.append("preflight")
        return report, 3

    pf = preflight.scan(root)
    report["preflight"] = pf
    phases.append("preflight")
    if pf.get("verdict") != "OK":
        report["verdict"] = "STOP"
        report["reason"] = pf.get("reason", "preflight failed closed")
        return report, 3
    if pf.get("truncated"):
        # Preflight stopped early (file-count bound) without finding a
        # marker. "We didn't finish looking" is not "we looked and it's
        # clean" — fail closed rather than print an unqualified OK.
        report["verdict"] = "STOP"
        report["reason"] = (
            f"preflight scan was truncated after {pf.get('filesScanned', '?')} "
            "files without completing; it cannot certify this repo as "
            "ungoverned/non-production — failing closed. strix-wire is a "
            "quickstart for small sandbox repos; run it there, or point at "
            "a specific function"
        )
        return report, 3

    # Phase: enumerate source files ONCE; every later phase reuses the list.
    source_files = scanner._iter_source_files(root)
    report["scan_files_considered"] = len(source_files)

    # Phase: runtime.
    runtime = detect_runtime(root, source_files, markers)
    report["runtime"] = runtime
    phases.append("runtime")

    if runtime["language"] is None:
        report["remediation"].append(
            {
                "issue": "no supported language detected",
                "fix": (
                    "strix-wire wraps Python or TypeScript/JavaScript call "
                    "sites; point it at a repo with one of those, or ask for "
                    "the specific function you want governed"
                ),
            }
        )
    elif runtime["node_found"] is False:
        # ONE remediation entry — analysis itself continues; Node is only
        # needed later, at the (separately approved) run-proof step.
        report["remediation"].append(
            {
                "issue": "Node.js not found on PATH",
                "fix": (
                    "needed only for the optional run-proof step on a "
                    "TypeScript/JavaScript project — install Node 18+ from "
                    "https://nodejs.org; analysis and wrap do not need it"
                ),
            }
        )

    # Phase: scan + candidate analysis (temp-path exclusion is automatic).
    all_candidates = scanner.scan(root, limit=1000)
    kept, excluded = [], []
    for c in all_candidates:
        (excluded if _is_temp_path(c.file) else kept).append(c)

    candidate_dicts = [
        {
            "file": c.file,
            "line": c.line,
            "snippet": c.snippet,
            "category": c.category,
            "capability_id": c.capability_id,
            "confidence": c.confidence,
            "first_proof_eligible": c.first_proof_eligible,
        }
        for c in kept[:limit]
    ]
    recommended = next(
        (c for c in candidate_dicts if c["first_proof_eligible"]), None
    )
    coverage_map: dict[str, int] = {}
    for c in kept:
        family = c.capability_id.split(".", 1)[0]
        coverage_map[family] = coverage_map.get(family, 0) + 1

    report["scan"] = {
        "files_considered": len(source_files),
        "candidates": candidate_dicts,
        "candidates_total": len(kept),
        "excluded_temporary": [
            {"file": c.file, "line": c.line, "capability_id": c.capability_id}
            for c in excluded
        ],
        "recommended": recommended,
        "map": coverage_map,
    }
    phases.append("scan")
    phases.append("candidate-analysis")

    # Phase: helper integrity.
    report["helper_integrity"] = helper_integrity(root, source_files)
    phases.append("helper-integrity")

    report["verdict"] = "OK" if kept else "NO_CANDIDATES"
    return report, 0


def _format_human(report: dict) -> str:
    # ASCII only: this block must render identically in every terminal.
    lines = [
        "STRIX WIRE -- ANALYSIS COMPLETE (read-only)",
        "",
        f"  Scope       {report['consent']['scope_root']}",
    ]
    if report.get("verdict") == "STOP":
        lines += [
            "  PREFLIGHT   STOP -- " + report.get("reason", ""),
            "",
            "Analysis halted before scanning (fail closed). Nothing was read",
            "beyond the preflight markers; nothing was modified.",
        ]
        return "\n".join(lines)
    if report.get("verdict") in ("ERROR", "REMEDIATION_REQUIRED"):
        for item in report.get("remediation", []):
            lines.append(f"  FIX         {item['issue']} -- {item['fix']}")
        if "error" in report:
            lines.append(f"  ERROR       {report['error']}")
        return "\n".join(lines)

    scan = report["scan"]
    runtime = report["runtime"]
    lines += [
        f"  PREFLIGHT   OK",
        f"  RUNTIME     python {runtime['python']}"
        + (f" | project language: {runtime['language']}" if runtime["language"] else ""),
        f"  SCANNED     {scan['files_considered']} files for hard-to-undo actions",
        f"  FOUND       {scan['candidates_total']} candidates"
        + (
            f" ({len(scan['excluded_temporary'])} more excluded from temporary paths)"
            if scan["excluded_temporary"]
            else ""
        ),
    ]
    if scan["recommended"]:
        r = scan["recommended"]
        lines.append(
            f"  RECOMMENDED {r['file']}:{r['line']}  ({r['capability_id']})"
        )
    copies = report["helper_integrity"]["copies_in_repo"]
    if copies:
        for cp in copies:
            status = "identical to bundle" if cp["identical"] else "DIVERGES from bundle"
            lines.append(f"  HELPER      {cp['path']} -- {status}")
    else:
        lines.append("  HELPER      no governed-action helper in this repo yet")
    for item in report.get("remediation", []):
        lines.append(f"  NOTE        {item['issue']} -- {item['fix']}")
    lines += [
        "",
        "This analysis made no changes: no files written, no packages",
        "installed, no network contacted, nothing executed. The analysis",
        "authorization ends with this run. Applying a source change and",
        "running a governed action are separate approvals.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "strix-wire scoped read-only repository analysis — one command, "
            "one authorization, every mechanical analysis phase."
        )
    )
    parser.add_argument("--root", default=".", help="Analysis root (default: cwd).")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--limit", type=int, default=20, help="Max candidates to report (default: 20)."
    )
    parser.add_argument(
        "--allow-external-root",
        action="store_true",
        help=(
            "Permit a --root outside the current working directory. Never "
            "used during onboarding — the disclosed scope is the project "
            "the user opened."
        ),
    )
    args = parser.parse_args(argv)

    # Bind the executed scope to the disclosed scope: the ANALYSIS REQUEST
    # card shows the project the user opened, so the CLI refuses to wander.
    root = Path(args.root).resolve()
    cwd = Path.cwd().resolve()
    if not args.allow_external_root and root != cwd and cwd not in root.parents:
        print(
            f"error: --root {root} is outside the current working directory "
            f"({cwd}). The analysis authorization covers only the disclosed "
            "project scope; pass --allow-external-root only for a "
            "deliberately re-disclosed scope.",
            file=sys.stderr,
        )
        return 2

    report, code = run_analysis(root, limit=args.limit)
    print(json.dumps(report, indent=2) if args.json else _format_human(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
