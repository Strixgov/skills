#!/usr/bin/env python3
"""Strix Wire — the single read-only analysis entry point.

WHY THIS EXISTS
---------------
The read-only phase of ``/strix-wire`` used to be roughly eleven separate
shell commands: a preflight, a language probe, several ``ls``/``cat``
invocations, the scanner, then per-candidate inspection. Under Claude Code's
harness every one of those is its own permission prompt, so a user evaluating
the product answered about a dozen prompts before seeing a single result.
That is approval fatigue, and approval fatigue is a governance problem, not
just a UX one: a human clicking through eleven prompts is not consenting to
eleven things, they are learning to click.

This module collapses the entire read-only phase into ONE disclosed
operation with ONE consent boundary. It reads; it never writes, never
executes the customer's code, never touches the network, and never installs
anything.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
Running this grants no authority to change anything. Wrapping a call site is
a separate human approval, and executing the wrapped action is a third — see
``approval.py`` for the execution grant. One approval never buys the next.

FAIL-CLOSED COVERAGE (the load-bearing property)
------------------------------------------------
"No candidates found" and "I could not see the whole repository" are
different answers, and conflating them is how a scan quietly blesses an
ungoverned codebase. Every condition that could under-count — an unreadable
directory, an unreadable file, a walk that hit its file ceiling, a path that
escaped the disclosed root, a scanner crash, a per-candidate analysis
failure — sets ``status = ANALYSIS_INCOMPLETE`` and is enumerated in the
``integrity`` block. A clean ``status = OK`` therefore means the analyzer
actually saw what it claims to have seen.

READ BOUNDARY
-------------
Consent is to analyze ONE repository root, for ONE run. That is enforced,
not merely promised:

  * every directory and file is resolved (``realpath``) and rejected unless
    it is still inside the resolved root — which is what defeats a symlink,
    a Windows junction, ``..`` traversal, and a case-folding trick, none of
    which a lexical ``is_relative_to`` check would catch;
  * ``os.walk(followlinks=False)`` so directory symlinks are never descended
    (this also makes symlink cycles structurally impossible);
  * an optional ``sys.addaudithook`` boundary records any file opened
    outside the root during the walk phase.

The audit hook has an explicit allowlist, and honesty requires naming why:
Python itself reads files outside the repository — the interpreter's own
standard library and any installed packages. The hook is installed *after*
this module's imports complete, and the claim it supports is therefore the
precise one: *after analyzer initialization, repository-content reads do not
escape the disclosed root, except for interpreter and runtime paths named in
``read_boundary.allowlist``.*

USAGE
-----
    python3 analyze.py --root . --json
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import site
import sys
import sysconfig
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SKILL_DIR = Path(__file__).resolve().parent
if str(_SKILL_DIR) not in sys.path:
    sys.path.insert(0, str(_SKILL_DIR))

import preflight  # noqa: E402  (path set up above)
import scanner  # noqa: E402

__all__ = ["analyze", "walk_repository", "verify_helper_integrity", "main"]

STATUS_OK = "OK"
STATUS_STOP = "STOP"
STATUS_INCOMPLETE = "ANALYSIS_INCOMPLETE"

#: Every way coverage can be lost. A clean `status: OK` asserts that NONE of
#: these fired — so adding a new way to under-count means adding a code here
#: and calling `limit()`, which is what keeps "OK means we actually looked"
#: true by construction rather than by remembering to check a boolean.
LIMITATION_CODES = frozenset({
    "ROOT_UNRESOLVABLE",
    "ROOT_NOT_DIRECTORY",
    "PREFLIGHT_FAILED",
    "PREFLIGHT_TRUNCATED",
    "PREFLIGHT_UNREADABLE",
    "PREFLIGHT_ESCAPED",
    "WALK_TRUNCATED",
    "WALK_DEPTH_EXCEEDED",
    "WALK_UNREADABLE_DIR",
    "WALK_UNREADABLE_FILE",
    "WALK_ESCAPED",
    "WALK_FAILED",
    "SCANNER_FAILED",
    "SCANNER_UNREADABLE",
    "CANDIDATES_TRUNCATED",
    "CANDIDATE_ANALYSIS_FAILED",
    "LANGUAGE_DETECTION_FAILED",
    "HELPER_INTEGRITY_UNVERIFIED",
    "READ_BOUNDARY_VIOLATION",
})


def _incomplete_stub(root: str, code: str, detail: str) -> dict[str, Any]:
    """A minimal but SHAPE-COMPLETE incomplete document.

    Early returns used to omit `candidates`, `selected`, `limitations` and the
    rest, so a caller doing `doc["candidates"]` got a KeyError on exactly the
    paths where it most needed a safe answer. Every field a consumer may read
    is present and empty; incompleteness is expressed in the status, not by
    absence.
    """
    return {
        "schemaVersion": "strix.wire.analysis.v1",
        "root": root,
        "generatedAt": time.time(),
        "status": STATUS_INCOMPLETE,
        "analysisComplete": False,
        "limitations": [{"code": code, "detail": detail}],
        "incompleteReasons": [detail],
        "preflight": {},
        "language": {},
        "candidates": [],
        "selected": None,
        "helperIntegrity": {},
        "integrity": {},
        "readBoundary": {},
        "durationMs": 0,
    }

#: Ceiling on files enumerated in one analysis. Hitting it is not an error —
#: it is a *disclosed* truncation that forces ANALYSIS_INCOMPLETE, because a
#: truncated walk cannot honestly report "no candidates".
MAX_FILES = 20_000

#: Ceiling on directory depth below the root, for the same reason.
MAX_DEPTH = 40

SOURCE_EXTS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rb", ".sh"})

HELPER_MANIFEST = "MANIFEST.json"


# ---------------------------------------------------------------------------
# Read boundary
# ---------------------------------------------------------------------------


def _runtime_allowlist() -> list[str]:
    """Interpreter and runtime prefixes a Python process legitimately reads.

    Named explicitly so the read-boundary claim is falsifiable rather than
    vague. Anything outside the repository root and outside this list is a
    violation.
    """
    raw: list[str | None] = [
        sys.prefix,
        sys.base_prefix,
        sysconfig.get_path("stdlib"),
        sysconfig.get_path("platstdlib"),
        sysconfig.get_path("purelib"),
        sysconfig.get_path("platlib"),
        os.path.dirname(os.path.realpath(sys.executable)),
        str(_SKILL_DIR),
        tempfile.gettempdir(),
    ]
    # Some environments (embedded interpreters, unusual virtualenvs) do not
    # expose these; an unavailable path is simply one fewer allowlist entry.
    with contextlib.suppress(Exception):
        raw.extend(site.getsitepackages())
    with contextlib.suppress(Exception):
        raw.append(site.getusersitepackages())

    out: list[str] = []
    for entry in raw:
        if not entry:
            continue
        try:
            resolved = os.path.realpath(entry)
        except OSError:
            continue
        if resolved not in out:
            out.append(resolved)
    return sorted(out)


class ReadBoundary:
    """Records file opens that escape the disclosed root.

    Observation only. It never blocks an open — a hook that raises would turn
    an unexpected read into a crash mid-analysis, and the honest outcome of a
    boundary surprise is a reported violation plus ANALYSIS_INCOMPLETE, not a
    stack trace.
    """

    def __init__(self, root: str, allowlist: list[str]) -> None:
        self.root = root
        self.allowlist = allowlist
        self.violations: list[str] = []
        self._active = False
        self._installed = False

    def _permitted(self, path: str) -> bool:
        if path.startswith(self.root + os.sep) or path == self.root:
            return True
        return any(path == allowed or path.startswith(allowed + os.sep) for allowed in self.allowlist)

    def _hook(self, event: str, args: tuple) -> None:
        if not self._active or event != "open":
            return
        try:
            target = args[0]
            if not isinstance(target, (str, bytes, os.PathLike)):
                return  # a file descriptor, not a path
            resolved = os.path.realpath(os.fsdecode(target))
            if (
                not self._permitted(resolved)
                and resolved not in self.violations
                and len(self.violations) < 50
            ):
                self.violations.append(resolved)
        except Exception:
            return

    def install(self) -> None:
        if self._installed:
            return
        sys.addaudithook(self._hook)
        self._installed = True

    def __enter__(self) -> ReadBoundary:
        self._active = True
        return self

    def __exit__(self, *exc: object) -> None:
        self._active = False


# ---------------------------------------------------------------------------
# Walk
# ---------------------------------------------------------------------------


@dataclass
class WalkResult:
    files: list[Path] = field(default_factory=list)
    unreadable_dirs: list[str] = field(default_factory=list)
    unreadable_files: list[str] = field(default_factory=list)
    escaped_paths: list[str] = field(default_factory=list)
    truncated: bool = False
    depth_exceeded: bool = False
    scanned_file_count: int = 0

    @property
    def complete(self) -> bool:
        return not (self.truncated or self.depth_exceeded or self.unreadable_dirs or self.unreadable_files)


def walk_repository(root: Path, max_files: int = MAX_FILES, max_depth: int = MAX_DEPTH) -> WalkResult:
    """Enumerate source files under ``root``, fail-closed and root-bound.

    An escaped path (symlink, junction, ``..``) is excluded and recorded. An
    exclusion is a *deliberate refusal*, so it does not by itself make the
    analysis incomplete — but an unreadable path does, because that is
    coverage we wanted and did not get.
    """
    result = WalkResult()
    root_real = os.path.realpath(str(root))

    def _on_error(exc: OSError) -> None:
        target = getattr(exc, "filename", None) or str(exc)
        result.unreadable_dirs.append(str(target))

    for dirpath, dirnames, filenames in os.walk(root_real, onerror=_on_error, followlinks=False):
        try:
            dir_real = os.path.realpath(dirpath)
        except OSError:
            result.unreadable_dirs.append(dirpath)
            dirnames[:] = []
            continue

        # A directory that resolves outside the root is not ours to read.
        if dir_real != root_real and not dir_real.startswith(root_real + os.sep):
            result.escaped_paths.append(dirpath)
            dirnames[:] = []
            continue

        depth = 0
        if dir_real != root_real:
            depth = dir_real[len(root_real) :].count(os.sep)
        if depth >= max_depth:
            result.depth_exceeded = True
            dirnames[:] = []
            continue

        dirnames[:] = [d for d in dirnames if d not in scanner.SKIP_DIRS]

        for name in filenames:
            if os.path.splitext(name)[1].lower() not in SOURCE_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                file_real = os.path.realpath(full)
            except OSError:
                result.unreadable_files.append(full)
                continue
            # Root-escape check on the RESOLVED path: this is what stops a
            # file symlink (or a Windows junction) pointing out of the tree.
            if not file_real.startswith(root_real + os.sep):
                result.escaped_paths.append(full)
                continue
            if not os.path.isfile(file_real):
                continue
            if len(result.files) >= max_files:
                result.truncated = True
                return result
            result.files.append(Path(full))

    result.scanned_file_count = len(result.files)
    return result


# ---------------------------------------------------------------------------
# Helper integrity
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_helper_integrity(
    skill_dir: Path | None = None,
    helpers_dir: Path | None = None,
    required: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Check every shipped helper against the checked-in expected digest.

    The expected digests live in ``helpers/MANIFEST.json``, which is a
    reviewed, committed artifact regenerated only by
    ``scripts/generate_strix_wire_helper_manifest.py``. That is the point:
    the expectation has independent provenance. Hashing the current file and
    comparing it to itself would verify nothing, so a missing or unparseable
    manifest is ``HELPER_INTEGRITY_UNVERIFIED`` — never an implicit pass.

    ``helpers_dir`` overrides the default ``<skill_dir>/helpers`` for
    distributions that lay the tree out differently (the strix-personal
    plugin keeps helpers at its own root, beside a vendored copy of this
    file).

    ``required`` names the helpers a given distribution must actually ship.
    A distribution that legitimately carries a subset — the plugin ships the
    two hosted-mode helpers and not the two offline ones — declares that
    subset here; a required helper that is absent is a failure, while an
    unrequired absent one is reported ``NOT_SHIPPED`` and does not fail.
    Every helper that IS present is verified either way, so shipping a
    subset never becomes a way to smuggle a tampered file past the check.
    """
    skill_dir = skill_dir or _SKILL_DIR
    helpers_dir = helpers_dir or (skill_dir / "helpers")
    required_set = None if required is None else set(required)
    manifest_path = helpers_dir / HELPER_MANIFEST

    out: dict[str, Any] = {
        "verified": False,
        "reason": None,
        "manifestVersion": None,
        "helpers": {},
    }

    if not manifest_path.is_file():
        out["reason"] = "HELPER_INTEGRITY_UNVERIFIED: manifest missing"
        return out
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest["helpers"]
        if not isinstance(entries, dict) or not entries:
            raise ValueError("no helper entries")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        out["reason"] = f"HELPER_INTEGRITY_UNVERIFIED: manifest unreadable ({exc})"
        return out

    out["manifestVersion"] = manifest.get("schemaVersion")
    mismatches: list[str] = []
    for name, expected in sorted(entries.items()):
        path = helpers_dir / name
        record: dict[str, Any] = {
            "expectedSha256": (expected or {}).get("sha256"),
            "version": (expected or {}).get("version"),
        }
        if not path.is_file():
            if required_set is not None and name not in required_set:
                record["state"] = "NOT_SHIPPED"
            else:
                record["state"] = "MISSING"
                mismatches.append(name)
        else:
            try:
                actual = _sha256_file(path)
            except OSError as exc:
                record["state"] = f"UNREADABLE ({exc})"
                mismatches.append(name)
            else:
                record["actualSha256"] = actual
                if actual == record["expectedSha256"]:
                    record["state"] = "OK"
                else:
                    record["state"] = "MISMATCH"
                    mismatches.append(name)
        out["helpers"][name] = record

    if mismatches:
        out["reason"] = "HELPER_INTEGRITY_UNVERIFIED: " + ", ".join(sorted(mismatches))
        return out

    out["verified"] = True
    return out


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".go": "go",
    ".rb": "ruby",
}

_HELPER_BY_LANG = {
    "python": "governed_action.py",
    "typescript": "governedAction.ts",
    "javascript": "governedAction.ts",
}


def detect_language(root: Path, files: list[Path]) -> dict[str, Any]:
    """Pick one primary language from real file counts, not marker guessing."""
    counts: dict[str, int] = {}
    for path in files:
        lang = _LANG_BY_EXT.get(path.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    markers = {
        name: (root / name).exists()
        for name in (
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "setup.py",
            "go.mod",
            "Cargo.toml",
        )
    }

    primary = None
    if counts:
        primary = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
        # TypeScript beats JavaScript when both are present under one
        # package.json — the helper is the same file either way.
        if primary == "javascript" and counts.get("typescript"):
            primary = "typescript"

    return {
        "primary": primary,
        "fileCounts": dict(sorted(counts.items())),
        "markers": {k: v for k, v in sorted(markers.items()) if v},
        "helper": _HELPER_BY_LANG.get(primary or ""),
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyze(
    root: Path,
    *,
    limit: int = 20,
    enforce_read_boundary: bool = True,
    max_files: int = MAX_FILES,
    helpers_dir: Path | None = None,
    required_helpers: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Run the whole read-only phase and return one result document."""
    started = time.time()
    incomplete_reasons: list[str] = []
    limitations: list[dict[str, str]] = []

    def add_limitation(code: str, detail: str) -> None:
        """Record one coverage limitation, in both the machine-readable and
        human forms. Every caller that could under-count goes through here so
        no source can be added without also reaching the final status."""
        limitations.append({"code": code, "detail": detail})
        incomplete_reasons.append(detail)

    try:
        root_real = Path(os.path.realpath(str(root)))
    except OSError as exc:
        return _incomplete_stub(str(root), "ROOT_UNRESOLVABLE", f"root unresolvable: {exc}")
    if not root_real.is_dir():
        return _incomplete_stub(
            str(root_real), "ROOT_NOT_DIRECTORY", f"root is not a directory: {root_real}"
        )

    result: dict[str, Any] = {
        "schemaVersion": "strix.wire.analysis.v1",
        "root": str(root_real),
        "generatedAt": None,
        "status": STATUS_OK,
        "incompleteReasons": incomplete_reasons,
        "limitations": limitations,
        # Derived once, at the end, from `limitations` — never set piecemeal.
        "analysisComplete": True,
    }

    # --- Phase 1: preflight (fail-closed; STOP short-circuits everything) ---
    try:
        pre = preflight.scan(root_real)
    except Exception as exc:
        result["status"] = STATUS_STOP
        result["preflight"] = {
            "verdict": "STOP",
            "reason": f"preflight failed to run ({exc}); failing closed",
        }
        result["generatedAt"] = time.time()
        return result

    result["preflight"] = pre
    # preflight.py's own "STOP" verdict is overloaded: it fires both when a
    # real governed/production marker was found (a genuine reason not to
    # wire) AND when preflight merely could not finish looking (an
    # unreadable subtree, an escaped path, a truncated walk — `not
    # complete`, no marker at all). Only the first is this module's STOP;
    # the second is exactly what ANALYSIS_INCOMPLETE exists for (see the
    # module docstring / CLAUDE.md contract) and must fall through to the
    # ordinary limitations path below instead of short-circuiting here.
    if pre.get("verdict") == "STOP" and (pre.get("governed") or pre.get("production")):
        result["status"] = STATUS_STOP
        result["analysisComplete"] = bool(pre.get("complete", False))
        result["generatedAt"] = time.time()
        # Shape-complete even on the STOP path (see _incomplete_stub).
        result.setdefault("language", {})
        result.setdefault("candidates", [])
        result.setdefault("selected", None)
        result.setdefault("helperIntegrity", {})
        result.setdefault("integrity", {})
        result.setdefault("readBoundary", {})
        result.setdefault("durationMs", int((time.time() - started) * 1000))
        return result

    # Preflight said OK, or STOP-for-coverage-only — but neither means it saw
    # everything. Its coverage signals were previously computed and then
    # never read by this layer, so a guard that gave up early still produced a
    # clean analysis. Each one now becomes a limitation.
    if pre.get("truncated"):
        add_limitation(
            "PREFLIGHT_TRUNCATED",
            f"preflight stopped at its ceiling after {pre.get('filesScanned', '?')} "
            "files; it did not finish examining this repository",
        )
    for item in pre.get("unreadable", []) or []:
        add_limitation(
            "PREFLIGHT_UNREADABLE",
            f"preflight could not read {item.get('path')}: {item.get('reason')}",
        )
    for item in pre.get("unscannedSubtrees", []) or []:
        add_limitation(
            "PREFLIGHT_ESCAPED",
            f"preflight excluded {item.get('path')}: {item.get('reason')}",
        )

    # --- Phase 2: read boundary + walk ---
    boundary = ReadBoundary(str(root_real), _runtime_allowlist())
    if enforce_read_boundary:
        boundary.install()

    try:
        if enforce_read_boundary:
            with boundary:
                walk = walk_repository(root_real, max_files=max_files)
        else:
            walk = walk_repository(root_real, max_files=max_files)
    except Exception as exc:
        walk = WalkResult()
        add_limitation("WALK_FAILED", f"repository walk failed: {exc}")

    if walk.truncated:
        add_limitation("WALK_TRUNCATED", f"walk truncated at the {max_files}-file ceiling; coverage partial")
    if walk.depth_exceeded:
        add_limitation("WALK_DEPTH_EXCEEDED", f"directory depth exceeded {MAX_DEPTH}; deeper paths not analyzed")
    if walk.unreadable_dirs:
        add_limitation("WALK_UNREADABLE_DIR", f"{len(walk.unreadable_dirs)} directory/directories unreadable")
    if walk.unreadable_files:
        add_limitation("WALK_UNREADABLE_FILE", f"{len(walk.unreadable_files)} file(s) unreadable during walk")

    # --- Phase 3: pattern scan ---
    unreadable_at_scan: list[str] = []
    candidates: list[scanner.Candidate] = []
    try:
        candidates = scanner.scan_files(root_real, walk.files, limit=limit, unreadable=unreadable_at_scan)
    except Exception as exc:
        add_limitation("SCANNER_FAILED", f"scanner failed: {exc}")
    if unreadable_at_scan:
        add_limitation("SCANNER_UNREADABLE", f"{len(unreadable_at_scan)} file(s) unreadable during scan")

    # --- Phase 4: per-candidate analysis ---
    rendered: list[dict[str, Any]] = []
    for cand in candidates:
        try:
            rendered.append(
                {
                    "candidateId": f"{cand.file}:{cand.line}",
                    "file": cand.file,
                    "line": cand.line,
                    "snippet": cand.snippet,
                    "category": cand.category,
                    "capability_id": cand.capability_id,
                    "confidence": cand.confidence,
                    "first_proof_eligible": cand.first_proof_eligible,
                }
            )
        except Exception as exc:
            add_limitation("CANDIDATE_ANALYSIS_FAILED", f"candidate analysis failed: {exc}")

    # --- Phase 5: language + helper integrity ---
    try:
        language = detect_language(root_real, walk.files)
    except Exception as exc:
        language = {"primary": None, "error": str(exc)}
        add_limitation("LANGUAGE_DETECTION_FAILED", f"language detection failed: {exc}")

    try:
        integrity = verify_helper_integrity(helpers_dir=helpers_dir, required=required_helpers)
    except Exception as exc:
        integrity = {
            "verified": False,
            "reason": f"HELPER_INTEGRITY_UNVERIFIED: {exc}",
        }
    if not integrity.get("verified"):
        add_limitation("HELPER_INTEGRITY_UNVERIFIED", integrity.get("reason") or "helper integrity unverified")

    if enforce_read_boundary and boundary.violations:
        add_limitation("READ_BOUNDARY_VIOLATION", f"{len(boundary.violations)} read(s) escaped the disclosed root")

    result["language"] = language
    result["candidates"] = rendered
    result["helperIntegrity"] = integrity
    result["integrity"] = {
        "filesEnumerated": len(walk.files),
        "truncated": walk.truncated,
        "depthExceeded": walk.depth_exceeded,
        "unreadableDirs": walk.unreadable_dirs[:50],
        "unreadableFiles": (walk.unreadable_files + unreadable_at_scan)[:50],
        "excludedEscapedPaths": walk.escaped_paths[:50],
        "excludedEscapedCount": len(walk.escaped_paths),
    }
    result["readBoundary"] = {
        "enforced": enforce_read_boundary,
        "root": str(root_real),
        "allowlist": boundary.allowlist if enforce_read_boundary else [],
        "violations": boundary.violations,
        "claim": (
            "After analyzer initialization, repository-content reads did not "
            "escape the disclosed root, except for interpreter and runtime "
            "paths named in readBoundary.allowlist."
        ),
    }

    # SINGLE derivation point. Status and completeness both come from
    # `limitations`; no layer sets them independently, so a truncation that is
    # recorded cannot fail to reach the verdict.
    result["analysisComplete"] = not limitations
    if not result["analysisComplete"]:
        result["status"] = STATUS_INCOMPLETE

    # A wrap target is only offered when the analysis is trustworthy AND the
    # helper we would copy is the one we think it is.
    result["selected"] = None
    if result["status"] == STATUS_OK:
        for cand in rendered:
            if cand["first_proof_eligible"]:
                result["selected"] = cand
                break

    result["durationMs"] = int((time.time() - started) * 1000)
    result["generatedAt"] = time.time()
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


# Unicode bidirectional-formatting controls. Not in the C0/C1 ranges, so the
# categorical filter below misses them, yet they reverse rendered text — a
# filename can display as its mirror image and hide what is really being
# approved.
_BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩‎‏"

#: Cap on any single repo-controlled field in the operator projection. Long
#: enough for a real path or source line, short enough that one field cannot
#: scroll the decision surface off-screen.
_SAFE_MAX = 160


def _safe(value: Any) -> str:
    """Render a repo-controlled value inert for an operator's terminal.

    The operator approves a source change and an irreversible run FROM this
    output, so anything the scanned repository controls — a snippet, a path, a
    candidate id, a preflight marker — is untrusted input to the decision
    surface, exactly like HTML escaping before writing to a page.

    Removes, not escapes (escaping would preserve length and still allow
    off-screen scrolling): all C0/C1 control characters including ESC, CR, LF,
    backspace, NUL, VT and FF — which kills ANSI CSI *and* OSC sequences at the
    source, since both begin with ESC — plus Unicode bidi overrides. The result
    is single-line, bounded, and printable.

    Evidence fidelity is unaffected: the JSON document still carries raw bytes.
    This is only the human projection (Gate H).
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    cleaned = "".join(
        ch
        for ch in value
        if ch not in _BIDI_CONTROLS
        and not (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F)
    )
    cleaned = cleaned.strip()
    if len(cleaned) > _SAFE_MAX:
        cleaned = cleaned[: _SAFE_MAX - 3] + "..."
    return cleaned


def _format_human(doc: dict[str, Any]) -> str:
    # Every interpolation below that the scanned repository can influence goes
    # through _safe(). `status` is our own enum and the counts are ints, so
    # those are trusted; paths, snippets, ids, markers and reasons are not.
    lines: list[str] = []
    status = doc.get("status")
    lines.append(f"Strix Wire analysis — {_safe(status)}")
    lines.append(f"root: {_safe(doc.get('root'))}")

    if status == STATUS_STOP:
        pre = doc.get("preflight", {})
        lines.append(f"STOP: {_safe(pre.get('reason', 'preflight refused'))}")
        markers = pre.get("markers") or []
        for marker in markers[:10]:
            if isinstance(marker, dict):
                label = _safe(marker.get("marker"))
                path = _safe(marker.get("path"))
                kind = _safe(marker.get("kind"))
                lines.append(f"  marker: [{kind}] {label}" + (f" ({path})" if path else ""))
            else:
                lines.append(f"  marker: {_safe(marker)}")
        unscanned = pre.get("unscannedSubtrees") or []
        for item in unscanned[:10]:
            if isinstance(item, dict):
                lines.append(
                    f"  NOT SCANNED: {_safe(item.get('path'))} — {_safe(item.get('reason'))}"
                )
        lines.append("\nstrix-wire is for ungoverned, non-production repositories.")
        return "\n".join(lines)

    integ = doc.get("integrity", {})
    lines.append(f"files analyzed: {integ.get('filesEnumerated', 0)}")
    if integ.get("excludedEscapedCount"):
        lines.append(f"excluded (escaped disclosed root): {integ['excludedEscapedCount']}")

    lang = doc.get("language", {})
    lines.append(f"language: {_safe(lang.get('primary')) or 'undetected'}")

    if status == STATUS_INCOMPLETE:
        lines.append("\nANALYSIS INCOMPLETE — coverage could not be established:")
        for reason in doc.get("incompleteReasons", []):
            lines.append(f"  - {_safe(reason)}")
        lines.append(
            "\nCandidates below (if any) are NOT a complete picture of this "
            "repository. Do not read this as 'nothing to govern'."
        )

    cands = doc.get("candidates", [])
    lines.append(f"\ncandidates: {len(cands)}")
    for cand in cands[:10]:
        flag = "*" if cand.get("first_proof_eligible") else " "
        cid = _safe(cand.get("candidateId"))
        cap = _safe(cand.get("capability_id"))
        conf = _safe(cand.get("confidence"))
        lines.append(f" {flag} {cid}  {cap} ({conf})")
        # The snippet is raw source from the scanned repo — the primary
        # injection vector, since its whole purpose is to show repo content.
        lines.append(f"     {_safe(cand.get('snippet'))}")

    selected = doc.get("selected")
    target = _safe(selected.get("candidateId")) if selected else "none"
    lines.append(f"\nproposed wrap target: {target}")
    if not selected and status != STATUS_OK:
        lines.append("(no target proposed while the analysis is incomplete)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description=(
            "Strix Wire read-only analysis: preflight, language detection, "
            "mutation scan, and candidate ranking in one disclosed operation. "
            "Writes nothing, executes nothing, contacts no network."
        ),
    )
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument(
        "--helpers-dir",
        default=None,
        help=(
            "Directory holding the helpers + MANIFEST.json. Defaults to "
            "<skill dir>/helpers; override for a distribution that lays the "
            "tree out differently."
        ),
    )
    parser.add_argument(
        "--require-helpers",
        default=None,
        help=(
            "Comma-separated helper filenames this distribution must ship. "
            "Manifest entries outside the list are reported NOT_SHIPPED "
            "instead of failing; anything present is verified regardless."
        ),
    )
    parser.add_argument(
        "--no-read-boundary",
        action="store_true",
        help="Skip the audit-hook read boundary (diagnostics only).",
    )
    args = parser.parse_args(argv)

    doc = analyze(
        Path(args.root),
        limit=args.limit,
        enforce_read_boundary=not args.no_read_boundary,
        max_files=args.max_files,
        helpers_dir=Path(args.helpers_dir) if args.helpers_dir else None,
        required_helpers=(
            [h.strip() for h in args.require_helpers.split(",") if h.strip()]
            if args.require_helpers
            else None
        ),
    )

    if args.json:
        print(json.dumps(doc, sort_keys=True, default=str))
    else:
        print(_format_human(doc))

    # Exit codes mirror preflight.py's contract: 0 proceed, 3 STOP, 4 the
    # analysis ran but cannot claim complete coverage.
    if doc["status"] == STATUS_STOP:
        return 3
    if doc["status"] == STATUS_INCOMPLETE:
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
