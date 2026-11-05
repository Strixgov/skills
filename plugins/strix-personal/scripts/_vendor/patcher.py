"""Rollback-safe wrapping of a single call site, plus the bypass check.

Gate E discipline:
  * back up before any write;
  * refuse to auto-wrap anything that cannot be transformed safely (multi-line
    calls, multiple assignment targets) — the candidate stays WRAPPABLE and a
    human wraps it under review;
  * never touch test paths (inherited from the scanner);
  * a candidate cannot reach ENFORCED while a sibling *unwrapped* call to the
    same capability still exists (``detect_bypass`` / ``is_routed_through_boundary``).

Vendored byte-for-byte into the ``strix-personal`` plugin — the scanner import
uses the same dual path as ``lifecycle.py``.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

try:  # installed package
    from solo_builder.action_scanner import (
        AI_PATTERNS,
        MUTATION_PATTERNS,
        Candidate,
        _compile,
        _scan_text,
    )
except ImportError:  # vendored standalone (plugin scripts/_vendor/)
    from action_scanner import (  # type: ignore
        AI_PATTERNS,
        MUTATION_PATTERNS,
        Candidate,
        _compile,
        _scan_text,
    )

BACKUP_SUFFIX = ".strix-bak"

_PY_EXTS = frozenset({".py"})
_TS_EXTS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"})

_DEFAULT_PY_IMPORT = "from strix_wire import governed_action  # Strix Personal"
_DEFAULT_TS_IMPORT = 'import { governedAction } from "./governedAction"; // Strix Personal'


class PatchError(RuntimeError):
    """Raised when a wrap cannot be applied safely."""


# ---------------------------------------------------------------------------
# Backup / restore
# ---------------------------------------------------------------------------


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + BACKUP_SUFFIX)


def backup_file(path: Path) -> Path:
    # strix: allow capability=data.export reason="docstring of a local file-backup helper; the match is prose, no data export happens"
    """Copy ``path`` to a sibling ``<name>.strix-bak``. Returns the backup path."""
    path = Path(path)
    bak = _backup_path(path)
    shutil.copy2(path, bak)
    return bak


def has_backup(path: Path) -> bool:
    return _backup_path(Path(path)).exists()


def restore_file(path: Path) -> None:
    """Restore ``path`` from its ``.strix-bak`` backup and remove the backup."""
    path = Path(path)
    bak = _backup_path(path)
    if not bak.exists():
        raise PatchError(f"no backup to restore for {path}")
    shutil.copy2(bak, path)
    bak.unlink()


def discard_backup(path: Path) -> None:
    """Remove the backup without restoring (commit the change)."""
    bak = _backup_path(Path(path))
    if bak.exists():
        bak.unlink()


class RollbackGuard:
    """Context manager that backs up files on enter and restores on error.

    On a clean exit the backups are discarded (the edits are committed). On an
    exception every guarded file is restored to its pre-edit bytes.

        with RollbackGuard([path]) as guard:
            apply_wrap(...)   # if this raises, path is restored automatically
    """

    def __init__(self, paths: list[Path]):
        self.paths = [Path(p) for p in paths]
        self._backed_up: list[Path] = []

    def __enter__(self) -> RollbackGuard:
        for p in self.paths:
            backup_file(p)
            self._backed_up.append(p)
        return self

    def rollback(self) -> None:
        for p in self._backed_up:
            if has_backup(p):
                restore_file(p)

    def commit(self) -> None:
        for p in self._backed_up:
            discard_backup(p)

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        return False  # never suppress exceptions


# ---------------------------------------------------------------------------
# Wrap planning
# ---------------------------------------------------------------------------


@dataclass
class WrapPlan:
    """A proposed wrap. ``new_text is None`` means "not safe to auto-wrap"."""

    file: str
    line: int
    capability_id: str
    language: str  # "python" | "typescript"
    import_line: str
    new_text: str | None = None
    skipped_reason: str | None = None

    @property
    def is_applicable(self) -> bool:
        return self.new_text is not None


def _language_for(ext: str) -> str | None:
    if ext in _PY_EXTS:
        return "python"
    if ext in _TS_EXTS:
        return "typescript"
    return None


def _parens_balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# Single-target Python assignment: `name = <call>` (no tuple target, no compare).
_PY_ASSIGN_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<lhs>[A-Za-z_][\w.\[\]]*)\s*=\s*(?P<rhs>\S.*?)\s*$")
# TS/JS declaration assignment: `const name = [await] <call>;`
_TS_ASSIGN_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<decl>const|let|var)\s+(?P<lhs>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?P<await>await\s+)?(?P<rhs>\S.*?);?\s*$"
)


def _looks_like_call(rhs: str) -> bool:
    return "(" in rhs and rhs.rstrip().endswith(")") and _parens_balanced(rhs)


def _plan_python(indent: str, lhs: str, rhs: str, cap: str) -> str:
    return (
        f"{indent}{lhs}, _strix_evidence_id = governed_action(\n"
        f'{indent}    capability_id="{cap}",\n'
        f"{indent}    payload={{}},  # TODO: add non-secret request params\n"
        f"{indent}    operation=lambda: {rhs},\n"
        f"{indent})"
    )


def _plan_typescript(indent: str, lhs: str, await_kw: str, rhs: str, cap: str) -> str:
    body = (await_kw or "") + rhs
    return (
        f"{indent}const {{ result: {lhs}, evidenceId: _strixEvidenceId }} = "
        f"await governedAction(\n"
        f'{indent}  {{ capabilityId: "{cap}", payload: {{}} }},\n'
        f"{indent}  async () => {body},\n"
        f"{indent});"
    )


def _import_insert_index(lines: list[str], language: str) -> int:
    """Pick a safe line index to insert the helper import."""
    import_re = re.compile(r"^\s*(import\s|from\s)") if language == "python" else re.compile(r"^\s*import\s")
    last_import = -1
    for i, line in enumerate(lines[:80]):
        if import_re.match(line):
            last_import = i
    if last_import >= 0:
        return last_import + 1
    # No imports: after a shebang if present, else top of file.
    if lines and lines[0].startswith("#!"):
        return 1
    return 0


def plan_wrap(
    root: Path,
    candidate: Candidate,
    *,
    py_import: str = _DEFAULT_PY_IMPORT,
    ts_import: str = _DEFAULT_TS_IMPORT,
) -> WrapPlan:
    """Produce a :class:`WrapPlan` for ``candidate`` under ``root``.

    Conservative: returns ``new_text=None`` (with ``skipped_reason``) whenever
    the call site is not a clean single-line, single-target assignment. Callers
    keep such candidates at WRAPPABLE and wrap them by hand.
    """
    root = Path(root)
    path = root / candidate.file
    ext = path.suffix.lower()
    language = _language_for(ext)
    import_line = py_import if language == "python" else ts_import

    base = WrapPlan(
        file=candidate.file,
        line=candidate.line,
        capability_id=candidate.capability_id,
        language=language or "unknown",
        import_line=import_line,
    )

    if language is None:
        base.skipped_reason = f"unsupported language for {ext}"
        return base

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        base.skipped_reason = f"cannot read file: {exc}"
        return base

    lines = text.splitlines()
    idx = candidate.line - 1
    if idx < 0 or idx >= len(lines):
        base.skipped_reason = "line out of range"
        return base

    target = lines[idx]

    if language == "python":
        m = _PY_ASSIGN_RE.match(target)
        if not m or "==" in target or "=>" in target:
            base.skipped_reason = "not a single-line `name = call(...)` assignment"
            return base
        rhs = m.group("rhs")
        if not _looks_like_call(rhs):
            base.skipped_reason = "right-hand side is not a single-line call"
            return base
        wrapped = _plan_python(m.group("indent"), m.group("lhs"), rhs, candidate.capability_id)
    else:
        m = _TS_ASSIGN_RE.match(target)
        if not m or "=>" in target.split("=", 1)[0]:
            base.skipped_reason = "not a single-line `const name = call(...)` assignment"
            return base
        rhs = m.group("rhs")
        if not _looks_like_call(rhs):
            base.skipped_reason = "right-hand side is not a single-line call"
            return base
        wrapped = _plan_typescript(
            m.group("indent"), m.group("lhs"), m.group("await") or "", rhs, candidate.capability_id
        )

    new_lines = list(lines)
    new_lines[idx] = wrapped
    if import_line.strip() not in text:
        new_lines.insert(_import_insert_index(new_lines, language), import_line)

    trailing = "\n" if text.endswith("\n") else ""
    base.new_text = "\n".join(new_lines) + trailing
    return base


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


@dataclass
class WrapResult:
    path: Path
    backup_path: Path
    capability_id: str

    def rollback(self) -> None:
        restore_file(self.path)

    def commit(self) -> None:
        discard_backup(self.path)


def apply_wrap(root: Path, plan: WrapPlan, *, backup: bool = True) -> WrapResult:
    """Apply ``plan`` to disk, backing the file up first.

    Raises :class:`PatchError` if the plan is not applicable. The returned
    :class:`WrapResult` can ``rollback()`` (restore) or ``commit()`` (drop the
    backup).
    """
    if not plan.is_applicable:
        raise PatchError(plan.skipped_reason or "plan is not applicable")
    path = Path(root) / plan.file
    if not path.is_file():
        raise PatchError(f"target file does not exist: {path}")
    bak = backup_file(path) if backup else _backup_path(path)
    path.write_text(plan.new_text, encoding="utf-8")  # type: ignore[arg-type]
    return WrapResult(path=path, backup_path=bak, capability_id=plan.capability_id)


# ---------------------------------------------------------------------------
# Bypass check (gates ENFORCED)
# ---------------------------------------------------------------------------


def _scan_buffer(
    text: str, ext: str, root: Path | None = None, rel_path: str = "<buffer>"
) -> list[Candidate]:
    compiled = _compile(MUTATION_PATTERNS + AI_PATTERNS)
    return _scan_text(text, rel_path, compiled, ext=ext, root=root)


def detect_bypass(
    text: str, capability_id: str, *, ext: str, root: Path | None = None, rel_path: str = "<buffer>"
) -> list[Candidate]:
    """Return any *ungoverned* call sites for ``capability_id`` in ``text``.

    Without root/rel_path provenance a wrapper is UNRESOLVED and remains in
    this result. Only reviewed local helper bytes establish governance.

    A non-empty result means a wrap can be bypassed — the same capability is
    still reachable without going through ``governed_action()``.
    """
    return [
        c
        for c in _scan_buffer(text, ext, root, rel_path)
        if c.capability_id == capability_id and not c.governed
    ]


def is_routed_through_boundary(
    text: str, capability_id: str, *, ext: str, root: Path | None = None, rel_path: str = "<buffer>"
) -> bool:
    """True iff every call to ``capability_id`` in ``text`` is governed.

    Requires at least one governed call to exist AND zero ungoverned calls.
    This is the precondition for promoting a candidate to ENFORCED.
    """
    matches = [c for c in _scan_buffer(text, ext, root, rel_path) if c.capability_id == capability_id]
    if not matches:
        return False
    if any(not c.governed for c in matches):
        return False
    return any(c.governed for c in matches)


__all__ = [
    "BACKUP_SUFFIX",
    "PatchError",
    "RollbackGuard",
    "WrapPlan",
    "WrapResult",
    "apply_wrap",
    "backup_file",
    "discard_backup",
    "detect_bypass",
    "has_backup",
    "is_routed_through_boundary",
    "plan_wrap",
    "restore_file",
]
