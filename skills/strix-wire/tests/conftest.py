"""Shared fixtures for the WIRE-CONSENT-1 contract suite.

These tests pin the /strix-wire consolidated consent architecture:
one scoped, read-only analysis authorization that cannot be upgraded into
mutation or execution authority. See docs/consent-architecture.md.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Audit hook: record every file the interpreter opens while `recording` is
# on. sys.addaudithook is irrevocable, so install one global hook and gate it.
# ---------------------------------------------------------------------------

_OPENED: list[str] = []
_RECORDING = False


def _audit(event: str, args) -> None:
    if _RECORDING and event == "open":
        path = args[0]
        if isinstance(path, (str, bytes, os.PathLike)):
            try:
                _OPENED.append(os.path.abspath(os.fsdecode(os.fspath(path))))
            except (TypeError, ValueError):
                pass


sys.addaudithook(_audit)


class OpenRecorder:
    """Context manager exposing every path opened inside the block."""

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __enter__(self) -> "OpenRecorder":
        global _RECORDING
        _OPENED.clear()
        _RECORDING = True
        return self

    def __exit__(self, *exc) -> None:
        global _RECORDING
        _RECORDING = False
        self.paths = list(_OPENED)


@pytest.fixture
def open_recorder():
    return OpenRecorder


# ---------------------------------------------------------------------------
# Module loading (same explicit-path technique analyze.py itself uses).
# ---------------------------------------------------------------------------


def load_skill_module(name: str):
    path = SKILL_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"strix_wire_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def analyze_mod():
    return load_skill_module("analyze")


# ---------------------------------------------------------------------------
# Fixture repositories.
# ---------------------------------------------------------------------------

CHARGE_PY = (
    "import stripe\n"
    "\n"
    "def charge(amount, token):\n"
    '    return stripe.Charge.create(amount=amount, currency="usd", source=token)\n'
)
DECOY_PY = (
    "import stripe\n"
    'stripe.Charge.create(amount=1, currency="usd", source="x")\n'
)


def make_python_repo(root: Path) -> Path:
    """An ungoverned, non-production Python repo with one clean candidate,
    two temp-path decoys, and one test-path decoy."""
    (root / "src" / "billing").mkdir(parents=True)
    (root / "tmp").mkdir()
    (root / "temp").mkdir()
    (root / "tests").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'headroom'\n")
    (root / "src" / "billing" / "charge.py").write_text(CHARGE_PY)
    (root / "tmp" / "decoy.py").write_text(DECOY_PY)
    (root / "temp" / "decoy2.py").write_text(DECOY_PY)
    (root / "tests" / "test_charge.py").write_text(DECOY_PY)
    return root


def make_ts_repo(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text('{"name": "headroom-ts", "private": true}\n')
    (root / "src" / "billing.ts").write_text(
        "export async function charge(amount: number, token: string) {\n"
        "  return await stripe.charges.create({ amount, currency: 'usd', source: token });\n"
        "}\n"
    )
    return root


@pytest.fixture
def workspace(tmp_path: Path) -> dict:
    """A parent directory holding the analysis root, a sibling repo with its
    own candidate, and a parent-level marker file — so out-of-scope access
    is detectable."""
    child = make_python_repo(tmp_path / "child")
    sibling = tmp_path / "sibling"
    (sibling / "src").mkdir(parents=True)
    (sibling / "src" / "outside.py").write_text(DECOY_PY)
    marker = tmp_path / "PARENT_MARKER.py"
    marker.write_text(DECOY_PY)
    return {"parent": tmp_path, "child": child, "sibling": sibling, "marker": marker}


def tree_snapshot(root: Path) -> dict[str, str]:
    """{relative path: sha256} for every file under root."""
    out: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out
