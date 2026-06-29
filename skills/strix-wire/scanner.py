#!/usr/bin/env python3
"""Irreversible-mutation scanner for /strix-wire.

Walks the working tree, matches a curated set of high-confidence patterns,
and prints a ranked list of candidates the skill can wrap with
``governedAction()``.

The patterns are deliberately conservative: we only flag call sites that
are unambiguously irreversible (payments, deletes, sends, schema
migrations). False positives waste the user's time; false negatives are
fine because the user always has the option to point at a specific
function.

Run as:

    python3 scanner.py [--json] [--root PATH] [--limit N]

Exit codes:
    0  — at least one candidate found
    2  — no candidates found
    3  — invalid invocation
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Each pattern is: (regex, category, capability_id, confidence, languages)
# - confidence ∈ {"high", "medium"}
# - languages is the set of suffixes the pattern applies to
PATTERNS: list[tuple[str, str, str, str, frozenset[str]]] = [
    # ── Payments — Stripe ────────────────────────────────────────────────
    (
        r"\bstripe\.\w+\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\bstripe\.Charge\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bstripe\.charges\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\bstripe\.PaymentIntent\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bstripe\.paymentIntents\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # ── Database deletes — Prisma / ORMs ─────────────────────────────────
    (
        r"\bprisma\.\w+\.delete(Many)?\s*\(",
        "db-delete",
        "database.delete",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\bprisma\.\w+\.update(Many)?\s*\(",
        "db-update",
        "database.update",
        "medium",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # SQLAlchemy session.delete / session.execute(delete()) is harder to
    # match reliably; we catch the raw-SQL form below.
    (
        r"""(?ix)        # raw SQL DELETE / DROP / TRUNCATE — quoted literal
        ["']\s*
        (?: DELETE\s+FROM | DROP\s+TABLE | TRUNCATE\s+TABLE | TRUNCATE )
        \s+
        """,
        "db-delete",
        "database.delete",
        "high",
        frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rb"}),
    ),
    # Mongoose / Sequelize destroy + remove
    (
        r"\.destroy\s*\(\s*\{\s*where",
        "db-delete",
        "database.delete",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # ── S3 / object storage ──────────────────────────────────────────────
    (
        r"\.delete_object\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bDeleteObjectCommand\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\.deleteObject\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\.put_object\s*\(",
        "s3-write",
        "storage.write",
        "medium",
        frozenset({".py"}),
    ),
    (
        r"\bPutObjectCommand\s*\(",
        "s3-write",
        "storage.write",
        "medium",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # ── Email / SMS sends ────────────────────────────────────────────────
    (
        r"\bsendgrid\.[A-Za-z_]*[Ss]end[A-Za-z_]*\s*\(",
        "email-send",
        "email.send",
        "high",
        frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\bSendGridAPIClient\b",
        "email-send",
        "email.send",
        "medium",
        frozenset({".py"}),
    ),
    (
        r"\bnodemailer\b[^\n]{0,80}\.sendMail\s*\(",
        "email-send",
        "email.send",
        "high",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    (
        r"\btwilio[^\n]{0,80}\.messages\.create\s*\(",
        "sms-send",
        "sms.send",
        "high",
        frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # ── Filesystem deletes ───────────────────────────────────────────────
    (
        r"\b(os\.remove|os\.unlink|shutil\.rmtree)\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".py"}),
    ),
    (
        r"\bfs\.(unlink|rm|unlinkSync|rmSync)\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"}),
    ),
    # ── Schema migrations ────────────────────────────────────────────────
    (
        r"(?i)alembic\.op\.(drop_|alter_|create_)",
        "schema-migration",
        "database.migrate",
        "high",
        frozenset({".py"}),
    ),
    (
        r"(?i)\bprisma migrate (deploy|reset)\b",
        "schema-migration",
        "database.migrate",
        "high",
        frozenset({".sh", ".ts", ".js"}),
    ),
]

# Directories we never descend into.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "vendor",
        "target",
        "coverage",
        "htmlcov",
        ".tox",
    }
)

# Path fragments that indicate test code — never wrap these.
TEST_PATH_MARKERS = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/fixtures/",
    "/mocks/",
    "/__mocks__/",
)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    file: str
    line: int
    snippet: str
    category: str
    capability_id: str
    confidence: str  # "high" | "medium"


def _is_test_path(path: str) -> bool:
    """True if the path looks like test code."""
    normalized = "/" + path.replace("\\", "/").lstrip("/") + "/"
    if any(marker in normalized for marker in TEST_PATH_MARKERS):
        return True
    name = os.path.basename(path)
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    # *.test.ts, *.spec.ts, etc.
    stem, _, _ext = name.rpartition(".")
    return stem.endswith((".test", ".spec"))


def _iter_source_files(root: Path) -> list[Path]:
    """Yield candidate source files under root, skipping vendored junk."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutate dirnames in place so os.walk respects the skip set.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (
                ".py",
                ".ts",
                ".tsx",
                ".js",
                ".jsx",
                ".mjs",
                ".go",
                ".rb",
                ".sh",
            ):
                continue
            full = Path(dirpath) / fn
            out.append(full)
    return out


def scan(root: Path, limit: int = 20) -> list[Candidate]:
    """Scan ``root`` and return candidates ranked by confidence then path."""
    candidates: list[Candidate] = []
    compiled = [
        (re.compile(pat), cat, cap, conf, exts)
        for pat, cat, cap, conf, exts in PATTERNS
    ]

    for src in _iter_source_files(root):
        rel = str(src.relative_to(root))
        if _is_test_path(rel):
            continue
        ext = src.suffix.lower()
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for regex, category, capability_id, confidence, exts in compiled:
                if ext not in exts:
                    continue
                if regex.search(line):
                    candidates.append(
                        Candidate(
                            file=rel,
                            line=lineno,
                            snippet=line.rstrip(),
                            category=category,
                            capability_id=capability_id,
                            confidence=confidence,
                        )
                    )
                    break  # one hit per line is enough

    # Sort: high before medium, then by file path for stability.
    confidence_rank = {"high": 0, "medium": 1}
    candidates.sort(
        key=lambda c: (confidence_rank.get(c.confidence, 9), c.file, c.line)
    )
    return candidates[:limit]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_human(candidates: list[Candidate]) -> str:
    if not candidates:
        return (
            "No irreversible-mutation candidates found.\n"
            "Patterns checked: payments (stripe), db deletes, s3 deletes,\n"
            "email/SMS sends, filesystem deletes, schema migrations.\n"
            "If you have a specific function in mind, point me at it."
        )
    lines = []
    for i, c in enumerate(candidates, start=1):
        lines.append(
            f"{i}. [{c.confidence}] {c.file}:{c.line}  ({c.capability_id})\n"
            f"   {c.snippet.strip()}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan for irreversible mutations to wrap with governedAction()."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan (default: cwd).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable output.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum candidates to return (default: 20).",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 3

    candidates = scan(root, limit=args.limit)

    if args.json:
        print(json.dumps([asdict(c) for c in candidates], indent=2))
    else:
        print(_format_human(candidates))

    return 0 if candidates else 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
