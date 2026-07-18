#!/usr/bin/env python3
"""Action-point scanner for /strix-wire.

Walks the working tree, matches a curated set of high-confidence patterns,
and prints a ranked list of candidates the skill can wrap with
``governedAction()``.

Two tiers of coverage (GSD-1 — governed surface discovery):

* **Consequential action points** — irreversible mutations (payments,
  refunds, deletes, sends, schema migrations, infra changes, IAM grants,
  flag flips, bulk exports, message publishes) plus the two consequential
  AI surfaces: agent runs (``ai.agent_run``) and LLM tool dispatch
  (``ai.tool_use``). These are first-proof eligible (PROOF-1) and rank
  first — on an AI-native codebase the agent loop or tool dispatch is
  the wrap target, not the incidental Stripe call.

* **Observe-only AI surfaces** — model calls, embeddings, retrieval
  (``ai.completion`` / ``ai.embedding`` / ``ai.retrieval``). Reported so
  the map is honest, but never selected as the first-proof wrap target:
  a model call is observability, not an irreversible side effect.

The patterns are deliberately conservative: false positives waste the
user's time; false negatives are fine because the user always has the
option to point at a specific function.

The PATTERNS block below is GENERATED from the single-source registry at
``src/solo_builder/pattern_catalog.py`` — edit the catalog, then run
``python -m solo_builder.pattern_catalog --generate-strix-wire``.

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

# BEGIN GENERATED PATTERNS (pattern_catalog) — DO NOT EDIT BY HAND
# Regenerate via: python -m solo_builder.pattern_catalog --generate-strix-wire
#
# Source of truth: src/solo_builder/pattern_catalog.py (GSD-1 Phase 0).
# Each pattern is: (regex, category, capability_id, confidence, extensions)
PATTERNS: list[tuple[str, str, str, str, frozenset[str]]] = [
    (
        r"\bstripe\.Charge\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bstripe\.PaymentIntent\.create\s*\(",
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
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bstripe\.paymentIntents\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bStripe::(Charge|PaymentIntent)\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".rb"}),
    ),
    (
        r"\bstripe\.Refund\.create\s*\(",
        "payments",
        "payment.refund",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bstripe\.refunds\.create\s*\(",
        "payments",
        "payment.refund",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bStripe::Refund\.create\s*\(",
        "payments",
        "payment.refund",
        "high",
        frozenset({".rb"}),
    ),
    (
        r"\bprisma\.\w+\.delete(Many)?\s*\(",
        "db-delete",
        "database.delete",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.delete_object\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.delete_objects\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".py"}),
    ),
    (
        r"(?i)(?:alembic\.)?\bop\.(drop_|alter_|create_)",
        "schema-migration",
        "database.migrate",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\b(os\.remove|os\.unlink|shutil\.rmtree)\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".py"}),
    ),
    (
        r"\b[A-Za-z_][A-Za-z0-9_]*\.unlink\s*\(",
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
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bos\.Remove(All)?\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".go"}),
    ),
    (
        r"\bFile\.(delete|unlink)\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".rb"}),
    ),
    (
        r"\bFileUtils\.(rm_rf|rm_r|rm_f|rm|remove_entry|remove_dir|remove)\s*\(",
        "file-delete",
        "filesystem.delete",
        "medium",
        frozenset({".rb"}),
    ),
    (
        r"\bsendgrid\.[A-Za-z_]*[Ss]end[A-Za-z_]*\s*\(",
        "email-send",
        "email.send",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\btwilio[^\n]{0,80}\.messages\.create\s*\(",
        "sms-send",
        "sms.send",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bprisma\.\w+\.update(Many)?\s*\(",
        "db-update",
        "database.update",
        "medium",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.destroy\s*\(\s*\{\s*where",
        "db-delete",
        "database.delete",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"""(?i)["']\s*(?:DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|TRUNCATE)\s+""",
        "db-delete",
        "database.delete",
        "high",
        frozenset({".go", ".js", ".jsx", ".mjs", ".py", ".rb", ".ts", ".tsx"}),
    ),
    (
        r"\bDeleteObjectCommand\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.deleteObject\s*\(",
        "s3-delete",
        "storage.delete",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
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
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bnodemailer\b[^\n]{0,80}\.sendMail\s*\(",
        "email-send",
        "email.send",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bstripe\.\w+\.create\s*\(",
        "payments",
        "payment.charge",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bSendGridAPIClient\b",
        "email-send",
        "email.send",
        "medium",
        frozenset({".py"}),
    ),
    (
        r"(?i)\bprisma migrate (deploy|reset)\b",
        "schema-migration",
        "database.migrate",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bterraform\s+destroy\b",
        "infra-destroy",
        "infra.destroy",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bpulumi\s+destroy\b",
        "infra-destroy",
        "infra.destroy",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bkubectl\s+delete\b",
        "infra-destroy",
        "infra.destroy",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.terminate_instances\s*\(",
        "infra-destroy",
        "infra.destroy",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.delete_stack\s*\(",
        "infra-destroy",
        "infra.destroy",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bterraform\s+apply\b",
        "infra-apply",
        "infra.apply",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bpulumi\s+up\b",
        "infra-apply",
        "infra.apply",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bkubectl\s+apply\b",
        "infra-apply",
        "infra.apply",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.attach_role_policy\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.attach_user_policy\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.put_user_policy\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.put_role_policy\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.create_access_key\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.add_user_to_group\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bAttachRolePolicyCommand\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bAttachUserPolicyCommand\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bPutUserPolicyCommand\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bCreateAccessKeyCommand\s*\(",
        "iam-grant",
        "iam.grant",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.detach_role_policy\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.detach_user_policy\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.delete_role_policy\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.delete_access_key\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bDetachRolePolicyCommand\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bDeleteAccessKeyCommand\s*\(",
        "iam-revoke",
        "iam.revoke",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.(?:enable|disable)_feature_flag\s*\(",
        "flag-flip",
        "flag.flip",
        "medium",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bfeature_?[Ff]lags?\.(?:update|toggle|enable|disable|set)\w*\s*\(",
        "flag-flip",
        "flag.flip",
        "medium",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"/api/v2/flags",
        "flag-flip",
        "flag.flip",
        "medium",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\b(?:pg_dump|mongodump|mysqldump)\b",
        "data-export",
        "data.export",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.extract_table\s*\(",
        "data-export",
        "data.export",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bcreate_export_task\s*\(",
        "data-export",
        "data.export",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"""(?i)["']\s*COPY\s+.+\s+TO\s+""",
        "data-export",
        "data.export",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bsns(?:_client)?\.publish\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\.send_message\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bproducer\.send\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\btopic\.publish\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bPublishCommand\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\bSendMessageCommand\s*\(",
        "message-publish",
        "message.publish",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.chat\.completions\.create\s*\(",
        "ai-provider",
        "ai.completion",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.responses\.create\s*\(",
        "ai-provider",
        "ai.completion",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.messages\.create\s*\(",
        "ai-provider",
        "ai.completion",
        "medium",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.embeddings\.create\s*\(",
        "ai-embedding",
        "ai.embedding",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bStateGraph\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bcreate_react_agent\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bFastMCP\s*\(",
        "ai-tool-use",
        "ai.tool_use",
        "high",
        frozenset({".py"}),
    ),
    (
        r"@\s*(?:mcp|server|app)\.tool\b",
        "ai-tool-use",
        "ai.tool_use",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\b(?:McpServer|Server)\s*\(\s*\{\s*name",
        "ai-tool-use",
        "ai.tool_use",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\btool_choice\s*[=:]",
        "ai-tool-use",
        "ai.tool_use",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bCrew\s*\(\s*agents",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\b(?:ConversableAgent|GroupChat|AssistantAgent|UserProxyAgent)\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\b(?:CodeAgent|ToolCallingAgent)\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bAgentExecutor\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\binitialize_agent\s*\(",
        "ai-agent",
        "ai.agent_run",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\binvoke_model\s*\(",
        "ai-provider",
        "ai.completion",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bInvokeModelCommand\s*\(",
        "ai-provider",
        "ai.completion",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\b(ChatAnthropic|ChatOpenAI|ChatBedrock|ChatVertexAI|ChatGoogleGenerativeAI|ChatCohere|ChatMistralAI)\s*\(",
        "ai-provider",
        "ai.completion",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bpinecone\.Index\s*\(",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bchromadb\.(?:Client|PersistentClient|HttpClient)",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".py"}),
    ),
    (
        r"\bQdrantClient\s*\(",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\bChromaClient\s*\(",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"}),
    ),
    (
        r"\.as_retriever\s*\(",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}),
    ),
    (
        r"\.as_query_engine\s*\(",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        frozenset({".py"}),
    ),
]

# PROOF-1 tiering: a first proof may only bind to a consequential
# (irreversible) capability. Observe-only AI surfaces are reported —
# they are the map — but never selected as the wrap target.
FIRST_PROOF_ELIGIBLE: frozenset[str] = frozenset({
    "ai.agent_run", "ai.tool_use", "data.export", "database.delete", "database.migrate", "database.update", "email.send", "filesystem.delete", "flag.flip", "iam.grant", "iam.revoke", "infra.apply", "infra.destroy", "message.publish", "payment.charge", "payment.refund", "sms.send", "storage.delete", "storage.write",
})

OBSERVE_ONLY_CAPABILITIES: frozenset[str] = frozenset({
    "ai.completion", "ai.embedding", "ai.retrieval",
})
# END GENERATED PATTERNS

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
    # PROOF-1 tiering: True when a first proof may bind to this
    # candidate (irreversible mutations + ai.tool_use / ai.agent_run);
    # False for observe-only AI surfaces (ai.completion / ai.embedding
    # / ai.retrieval), which are reported but never wrapped first.
    first_proof_eligible: bool = True


def _candidate_tier(capability_id: str) -> int:
    """Ranking tier: 0 = consequential AI (the novel find — agent runs
    and tool dispatch outrank incidental CRUD), 1 = irreversible
    mutations, 2 = observe-only AI surfaces."""
    if capability_id in ("ai.tool_use", "ai.agent_run"):
        return 0
    if capability_id in OBSERVE_ONLY_CAPABILITIES:
        return 2
    return 1


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
                            first_proof_eligible=(
                                capability_id in FIRST_PROOF_ELIGIBLE
                            ),
                        )
                    )
                    break  # one hit per line is enough

    # Sort: consequential AI (agent runs / tool dispatch) first, then
    # irreversible mutations, then observe-only AI surfaces; within a
    # tier, high before medium, then by file path for stability.
    confidence_rank = {"high": 0, "medium": 1}
    candidates.sort(
        key=lambda c: (
            _candidate_tier(c.capability_id),
            confidence_rank.get(c.confidence, 9),
            c.file,
            c.line,
        )
    )
    return candidates[:limit]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_human(candidates: list[Candidate]) -> str:
    if not candidates:
        return (
            "No action-point candidates found — this is guidance, not a dead end.\n"
            "\n"
            "Patterns checked: payments/refunds (stripe), db deletes/updates,\n"
            "raw destructive SQL, s3 deletes/writes, email/SMS sends,\n"
            "filesystem deletes, schema migrations, infra apply/destroy,\n"
            "IAM grants/revokes, feature-flag flips, bulk data exports,\n"
            "message publishes, and AI surfaces (agent runs, MCP/LLM tool\n"
            "dispatch, model calls, embeddings, retrieval).\n"
            "\n"
            "Languages scanned: Python, JavaScript/TypeScript, Go, Ruby.\n"
            "\n"
            "A miss usually means one of three things:\n"
            "  1. This repo has no irreversible action yet (nothing to wire).\n"
            "  2. Your action uses a library/idiom not in the pattern set\n"
            "     above — e.g. a Go/Ruby SDK beyond the delete + Stripe\n"
            "     idioms, or a bespoke internal client.\n"
            "  3. The call is already wrapped with governed_action() /\n"
            "     governedAction() (those are excluded by design).\n"
            "\n"
            "If you have a specific function in mind, point me at it and I\n"
            "will wire governed_action() around it directly — the pattern\n"
            "set is a convenience, not a requirement."
        )
    lines = []
    for i, c in enumerate(candidates, start=1):
        marker = "" if c.first_proof_eligible else "  (observe-only — not first-proof eligible)"
        lines.append(
            f"{i}. [{c.confidence}] {c.file}:{c.line}  ({c.capability_id}){marker}\n"
            f"   {c.snippet.strip()}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan for action points (irreversible mutations + AI surfaces) "
            "to wrap with governedAction()."
        )
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
