"""Source-scanned proof of WIRE-CONSENT-1.

Two directions:

1. The analyzer (and its vendored preflight/scanner) contains no mutation,
   subprocess, or network capability — so the broad analysis authorization
   is incapable of being upgraded into action authority (Gate J).
2. SKILL.md keeps the governance checkpoints separate and explicit — the
   ANALYSIS REQUEST card matches the analyzer's actual grant list, the wrap
   and the run each demand their own confirmation, and skipped/declined
   states are valid terminals.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from conftest import SKILL_DIR

SKILL_MD = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
ANALYZE_SRC = (SKILL_DIR / "analyze.py").read_text(encoding="utf-8")
PREFLIGHT_SRC = (SKILL_DIR / "preflight.py").read_text(encoding="utf-8")
SCANNER_SRC = (SKILL_DIR / "scanner.py").read_text(encoding="utf-8")


def normalized(text: str) -> str:
    """Collapse whitespace (and blockquote markers) so phrase checks
    survive line wrapping."""
    text = re.sub(r"^\s*>\s?", "", text, flags=re.M)
    return re.sub(r"\s+", " ", text)


def code_only(source: str) -> str:
    """The source's executable tokens — docstrings, comments, and string
    literals stripped — so the forbidden-primitive scan can't be fooled or
    false-positived by prose or by detection-pattern strings."""
    kept: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        if tok.string.strip():
            kept.append(tok.string)
    joined = " ".join(kept)
    return joined.replace(" . ", ".").replace(" (", "(")


SKILL_FLAT = normalized(SKILL_MD)


# ---------------------------------------------------------------------------
# Gate J: the analysis tooling has no write / exec / network capability.
# ---------------------------------------------------------------------------

FORBIDDEN_IN_ANALYSIS = [
    "subprocess",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "socket",
    "urllib",
    "http.client",
    "requests",
    "httpx",
    "shutil",
    "tempfile",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.chmod",
    "os.makedirs",
    "os.mkdir",
    "rmtree",
    "write_text",
    "write_bytes",
    "eval(",
    "exec(",  # exec_module (importlib, own bundle) tokenizes apart — no hit
]


def _violations(source: str) -> list[str]:
    code = code_only(source)
    hits = []
    for token in FORBIDDEN_IN_ANALYSIS:
        for m in re.finditer(re.escape(token), code):
            context = code[max(0, m.start() - 30) : m.end() + 30]
            hits.append(f"{token!r} in ...{context!r}...")
    return hits


def test_analyzer_has_no_mutation_or_network_primitive():
    assert _violations(ANALYZE_SRC) == []


def test_vendored_preflight_and_scanner_are_equally_inert():
    assert _violations(PREFLIGHT_SRC) == []
    assert _violations(SCANNER_SRC) == []


def test_every_open_in_the_analysis_stack_is_read_only():
    for name, src in (
        ("analyze.py", ANALYZE_SRC),
        ("preflight.py", PREFLIGHT_SRC),
        ("scanner.py", SCANNER_SRC),
    ):
        for m in re.finditer(r"\bopen\(([^)]*)\)", src):
            args = m.group(1)
            assert not re.search(r"['\"][^'\"]*[wax+][^'\"]*['\"]", args.split(",", 1)[1] if "," in args else ""), (
                f"{name}: open() with a writable mode: open({args})"
            )


# ---------------------------------------------------------------------------
# The ANALYSIS REQUEST card matches the analyzer's actual grant list.
# ---------------------------------------------------------------------------


def _card_block() -> str:
    start = SKILL_MD.index("STRIX WIRE — ANALYSIS REQUEST")
    end = SKILL_MD.index("```", start)
    return SKILL_MD[start:end]


def test_card_grants_match_analyzer_grants(analyze_mod):
    card = _card_block()
    will = [l.strip()[2:] for l in card.splitlines() if l.strip().startswith("✓")]
    will_not = [l.strip()[2:] for l in card.splitlines() if l.strip().startswith("✕")]
    assert will == analyze_mod.CONSENT_COVERS
    assert will_not == analyze_mod.CONSENT_DOES_NOT_AUTHORIZE


def test_card_declares_scope_and_single_run():
    card = _card_block()
    assert "Scope:" in card
    assert "exactly one run" in card


# ---------------------------------------------------------------------------
# The consolidated flow: one command; no per-phase prompts.
# ---------------------------------------------------------------------------


def test_skill_orchestrates_exactly_one_analysis_command():
    assert "Run exactly ONE command" in SKILL_MD
    assert "analyze.py" in SKILL_MD
    # The old per-phase invocations must be forbidden during onboarding.
    assert "never run `preflight.py`, `scanner.py`" in SKILL_FLAT
    # And a failing analyzer must not be decomposed back into prompts.
    assert "fail closed" in SKILL_FLAT
    assert "do NOT" in SKILL_FLAT and "individual commands" in SKILL_FLAT


def test_missing_toolchain_is_one_remediation():
    assert "one remediation, never a prompt loop" in SKILL_FLAT
    assert "Never probe alternative interpreters across multiple prompts" in SKILL_FLAT


# ---------------------------------------------------------------------------
# Governance checkpoints stay separate and explicit.
# ---------------------------------------------------------------------------


def test_the_critical_rule_is_stated():
    assert "collapse mechanical permissions, not governance decisions" in SKILL_FLAT.lower()


def test_wrap_requires_its_own_confirmation():
    assert "PROPOSED CHANGE" in SKILL_MD
    assert "Actions that will execute:" in SKILL_MD and "\n0\n" in SKILL_MD
    assert "Analysis consent never authorizes the wrap or the run" in SKILL_FLAT
    assert "One confirmation is never enough to both wrap and run" in SKILL_FLAT


def test_execution_requires_a_separate_confirmation():
    assert "RUN SANDBOX PROOF" in SKILL_MD
    assert "Execution gets its own explicit confirmation" in SKILL_FLAT
    assert "did NOT authorize execution" in SKILL_FLAT
    assert "capability- and target-specific" in SKILL_FLAT
    # Both governance checkpoints go through an explicit question.
    assert SKILL_MD.count("AskUserQuestion") >= 2


def test_skip_and_stop_are_valid_terminal_states():
    assert "zero files changed" in SKILL_FLAT
    assert '"Stop here" is a valid terminal state' in SKILL_FLAT
    assert "No execution evidence exists and none is claimed" in SKILL_FLAT


def test_wrap_application_executes_nothing():
    assert "Applying the wrap executes nothing" in SKILL_FLAT
    assert "Actions executed: 0" in SKILL_FLAT


# ---------------------------------------------------------------------------
# Consent expiry and re-scoping.
# ---------------------------------------------------------------------------


def test_analysis_consent_expires_and_rescoping_requires_fresh_consent():
    assert "expires at the end of the run" in SKILL_FLAT
    assert "requires a fresh ANALYSIS REQUEST" in SKILL_FLAT
    assert "Never treat an earlier analysis approval as standing permission" in SKILL_FLAT


def test_offline_mode_never_hardcodes_a_standing_approval():
    # The one-run Phase 4 approval must live in the run command (env var),
    # never as a literal in committed source — a hardcoded True would be a
    # permanent, code-resident execution authorization (invariant 7). The
    # wrap patterns the agent copies are the fenced code blocks; prose may
    # mention the anti-pattern, code blocks must never contain it.
    code_blocks = re.findall(r"```[a-z]*\n(.*?)```", SKILL_MD, flags=re.S)
    offending = [
        b
        for b in code_blocks
        if "approval_granted=True" in b or "approvalGranted: true" in b
    ]
    assert offending == [], "a copyable wrap pattern hardcodes the approval flag"
    assert "STRIX_WIRE_RUN_APPROVED" in SKILL_MD
    assert "Never write a literal" in SKILL_FLAT
    assert "denied by default" in SKILL_FLAT


def test_harness_prompts_are_echoes_not_approvals():
    assert "Harness prompts are echoes, not extra approvals" in SKILL_FLAT
    assert "Never re-ask the governance question" in SKILL_FLAT


def test_scope_binding_and_fail_closed_preflight_are_documented():
    assert "--allow-external-root" in SKILL_MD
    assert "refuses a root outside the current working directory" in SKILL_FLAT
    assert "never reported as" in SKILL_FLAT  # truncation fail-closed language


def test_approval_budget_is_stated():
    assert "analysis only = **1** approval" in SKILL_FLAT
    assert "analysis plus wrap = **2**" in SKILL_FLAT
    assert "analysis, wrap, and sandbox proof = **3**" in SKILL_FLAT


# ---------------------------------------------------------------------------
# The analyzer's consent metadata is structurally sound.
# ---------------------------------------------------------------------------


def test_consent_block_shape(analyze_mod):
    block = analyze_mod._consent_block(Path("."))
    assert len(block["covers"]) == 6
    assert len(block["does_not_authorize"]) == 6
    assert block["expires"] == "end-of-run"
    assert block["contract"] == "WIRE-CONSENT-1"
