"""The Strix Personal action lifecycle: DETECTED → … → VERIFIED.

The load-bearing rule (mirrors the type-disjointness discipline in ADR-009 /
ADR-010): a ``ScanReport`` is **not** evidence. It carries no ``record_hash``,
``chain_seq``, or ``prev_hash``, and it cannot promote a candidate past
``WRAPPED`` from scan data alone. ``TESTED`` / ``ENFORCED`` / ``VERIFIED`` each
require an explicit runtime signal. This is the structural form of "never
convert detected directly into governed."

This module is vendored byte-for-byte into the ``strix-personal`` plugin, so
the scanner import uses a dual path: the installed package when available, the
vendored sibling otherwise. Do not collapse the ``try/except`` — it is what
lets one file serve both locations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum

try:  # installed package
    from solo_builder.action_scanner import (
        CONFIDENCE_MEANING,
        SEVERITY_MEANING,
        Candidate,
        scan,
    )
except ImportError:  # vendored standalone (plugin scripts/_vendor/)
    from action_scanner import (  # type: ignore
        CONFIDENCE_MEANING,
        SEVERITY_MEANING,
        Candidate,
        scan,
    )

# Re-exported: the meanings live beside the values they explain
# (DEFAULT_POLICY and Candidate.confidence in action_scanner), so the CLI's
# `solo govern scan` and this plugin report cannot drift into two glossaries.


class LifecycleError(RuntimeError):
    """Raised on an illegal state transition (e.g. DETECTED → VERIFIED)."""


class ActionState(str, Enum):
    """Where a single action point sits on the road to governance."""

    DETECTED = "detected"
    WRAPPABLE = "wrappable"
    WRAPPED = "wrapped"
    TESTED = "tested"
    ENFORCED = "enforced"
    VERIFIED = "verified"
    SUPPRESSED = "suppressed"


# The main progression. SUPPRESSED is a terminal off-ramp, not on this line.
_PROGRESSION: list[ActionState] = [
    ActionState.DETECTED,
    ActionState.WRAPPABLE,
    ActionState.WRAPPED,
    ActionState.TESTED,
    ActionState.ENFORCED,
    ActionState.VERIFIED,
]
_RANK: dict[ActionState, int] = {s: i for i, s in enumerate(_PROGRESSION)}

# States that may ONLY be entered with a matching runtime signal. This is the
# barrier that stops scan data from manufacturing a "governed" verdict.
_SIGNAL_KIND_FOR: dict[ActionState, str] = {
    ActionState.TESTED: "test",
    ActionState.ENFORCED: "bypass",
    ActionState.VERIFIED: "evidence",
}

# The minimum state a candidate must already hold before it may enter a given
# state. This is what makes "never convert detected directly into governed"
# structural: you cannot reach VERIFIED unless you are already ENFORCED, and a
# signal alone never lets a DETECTED candidate leap the whole chain.
_MIN_PRECURSOR: dict[ActionState, ActionState] = {
    ActionState.TESTED: ActionState.WRAPPED,
    ActionState.ENFORCED: ActionState.WRAPPED,
    ActionState.VERIFIED: ActionState.ENFORCED,
}

# The furthest a candidate can be placed from static scan information alone.
MAX_STATIC_STATE = ActionState.WRAPPED


@dataclass(frozen=True)
class RuntimeSignal:
    """An out-of-band fact that justifies advancing past WRAPPED.

    ``kind`` is one of ``"test"`` (a deny/approval scenario passed),
    ``"bypass"`` (the boundary-routing check passed — no sibling unwrapped
    call), or ``"evidence"`` (a real signed record was produced).
    """

    kind: str
    passed: bool = True
    evidence_id: str | None = None
    detail: str | None = None


def _is_wrappable(candidate: Candidate) -> bool:
    """True if a candidate is a recognized, mechanically-wrappable call site.

    Dependency-manifest candidates (``category == "ai-dependency"``) are
    informational only — there is no call site to wrap — so they stay
    DETECTED.
    """
    return candidate.kind in ("mutation", "ai") and candidate.category != "ai-dependency"


def initial_state(candidate: Candidate) -> ActionState:
    """Resolve a candidate's starting lifecycle state from static scan data.

    Never returns anything past ``WRAPPED`` — runtime promotion is required
    for TESTED / ENFORCED / VERIFIED.
    """
    if candidate.suppressed:
        return ActionState.SUPPRESSED
    if candidate.governed:
        return ActionState.WRAPPED
    if _is_wrappable(candidate):
        return ActionState.WRAPPABLE
    return ActionState.DETECTED


@dataclass
class LifecycleEntry:
    """One action point and its current lifecycle state.

    Intentionally NOT evidence-shaped: no ``record_hash`` / ``chain_seq`` /
    ``prev_hash``. ``dataclasses.asdict()`` on this can never be mistaken for
    an authoritative evidence row.
    """

    candidate: Candidate
    state: ActionState
    evidence_id: str | None = None
    history: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def detect(cls, candidate: Candidate) -> LifecycleEntry:
        st = initial_state(candidate)
        return cls(candidate=candidate, state=st, history=[(st.value, "detected by scanner")])

    @property
    def capability_id(self) -> str:
        return self.candidate.capability_id

    @property
    def location(self) -> str:
        return f"{self.candidate.file}:{self.candidate.line}"

    @property
    def is_governed(self) -> bool:
        """True once the candidate is at least WRAPPED, or operator-suppressed."""
        if self.state == ActionState.SUPPRESSED:
            return True
        return _RANK.get(self.state, -1) >= _RANK[ActionState.WRAPPED]


def promote(
    entry: LifecycleEntry,
    target: ActionState,
    *,
    signal: RuntimeSignal | None = None,
    reason: str = "",
) -> LifecycleEntry:
    """Advance ``entry`` to ``target``, enforcing the transition rules.

    Rules:
      * Movement is forward-only along the progression (no silent downgrade).
      * SUPPRESSED may be entered from any non-terminal progression state.
      * TESTED / ENFORCED / VERIFIED require a matching, passing ``signal``;
        VERIFIED additionally requires an ``evidence_id``.

    Raises ``LifecycleError`` on any illegal transition. Mutates and returns
    ``entry`` for convenience.
    """
    current = entry.state

    if target == current:
        return entry

    if target == ActionState.SUPPRESSED:
        if current in (ActionState.VERIFIED, ActionState.SUPPRESSED):
            raise LifecycleError(f"cannot suppress from terminal state {current.value}")
        entry.state = target
        entry.history.append((target.value, reason or "operator suppressed"))
        return entry

    if current == ActionState.SUPPRESSED:
        raise LifecycleError("a suppressed action cannot re-enter the progression")

    if target not in _RANK:
        raise LifecycleError(f"unknown target state {target!r}")

    if _RANK[target] <= _RANK[current]:
        raise LifecycleError(
            f"illegal transition {current.value} → {target.value} (lifecycle is forward-only)"
        )

    precursor = _MIN_PRECURSOR.get(target)
    if precursor is not None and _RANK[current] < _RANK[precursor]:
        raise LifecycleError(
            f"cannot reach {target.value} from {current.value}: "
            f"must be at least {precursor.value} first "
            "(no leaping the lifecycle on a signal alone)"
        )

    required_kind = _SIGNAL_KIND_FOR.get(target)
    if required_kind is not None:
        if signal is None or signal.kind != required_kind or not signal.passed:
            raise LifecycleError(
                f"{target.value} requires a passing {required_kind!r} signal "
                f"(refusing to promote {entry.location} on scan data alone)"
            )
        if target == ActionState.VERIFIED:
            ev = signal.evidence_id
            if not ev:
                raise LifecycleError("VERIFIED requires a non-empty evidence_id")
            entry.evidence_id = ev

    entry.state = target
    detail = reason or (signal.detail if signal else "") or "promoted"
    entry.history.append((target.value, detail))
    return entry


# Severity badges reused from the scanner's vocabulary.
# Cap on grouped non-blocking capabilities shown before collapsing to a
# count. Truncation is stated, never silent — an elided row must still be
# accounted for in the line that hides it.
_MAX_GROUPS = 8

_SEVERITY_BADGE = {"error": "\U0001f534 error", "warning": "\U0001f7e1 warning", "note": "\U0001f535 note"}

# Mirrors ``solo_builder.governance_coverage.MEASUREMENT_DISCLAIMER`` byte for
# byte. Duplicated rather than imported because this module is vendored into
# the strix-personal plugin standalone and ``governance_coverage`` is not;
# ``tests/test_strix_personal_lifecycle.py`` fails the build if the two drift.
MEASUREMENT_DISCLAIMER = "unsigned measurement, never proof — static-pattern visibility only"

# The staged path, in order. ``effect`` is the load-bearing column: a reader
# deciding what to run next needs to know which stages can change something
# before they run it, not after. Sourced from each command's own `description`
# in ``plugins/strix-personal/commands/``.
PIPELINE: tuple[tuple[str, str, str, str], ...] = (
    ("/strix-scan", "detect", "read-only", "inventory every consequential action"),
    (
        "/strix-plan",
        "decide",
        "read-only",
        "group findings into capabilities, propose policy, pick what to wrap",
    ),
    (
        "/strix-apply",
        "govern",
        "writes code",
        "wrap ONE call site; shows the diff first. Does not run the action",
    ),
    (
        "/strix-test",
        "verify",
        "safe exercise",
        "exercise the wrapped capability — allowed, approval-required, tamper — without firing the real effect",
    ),
    ("/strix-status", "track", "read-only", "where each action point sits, and coverage"),
)

# ``/strix-wire`` is NOT a stage in the pipeline above. It is a one-shot in
# this same plugin (skills/strix-wire/) that scans, wraps, AND runs the wrapped
# action once to mint a live evidence record. That last step is why it cannot
# be described as "step 3.5": on an inventory whose blocking tier is deletes,
# the fast path fires a real delete. Stated in ``render()`` unconditionally,
# never behind ``--no-legend``.
FAST_PATH_COMMAND = "/strix-wire"

# What each lifecycle state MEANS. Keyed by ``ActionState`` value.
STATE_MEANING: dict[str, str] = {
    "detected": "found, but no single call site to wrap (e.g. a dependency manifest)",
    "wrappable": "a real call site Strix can wrap — nothing is wrapped yet",
    "wrapped": "the call site is inside a governed_action() wrap",
    "tested": "a deny/approval scenario passed against it (recorded by /strix-test)",
    "enforced": "no sibling unwrapped call site bypasses the boundary, repo-wide (recorded by /strix-apply)",
    "verified": "a real signed record was produced by this call site (recorded by /strix-test)",
    "suppressed": "operator opted it out with a justified `strix: allow` directive",
}


@dataclass
class ScanReport:
    """A lifecycle view over a set of scanned action points.

    DELIBERATELY type-disjoint from evidence: this dataclass declares no
    ``record_hash`` / ``chain_seq`` / ``prev_hash`` field. The invariant is
    asserted in ``tests/test_strix_personal_lifecycle.py`` so a future field
    addition that would let a report impersonate evidence fails the build.
    """

    entries: list[LifecycleEntry] = field(default_factory=list)

    # ---- builders -------------------------------------------------------
    @classmethod
    def from_candidates(cls, candidates: list[Candidate]) -> ScanReport:
        return cls(entries=[LifecycleEntry.detect(c) for c in candidates])

    @classmethod
    def from_scan(cls, root, **scan_kwargs) -> ScanReport:
        """Convenience: run the scanner and build a report in one step."""
        return cls.from_candidates(scan(root, **scan_kwargs))

    # ---- rollups --------------------------------------------------------
    @property
    def total(self) -> int:
        return len(self.entries)

    def by_state(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.state.value] = out.get(e.state.value, 0) + 1
        return out

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            sev = e.candidate.severity
            out[sev] = out.get(sev, 0) + 1
        return out

    def governed_count(self) -> int:
        return sum(1 for e in self.entries if e.is_governed)

    def coverage(self) -> float:
        """(governed-or-better) / total. 1.0 for an empty report (vacuous)."""
        if not self.entries:
            return 1.0
        return min(1.0, self.governed_count() / self.total)

    def open_blocking(self) -> list[LifecycleEntry]:
        """Ungoverned, error-severity action points — the things to fix first."""
        return [e for e in self.entries if not e.is_governed and e.candidate.severity == "error"]

    def headline(self) -> str:
        return (
            f"Total: {self.total} · "
            f"Coverage: {self.coverage():.1%} · "
            f"Blocking: {len(self.open_blocking())} · "
            f"Governed: {self.governed_count()}"
        )

    # ---- rendering ------------------------------------------------------
    def legend(self) -> list[str]:
        """The 'how to read this' block.

        Severity words are the ones a linter uses for broken code, and the
        lifecycle words are Strix-specific — without this, a reader can only
        guess whether ``error 12`` means twelve bugs (it does not: it means
        twelve ungoverned irreversible call sites) or whether ``Coverage: 0%``
        means the scan failed (it did not).
        """
        present_states = self.by_state()
        present_conf = {e.candidate.confidence for e in self.entries}

        lines = ["How to read this — three independent axes"]
        lines.append("")
        lines.append("  1. Severity     how bad it is IF it runs ungoverned. Assigned by POLICY per")
        lines.append("                  capability — NOT a measure of how sure the scanner is.")
        for sev in ("error", "warning", "note"):
            lines.append(f"     {_SEVERITY_BADGE.get(sev, sev):<12}{SEVERITY_MEANING[sev]}")
        lines.append("     Override per capability under [govern.policy] in .solo.toml.")
        lines.append("")
        lines.append("  2. Confidence   how sure the pattern match is that this really is that kind")
        lines.append("                  of call. False-positive risk — unrelated to severity.")
        for conf in ("high", "medium"):
            if conf in present_conf:
                lines.append(f"     {conf:<12}{CONFIDENCE_MEANING[conf]}")
        lines.append("")
        lines.append("  3. Lifecycle    where the call site sits in the governance process.")
        lines.append("                  " + " → ".join(s.value for s in _PROGRESSION))
        for state in (*_PROGRESSION, ActionState.SUPPRESSED):
            if state.value in present_states:
                lines.append(f"     {state.value:<12}{STATE_MEANING[state.value]}")
        lines.append(f"     A static scan stops at `{MAX_STATIC_STATE.value}`; tested/enforced/verified")
        lines.append("     each require a runtime signal this scan cannot produce. The commands")
        lines.append("     above record those signals; /strix-status replays them, and re-checks")
        lines.append("     each one against the current code before it counts.")
        lines.append("")
        lines.append("  A finding can be high-severity AND ungoverned — that is the normal starting")
        lines.append('  state, not a contradiction. `error` means "this SHOULD be gated", never')
        lines.append('  "this IS gated".')
        lines.append("")
        lines.append("  Coverage      (governed + suppressed) / total — how much is wrapped, not how")
        lines.append("                safe it is.")
        lines.append("")
        lines.append("  The staged path — nothing irreversible runs until you choose it:")
        for cmd, verb, effect, what in PIPELINE:
            lines.append(f"     {cmd:<15}{verb:<8}({effect})")
            lines.append(f"     {'':<15}{what}")
        lines.append("")
        lines.append("  Blocking      ungoverned AND unsuppressed AND severity == error. Two ways a")
        lines.append("                row leaves this count: govern it (wrap the call), or suppress it")
        lines.append('                with an inline `strix: allow capability=<id> reason="..."`')
        lines.append("                directive, which records an operator's justification. A reason")
        lines.append("                is required. warning/note never count as blocking, at any")
        lines.append("                coverage.")
        return lines

    def render(self, *, legend: bool = True) -> str:
        """Human-readable consumer report with the lifecycle table."""
        if not self.entries:
            return (
                "\U0001f512 Strix Personal — no consequential action points found.\n"
                "Patterns checked: payments, db deletes, storage, email/SMS, "
                "filesystem deletes, schema migrations, AI surfaces.\n"
                f"{MEASUREMENT_DISCLAIMER}. A clean scan means these patterns did not "
                "match — not that this repo has no consequential actions."
            )

        lines: list[str] = ["\U0001f512 Strix Personal — action inventory", ""]
        lines.append(self.headline())
        lines.append("")

        sev = self.by_severity()
        sev_bits = [f"{_SEVERITY_BADGE.get(k, k)} {sev[k]}" for k in ("error", "warning", "note") if k in sev]
        if sev_bits:
            lines.append("By severity:  " + " · ".join(sev_bits))

        state_counts = self.by_state()
        state_bits = [
            f"{s.value} {state_counts[s.value]}"
            for s in (*_PROGRESSION, ActionState.SUPPRESSED)
            if s.value in state_counts
        ]
        if state_bits:
            lines.append("Lifecycle:    " + " · ".join(state_bits))
        lines.append("")

        blocking = self.open_blocking()
        if blocking:
            lines.append(f"Open action points ({len(blocking)} blocking):")
            for e in blocking:
                # Confidence rides the row: without it a `medium` inference
                # is visually identical to an unambiguous match, and the
                # reader cannot tell which findings to sanity-check first.
                lines.append(
                    f"  {_SEVERITY_BADGE.get(e.candidate.severity, e.candidate.severity)}"
                    f"  [{e.capability_id}]  {e.candidate.confidence} confidence"
                    f"{'  ' + e.candidate.scope if e.candidate.scope else ''}"
                    f"  {e.location}"
                )
                lines.append(f"      {e.candidate.snippet.strip()}")
            lines.append("")

        # Everything that is not blocking was counted in the headline and then
        # never shown. A reader seeing "note 33" had no way to learn what those
        # 33 were without re-running with --json. Grouped rather than listed:
        # the shape is the useful part, and 33 lines would bury the blocking
        # section that actually needs attention.
        rest = [e for e in self.entries if e not in blocking]
        if rest:
            by_cap: dict[str, list[LifecycleEntry]] = {}
            for e in rest:
                by_cap.setdefault(e.capability_id, []).append(e)
            # Severity first, then frequency — a lone `warning` outranks a
            # dozen `note`s, because the ordering should track consequence,
            # not volume.
            sev_rank = {"error": 0, "warning": 1, "note": 2}
            groups = sorted(
                by_cap.items(),
                key=lambda kv: (sev_rank.get(kv[1][0].candidate.severity, 9), -len(kv[1]), kv[0]),
            )
            lines.append(f"Also found — not blocking ({len(rest)}):")
            for cap, entries in groups[:_MAX_GROUPS]:
                entry_sev = entries[0].candidate.severity
                badge = _SEVERITY_BADGE.get(entry_sev, entry_sev)
                # Pad on the label, not the badge: the emoji is one char to
                # str but renders double-width, so ljust on the whole badge
                # misaligns exactly the columns it is meant to line up.
                badge = badge + " " * (len("warning") - len(entry_sev))
                count = f"{len(entries)}x" if len(entries) > 1 else ""
                lines.append(f"  {badge}  {cap:<20}{count:>4}  first: {entries[0].location}")
            if len(groups) > _MAX_GROUPS:
                hidden = sum(len(v) for _, v in groups[_MAX_GROUPS:])
                lines.append(
                    f"  … and {len(groups) - _MAX_GROUPS} more capabilities ({hidden} action points)"
                )
            lines.append("  Full per-row detail: re-run with --json.")
            lines.append("")

        if legend:
            lines.extend(self.legend())
            lines.append("")

        # Always emitted, legend or not: the report must never travel without
        # its own boundary. Detection is not enforcement.
        lines.append(f"{MEASUREMENT_DISCLAIMER}.")
        lines.append("Nothing here is signed, and nothing is enforced until a call site is wrapped.")
        lines.append("")

        lines.append("Next: /strix-plan — decide what to govern. Read-only; changes nothing.")

        # The fast path is a real footgun on an inventory like this one, so it
        # is named here rather than left to be discovered from a README. Not
        # part of the legend: --no-legend must not be able to hide it.
        blocking = self.open_blocking()
        if blocking:
            worst = blocking[0].capability_id
            lines.append("")
            lines.append(f"{FAST_PATH_COMMAND} is a DIFFERENT flow, not a stage in the one above — a")
            lines.append("one-shot that scans, wraps, and RUNS the wrapped action once to mint a live")
            lines.append(f"evidence record. On this inventory that means firing a real `{worst}`.")
            lines.append("Only appropriate once you know which call it will fire and against what.")
            lines.append("Plan before you wire.")
        return "\n".join(lines)


def _report_has_no_evidence_fields() -> bool:
    """Self-check used by the disjointness test: a report is not evidence."""
    forbidden = {"record_hash", "chain_seq", "prev_hash", "signature", "signing_key_id"}
    report_fields = {f.name for f in fields(ScanReport)}
    entry_fields = {f.name for f in fields(LifecycleEntry)}
    return not (forbidden & (report_fields | entry_fields))


__all__ = [
    "ActionState",
    "MEASUREMENT_DISCLAIMER",
    "CONFIDENCE_MEANING",
    "FAST_PATH_COMMAND",
    "PIPELINE",
    "SEVERITY_MEANING",
    "STATE_MEANING",
    "LifecycleEntry",
    "LifecycleError",
    "RuntimeSignal",
    "ScanReport",
    "MAX_STATIC_STATE",
    "initial_state",
    "promote",
]
