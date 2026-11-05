"""Runtime-signal journal: how an action point advances past ``WRAPPED``.

The lifecycle rule is unchanged and stays load-bearing — a static scan can
never place an action past ``WRAPPED``. What was missing is the *other half*:
nothing in the toolchain ever constructed a ``RuntimeSignal``, so the three
states above ``WRAPPED`` were reachable only from a test. ``/strix-apply``
computed the bypass result and printed it; ``/strix-test`` observed real
verdicts; ``/strix-status`` re-scanned from scratch and reset everything to at
most ``WRAPPED``. A runtime fact could be *observed* but had nowhere to live.

This module is that place. It is deliberately the smallest thing that closes
the gap:

* **Not evidence.** A ``SignalRecord`` declares no ``record_hash`` /
  ``chain_seq`` / ``prev_hash`` / ``signature``, exactly like ``ScanReport``
  (Gate H). It is an unsigned local measurement of what a command observed —
  it does not become proof by being written down. ``VERIFIED`` records the
  ``evidence_id`` of the signed record; the signed record itself lives in the
  kernel and is what a third party verifies.

* **Bound, so a signal cannot float.** Every record carries a ``binding``:
  a digest of the exact thing the claim was made about. A site-scoped claim
  (``test`` / ``evidence``) binds to that call's own normalized text, NOT its
  line number, so an unrelated edit above it does not invalidate a true fact
  and a rewritten call does not inherit a stale one. A repo-scoped claim
  (``bypass`` — "no ungoverned sibling exists") binds to every call site of
  that capability, because that is the scope of the claim being made.

* **Stale-fails-closed.** On replay, bindings are recomputed from the current
  tree. A signal whose binding no longer matches is dropped and the entry
  falls back to its static state. Silence would be the bug: ``apply_signals``
  reports every dropped signal so the surface can say a claim expired rather
  than quietly showing a stale ``ENFORCED``.

* **A failure revokes, and caps.** Records are append-only, and the newest
  record for a given (kind, site) wins *whatever it says*. A failing check
  does not merely withhold its state — it holds the entry strictly *below*
  it, because the linear rendering makes a higher state assert every lower
  one. A failed deny-scenario test must not sit invisible under a ``VERIFIED``
  earned by two unrelated signals.

The journal lives under ``.solo/``, which is conventionally gitignored, and
that is the right default: it is a record of what *this* machine observed
about *this* working tree. Committing it would not make its claims travel —
every one is re-checked against the reader's own tree before it counts — but
it would invite reading a teammate's local run as a shared guarantee, which is
the one thing an unsigned measurement must never become.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

try:  # installed package
    from solo_builder.action_scanner import Candidate
except ImportError:  # vendored standalone (plugin scripts/_vendor/)
    from action_scanner import Candidate  # type: ignore

try:
    from solo_builder.strix_personal.lifecycle import (
        ActionState,
        LifecycleEntry,
        LifecycleError,
        RuntimeSignal,
        ScanReport,
        promote,
    )
except ImportError:  # vendored standalone
    from lifecycle import (  # type: ignore
        ActionState,
        LifecycleEntry,
        LifecycleError,
        RuntimeSignal,
        ScanReport,
        promote,
    )


#: Journal location, relative to the repository root.
JOURNAL_RELPATH = Path(".solo") / "strix-personal" / "signals.jsonl"

#: The three signal kinds, and the state each one unlocks. Mirrors
#: ``lifecycle._SIGNAL_KIND_FOR`` inverted; the pairing is asserted in tests so
#: a new lifecycle state cannot appear here without a producer.
STATE_FOR_KIND: dict[str, ActionState] = {
    "test": ActionState.TESTED,
    "bypass": ActionState.ENFORCED,
    "evidence": ActionState.VERIFIED,
}

#: Which command is expected to produce each kind. Rendered in the status
#: surface so "why is nothing TESTED?" has an answer in the tool.
PRODUCER_FOR_KIND: dict[str, str] = {
    "test": "/strix-test",
    "bypass": "/strix-apply (bypass check)",
    "evidence": "/strix-test (a real signed record)",
}

#: A ``bypass`` claim is about a whole capability across the repo; the other
#: two are about one call site. This drives both binding and matching.
REPO_SCOPED_KINDS = frozenset({"bypass"})

#: Replay order. Must be non-decreasing in lifecycle rank so
#: ``lifecycle._MIN_PRECURSOR`` is satisfied by construction: ENFORCED needs
#: WRAPPED, VERIFIED needs ENFORCED. Replaying an ``evidence`` signal first
#: would refuse a legitimate promotion purely because of journal ordering.
_KIND_RANK = {"test": 0, "bypass": 1, "evidence": 2}

_WS = re.compile(r"\s+")


class SignalError(RuntimeError):
    """Raised on a malformed signal record or an unwritable journal."""


def _RANK_OF(state: ActionState) -> int:
    from_lifecycle = _lifecycle_rank()
    return from_lifecycle.get(state, -1)


def _lifecycle_rank() -> dict[ActionState, int]:
    try:
        from solo_builder.strix_personal.lifecycle import _RANK
    except ImportError:  # vendored standalone
        from lifecycle import _RANK  # type: ignore
    return _RANK


def _below(state: ActionState) -> ActionState:
    """The highest state still permitted when ``state``'s own check failed.

    A failed check does not merely withhold its state — it caps the entry
    below it, because the linear rendering makes a higher state assert every
    lower one. Falls back to the state itself only if it is the floor, which
    cannot happen for the three signal-gated states.
    """
    try:
        from solo_builder.strix_personal.lifecycle import _PROGRESSION
    except ImportError:  # vendored standalone
        from lifecycle import _PROGRESSION  # type: ignore
    idx = _PROGRESSION.index(state)
    return _PROGRESSION[max(0, idx - 1)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _norm(text: str) -> str:
    """Whitespace-normalized call text.

    Reformatting is not a semantic change, so an indentation or line-wrap edit
    must not expire a true signal. A changed identifier, argument, or wrap
    state must.
    """
    return _WS.sub(" ", text).strip()


def _digest(parts: list[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def site_binding(candidate: Candidate) -> str:
    """Binding for a site-scoped claim (``test`` / ``evidence``).

    Includes ``governed``: a claim made about a wrapped call does not survive
    the wrap being removed.
    """
    return _digest(
        [
            candidate.capability_id,
            str(candidate.file).replace("\\", "/"),
            _norm(candidate.snippet),
            "governed" if candidate.governed else "ungoverned",
        ]
    )


def capability_binding(capability_id: str, candidates: list[Candidate]) -> str:
    """Binding for a repo-scoped claim (``bypass``).

    "No ungoverned sibling call exists" is a statement about *every* call site
    of the capability, so it must expire when any of them appears, disappears,
    or changes wrap state — including in a file the original check never read.
    """
    rows = sorted(
        f"{str(c.file).replace(chr(92), '/')}|{_norm(c.snippet)}|{int(c.governed)}"
        for c in candidates
        if c.capability_id == capability_id
    )
    return _digest([capability_id, str(len(rows)), *rows])


@dataclass(frozen=True)
class SignalRecord:
    """One recorded out-of-band observation.

    NOT evidence-shaped, by construction — see the module docstring. The
    absence of the evidence field names is asserted by
    ``_record_has_no_evidence_fields`` and pinned in the test suite.
    """

    kind: str
    capability_id: str
    file: str
    line: int
    binding: str
    passed: bool
    recorded_at: str = field(default_factory=_now)
    source: str = ""
    evidence_id: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.kind not in STATE_FOR_KIND:
            raise SignalError(f"unknown signal kind {self.kind!r} (expected one of {sorted(STATE_FOR_KIND)})")
        if not self.capability_id:
            raise SignalError("signal requires a capability_id")
        if not self.binding:
            raise SignalError("signal requires a binding — an unbound signal could float to any call site")
        if self.kind == "evidence" and self.passed and not self.evidence_id:
            raise SignalError(
                "a passing 'evidence' signal requires an evidence_id "
                "(VERIFIED names the signed record it rests on)"
            )

    # ---- identity -------------------------------------------------------
    @property
    def key(self) -> tuple[str, str, str]:
        """Supersession key: newest record for this key wins, pass or fail."""
        if self.kind in REPO_SCOPED_KINDS:
            return (self.kind, self.capability_id, "")
        return (self.kind, self.capability_id, self.binding)

    def to_signal(self) -> RuntimeSignal:
        return RuntimeSignal(
            kind=self.kind,
            passed=self.passed,
            evidence_id=self.evidence_id,
            detail=self.detail or f"recorded by {self.source or 'unknown'} at {self.recorded_at}",
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict) -> SignalRecord:
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            # Forward-compatible read would let an unrecognized field silently
            # change meaning. Refuse the row instead; the reader drops it.
            raise SignalError(f"unrecognized signal field(s): {sorted(unknown)}")
        return cls(**data)


def _record_has_no_evidence_fields() -> bool:
    """Self-check used by the disjointness test: a signal is not evidence."""
    forbidden = {"record_hash", "chain_seq", "prev_hash", "signature", "signing_key_id"}
    return not (forbidden & {f.name for f in fields(SignalRecord)})


class SignalJournal:
    """Append-only local journal of runtime signals.

    Plain JSONL under ``.solo/`` — the same unsigned, local, operator-owned
    class of file as the audit log's neighbours. It is not synced, not signed,
    and carries no authority of its own: every claim in it is re-checked
    against the current tree before it is allowed to move a lifecycle state.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @classmethod
    def for_root(cls, root: Path | str, *, override: str | None = None) -> SignalJournal:
        env = override or os.environ.get("STRIX_PERSONAL_SIGNALS")
        if env:
            return cls(Path(env))
        return cls(Path(root) / JOURNAL_RELPATH)

    # ---- write ----------------------------------------------------------
    def append(self, record: SignalRecord) -> SignalRecord:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(record.to_json() + "\n")
        except OSError as exc:  # pragma: no cover - environment dependent
            raise SignalError(f"cannot write signal journal at {self.path}: {exc}") from exc
        return record

    # ---- read -----------------------------------------------------------
    def read_all(self) -> list[SignalRecord]:
        """Every parseable record, in file order. Unparseable rows are skipped.

        A corrupt line must not take down the surface, and must not be
        interpreted charitably either — it is simply not a signal.
        """
        if not self.path.exists():
            return []
        out: list[SignalRecord] = []
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - environment dependent
            raise SignalError(f"cannot read signal journal at {self.path}: {exc}") from exc
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(SignalRecord.from_dict(json.loads(line)))
            except (json.JSONDecodeError, SignalError, TypeError):
                continue
        return out

    def current(self) -> list[SignalRecord]:
        """Newest record per supersession key — a later failure revokes a pass."""
        latest: dict[tuple[str, str, str], SignalRecord] = {}
        for rec in self.read_all():
            latest[rec.key] = rec
        return list(latest.values())


@dataclass
class DroppedSignal:
    """A signal that was present but not applied, and why."""

    record: SignalRecord
    reason: str


@dataclass
class ApplyOutcome:
    """What ``apply_signals`` did. Every input is accounted for.

    ``applied`` + ``dropped`` covers every current record, so a surface can
    state "3 signals applied, 1 expired" rather than showing a number that
    silently shrank.
    """

    applied: list[tuple[LifecycleEntry, SignalRecord]] = field(default_factory=list)
    dropped: list[DroppedSignal] = field(default_factory=list)

    @property
    def advanced(self) -> int:
        return len({id(e) for e, _ in self.applied})

    def summary(self) -> str:
        if not self.applied and not self.dropped:
            return "No runtime signals recorded — every state is from the static scan."
        bits = [f"{len(self.applied)} runtime signal(s) applied"]
        if self.dropped:
            expired = sum(1 for d in self.dropped if d.reason.startswith("expired"))
            if expired:
                bits.append(f"{expired} expired (the code they were recorded against changed)")
            other = len(self.dropped) - expired
            if other:
                bits.append(f"{other} not applicable")
        return " · ".join(bits) + "."


def apply_signals(
    report: ScanReport,
    records: list[SignalRecord],
    *,
    candidates: list[Candidate] | None = None,
) -> ApplyOutcome:
    """Replay ``records`` onto ``report``, promoting entries past ``WRAPPED``.

    The static invariant is untouched: this function never *invents* a state.
    It only replays facts another command observed, and only when the binding
    still matches the tree that was just scanned. Everything else is reported
    as dropped.

    Ordering is by lifecycle rank, so ``_MIN_PRECURSOR`` is satisfied by
    construction — an ``evidence`` signal on an entry that never got its
    ``bypass`` signal is refused by ``promote`` and surfaces as dropped, not as
    a leap from WRAPPED to VERIFIED.
    """
    outcome = ApplyOutcome()
    pool = candidates if candidates is not None else [e.candidate for e in report.entries]

    # Recompute bindings from the tree as it is NOW.
    cap_now: dict[str, str] = {}
    for cap in {c.capability_id for c in pool}:
        cap_now[cap] = capability_binding(cap, pool)

    by_cap: dict[str, list[LifecycleEntry]] = {}
    for entry in report.entries:
        by_cap.setdefault(entry.capability_id, []).append(entry)

    def _resolve(rec: SignalRecord) -> tuple[list[LifecycleEntry], str | None, str]:
        """Match a record to current entries and check its binding is fresh.

        One resolution path for passes and failures alike: a stale failure is
        exactly as expired as a stale pass, and must not impose a ceiling on
        code it was never recorded against.
        """
        if rec.kind in REPO_SCOPED_KINDS:
            # Repo-scoped: the claim covers the capability, so compare the
            # recorded binding against the whole capability's current shape.
            targets = by_cap.get(rec.capability_id, [])
            expected = cap_now.get(rec.capability_id)
            label = f"capability {rec.capability_id}"
        else:
            # Site-scoped: the binding IS the site's identity. Matching on it
            # rather than on file:line is what lets a signal follow its call
            # when unrelated code above it moves, and what stops it from
            # attaching to a different call that happens to land on that line.
            targets = [e for e in report.entries if site_binding(e.candidate) == rec.binding]
            expected = rec.binding if targets else None
            label = f"{rec.file}:{rec.line}"

        if not targets:
            return (
                [],
                (
                    f"expired: no current call site matches this {rec.kind} signal ({label}) — "
                    "the code it was recorded against changed or was removed"
                ),
                label,
            )
        if expected is not None and expected != rec.binding:
            return (
                [],
                (f"expired: the {label} call sites changed since this {rec.kind} signal was recorded"),
                label,
            )
        return targets, None, label

    # ---- pass 1: a recorded FAILURE lowers the ceiling ------------------
    #
    # The states render as one linear value, so `verified` on its own line
    # asserts everything below it as well. A failed check must therefore cap
    # the entry strictly BELOW the state that check gates — not merely fail to
    # raise it. Without this, a failing deny-scenario test sat invisible under
    # a VERIFIED produced by two unrelated signals, which is precisely the
    # single-green-badge collapse the lifecycle exists to prevent.
    ceilings: dict[int, tuple[ActionState, SignalRecord]] = {}
    for rec in records:
        if rec.passed:
            continue
        targets, why, label = _resolve(rec)
        if why is not None:
            outcome.dropped.append(DroppedSignal(rec, why))
            continue
        cap_state = _below(STATE_FOR_KIND[rec.kind])
        for entry in targets:
            prev = ceilings.get(id(entry))
            if prev is None or _RANK_OF(cap_state) < _RANK_OF(prev[0]):
                ceilings[id(entry)] = (cap_state, rec)
        outcome.dropped.append(
            DroppedSignal(
                rec,
                f"not applied: the recorded {rec.kind} check did not pass — "
                f"{label} is held at `{cap_state.value}` until it is re-run and passes",
            )
        )

    # ---- pass 2: replay the passing signals -----------------------------
    #
    # Ordered by lifecycle rank so ``_MIN_PRECURSOR`` is satisfied by
    # construction: an ``evidence`` signal on an entry that never got its
    # ``bypass`` signal is refused by ``promote`` and surfaces as dropped,
    # not as a leap from WRAPPED to VERIFIED.
    for rec in sorted((r for r in records if r.passed), key=lambda r: _KIND_RANK.get(r.kind, 99)):
        targets, why, label = _resolve(rec)
        if why is not None:
            outcome.dropped.append(DroppedSignal(rec, why))
            continue

        target_state = STATE_FOR_KIND[rec.kind]
        signal = rec.to_signal()
        moved = False
        for entry in targets:
            if entry.state == ActionState.SUPPRESSED:
                continue
            capped = ceilings.get(id(entry))
            if capped is not None and _RANK_OF(target_state) > _RANK_OF(capped[0]):
                outcome.dropped.append(
                    DroppedSignal(
                        rec,
                        f"not applied: {entry.location} is capped at `{capped[0].value}` by a "
                        f"failing {capped[1].kind} signal",
                    )
                )
                continue
            try:
                promote(entry, target_state, signal=signal)
                outcome.applied.append((entry, rec))
                moved = True
            except LifecycleError as exc:
                outcome.dropped.append(DroppedSignal(rec, f"not applied: {exc}"))
        if not moved and not any(d.record is rec for d in outcome.dropped):
            outcome.dropped.append(DroppedSignal(rec, f"not applied: no eligible entry for {label}"))

    return outcome


def record_bypass(
    *,
    capability_id: str,
    candidates: list[Candidate],
    passed: bool,
    source: str = "/strix-apply",
    detail: str = "",
) -> SignalRecord:
    """Build the repo-scoped ENFORCED signal from a bypass check."""
    first = next((c for c in candidates if c.capability_id == capability_id), None)
    return SignalRecord(
        kind="bypass",
        capability_id=capability_id,
        file=str(first.file).replace("\\", "/") if first else "",
        line=first.line if first else 0,
        binding=capability_binding(capability_id, candidates),
        passed=passed,
        source=source,
        detail=detail
        or ("all calls route through the boundary" if passed else "ungoverned sibling call remains"),
    )


def record_site(
    *,
    kind: str,
    candidate: Candidate,
    passed: bool,
    evidence_id: str | None = None,
    source: str = "/strix-test",
    detail: str = "",
) -> SignalRecord:
    """Build a site-scoped TESTED / VERIFIED signal for one call site."""
    return SignalRecord(
        kind=kind,
        capability_id=candidate.capability_id,
        file=str(candidate.file).replace("\\", "/"),
        line=candidate.line,
        binding=site_binding(candidate),
        passed=passed,
        evidence_id=evidence_id,
        source=source,
        detail=detail,
    )


__all__ = [
    "JOURNAL_RELPATH",
    "PRODUCER_FOR_KIND",
    "REPO_SCOPED_KINDS",
    "STATE_FOR_KIND",
    "ApplyOutcome",
    "DroppedSignal",
    "SignalError",
    "SignalJournal",
    "SignalRecord",
    "apply_signals",
    "capability_binding",
    "record_bypass",
    "record_site",
    "site_binding",
]
