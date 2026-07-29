#!/usr/bin/env python3
"""Strix Wire run approval — a single-use, expiring, bound execution grant.

WHY THIS EXISTS
---------------
The previous flow told the wrapping agent to write ``approval_granted=True``
directly into the customer's source tree. That converted one human decision
into *permanent, unattended authority*: every future run of that code — in
CI, in a cron job, on a teammate's laptop — silently satisfied the approval
gate that the human only ever cleared once, for one run, in front of a diff.

A bare boolean environment variable (``STRIX_WIRE_RUN_APPROVED=1``) is
better but still replayable: exported into a shell it is inherited by every
later process, survives into unrelated commands, and says nothing about
*which* action it approved.

This module implements the actual contract instead:

    A run approval authorizes ONE execution, of ONE capability, at ONE
    call site, with ONE approved patch, in ONE repository, for a bounded
    time window — and is destroyed by being used.

INVARIANTS
----------
RA-1  Source at rest grants no execution authority. Nothing committed to the
      customer's repository can satisfy the gate; the grant lives only in an
      out-of-tree record plus a secret that exists only in the approving
      shell's environment for the duration of one command.
RA-2  Single use. Consumption is an atomic claim (``os.rename``); a second
      consumer of the same token always loses, including under concurrency.
RA-3  Bound. Consumption re-derives the binding (repository root, capability,
      candidate, approved patch hash, mode) and refuses any mismatch — a
      token minted for candidate A cannot execute candidate B, and a token
      minted for patch A cannot authorize a modified patch B.
RA-4  Expiring. A token past ``expiresAt`` is refused and burned.
RA-5  Fail closed. A missing, malformed, unknown, expired, already-consumed,
      or mis-bound token yields ``False`` — never an exception that a caller
      might catch into a permissive default, and never a silent ``True``.
RA-6  Non-inherited. ``consume()`` removes the secret from ``os.environ`` as
      its first action, so child processes spawned by the wrapped operation
      never see it.
RA-7  A failed validation still burns the token. An attacker who can guess or
      replay does not get retries.

THE RECORD FILE NEVER CONTAINS THE SECRET
-----------------------------------------
The token is a 256-bit random secret held only by the approving shell. The
on-disk record is named for ``sha256(token)`` and stores only the binding.
Reading the repository — or the record directory — therefore does not let
you execute: you cannot invert the hash to recover the token.

USAGE
-----
Mint (the skill does this only after the human approves the run)::

    $ python3 approval.py mint --root . \
        --capability payment.refund \
        --candidate src/billing/refund.py:47 \
        --patch-hash <sha256-of-approved-diff> \
        --mode OFFLINE --ttl 900
    swa1.<runId>.<secret>

Consume (the wrapped call site does this, once, at run time)::

    import strix_wire_approval

    approval_granted=strix_wire_approval.consume(
        capability_id="payment.refund",
        candidate="src/billing/refund.py:47",
        patch_hash="<sha256-of-approved-diff>",
    )

This file is copied into the customer tree as ``strix_wire_approval.py``. It
is dependency-free (stdlib only) and safe to commit: it contains no secret
and, by RA-1, grants nothing on its own.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import secrets
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any

__all__ = [
    "ENV_VAR",
    "TOKEN_PREFIX",
    "ApprovalError",
    "binding_hash",
    "consume",
    "mint",
]

#: The environment variable carrying the single-use secret.
#:
#: Deliberately NOT the historical ``STRIX_WIRE_RUN_APPROVED``. That name held
#: a boolean; if an operator still has ``STRIX_WIRE_RUN_APPROVED=1`` exported
#: from an older session it must not satisfy this gate. A distinct name makes
#: the old value inert by construction rather than by our remembering to
#: check for it.
ENV_VAR = "STRIX_WIRE_RUN_APPROVAL"

TOKEN_PREFIX = "swa1"

#: Approvals live outside the source tree's normal review surface but inside
#: the workspace, so they are naturally scoped to one checkout.
APPROVAL_SUBDIR = Path(".strix") / "wire" / "approvals"

#: Hard ceiling on how long a run approval can be valid, regardless of what
#: ``--ttl`` asks for. An approval is meant to cover the next few seconds of
#: one supervised run, not a work session.
MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 900

VALID_MODES = frozenset({"SANDBOX", "OFFLINE", "PERSONAL"})


class ApprovalError(Exception):
    """Raised only by :func:`mint` (the operator-facing path).

    :func:`consume` never raises — see RA-5.
    """


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Deterministic JSON bytes. Mirrors the repo-wide canonical rules."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _root_identity(root: Path) -> str:
    """Stable identity for a repository root.

    ``realpath`` so that a symlinked or bind-mounted view of the same tree
    resolves to the same identity, and a *different* tree never does.
    """
    resolved = os.path.realpath(str(root))
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


def binding_hash(
    *,
    root: Path,
    capability_id: str,
    candidate: str,
    patch_hash: str,
    mode: str,
) -> str:
    """Content-address the five things an approval is bound to (RA-3)."""
    return hashlib.sha256(
        _canonical(
            {
                "bindingVersion": 1,
                "capabilityId": capability_id,
                "candidate": candidate,
                "mode": mode,
                "patchHash": patch_hash,
                "repoRootHash": _root_identity(root),
            }
        )
    ).hexdigest()


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _approvals_dir(root: Path) -> Path:
    return Path(root) / APPROVAL_SUBDIR


def _record_path(root: Path, token_id: str) -> Path:
    return _approvals_dir(root) / f"{token_id}.json"


def _consumed_path(root: Path, token_id: str) -> Path:
    return _approvals_dir(root) / f"{token_id}.consumed"


# ---------------------------------------------------------------------------
# Mint
# ---------------------------------------------------------------------------


def mint(
    *,
    root: Path,
    capability_id: str,
    candidate: str,
    patch_hash: str,
    mode: str = "OFFLINE",
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> tuple[str, dict[str, Any]]:
    """Create one single-use approval. Returns ``(token, record)``.

    The token is returned to the caller and never written to disk.
    """
    if mode not in VALID_MODES:
        raise ApprovalError(
            f"unknown mode {mode!r}; expected one of {sorted(VALID_MODES)}"
        )
    for name, value in (
        ("capability_id", capability_id),
        ("candidate", candidate),
        ("patch_hash", patch_hash),
    ):
        if not value or not str(value).strip():
            raise ApprovalError(f"{name} is required and must be non-empty")
    if ttl_seconds <= 0:
        raise ApprovalError("ttl must be positive")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ApprovalError(
            f"ttl {ttl_seconds}s exceeds the {MAX_TTL_SECONDS}s ceiling; a run "
            "approval covers one supervised run, not a session"
        )

    root = Path(root)
    if not root.is_dir():
        raise ApprovalError(f"root {root} is not a directory")

    issued_at = time.time() if now is None else now
    run_id = uuid.uuid4().hex
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    token = f"{TOKEN_PREFIX}.{run_id}.{secret}"

    record = {
        "schemaVersion": "strix.wire.run-approval.v1",
        "runId": run_id,
        "tokenId": _token_id(token),
        "bindingHash": binding_hash(
            root=root,
            capability_id=capability_id,
            candidate=candidate,
            patch_hash=patch_hash,
            mode=mode,
        ),
        # Descriptive echo so an operator auditing the directory can see what
        # was approved. Authority comes from bindingHash, never from these.
        "capabilityId": capability_id,
        "candidate": candidate,
        "patchHash": patch_hash,
        "mode": mode,
        "issuedAt": issued_at,
        "expiresAt": issued_at + ttl_seconds,
    }

    directory = _approvals_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    # Best effort: Windows and some mounts do not support POSIX modes. The
    # directory is a convenience for the operator, not the security boundary —
    # that is the token, which never touches disk.
    with contextlib.suppress(OSError):
        os.chmod(directory, stat.S_IRWXU)  # 0700

    path = _record_path(root, record["tokenId"])
    # O_EXCL: a token id collision must never silently overwrite a record.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh, sort_keys=True)
    return token, record


# ---------------------------------------------------------------------------
# Consume
# ---------------------------------------------------------------------------


def consume(
    *,
    capability_id: str,
    candidate: str,
    patch_hash: str,
    root: Path | str | None = None,
    mode: str | None = None,
    token: str | None = None,
    now: float | None = None,
) -> bool:
    """Redeem the run approval for exactly this action. Never raises (RA-5).

    Returns ``True`` only when a valid, unexpired, unconsumed token bound to
    precisely this ``(root, capability_id, candidate, patch_hash, mode)``
    was presented. Every other outcome — including internal error — is
    ``False``.
    """
    # RA-6: strip the secret from the environment before doing anything else,
    # so a child process spawned by the wrapped operation cannot inherit it,
    # and so an exception later cannot leave it lying around.
    env_token = os.environ.pop(ENV_VAR, None)
    presented = token if token is not None else env_token

    try:
        if not presented or not presented.startswith(TOKEN_PREFIX + "."):
            return False

        search_root = Path(root) if root is not None else Path.cwd()
        token_id = _token_id(presented)
        record_path = _record_path(search_root, token_id)
        claimed_path = _consumed_path(search_root, token_id)

        # RA-2 / RA-7: claim atomically FIRST. Whoever wins the rename owns
        # the token; everyone else — including a concurrent duplicate and a
        # retry after a failed validation — finds nothing.
        try:
            os.rename(record_path, claimed_path)
        except OSError:
            return False

        try:
            record = json.loads(claimed_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False

        if not isinstance(record, dict):
            return False
        if record.get("schemaVersion") != "strix.wire.run-approval.v1":
            return False
        if record.get("tokenId") != token_id:
            return False

        # RA-4: expiry.
        current = time.time() if now is None else now
        try:
            expires_at = float(record["expiresAt"])
        except (KeyError, TypeError, ValueError):
            return False
        if current >= expires_at:
            return False

        # RA-3: the binding must be re-derived from what the CALLER claims to
        # be doing, then compared. The record's own descriptive fields are
        # never trusted as the answer.
        expected_mode = mode if mode is not None else record.get("mode")
        if expected_mode not in VALID_MODES:
            return False
        derived = binding_hash(
            root=search_root,
            capability_id=capability_id,
            candidate=candidate,
            patch_hash=patch_hash,
            mode=expected_mode,
        )
        stored = record.get("bindingHash")
        return isinstance(stored, str) and secrets.compare_digest(derived, stored)
    except Exception:
        # RA-5: no failure mode reaches the caller as anything but "denied".
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="approval.py",
        description=(
            "Mint or inspect a single-use, expiring, bound Strix Wire run "
            "approval."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    m = sub.add_parser("mint", help="Mint one single-use run approval.")
    m.add_argument("--root", default=".", help="Repository root (default: cwd).")
    m.add_argument("--capability", required=True, help="Capability id.")
    m.add_argument(
        "--candidate", required=True, help="Call site, e.g. 'src/a.py:47'."
    )
    m.add_argument(
        "--patch-hash", required=True, help="sha256 of the approved diff."
    )
    m.add_argument("--mode", default="OFFLINE", choices=sorted(VALID_MODES))
    m.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    m.add_argument("--json", action="store_true", help="Emit JSON.")

    s = sub.add_parser(
        "status", help="Show approval records without consuming any."
    )
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "mint":
        try:
            token, record = mint(
                root=Path(args.root),
                capability_id=args.capability,
                candidate=args.candidate,
                patch_hash=args.patch_hash,
                mode=args.mode,
                ttl_seconds=args.ttl,
            )
        except (ApprovalError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"token": token, "record": record}, sort_keys=True))
        else:
            print(token)
            print(
                f"# single-use; expires in {args.ttl}s; bound to "
                f"{args.capability} @ {args.candidate}",
                file=sys.stderr,
            )
        return 0

    directory = _approvals_dir(Path(args.root))
    rows = []
    if directory.is_dir():
        for path in sorted(directory.iterdir()):
            if path.suffix not in (".json", ".consumed"):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {"error": "unreadable"}
            data["state"] = "consumed" if path.suffix == ".consumed" else "open"
            rows.append(data)
    if args.json:
        print(json.dumps({"approvals": rows}, sort_keys=True))
    else:
        if not rows:
            print("No run approvals on record.")
        for row in rows:
            print(
                f"{row.get('state', '?'):9} {row.get('capabilityId', '?')} "
                f"@ {row.get('candidate', '?')} (run {row.get('runId', '?')})"
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
