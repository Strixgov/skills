"""Customer-side helper that turns one mutation into a recorded Strix action.

This is the reference implementation copied into customer codebases by the
``/strix-wire`` Claude Code skill. The contract is small and intentionally
boring:

1. Caller hands us a ``capability_id``, the request ``payload`` (no secrets),
   and the operation to run.
2. We ask the Strix kernel whether the action is allowed
   (``POST /api/v1/evaluate``).
3. If allowed, we run the operation.
4. We POST an evidence record to ``POST /api/v1/evidence/ingest``
   (body: ``{"records": [...]}``) and return ``(result, evidence_id)``.

Evidence identity: the ingest endpoint's response carries batch counters
(``{ingested, skipped, quarantined, ...}``), NOT per-record ids — so this
helper GENERATES the ``evidence_id`` client-side (UUID v4), sends it inside
the record, and returns that same id after confirming the batch was
accepted. The record's dedup identity server-side is
``(tenantId, evidenceHash)``; we bind the generated ``evidence_id`` into the
hashed material so every execution produces a distinct evidence row
(a retry of the SAME record is idempotent — reported as ``skipped``).

Canonical bytes match ``solo_builder._canonical`` (sorted keys, no
whitespace, UTF-8) so hashes reproduce across the Python and TypeScript
helpers byte-for-byte.

This module only depends on the Python standard library plus ``requests``
(optional — falls back to ``urllib`` if ``requests`` is unavailable). It
deliberately does NOT pull in the full solo-builder-core package; the
helper has to fit in one file the customer can audit.

Environment:

- ``STRIX_API_KEY``    — required.
- ``STRIX_TENANT_ID``  — required.
- ``STRIX_API_URL``    — optional, defaults to ``https://www.strixgov.com``.
- ``STRIX_ACTOR``      — optional, identifies who ran the action.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

T = TypeVar("T")

_DEFAULT_URL = "https://www.strixgov.com"
_EVALUATE_PATH = "/api/v1/evaluate"
_EVIDENCE_PATH = "/api/v1/evidence/ingest"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class StrixError(RuntimeError):
    """Base class for any failure surfaced to the caller."""


class StrixDenied(StrixError):
    """The kernel refused the action. The operation was NOT run."""


class StrixApprovalRequired(StrixError):
    """The kernel asked for explicit approval (action-token flow)."""


class StrixUnreachable(StrixError):
    """The kernel could not be reached; we will not silently allow."""


# ---------------------------------------------------------------------------
# Canonical bytes — matches solo_builder._canonical.canonicalize
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> bytes:
    """Deterministic JSON bytes. Matches the byte contract in ADR-005 §4."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# Transport — requests if available, urllib otherwise.
# ---------------------------------------------------------------------------


def _post_json(url: str, body: dict, headers: dict, timeout: float = 5.0) -> dict:
    """POST JSON, return parsed JSON. Raises ``StrixUnreachable`` on any
    network / decode failure, ``StrixDenied`` on 4xx, ``StrixError`` on 5xx.

    Error messages are scrubbed of the Authorization header value so a
    credential can never leak into logs, exceptions, or CI comments.
    """
    payload = _canonicalize(body)
    full_headers = {"Content-Type": "application/json", **headers}

    def _scrub(text: str) -> str:
        auth = full_headers.get("Authorization", "")
        if auth:
            text = text.replace(auth, "Bearer <redacted>")
            token = auth.split(" ", 1)[-1]
            for t in (token, token.strip()):
                if t:
                    text = text.replace(t, "<redacted>")
        return text

    # Try requests first (preferred — better proxy / retry behavior).
    try:
        import requests

        try:
            resp = requests.post(url, data=payload, headers=full_headers, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            raise StrixUnreachable(f"network error: {_scrub(str(exc))}") from None
        status = resp.status_code
        text = resp.text
    except ImportError:
        # urllib fallback
        from urllib.error import HTTPError, URLError
        from urllib.request import Request, urlopen

        req = Request(url, data=payload, headers=full_headers, method="POST")
        try:
            with urlopen(req, timeout=timeout) as r:  # noqa: S310
                status = r.status
                text = r.read().decode("utf-8")
        except HTTPError as exc:
            status = exc.code
            text = exc.read().decode("utf-8", errors="replace")
        except (URLError, OSError) as exc:
            raise StrixUnreachable(f"network error: {_scrub(str(exc))}") from None

    if 400 <= status < 500:
        raise StrixDenied(f"strix {status}: {_scrub(text[:200])}")
    if status >= 500:
        raise StrixError(f"strix {status}: {_scrub(text[:200])}")
    try:
        return json.loads(text) if text else {}
    except json.JSONDecodeError:
        raise StrixUnreachable(f"strix returned non-JSON: {_scrub(text[:200])}") from None


# ---------------------------------------------------------------------------
# Evidence envelope — matches the /api/v1/evidence/ingest IngestRecord
# ---------------------------------------------------------------------------


def _post_evidence(
    *,
    base: str,
    headers: dict,
    timeout: float,
    capability_id: str,
    actor: str,
    tenant_id: str,
    payload_hash: str,
    result_hash: str | None,
    outcome: str,
    duration_ms: int,
    payload: dict[str, Any] | None = None,
) -> str:
    """POST one evidence record; return the client-generated evidence id.

    Server-side dedup identity is ``(tenantId, evidenceHash)``. Binding the
    fresh ``evidence_id`` into the hashed material makes every execution a
    distinct evidence row while keeping a retry of the SAME record
    idempotent (the server reports it as ``skipped``).

    ``payload`` is included only on the success path — the error path
    records hashes only, so params of a failed operation are never
    persisted.
    """
    evidence_id = str(uuid.uuid4())
    evidence_hash = _sha256_hex(
        _canonicalize(
            {
                "capabilityId": capability_id,
                "evidenceId": evidence_id,
                "outcome": outcome,
                "payloadHash": payload_hash,
                "resultHash": result_hash,
            }
        )
    )
    metadata: dict[str, Any] = {
        "payloadHash": payload_hash,
        "resultHash": result_hash,
        "outcome": outcome,
        "durationMs": duration_ms,
    }
    if payload is not None:
        metadata["payload"] = payload
    record = {
        "tenantId": tenant_id,
        "capabilityId": capability_id,
        "actorId": actor,
        "actorRole": "operator",
        "decision": "allow",
        "reason": (
            "governed action executed"
            if outcome == "ok"
            else "governed action failed after allow"
        ),
        "source": "strix-wire",
        "evidenceHash": evidence_hash,
        "evidenceId": evidence_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "metadata": metadata,
    }
    resp = _post_json(
        f"{base}{_EVIDENCE_PATH}",
        body={"records": [record]},
        headers=headers,
        timeout=timeout,
    )
    ingested = int(resp.get("ingested") or 0)
    skipped = int(resp.get("skipped") or 0)
    quarantined = int(resp.get("quarantined") or 0)
    if ingested + skipped < 1:
        raise StrixError(
            "evidence endpoint accepted 0 records "
            f"(ingested={ingested}, skipped={skipped}, quarantined={quarantined})"
        )
    return evidence_id


# ---------------------------------------------------------------------------
# The public surface
# ---------------------------------------------------------------------------


def governed_action(
    capability_id: str,
    payload: dict[str, Any],
    operation: Callable[[], T],
    *,
    actor: str | None = None,
    api_key: str | None = None,
    tenant_id: str | None = None,
    strix_url: str | None = None,
    timeout: float = 5.0,
) -> tuple[T, str]:
    """Govern an irreversible mutation. Returns ``(result, evidence_id)``.

    Args:
        capability_id: e.g. ``"payment.charge"``, ``"database.delete"``.
        payload:       Non-secret request parameters. Hashed and recorded.
        operation:     A zero-arg callable that performs the mutation.
        actor:         Who is running the action. Defaults to ``$STRIX_ACTOR``
                       or ``"solo-cli"``.
        api_key:       Defaults to ``$STRIX_API_KEY``.
        tenant_id:     Defaults to ``$STRIX_TENANT_ID``.
        strix_url:     Defaults to ``$STRIX_API_URL`` or the canonical host.
        timeout:       Per-request HTTP timeout in seconds.

    Raises:
        StrixDenied:            The kernel said no. The operation was NOT run.
        StrixApprovalRequired:  Out-of-band approval needed (token flow).
        StrixUnreachable:       Network failed. The operation was NOT run.
        Exception:              Anything the operation itself raises (after
                                we record a failure evidence record).
    """
    # Strip surrounding whitespace/newlines — a secret saved with a trailing
    # newline would otherwise produce an invalid (and credential-leaking)
    # Authorization header.
    key = (api_key or os.environ.get("STRIX_API_KEY") or "").strip()
    tenant = (tenant_id or os.environ.get("STRIX_TENANT_ID") or "").strip()
    if not key or not tenant:
        raise StrixError(
            "STRIX_API_KEY and STRIX_TENANT_ID must be set "
            "(pass them explicitly or export them in the environment)."
        )
    who = actor or os.environ.get("STRIX_ACTOR", "solo-cli")
    base = (strix_url or os.environ.get("STRIX_API_URL") or _DEFAULT_URL).rstrip("/")

    headers = {
        "Authorization": f"Bearer {key}",
        "X-Tenant-Id": tenant,
    }

    # 1. Pre-flight: ask the kernel for a decision. The payload hash rides
    #    in `context` — the kernel's public input boundary — so it lands on
    #    the decision's audit row (same channel the FailGuard verdict uses).
    payload_hash = _sha256_hex(_canonicalize(payload))
    decision = _post_json(
        f"{base}{_EVALUATE_PATH}",
        body={
            "capabilityId": capability_id,
            "actor": {"id": who, "role": "operator"},
            "context": {"payloadHash": payload_hash, "source": "strix-wire"},
        },
        headers=headers,
        timeout=timeout,
    )
    action = (decision.get("action") or decision.get("decision") or "").lower()
    if action == "deny":
        reason = decision.get("reason") or "policy denied"
        raise StrixDenied(f"{capability_id}: {reason}")
    if action in ("escalate", "require_approval"):
        raise StrixApprovalRequired(
            f"{capability_id} requires approval — run "
            f"`solo kernel approve {capability_id}` and retry."
        )
    if action != "allow":
        raise StrixError(f"unexpected kernel decision: {action!r}")

    # 2. Run the operation. Time it for the evidence record.
    started_at = time.time()
    try:
        result = operation()
    except Exception:  # noqa: BLE001
        # Best-effort: record the failure as evidence too, but don't mask
        # the original exception.
        with contextlib.suppress(StrixError):
            _post_evidence(
                base=base,
                headers=headers,
                timeout=timeout,
                capability_id=capability_id,
                actor=who,
                tenant_id=tenant,
                payload_hash=payload_hash,
                result_hash=None,
                outcome="error",
                duration_ms=int((time.time() - started_at) * 1000),
            )
        raise

    # 3. Record evidence.
    result_hash = _sha256_hex(_canonicalize(_to_jsonable(result)))
    evidence_id = _post_evidence(
        base=base,
        headers=headers,
        timeout=timeout,
        capability_id=capability_id,
        actor=who,
        tenant_id=tenant,
        payload_hash=payload_hash,
        result_hash=result_hash,
        outcome="ok",
        duration_ms=int((time.time() - started_at) * 1000),
        payload=payload,
    )
    return result, evidence_id


def _to_jsonable(obj: Any) -> Any:
    """Best-effort conversion of ``operation()`` results to JSON-serializable
    form for hashing. We only care about deterministic bytes, not perfect
    fidelity — so non-serializable parts collapse to their repr.
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if hasattr(obj, "to_dict"):
        try:
            return _to_jsonable(obj.to_dict())
        except Exception:  # noqa: BLE001
            pass
    if hasattr(obj, "__dict__"):
        try:
            return _to_jsonable(vars(obj))
        except Exception:  # noqa: BLE001
            pass
    return repr(obj)


__all__ = [
    "governed_action",
    "StrixError",
    "StrixDenied",
    "StrixApprovalRequired",
    "StrixUnreachable",
]
