"""Local Mode /strix-wire helper — offline, zero-account, zero-hosted-dependency.

Copied by the `/strix-wire` skill's **Offline Mode** path into a customer's
own source tree — the sibling of `governed_action.py` (Sandbox Mode). This
file has NO import of `solo_builder`; it must run standalone in ANY Python
project. Its one real dependency is the widely-available `cryptography`
package (Python's standard library has no Ed25519 *signing* primitive as of
3.12); see `StrixLocalKeyError` below for the honest failure when it's
missing — Local Mode never silently degrades to an unsigned record.

Local Mode's loop, spelled out completely differently from Sandbox Mode's:

  1. **normalize**  — `capability_id` + action name + non-secret params.
  2. **evaluate**   — a small, deterministic, OFFLINE policy table decides
                       ALLOW / DENY / REQUIRE_APPROVAL. There is no network
                       call and no hosted kernel — this is a real but
                       minimal, single-machine policy, not the Strix
                       kernel's multi-tenant PolicyEngine.
  3. **decide**     — DENY raises before anything else happens.
                       REQUIRE_APPROVAL raises unless `approval_granted=True`
                       (the caller's attestation that a human already
                       confirmed this exact run — the skill's own
                       "Proceed and run it" step).
  4. **authorize**  — implicit in step 3: getting past it IS the
                       authorization; there is no separate token to redeem.
  5. **execute**    — run `operation()` at most once.
  6. **record**     — build the canonical LOCAL_SIGNED_V1 payload, sign it
                       with a local Ed25519 key (generated on first run and
                       persisted under `.strix/keys/`, never printed or
                       logged), and append it to a hash-chained local file
                       under `.strix/evidence/`.

Zero network calls anywhere in this file. Zero Strix account. The receipt
this mints is independently verifiable with `solo strix-wire verify <path>`
(from any solo-builder-core checkout/install, or any from-scratch verifier
that implements the LOCAL_SIGNED_V1 contract — see
`docs/architecture/local-mode-strix-wire-v1.md`) — verification needs only
this project's `.strix/keys/registry.json` and the receipt itself; it
reaches no Strix server and needs no Strix credential.

**What this proves, precisely — read before wiring this into anything
consequential.** A LOCAL_SIGNED_V1 receipt is a `LOCAL_MACHINE_ASSERTION`:
it proves the holder of a specific local key produced a hash-chained,
tamper-evident record of one authorized, executed action. It does **not**
prove Strix-operated custody, centralized policy administration, or
protection against a machine owner who controls both this file and the key
it generates. Every verification result carries this trust-scope text
verbatim — never drop it when reporting a verdict to a user. See
`docs/architecture/local-mode-strix-wire-v1.md` in the solo-builder-core
repo for the full non-claims list and threat model.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
import warnings
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generic, TypeVar

T = TypeVar("T")

SCHEMA_VERSION = "local-receipt-v1"
# Additive-versioned sibling: the v1 field set PLUS `relianceRef` — minted
# if and only if the action declared a Local Reliance requirement (Local
# Reliance Gate v1; see docs/architecture/local-reliance-gate-v1.md in the
# solo-builder-core repo). Actions without one keep minting v1 byte-identically.
SCHEMA_VERSION_V2 = "local-receipt-v2"
# Additive-versioned sibling of SCHEMA_VERSION_V2: the v2 field set PLUS
# `chainRef` — minted if and only if the action ran through a ChainSession
# (Chained Governed Autonomy v1; see
# docs/architecture/chained-governed-autonomy-v1.md in solo-builder-core).
# Version selection is priority-ordered by presence, not field count: any
# populated chain_ref -> v3 (even with no reliance_ref at all — a
# non-attestation-gated chain's root step has a chainRef but nothing to
# require yet); else any populated reliance_ref -> v2; else v1.
SCHEMA_VERSION_V3 = "local-receipt-v3"
# Additive-versioned SIBLING of SCHEMA_VERSION_V3 (Chained Governed
# Autonomy v2; see docs/architecture/chained-governed-autonomy-v2.md in
# solo-builder-core): the v3 field set with `chainRef` REPLACED by
# `dagRef` — minted if and only if the action ran through a DagSession.
# v4 is NOT built on top of v3: a record is v3 XOR v4, never both.
# Version selection is priority-ordered by presence: any populated
# dag_ref -> v4; else any populated chain_ref -> v3; else any populated
# reliance_ref -> v2; else v1.
SCHEMA_VERSION_V4 = "local-receipt-v4"
RECORD_MODE = "LOCAL_SIGNED_V1"
DEFAULT_STATE_DIR = ".strix"
RELIANCE_POLICY_SCHEMA_VERSION = "local-reliance-policy-v1"

# Attestation-Gated Execution v1 — a second, independent artifact family the
# SAME reliance gate can require (see docs/architecture/
# attestation-gated-execution-v1.md in solo-builder-core). This helper only
# VERIFIES presented attestations as part of reliance evaluation; issuing one
# is the local issuer's job (``solo strix-wire attest issue`` or equivalent
# tooling), not this consumer-side orchestration helper.
ATTESTATION_SCHEMA_VERSION = "local-agent-attestation-v1"
ATTESTATION_RECORD_MODE = "LOCAL_AGENT_ATTESTATION_V1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StrixLocalError(RuntimeError):
    """Base class for any Local Mode failure."""


class StrixLocalDenied(StrixLocalError):
    """Local policy denied the action. The operation was NOT run."""


class StrixLocalApprovalRequired(StrixLocalError):
    """Local policy requires approval that was not granted. NOT run."""


class StrixLocalKeyError(StrixLocalError):
    """The local signing key is missing, corrupt, or mismatched — or the
    `cryptography` package is not installed. Never silently unsigned."""


class StrixLocalReceiptPersistenceError(StrixLocalError):
    """The operation ran successfully but the receipt could not be
    persisted. Raised AFTER the side effect already happened — the
    mutation is real; only the durable evidence trail failed to write."""


class StrixLocalRelianceDenied(StrixLocalError):
    """A declared reliance requirement did not independently re-verify.
    The operation was NOT run and no receipt was minted. The full layered
    result dict is on ``.reliance`` — surface WHICH requirement failed and
    why; never convert this into execution success."""

    def __init__(self, message: str, reliance: dict[str, Any]) -> None:
        super().__init__(message)
        self.reliance = reliance


class StrixLocalChainPredecessorUnverified(StrixLocalError):
    """Chained Governed Autonomy v1 — a caller supplied a ``chain_step``
    claiming a non-root predecessor but no independently-verified,
    satisfied ``"chain-predecessor"`` reliance requirement backs that
    claim. The operation was NOT run and no receipt was minted. Reachable
    only by calling ``governed_action_local`` directly with a hand-built
    ``LocalChainStep``, bypassing ``ChainSession`` (which always
    constructs a matching requirement for a non-root step)."""


class StrixLocalDagParentUnverified(StrixLocalError):
    """Chained Governed Autonomy v2 — a caller supplied a ``dag_step``
    declaring one or more parents, but at least one declared parent index
    has no independently-verified, satisfied ``"dag-parent-{i}"`` reliance
    requirement backing it (or the declared parent set contains a
    duplicate evidence id). The operation was NOT run and no receipt was
    minted. Reachable only by calling ``governed_action_local`` directly
    with a hand-built ``LocalDagStep``, bypassing ``DagSession`` (which
    always constructs a matching requirement per declared parent, and
    rejects duplicates at construction time)."""


# ---------------------------------------------------------------------------
# Canonical bytes — byte-identical to solo_builder._canonical.canonicalize
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _hash_canonical(obj: Any) -> str:
    return hashlib.sha256(_canonicalize(obj)).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ModuleNotFoundError as exc:  # pragma: no cover - environment-dependent
        raise StrixLocalKeyError(
            "the 'cryptography' package is required for Local Mode signing "
            "(pip install cryptography). Local Mode does NOT fall back to an "
            "unsigned record when it's missing — no first proof counts unless "
            "it's real (PROOF-1)."
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey


# ---------------------------------------------------------------------------
# Local key manager
# ---------------------------------------------------------------------------


class LocalSigningKey:
    __slots__ = ("created_at", "kid", "private_key_hex", "public_key_fingerprint", "public_key_hex")

    def __init__(
        self, kid: str, private_key_hex: str, public_key_hex: str, public_key_fingerprint: str, created_at: str
    ) -> None:
        self.kid = kid
        self.private_key_hex = private_key_hex
        self.public_key_hex = public_key_hex
        self.public_key_fingerprint = public_key_fingerprint
        self.created_at = created_at

    def __repr__(self) -> str:  # pragma: no cover - defensive: never print the key
        return f"LocalSigningKey(kid={self.kid!r})"


def _fingerprint(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()


def _kid_for(pub_bytes: bytes) -> str:
    return f"local-{_fingerprint(pub_bytes)[:16]}"


def resolve_public_key(state_dir: Path, kid: str) -> bytes | None:
    """Offline lookup used by verification — never trusts anything but the
    registry file on disk. Returns ``None`` for an unknown kid."""
    registry_path = state_dir / "keys" / "registry.json"
    if not registry_path.exists():
        return None
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    meta = data.get("keys", {}).get(kid)
    if not meta or not meta.get("publicKeyHex"):
        return None
    try:
        return bytes.fromhex(meta["publicKeyHex"])
    except ValueError:
        return None


def generate_or_load_key(state_dir: Path) -> LocalSigningKey:
    """Idempotent: return the existing current key, generating one (and a
    ``.gitignore`` for the private key files) on first run. Raises
    :class:`StrixLocalKeyError` on any corruption or mismatch rather than
    silently regenerating — a tampered/deleted key file is a fault."""
    Ed25519PrivateKey, _ = _require_cryptography()
    keys_dir = state_dir / "keys"
    registry_path = keys_dir / "registry.json"

    if registry_path.exists():
        try:
            data = json.loads(registry_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise StrixLocalKeyError(f"corrupt key registry at {registry_path}: {exc}") from exc
        kid = data.get("currentKid")
        if kid:
            meta = data.get("keys", {}).get(kid)
            if meta is None:
                raise StrixLocalKeyError(f"registry names current kid {kid!r} but has no metadata for it")
            key_path = keys_dir / f"{kid}.key"
            if not key_path.exists():
                raise StrixLocalKeyError(
                    f"private key file missing for kid {kid!r} at {key_path} — it was deleted or "
                    "moved. Historical receipts under this kid still verify from the registry's "
                    "public key; remove 'currentKid' from registry.json to mint a fresh signing key."
                )
            raw = key_path.read_text(encoding="utf-8").strip()
            try:
                priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
            except Exception as exc:  # noqa: BLE001
                raise StrixLocalKeyError(f"private key file for kid {kid!r} is corrupt or invalid: {exc}") from exc
            pub_hex = priv.public_key().public_bytes_raw().hex()
            if pub_hex != meta.get("publicKeyHex"):
                raise StrixLocalKeyError(
                    f"private key file for kid {kid!r} does not match its registry public key — "
                    "possible tamper. Refusing to sign."
                )
            return LocalSigningKey(kid, raw, pub_hex, _fingerprint(bytes.fromhex(pub_hex)), str(meta.get("createdAt", "")))

    # First run (or no currentKid yet): generate.
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    kid = _kid_for(bytes.fromhex(pub_hex))
    created_at = _iso_now()

    keys_dir.mkdir(parents=True, exist_ok=True)
    key_path = keys_dir / f"{kid}.key"
    key_path.write_text(priv_hex, encoding="utf-8")
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        warnings.warn(f"could not set restrictive (0600) permissions on {key_path}", stacklevel=2)

    data = {
        "currentKid": kid,
        "keys": {
            kid: {
                "publicKeyHex": pub_hex,
                "publicKeyFingerprint": _fingerprint(bytes.fromhex(pub_hex)),
                "createdAt": created_at,
                "status": "active",
                "algorithm": "ed25519",
            }
        },
    }
    if registry_path.exists():
        try:
            existing = json.loads(registry_path.read_text(encoding="utf-8"))
            existing.setdefault("keys", {}).update(data["keys"])
            existing["currentKid"] = kid
            data = existing
        except ValueError:
            pass  # corrupt existing registry — overwrite with a fresh one rather than crash
    tmp = registry_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(registry_path)

    gitignore = keys_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*.key\n", encoding="utf-8")

    return LocalSigningKey(kid, priv_hex, pub_hex, _fingerprint(bytes.fromhex(pub_hex)), created_at)


# ---------------------------------------------------------------------------
# Local policy — deterministic, offline (mirrors solo_builder's default rules)
# ---------------------------------------------------------------------------

#: capability_id -> (risk, approval_threshold | None). Every entry the
#: strix-wire scanner can emit is, by construction, an irreversible
#: mutation, so the default policy requires local confirmation
#: (REQUIRE_APPROVAL) for everything except LOW-risk reads. This is NOT the
#: hosted Strix kernel's policy engine — a minimal, single-machine stand-in.
DEFAULT_POLICY_RULES: dict[str, tuple[str, float | None]] = {
    "payment.charge": ("HIGH", None),
    "payment.refund": ("HIGH", 500.0),
    "database.delete": ("HIGH", None),
    "database.update": ("HIGH", None),
    "database.create": ("MEDIUM", None),
    "storage.delete": ("HIGH", None),
    "storage.write": ("MEDIUM", None),
    "email.send": ("MEDIUM", None),
    "sms.send": ("MEDIUM", None),
    "filesystem.delete": ("HIGH", None),
    "database.migrate": ("CRITICAL", None),
    "infra.apply": ("CRITICAL", None),
    "infra.destroy": ("CRITICAL", None),
    "iam.grant": ("CRITICAL", None),
    "iam.revoke": ("CRITICAL", None),
    "flag.flip": ("MEDIUM", None),
    "data.export": ("HIGH", None),
    "message.publish": ("MEDIUM", None),
    "ai.tool_use": ("HIGH", None),
    "ai.agent_run": ("HIGH", None),
}

_AUTO_ALLOW_RISK = {"LOW"}


def policy_ref(rules: Mapping[str, tuple[str, float | None]] = DEFAULT_POLICY_RULES, version: str = "local-policy-v1") -> dict[str, str]:
    version_hash = _hash_canonical(
        {"rules": {cap: {"risk": r, "approvalThreshold": t} for cap, (r, t) in sorted(rules.items())}}
    )
    return {"version": version, "hash": version_hash}


def evaluate_policy(
    capability_id: str, params: Mapping[str, Any], rules: Mapping[str, tuple[str, float | None]] = DEFAULT_POLICY_RULES
) -> tuple[str, str]:
    """Return ``(raw_decision, reason)``: one of ``"ALLOW"``, ``"DENY"``,
    ``"REQUIRE_APPROVAL"``. An unrecognized capability id always requires
    approval — never auto-allows an unknown action."""
    rule = rules.get(capability_id)
    if rule is None:
        return "REQUIRE_APPROVAL", f"capability {capability_id!r} has no local policy rule — approval required"
    risk, threshold = rule
    if risk in _AUTO_ALLOW_RISK:
        return "ALLOW", f"{risk} risk — auto-allowed under local policy"
    if threshold is not None:
        amount = params.get("amount")
        if isinstance(amount, (int, float)) and amount >= threshold:
            return "REQUIRE_APPROVAL", f"amount {amount} >= approval threshold {threshold} for {capability_id}"
    return "REQUIRE_APPROVAL", f"{risk} risk action — local confirmation required before execution"


# ---------------------------------------------------------------------------
# Local Reliance Gate v1 — verified prior proof as an execution precondition
# (mirrors solo_builder.strix_wire_local_reliance; byte-identical policyHash,
# statuses, reason codes, and detail strings — cross-language conformance
# with governedAction.local.ts depends on it)
# ---------------------------------------------------------------------------

_ALLOWED_DECISIONS = ("ALLOW", "REQUIRE_APPROVAL_GRANTED")
_ALLOWED_EXECUTION_STATUSES = ("SUCCEEDED", "FAILED")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_RELIANCE_DETAILS = {
    "RECORD_MODE_DISALLOWED": "the receipt recordMode is not an allowed receipt type for this requirement",
    "UNSUPPORTED_SCHEMA_VERSION": "the receipt schemaVersion is not supported by this verifier",
    "EVIDENCE_HASH_INVALID": "evidenceHash does not match the recomputed canonical hash",
    "CHAIN_INVALID": "proofChainHash does not match the recomputed value",
    "SIGNATURE_MISSING": "no signature present on the receipt",
    "SIGNATURE_INVALID": "signature does not verify against the resolved public key",
    "KEY_UNRESOLVED": "signingKeyId does not resolve in the presented key registry",
    "CAPABILITY_MISMATCH": "receipt capabilityId does not match the required capability",
    "DECISION_MISMATCH": "receipt decision is not an accepted decision for this requirement",
    "EXECUTION_STATUS_MISMATCH": "receipt executionStatus does not match the required execution status",
    "WORKSPACE_MISMATCH": "receipt workspaceFingerprint does not match the protected action's workspace",
    "SIGNING_KEY_MISMATCH": "receipt signingKeyId is not a key in this workspace's local registry",
    "PARAMS_HASH_MISMATCH": "receipt paramsHash does not match the required subject binding",
    "TIMESTAMP_UNPARSEABLE": "receipt createdAt is not a strict RFC3339 Z-suffixed timestamp",
    "RECEIPT_FUTURE_DATED": "receipt createdAt is in the future",
}

# Attestation-Gated Execution v1 reason codes + details — identical strings
# to solo_builder.strix_wire_local_reliance's _ATTESTATION_DETAILS. Public
# contract; additive only, never rename/reuse.
_ATTESTATION_DETAILS = {
    "ATTESTATION_MALFORMED": "the presented attestation is not a well-formed JSON object with a payload",
    "ATTESTATION_SCHEMA_UNSUPPORTED": "the attestation recordMode/schemaVersion is not supported by this verifier",
    "ATTESTATION_HASH_MISMATCH": "attestationHash does not match the recomputed canonical hash",
    "ATTESTATION_SIGNATURE_INVALID": (
        "attestation signature is missing or does not verify against the resolved issuer public key"
    ),
    "ATTESTATION_KEY_UNKNOWN": "signingKeyId does not resolve in the presented issuer key registry",
    "ATTESTATION_ISSUER_NOT_ALLOWED": "attestation issuerId is not on this requirement's permitted-issuer allow-list",
    "ATTESTATION_AGENT_MISMATCH": "attestation agentId does not match the required requesting agent identity",
    "ATTESTATION_CLASS_MISMATCH": "attestation agentClass does not match the required class",
    "ATTESTATION_WORKSPACE_MISMATCH": "attestation workspaceFingerprint does not match the protected action's workspace",
    "ATTESTATION_SCOPE_MISMATCH": "attestation capabilityScopes does not include the protected capability",
    "ATTESTATION_NOT_YET_VALID": "attestation issuedAt is in the future",
    "ATTESTATION_EXPIRED": "attestation has expired",
    "ATTESTATION_REVOKED": "attestation has been revoked",
    "ATTESTATION_UNVERIFIABLE": "attestation could not be verified for a reason this gate could not classify further",
}


def _scope_matches(pattern: str, capability_id: str) -> bool:
    """Exact match, or a ``"<prefix>.*"`` wildcard matching any capability
    strictly under that prefix. Mirrors
    solo_builder.strix_wire_local_attestation.scope_matches byte-for-byte."""
    if pattern == capability_id:
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        return capability_id.startswith(prefix + ".")
    return False


def _resolve_attestation_issuer_key(state_dir: Path, kid: str) -> bytes | None:
    """Offline lookup for the LOCAL attestation issuer's key registry,
    rooted at ``<state_dir>/attestation/issuer/keys/registry.json`` —
    deliberately separate from the workspace's own governed-action signing
    key registry at ``<state_dir>/keys/registry.json`` (the issuer is a
    distinct local authority, mirrors
    solo_builder.strix_wire_local_attestation.issuer_key_store)."""
    return resolve_public_key(state_dir / "attestation" / "issuer", kid)


def _is_attestation_revoked(state_dir: Path, attestation_id: str) -> bool:
    """Mirrors solo_builder.strix_wire_local_attestation.LocalAttestationRevocationList.
    A missing revocation list file means nothing is revoked; a corrupt one
    is a loud fault (never silently treated as empty)."""
    path = state_dir / "attestation" / "revoked.json"
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise StrixLocalError(f"corrupt attestation revocation list at {path}: {exc}") from exc
    revoked = data.get("revoked") if isinstance(data, dict) else None
    if not isinstance(revoked, dict):
        raise StrixLocalError(f"malformed attestation revocation list at {path}: missing 'revoked'")
    return attestation_id in revoked


def _verify_local_attestation_crypto(record: Any, state_dir: Path) -> dict[str, Any]:
    """Mirror of solo_builder.strix_wire_local_attestation.verify_attestation_crypto.
    Recomputes everything, trusts nothing stored. Never raises for bad input."""
    out: dict[str, Any] = {
        "hashValid": False,
        "signaturePresent": False,
        "signatureValid": None,
        "keyResolved": False,
        "recordMode": None,
        "status": "UNVERIFIABLE",
        "cryptoCode": None,
    }
    payload = record.get("payload") if isinstance(record, dict) else None
    if not isinstance(payload, dict):
        out["cryptoCode"] = "ATTESTATION_MALFORMED"
        return out

    record_mode = payload.get("recordMode")
    schema_version = payload.get("schemaVersion")
    out["recordMode"] = record_mode if isinstance(record_mode, str) else None
    if record_mode != ATTESTATION_RECORD_MODE or schema_version != ATTESTATION_SCHEMA_VERSION:
        out["cryptoCode"] = "ATTESTATION_SCHEMA_UNSUPPORTED"
        return out

    core = {k: v for k, v in payload.items() if k != "attestationHash"}
    out["hashValid"] = _hash_canonical(core) == payload.get("attestationHash")

    signature_hex = record.get("signature")
    out["signaturePresent"] = isinstance(signature_hex, str) and bool(signature_hex)

    kid = payload.get("signingKeyId")
    pub = _resolve_attestation_issuer_key(state_dir, kid) if isinstance(kid, str) else None
    out["keyResolved"] = pub is not None
    if out["signaturePresent"] and pub is not None:
        try:
            _, Ed25519PublicKey = _require_cryptography()
            Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature_hex), _canonicalize(payload))
            out["signatureValid"] = True
        except Exception:  # noqa: BLE001 - any parse/crypto failure is a signature failure
            out["signatureValid"] = False

    if not out["hashValid"]:
        out["status"], out["cryptoCode"] = "INVALID", "ATTESTATION_HASH_MISMATCH"
    elif not out["signaturePresent"]:
        out["status"], out["cryptoCode"] = "INVALID", "ATTESTATION_SIGNATURE_INVALID"
    elif not out["keyResolved"]:
        out["status"], out["cryptoCode"] = "UNVERIFIABLE", "ATTESTATION_KEY_UNKNOWN"
    elif not out["signatureValid"]:
        out["status"], out["cryptoCode"] = "INVALID", "ATTESTATION_SIGNATURE_INVALID"
    else:
        out["status"], out["cryptoCode"] = "VERIFIED", None
    return out


class RelianceRequirement:
    """One required prior proof. Two artifact families dispatch off
    ``receipt_type``: the original ``RECORD_MODE`` (LOCAL_SIGNED_V1
    receipts) and, as of Attestation-Gated Execution v1,
    ``ATTESTATION_RECORD_MODE`` (LOCAL_AGENT_ATTESTATION_V1 identity
    attestations) — evaluated by the SAME gate, never a parallel
    authorization system. For a LOCAL_SIGNED_V1 requirement: independently
    re-verified at gate time — hash, chain link, signature, key resolution
    — plus content bindings (capability / decision / execution status /
    workspace / signing key / params hash) and freshness. Fail-closed at
    declaration: unsupported semantics raise here, never silently allow."""

    __slots__ = (
        "agent_id_from_request",
        "allow_unresolved_key",
        "capability_id",
        "capability_scope_must_include_subject",
        "decisions",
        "execution_status",
        "expected_agent_id",
        "max_age_seconds",
        "params_hash",
        "permitted_issuers",
        "receipt_path",
        "receipt_type",
        "required_class",
        "requirement_id",
        "same_signing_key",
        "same_workspace",
    )

    def __init__(
        self,
        capability_id: str,
        receipt_path: str | Path,
        *,
        requirement_id: str = "",
        receipt_type: str = RECORD_MODE,
        decisions: tuple[str, ...] = _ALLOWED_DECISIONS,
        execution_status: str = "SUCCEEDED",
        max_age_seconds: int | None = None,
        same_workspace: bool = True,
        same_signing_key: bool = False,
        allow_unresolved_key: bool = False,
        params_hash: str | None = None,
        agent_id_from_request: bool = False,
        expected_agent_id: str | None = None,
        required_class: str | None = None,
        permitted_issuers: tuple[str, ...] = (),
        capability_scope_must_include_subject: bool = False,
    ) -> None:
        if receipt_type not in (RECORD_MODE, ATTESTATION_RECORD_MODE):
            raise StrixLocalError(
                f"unsupported receiptType {receipt_type!r} — Local Reliance Gate v1 accepts only "
                f"{RECORD_MODE!r} or {ATTESTATION_RECORD_MODE!r}"
            )
        is_attestation = receipt_type == ATTESTATION_RECORD_MODE
        if not is_attestation and (not capability_id or not str(capability_id).strip()):
            raise StrixLocalError("reliance requirement capability_id must be a non-empty string")
        if not decisions or any(d not in _ALLOWED_DECISIONS for d in decisions):
            raise StrixLocalError(f"reliance decisions must be a non-empty subset of {_ALLOWED_DECISIONS}")
        if execution_status not in _ALLOWED_EXECUTION_STATUSES:
            raise StrixLocalError(f"reliance execution_status must be one of {_ALLOWED_EXECUTION_STATUSES}")
        if max_age_seconds is not None and (
            isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0
        ):
            raise StrixLocalError("reliance max_age_seconds must be a positive integer when set")
        if params_hash is not None and (
            not isinstance(params_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", params_hash)
        ):
            raise StrixLocalError("reliance params_hash must be a 64-char lowercase sha256 hex string")

        attestation_fields_set = (
            agent_id_from_request
            or expected_agent_id is not None
            or required_class is not None
            or bool(permitted_issuers)
            or capability_scope_must_include_subject
        )
        if not is_attestation:
            if attestation_fields_set:
                raise StrixLocalError(
                    "agentIdFromRequest/expectedAgentId/requiredClass/permittedIssuers/"
                    "capabilityScopeMustIncludeSubject are attestation-only fields — set receiptType "
                    f"to {ATTESTATION_RECORD_MODE!r} to use them"
                )
        else:
            if same_signing_key:
                raise StrixLocalError("sameSigningKey has no meaning on an attestation requirement")
            if params_hash is not None:
                raise StrixLocalError("paramsHash has no meaning on an attestation requirement")
            if agent_id_from_request and expected_agent_id is not None:
                raise StrixLocalError("agentIdFromRequest and expectedAgentId are mutually exclusive")
            if not permitted_issuers:
                raise StrixLocalError(
                    "an attestation requirement must declare at least one permittedIssuers entry"
                )

        self.capability_id = capability_id
        self.receipt_path = str(receipt_path)
        self.requirement_id = requirement_id
        self.receipt_type = receipt_type
        self.decisions = tuple(decisions)
        self.execution_status = execution_status
        self.max_age_seconds = max_age_seconds
        self.same_workspace = bool(same_workspace)
        self.same_signing_key = bool(same_signing_key)
        self.allow_unresolved_key = bool(allow_unresolved_key)
        self.params_hash = params_hash
        self.agent_id_from_request = bool(agent_id_from_request)
        self.expected_agent_id = expected_agent_id
        self.required_class = required_class
        self.permitted_issuers = tuple(permitted_issuers)
        self.capability_scope_must_include_subject = bool(capability_scope_must_include_subject)

    def to_canonical_dict(self) -> dict[str, Any]:
        # Semantic view only — receipt_path is a locator, never hashed.
        if self.receipt_type == ATTESTATION_RECORD_MODE:
            return {
                "requirementId": self.requirement_id,
                "artifactType": self.receipt_type,
                "agentIdFromRequest": self.agent_id_from_request,
                "expectedAgentId": self.expected_agent_id,
                "requiredClass": self.required_class,
                "permittedIssuers": sorted(self.permitted_issuers),
                "capabilityScopeMustIncludeSubject": self.capability_scope_must_include_subject,
                "sameWorkspace": self.same_workspace,
                "maxAgeSeconds": self.max_age_seconds,
                "allowUnresolvedKey": self.allow_unresolved_key,
            }
        return {
            "requirementId": self.requirement_id,
            "capabilityId": self.capability_id,
            "receiptType": self.receipt_type,
            "decisions": sorted(self.decisions),
            "executionStatus": self.execution_status,
            "maxAgeSeconds": self.max_age_seconds,
            "sameWorkspace": self.same_workspace,
            "sameSigningKey": self.same_signing_key,
            "allowUnresolvedKey": self.allow_unresolved_key,
            "paramsHash": self.params_hash,
        }


def _chain_ref_shape_valid(chain_ref: Any) -> bool:
    """Chained Governed Autonomy v1 structural shape check: chainRef must be
    a dict with chainId/stepIndex, and stepIndex 0 <-> no predecessor claim
    (both directions), mirroring the reference engine's verify_record."""
    if not isinstance(chain_ref, dict):
        return False
    if not isinstance(chain_ref.get("chainId"), str) or not isinstance(chain_ref.get("stepIndex"), int):
        return False
    step_index = chain_ref.get("stepIndex")
    prev_id = chain_ref.get("previousStepEvidenceId")
    prev_hash = chain_ref.get("previousStepEvidenceHash")
    if step_index == 0:
        return prev_id is None and prev_hash is None
    return prev_id is not None and prev_hash is not None


def _dag_ref_well_formed(dag_ref: Any) -> bool:
    """Chained Governed Autonomy v2 structural shape check: dagRef must be
    a dict with dagId/stepIndex and a parentEvidenceRefs list of
    {evidenceId, evidenceHash} objects with no duplicate evidenceId —
    mirroring the reference engine's verify_record. Unlike chainRef,
    stepIndex == 0 does NOT imply empty parentEvidenceRefs (a DAG can have
    multiple independent source nodes at different stepIndex values)."""
    if not isinstance(dag_ref, dict):
        return False
    if not isinstance(dag_ref.get("dagId"), str) or not isinstance(dag_ref.get("stepIndex"), int):
        return False
    parent_refs = dag_ref.get("parentEvidenceRefs")
    if not isinstance(parent_refs, list):
        return False
    if not all(
        isinstance(r, dict) and isinstance(r.get("evidenceId"), str) and isinstance(r.get("evidenceHash"), str)
        for r in parent_refs
    ):
        return False
    parent_ids = [r["evidenceId"] for r in parent_refs]
    return len(set(parent_ids)) == len(parent_ids)


def _verify_local_record_for_reliance(record: Any, state_dir: Path) -> dict[str, Any]:
    """Minimal mirror of solo-builder-core's ``verify_record``: recompute
    everything, trust nothing stored. Returns the layered booleans + the
    three-state status. Never raises for bad input."""
    out = {
        "hashValid": False,
        "chainValid": False,
        "signaturePresent": False,
        "signatureValid": None,
        "keyResolved": False,
        "status": "UNVERIFIABLE",
        "cryptoCode": "UNSUPPORTED_SCHEMA_VERSION",
    }
    payload = record.get("payload") if isinstance(record, dict) else None
    if not isinstance(payload, dict):
        out["cryptoCode"] = "RECEIPT_MALFORMED"
        return out
    record_mode = payload.get("recordMode")
    schema_version = payload.get("schemaVersion")
    if record_mode != RECORD_MODE:
        out["cryptoCode"] = "RECORD_MODE_DISALLOWED"
        return out
    if schema_version not in (SCHEMA_VERSION, SCHEMA_VERSION_V2, SCHEMA_VERSION_V3, SCHEMA_VERSION_V4):
        out["cryptoCode"] = "UNSUPPORTED_SCHEMA_VERSION"
        return out

    core = {k: v for k, v in payload.items() if k not in ("evidenceHash", "proofChainHash")}
    out["hashValid"] = _hash_canonical(core) == payload.get("evidenceHash")
    out["chainValid"] = (
        _hash_canonical(
            {
                "evidenceHash": payload.get("evidenceHash"),
                "prevHash": payload.get("prevHash"),
                "chainSeq": payload.get("chainSeq"),
            }
        )
        == payload.get("proofChainHash")
    )
    signature_hex = record.get("signature")
    out["signaturePresent"] = isinstance(signature_hex, str) and bool(signature_hex)

    kid = payload.get("signingKeyId")
    pub = resolve_public_key(state_dir, kid) if isinstance(kid, str) else None
    out["keyResolved"] = pub is not None
    if out["signaturePresent"] and pub is not None:
        try:
            _, Ed25519PublicKey = _require_cryptography()
            Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature_hex), _canonicalize(payload))
            out["signatureValid"] = True
        except Exception:  # noqa: BLE001 - any parse/crypto failure is a signature failure
            out["signatureValid"] = False

    # Version/field cross-checks (a v1 smuggling relianceRef, a v2 without
    # one, a non-v3 smuggling chainRef, a v3 without a structured one, a
    # non-v4 smuggling dagRef, or a v4 without a structured one, is
    # structurally INVALID for its declared version).
    structural_invalid = (
        (schema_version == SCHEMA_VERSION and "relianceRef" in payload)
        or (schema_version == SCHEMA_VERSION_V2 and not isinstance(payload.get("relianceRef"), dict))
        or (schema_version in (SCHEMA_VERSION, SCHEMA_VERSION_V2) and "chainRef" in payload)
        or (schema_version == SCHEMA_VERSION_V3 and not _chain_ref_shape_valid(payload.get("chainRef")))
        or (schema_version in (SCHEMA_VERSION, SCHEMA_VERSION_V2, SCHEMA_VERSION_V3) and "dagRef" in payload)
        or (schema_version == SCHEMA_VERSION_V4 and "chainRef" in payload)
        or (
            schema_version == SCHEMA_VERSION_V4
            and "chainRef" not in payload
            and not _dag_ref_well_formed(payload.get("dagRef"))
        )
    )

    if not out["hashValid"]:
        out["status"], out["cryptoCode"] = "INVALID", "EVIDENCE_HASH_INVALID"
    elif not out["chainValid"]:
        out["status"], out["cryptoCode"] = "INVALID", "CHAIN_INVALID"
    elif structural_invalid:
        out["status"], out["cryptoCode"] = "INVALID", "UNSUPPORTED_SCHEMA_VERSION"
    elif not out["signaturePresent"]:
        out["status"], out["cryptoCode"] = "INVALID", "SIGNATURE_MISSING"
    elif not out["keyResolved"]:
        out["status"], out["cryptoCode"] = "UNVERIFIABLE", "KEY_UNRESOLVED"
    elif not out["signatureValid"]:
        out["status"], out["cryptoCode"] = "INVALID", "SIGNATURE_INVALID"
    else:
        out["status"], out["cryptoCode"] = "VERIFIED", None
    return out


def _registry_kids(state_dir: Path) -> list[str] | None:
    registry_path = state_dir / "keys" / "registry.json"
    if not registry_path.exists():
        return None
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    keys = data.get("keys")
    return list(keys.keys()) if isinstance(keys, dict) else None


def _reliance_policy_hash(capability_id: str, requirements: list[RelianceRequirement]) -> str:
    return _hash_canonical(
        {
            "schemaVersion": RELIANCE_POLICY_SCHEMA_VERSION,
            "relianceId": f"inline:{capability_id}",
            "version": 1,
            "subject": {"capabilityId": capability_id},
            "onFailure": "DENY",
            "threshold": None,
            "requires": [r.to_canonical_dict() for r in requirements],
        }
    )


def _unmet_requirement(req: RelianceRequirement, status: str, reason: str) -> dict[str, Any]:
    out = {
        "requirementId": req.requirement_id,
        "evidenceId": None,
        "evidenceHash": None,
        "recordMode": None,
        "hashValid": False,
        "chainValid": False,
        "signaturePresent": False,
        "signatureValid": None,
        "keyResolved": False,
        "capabilityMatched": False,
        "workspaceMatched": False,
        "decisionMatched": False,
        "executionStatusMatched": False,
        "signingKeyMatched": False,
        "paramsHashMatched": False,
        "freshnessValid": False,
        "status": status,
        "satisfied": False,
        "reason": reason,
    }
    if req.receipt_type == ATTESTATION_RECORD_MODE:
        out["artifactType"] = ATTESTATION_RECORD_MODE
        out["attestationAgentId"] = None
        out["attestationAgentClass"] = None
        out["attestationIssuerId"] = None
        out["scopeMatched"] = None
    return out


def evaluate_reliance_local(
    capability_id: str,
    requirements: list[RelianceRequirement],
    *,
    workspace_root: Path,
    state_dir: Path,
    now: datetime | None = None,
    requesting_agent_id: str | None = None,
) -> dict[str, Any]:
    """Pure-ish (filesystem reads only, zero network) reliance evaluation.
    Returns the layered result dict; NEVER trusts a stored verdict — every
    receipt/attestation is re-verified from its own bytes at gate time.

    ``requesting_agent_id`` (Attestation-Gated Execution v1): the live
    requesting agent's identity, bound against an ATTESTATION_RECORD_MODE
    requirement's ``agentIdFromRequest``.
    """
    now = now or datetime.now(timezone.utc)
    checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ws_fingerprint = _workspace_fingerprint(workspace_root)
    kids = _registry_kids(state_dir)

    materialized: list[RelianceRequirement] = []
    seen_ids: set[str] = set()
    for i, req in enumerate(requirements):
        rid = req.requirement_id or f"req-{i + 1}"
        if rid in seen_ids:
            raise StrixLocalError(f"duplicate reliance requirementId {rid!r}")
        seen_ids.add(rid)
        req.requirement_id = rid
        materialized.append(req)
    if not materialized:
        raise StrixLocalError("reliance requires at least one requirement — an empty list is not a gate")

    results: list[dict[str, Any]] = []
    for req in materialized:
        try:
            results.append(
                _evaluate_reliance_requirement(
                    req, workspace_root=workspace_root, state_dir=state_dir,
                    ws_fingerprint=ws_fingerprint, kids=kids, now=now,
                    requesting_agent_id=requesting_agent_id,
                    subject_capability_id=capability_id,
                )
            )
        except Exception as exc:  # noqa: BLE001 - a crashing verifier must deny, never escape as success
            results.append(
                _unmet_requirement(req, "ERROR", f"VERIFIER_ERROR: {type(exc).__name__}: {exc}")
            )

    # Distinct-evidence discipline: one receipt satisfies at most one requirement.
    seen_evidence: set[str] = set()
    for r in results:
        if r["satisfied"] and r["evidenceId"] is not None:
            if r["evidenceId"] in seen_evidence:
                r["satisfied"] = False
                r["reason"] = (
                    "DUPLICATE_EVIDENCE: the same evidenceId was presented for more than one requirement"
                )
            else:
                seen_evidence.add(r["evidenceId"])

    statuses = {r["status"] for r in results}
    if "INVALID" in statuses:
        verification_status = "INVALID"
    elif statuses - {"VERIFIED"}:
        verification_status = "UNVERIFIABLE"
    else:
        verification_status = "VERIFIED"

    proceed = all(r["satisfied"] for r in results)
    if proceed:
        reason = "ALL_REQUIREMENTS_SATISFIED: all required proof conditions passed"
    else:
        first = next(r for r in results if not r["satisfied"])
        reason = f"requirement {first['requirementId']!r} failed — {first['reason']}"

    return {
        "reliancePolicyId": f"inline:{capability_id}",
        "reliancePolicyVersion": 1,
        "policyHash": _reliance_policy_hash(capability_id, materialized),
        "verificationStatus": verification_status,
        "relianceVerdict": "PROCEED" if proceed else "DENY",
        "requirements": results,
        "reason": reason,
        "checkedAt": checked_at,
    }


def _evaluate_reliance_requirement(
    req: RelianceRequirement,
    *,
    workspace_root: Path,
    state_dir: Path,
    ws_fingerprint: str,
    kids: list[str] | None,
    now: datetime,
    requesting_agent_id: str | None,
    subject_capability_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch on the requirement's artifact family. Both branches produce
    the SAME result-dict shape and feed the SAME worst-of/dedup logic in
    ``evaluate_reliance_local`` — one reliance gate, two artifact
    vocabularies, never a second parallel authorization system."""
    if req.receipt_type == ATTESTATION_RECORD_MODE:
        return _evaluate_attestation_reliance_requirement(
            req, workspace_root=workspace_root, state_dir=state_dir,
            ws_fingerprint=ws_fingerprint, now=now, requesting_agent_id=requesting_agent_id,
            subject_capability_id=subject_capability_id,
        )
    return _evaluate_receipt_reliance_requirement(
        req, workspace_root=workspace_root, state_dir=state_dir, ws_fingerprint=ws_fingerprint, kids=kids, now=now,
    )


def _evaluate_receipt_reliance_requirement(
    req: RelianceRequirement,
    *,
    workspace_root: Path,
    state_dir: Path,
    ws_fingerprint: str,
    kids: list[str] | None,
    now: datetime,
) -> dict[str, Any]:
    path = Path(req.receipt_path)
    if not path.is_absolute():
        path = workspace_root / path
    if not path.exists():
        return _unmet_requirement(
            req, "MISSING", "REQUIRED_PROOF_MISSING: no receipt was presented for this requirement"
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        record = None
    if not isinstance(record, dict):
        return _unmet_requirement(
            req, "MALFORMED", "RECEIPT_MALFORMED: the presented receipt is not a JSON object"
        )
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return _unmet_requirement(
            req, "MALFORMED", "RECEIPT_MALFORMED: the presented receipt is not a JSON object with a payload"
        )

    vr = _verify_local_record_for_reliance(record, state_dir)
    crypto_code = vr.pop("cryptoCode")

    capability_matched = payload.get("capabilityId") == req.capability_id
    decision_matched = payload.get("decision") in req.decisions
    execution_status_matched = payload.get("executionStatus") == req.execution_status
    workspace_matched = (not req.same_workspace) or payload.get("workspaceFingerprint") == ws_fingerprint
    signing_key_matched = (not req.same_signing_key) or (
        kids is not None and payload.get("signingKeyId") in kids
    )
    action = payload.get("action")
    params_hash_matched = req.params_hash is None or (
        isinstance(action, dict) and action.get("paramsHash") == req.params_hash
    )

    created_raw = payload.get("createdAt")
    age_seconds: int | None = None
    freshness_code: str | None = None
    created = None
    if isinstance(created_raw, str) and _TIMESTAMP_RE.match(created_raw):
        try:
            # strptime is calendar-strict (rejects Feb 30, hour 24, second
            # 60) — the regex alone is not. A parse failure is an
            # untrustworthy timestamp, not a verifier crash.
            created = datetime.strptime(created_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            created = None
    if created is None:
        freshness_code = "TIMESTAMP_UNPARSEABLE"
    else:
        age_seconds = int((now - created).total_seconds())
        if age_seconds < 0:
            freshness_code = "RECEIPT_FUTURE_DATED"
        elif req.max_age_seconds is not None and age_seconds > req.max_age_seconds:
            freshness_code = "REQUIRED_PROOF_EXPIRED"
    freshness_valid = freshness_code is None

    # First failing check in the SAME fixed order as the reference impl.
    code: str | None = crypto_code if crypto_code not in (None, "KEY_UNRESOLVED") else None
    detail: str | None = None
    if code is None:
        if crypto_code == "KEY_UNRESOLVED" and not req.allow_unresolved_key:
            code = "KEY_UNRESOLVED"
        elif not capability_matched:
            code = "CAPABILITY_MISMATCH"
        elif not decision_matched:
            code = "DECISION_MISMATCH"
        elif not execution_status_matched:
            code = "EXECUTION_STATUS_MISMATCH"
        elif not workspace_matched:
            code = "WORKSPACE_MISMATCH"
        elif not signing_key_matched:
            code = "SIGNING_KEY_MISMATCH"
        elif not params_hash_matched:
            code = "PARAMS_HASH_MISMATCH"
        elif not freshness_valid:
            code = freshness_code
            if code == "REQUIRED_PROOF_EXPIRED":
                detail = f"receipt age {age_seconds}s exceeds required maximum age {req.max_age_seconds}s"

    satisfied = code is None
    if satisfied:
        reason = "SATISFIED: all required proof conditions passed for this requirement"
        if crypto_code == "KEY_UNRESOLVED":
            reason = (
                "SATISFIED: conditions passed with an UNRESOLVED signing key — allowUnresolvedKey "
                "is set on this requirement; the receipt content is hash-consistent but NOT authenticated"
            )
    elif detail:
        reason = f"{code}: {detail}"
    elif code == "RECEIPT_MALFORMED":
        reason = "RECEIPT_MALFORMED: the presented receipt is not a JSON object with a payload"
    else:
        reason = f"{code}: {_RELIANCE_DETAILS[code]}"

    evidence_id = payload.get("evidenceId")
    evidence_hash = payload.get("evidenceHash")
    record_mode = payload.get("recordMode")
    return {
        "requirementId": req.requirement_id,
        "evidenceId": evidence_id if isinstance(evidence_id, str) else None,
        "evidenceHash": evidence_hash if isinstance(evidence_hash, str) else None,
        "recordMode": record_mode if isinstance(record_mode, str) else None,
        "hashValid": vr["hashValid"],
        "chainValid": vr["chainValid"],
        "signaturePresent": vr["signaturePresent"],
        "signatureValid": vr["signatureValid"],
        "keyResolved": vr["keyResolved"],
        "capabilityMatched": capability_matched,
        "workspaceMatched": workspace_matched,
        "decisionMatched": decision_matched,
        "executionStatusMatched": execution_status_matched,
        "signingKeyMatched": signing_key_matched,
        "paramsHashMatched": params_hash_matched,
        "freshnessValid": freshness_valid,
        "status": vr["status"],
        "satisfied": satisfied,
        "reason": reason,
    }


def _evaluate_attestation_reliance_requirement(
    req: RelianceRequirement,
    *,
    workspace_root: Path,
    state_dir: Path,
    ws_fingerprint: str,
    now: datetime,
    requesting_agent_id: str | None,
    subject_capability_id: str | None,
) -> dict[str, Any]:
    """Evaluate one ATTESTATION_RECORD_MODE requirement — the 16 checks of
    Attestation-Gated Execution v1, in the SAME fixed order as
    solo_builder.strix_wire_local_reliance._evaluate_attestation_requirement
    (cross-language conformance depends on this order matching exactly).

    Identity evidence is an INPUT here, never the authority: a VERIFIED
    attestation still must pass every content binding below before this
    requirement is satisfied, and satisfying it is only ONE input into the
    overall reliance verdict — the ordinary local policy in
    ``governed_action_local`` evaluates independently and must ALSO permit
    the action.
    """
    path = Path(req.receipt_path)
    if not path.is_absolute():
        path = workspace_root / path
    if not path.exists():
        return _unmet_requirement(
            req, "MISSING", "ATTESTATION_MISSING: no attestation was presented for this requirement"
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        record = None
    if not isinstance(record, dict):
        return _unmet_requirement(
            req, "MALFORMED", "ATTESTATION_MALFORMED: the presented attestation is not a JSON object"
        )
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return _unmet_requirement(
            req, "MALFORMED",
            "ATTESTATION_MALFORMED: the presented attestation is not a JSON object with a payload",
        )

    vr = _verify_local_attestation_crypto(record, state_dir)
    crypto_code = vr.pop("cryptoCode")

    attestation_id = payload.get("attestationId")
    attestation_hash = payload.get("attestationHash")
    record_mode = payload.get("recordMode")
    agent_id = payload.get("agentId") if isinstance(payload.get("agentId"), str) else None
    agent_class = payload.get("agentClass") if isinstance(payload.get("agentClass"), str) else None
    issuer_id = payload.get("issuerId") if isinstance(payload.get("issuerId"), str) else None

    issuer_matched = issuer_id is not None and issuer_id in req.permitted_issuers
    if req.agent_id_from_request:
        agent_matched = requesting_agent_id is not None and agent_id == requesting_agent_id
    elif req.expected_agent_id is not None:
        agent_matched = agent_id == req.expected_agent_id
    else:
        agent_matched = True
    class_matched = req.required_class is None or agent_class == req.required_class
    workspace_matched = (not req.same_workspace) or payload.get("workspaceFingerprint") == ws_fingerprint
    scopes = payload.get("capabilityScopes")
    if req.capability_scope_must_include_subject:
        scope_matched = bool(
            subject_capability_id is not None
            and isinstance(scopes, list)
            and any(isinstance(s, str) and _scope_matches(s, subject_capability_id) for s in scopes)
        )
    else:
        scope_matched = True

    issued_raw = payload.get("issuedAt")
    expires_raw = payload.get("expiresAt")
    issued_at = None
    expires_at = None
    if isinstance(issued_raw, str) and _TIMESTAMP_RE.match(issued_raw):
        try:
            issued_at = datetime.strptime(issued_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            issued_at = None
    if isinstance(expires_raw, str) and _TIMESTAMP_RE.match(expires_raw):
        try:
            expires_at = datetime.strptime(expires_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            expires_at = None

    not_yet_valid = issued_at is not None and issued_at > now
    expired = expires_at is not None and now > expires_at
    age_seconds = int((now - issued_at).total_seconds()) if issued_at is not None else None
    max_age_exceeded = (
        req.max_age_seconds is not None and age_seconds is not None and age_seconds > req.max_age_seconds
    )
    freshness_valid = (
        issued_at is not None and expires_at is not None and not not_yet_valid and not expired and not max_age_exceeded
    )
    revoked = attestation_id is not None and _is_attestation_revoked(state_dir, attestation_id)

    code: str | None = None
    detail: str | None = None
    if crypto_code == "ATTESTATION_KEY_UNKNOWN" and not req.allow_unresolved_key:
        code = "ATTESTATION_KEY_UNKNOWN"
    elif crypto_code is not None and crypto_code != "ATTESTATION_KEY_UNKNOWN":
        code = crypto_code
    elif not issuer_matched:
        code = "ATTESTATION_ISSUER_NOT_ALLOWED"
    elif not agent_matched:
        code = "ATTESTATION_AGENT_MISMATCH"
    elif not class_matched:
        code = "ATTESTATION_CLASS_MISMATCH"
    elif not workspace_matched:
        code = "ATTESTATION_WORKSPACE_MISMATCH"
    elif not scope_matched:
        code = "ATTESTATION_SCOPE_MISMATCH"
    elif issued_at is None or expires_at is None:
        code = "ATTESTATION_MALFORMED"
        detail = "issuedAt/expiresAt could not be parsed as strict RFC3339 Z-suffixed timestamps"
    elif not_yet_valid:
        code = "ATTESTATION_NOT_YET_VALID"
    elif expired:
        code = "ATTESTATION_EXPIRED"
        detail = "attestation expiresAt has passed"
    elif max_age_exceeded:
        code = "ATTESTATION_EXPIRED"
        detail = f"attestation age {age_seconds}s exceeds required maximum age {req.max_age_seconds}s"
    elif revoked:
        code = "ATTESTATION_REVOKED"

    satisfied = code is None
    if satisfied:
        reason = "SATISFIED: all required attestation conditions passed for this requirement"
        if crypto_code == "ATTESTATION_KEY_UNKNOWN":
            reason = (
                "SATISFIED: conditions passed with an UNRESOLVED signing key — allowUnresolvedKey "
                "is set on this requirement; the attestation content is hash-consistent but NOT authenticated"
            )
    else:
        failing_code = code or "ATTESTATION_UNVERIFIABLE"
        if detail:
            reason = f"{failing_code}: {detail}"
        else:
            reason = f"{failing_code}: {_ATTESTATION_DETAILS.get(failing_code, 'attestation verification could not complete')}"

    return {
        "requirementId": req.requirement_id,
        "evidenceId": attestation_id if isinstance(attestation_id, str) else None,
        "evidenceHash": attestation_hash if isinstance(attestation_hash, str) else None,
        "recordMode": record_mode if isinstance(record_mode, str) else None,
        "hashValid": vr["hashValid"],
        "chainValid": True,  # attestations are independently signed, not chained — vacuously true
        "signaturePresent": vr["signaturePresent"],
        "signatureValid": vr["signatureValid"],
        "keyResolved": vr["keyResolved"],
        "capabilityMatched": True,  # not an attestation concept — "passed or not required"
        "workspaceMatched": workspace_matched,
        "decisionMatched": True,  # not an attestation concept
        "executionStatusMatched": True,  # not an attestation concept
        "signingKeyMatched": True,  # sameSigningKey has no meaning for attestations
        "paramsHashMatched": True,  # paramsHash has no meaning for attestations
        "freshnessValid": freshness_valid,
        "status": vr["status"],
        "satisfied": satisfied,
        "reason": reason,
        "artifactType": ATTESTATION_RECORD_MODE,
        "attestationAgentId": agent_id,
        "attestationAgentClass": agent_class,
        "attestationIssuerId": issuer_id,
        "scopeMatched": scope_matched,
    }


def _attestation_requirement_ref(r: dict[str, Any]) -> dict[str, Any]:
    """Attestation-Gated Execution v1: the downstream receipt must bind
    agent id / class / issuer / capability-scope result / workspace-binding
    result / freshness result alongside attestationId/attestationHash
    (evidenceId/evidenceHash) and verification status (status)."""
    return {
        "requirementId": r["requirementId"],
        "evidenceId": r["evidenceId"],
        "evidenceHash": r["evidenceHash"],
        "recordMode": r["recordMode"],
        "status": r["status"],
        "satisfied": r["satisfied"],
        "reason": r["reason"],
        "artifactType": r["artifactType"],
        "attestationAgentId": r["attestationAgentId"],
        "attestationAgentClass": r["attestationAgentClass"],
        "attestationIssuerId": r["attestationIssuerId"],
        "scopeMatched": r["scopeMatched"],
        "workspaceMatched": r["workspaceMatched"],
        "freshnessValid": r["freshnessValid"],
    }


def _reliance_receipt_ref(result: dict[str, Any]) -> dict[str, Any]:
    """Compact projection bound into the downstream local-receipt-v2 signed
    payload. Semantic bindings only — no receipt paths, no formatting."""
    return {
        "reliancePolicyId": result["reliancePolicyId"],
        "reliancePolicyVersion": result["reliancePolicyVersion"],
        "policyHash": result["policyHash"],
        "relianceVerdict": result["relianceVerdict"],
        "verificationStatus": result["verificationStatus"],
        "checkedAt": result["checkedAt"],
        "requirements": [
            _attestation_requirement_ref(r) if r.get("artifactType") == ATTESTATION_RECORD_MODE else {
                "requirementId": r["requirementId"],
                "evidenceId": r["evidenceId"],
                "evidenceHash": r["evidenceHash"],
                "recordMode": r["recordMode"],
                "status": r["status"],
                "satisfied": r["satisfied"],
                "reason": r["reason"],
            }
            for r in result["requirements"]
        ],
    }


# ---------------------------------------------------------------------------
# Canonical payload + signing + chain
# ---------------------------------------------------------------------------


def _workspace_fingerprint(root: Path) -> str:
    return _hash_canonical({"path": str(root.resolve())})


def _build_payload(
    *,
    evidence_id: str,
    capability_id: str,
    action_name: str,
    params: Mapping[str, Any],
    ref: Mapping[str, str],
    decision: str,
    execution_status: str,
    workspace_root: Path,
    key: LocalSigningKey,
    chain_seq: int,
    prev_hash: str | None,
    reliance_ref: Mapping[str, Any] | None = None,
    chain_ref: Mapping[str, Any] | None = None,
    dag_ref: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if chain_ref is not None and dag_ref is not None:
        raise StrixLocalError(
            "chain_ref and dag_ref are mutually exclusive — a receipt is local-receipt-v3 XOR "
            "local-receipt-v4, never both"
        )
    action = {
        "name": action_name,
        "paramsHash": _hash_canonical(dict(params)),
        "paramsSchemaHash": _hash_canonical(sorted(str(k) for k in params)),
    }
    if dag_ref is not None:
        schema_version = SCHEMA_VERSION_V4
    elif chain_ref is not None:
        schema_version = SCHEMA_VERSION_V3
    elif reliance_ref is not None:
        schema_version = SCHEMA_VERSION_V2
    else:
        schema_version = SCHEMA_VERSION
    core = {
        "schemaVersion": schema_version,
        "recordMode": RECORD_MODE,
        "evidenceId": evidence_id,
        "createdAt": _iso_now(),
        "capabilityId": capability_id,
        "action": action,
        "policyRef": dict(ref),
        "decision": decision,
        "executionStatus": execution_status,
        "workspaceFingerprint": _workspace_fingerprint(workspace_root),
        "signingKeyId": key.kid,
        "publicKeyFingerprint": key.public_key_fingerprint,
        "runtimeVersion": "strix-wire-local-helper/1.0.0",
        "chainSeq": chain_seq,
        "prevHash": prev_hash,
    }
    if reliance_ref is not None:
        # Round-trip through the canonical serializer: plain JSON-safe deep
        # copy; rejects unserializable content eagerly.
        core["relianceRef"] = json.loads(_canonicalize(dict(reliance_ref)))
    if chain_ref is not None:
        core["chainRef"] = json.loads(_canonicalize(dict(chain_ref)))
    if dag_ref is not None:
        core["dagRef"] = json.loads(_canonicalize(dict(dag_ref)))
    evidence_hash = _hash_canonical(core)
    proof_chain_hash = _hash_canonical({"evidenceHash": evidence_hash, "prevHash": prev_hash, "chainSeq": chain_seq})
    return {**core, "evidenceHash": evidence_hash, "proofChainHash": proof_chain_hash}


def _sign(payload: Mapping[str, Any], key: LocalSigningKey) -> dict[str, Any]:
    Ed25519PrivateKey, _ = _require_cryptography()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key.private_key_hex))
    signature = priv.sign(_canonicalize(dict(payload))).hex()
    return {"payload": dict(payload), "signature": signature}


def _chain_paths(state_dir: Path) -> tuple[Path, Path]:
    evidence_dir = state_dir / "evidence"
    return evidence_dir, evidence_dir / "receipts.jsonl"


def _last_hash_and_seq(chain_path: Path) -> tuple[str | None, int]:
    """``seq`` counts every non-blank PHYSICAL line, including one that
    fails to parse — a corrupted or truncated line still occupies a
    chain-sequence slot on disk, so a newly minted receipt can never be
    assigned a chainSeq that collides with a record that already
    physically exists (mirrors solo_builder.strix_wire_local_receipt's
    ``LocalReceiptChain.next_seq``/``last_hash``, and matches the sibling
    TypeScript helper's ``lastHashAndSeq``, which already counted this
    way). ``last_hash`` only ever updates from a line that both parses AND
    carries a real ``evidenceHash`` — chaining must point to an actual
    existing hash, never to a corrupt or malformed line's absence of one."""
    if not chain_path.exists():
        return None, 0
    last_hash: str | None = None
    seq = 0
    for line in chain_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        seq += 1
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        payload = entry.get("payload") if isinstance(entry, dict) else None
        evidence_hash = payload.get("evidenceHash") if isinstance(payload, dict) else None
        if evidence_hash:
            last_hash = evidence_hash
    return last_hash, seq


def _append_and_export(state_dir: Path, record: Mapping[str, Any]) -> Path:
    evidence_dir, chain_path = _chain_paths(state_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with chain_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    evidence_id = record["payload"]["evidenceId"]
    single_path = evidence_dir / f"{evidence_id}.json"
    single_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return single_path


# ---------------------------------------------------------------------------
# The public surface
# ---------------------------------------------------------------------------


class LocalGovernedActionResult(Generic[T]):
    __slots__ = ("evidence_id", "receipt_path", "record", "result")

    def __init__(self, result: T, evidence_id: str, receipt_path: Path, record: dict[str, Any]) -> None:
        self.result = result
        self.evidence_id = evidence_id
        self.receipt_path = receipt_path
        self.record = record


class LocalChainStep:
    """Chained Governed Autonomy v1 — the minimal chain-position metadata
    :func:`governed_action_local` needs to derive the receipt's ``chainRef``
    projection. Constructed ONLY by :class:`ChainSession` from its own
    internal, non-caller-suppliable bookkeeping — this class does not
    itself construct the chain-predecessor reliance requirement (that is
    the session's job). ``previous_evidence_id``/``previous_evidence_hash``
    are ``None`` at ``step_index == 0`` (chain root)."""

    __slots__ = ("chain_id", "step_index", "previous_evidence_id", "previous_evidence_hash", "attestation_required")

    def __init__(
        self,
        *,
        chain_id: str,
        step_index: int,
        previous_evidence_id: str | None = None,
        previous_evidence_hash: str | None = None,
        attestation_required: bool = False,
    ) -> None:
        self.chain_id = chain_id
        self.step_index = step_index
        self.previous_evidence_id = previous_evidence_id
        self.previous_evidence_hash = previous_evidence_hash
        self.attestation_required = attestation_required


class LocalDagStep:
    """Chained Governed Autonomy v2 — the minimal DAG-position metadata
    :func:`governed_action_local` needs to derive the receipt's ``dagRef``
    projection. Constructed ONLY by :class:`DagSession` from its own
    internal, non-caller-suppliable bookkeeping — mirrors
    :class:`LocalChainStep`, generalized from a single optional predecessor
    to a list of zero or more parents. ``parent_evidence_ids`` is empty for
    a source node — valid at any ``step_index``, not only at 0. Each
    entry's role here is purely to tell this function HOW MANY parents
    were declared; the string values themselves are never trusted for the
    signed output (see the ``dag_step`` derivation below)."""

    __slots__ = ("dag_id", "step_index", "parent_evidence_ids", "attestation_required")

    def __init__(
        self,
        *,
        dag_id: str,
        step_index: int,
        parent_evidence_ids: tuple[str, ...] = (),
        attestation_required: bool = False,
    ) -> None:
        self.dag_id = dag_id
        self.step_index = step_index
        self.parent_evidence_ids = parent_evidence_ids
        self.attestation_required = attestation_required


def governed_action_local(
    capability_id: str,
    action_name: str,
    payload: dict[str, Any],
    operation: Callable[[], T],
    *,
    approval_granted: bool = False,
    workspace_root: Path | None = None,
    state_dir: Path | None = None,
    reliance: list[RelianceRequirement] | None = None,
    requesting_agent_id: str | None = None,
    chain_step: LocalChainStep | None = None,
    dag_step: LocalDagStep | None = None,
) -> LocalGovernedActionResult[T]:
    """Govern one irreversible mutation entirely offline. See module
    docstring for the full six-step contract.

    ``reliance`` (Local Reliance Gate v1): declared prior proofs. Each
    :class:`RelianceRequirement`'s receipt is loaded from its
    ``receipt_path`` (relative paths resolve against ``workspace_root``),
    independently re-verified (hash, chain link, signature, key
    resolution) and checked against the requirement's content bindings and
    freshness, strictly BEFORE ``operation()``. Any unmet requirement
    raises :class:`StrixLocalRelianceDenied`. The verified reliance
    projection is bound into the downstream signed receipt
    (``local-receipt-v2`` ``relianceRef``). Attestation-Gated Execution v1:
    a requirement whose ``receipt_type`` is ``ATTESTATION_RECORD_MODE`` is
    independently re-verified against the LOCAL issuer key registry +
    revocation list rooted under this same ``state_dir`` — identity
    evidence is an INPUT to this authorization decision, never the
    authorization itself; the ordinary policy above still evaluates
    independently and must ALSO permit the capability.
    ``requesting_agent_id``: the live requesting agent's identity, bound
    against an attestation requirement's ``agentIdFromRequest``.

    Raises:
        StrixLocalDenied:            local policy denied outright. NOT run.
        StrixLocalRelianceDenied:    a required prior proof did not verify.
                                     NOT run.
        StrixLocalApprovalRequired:  approval required, not granted. NOT run.
        StrixLocalKeyError:          the signing key is missing/corrupt, or
                                     `cryptography` is not installed.
        Exception:                   whatever `operation()` itself raises
                                     (a best-effort FAILED receipt is
                                     recorded first).
        StrixLocalReceiptPersistenceError: the operation succeeded but the
                                     receipt could not be written.
    """
    workspace_root = workspace_root or Path.cwd()
    state_dir = state_dir or (workspace_root / DEFAULT_STATE_DIR)

    raw_decision, reason = evaluate_policy(capability_id, payload)

    # Local Reliance Gate v1 — evaluated AFTER policy, BEFORE decide/
    # authorize/execute. Independent re-verification; stored verdicts are
    # never trusted.
    reliance_result: dict[str, Any] | None = None
    if reliance is not None:
        reliance_result = evaluate_reliance_local(
            capability_id, list(reliance), workspace_root=workspace_root, state_dir=state_dir,
            requesting_agent_id=requesting_agent_id,
        )

    if raw_decision == "DENY":
        raise StrixLocalDenied(f"{capability_id}: {reason}")
    if reliance_result is not None and reliance_result["relianceVerdict"] != "PROCEED":
        raise StrixLocalRelianceDenied(
            f"{capability_id}: reliance denied — {reliance_result['reason']}. "
            "The protected operation was not called.",
            reliance_result,
        )
    if raw_decision == "REQUIRE_APPROVAL" and not approval_granted:
        raise StrixLocalApprovalRequired(f"{capability_id}: {reason} (approval not granted)")
    # --- everything above runs BEFORE operation(); nothing below may
    # --- execute unless policy cleared, every declared reliance
    # --- requirement verified, and any required approval was granted.

    decision = "ALLOW" if raw_decision == "ALLOW" else "REQUIRE_APPROVAL_GRANTED"
    reliance_ref = _reliance_receipt_ref(reliance_result) if reliance_result is not None else None

    # Chained Governed Autonomy v1: chainRef is DERIVED from the reliance
    # evaluation that just cleared above — never accepted as raw input.
    chain_ref: dict[str, Any] | None = None
    if chain_step is not None:
        agent_id: str | None = None
        if chain_step.attestation_required and reliance_result is not None:
            att_result = next(
                (r for r in reliance_result["requirements"] if r["requirementId"] == "chain-attestation"), None
            )
            if att_result is not None:
                agent_id = att_result.get("attestationAgentId")

        # Same "derive, never trust raw input" treatment as agentId above:
        # a caller bypassing ChainSession (which always constructs a
        # matching, satisfied "chain-predecessor" requirement for a
        # non-root step) cannot make this function sign an unverified
        # predecessor claim — it fails closed instead.
        previous_evidence_id = chain_step.previous_evidence_id
        previous_evidence_hash = chain_step.previous_evidence_hash
        if previous_evidence_id is not None or previous_evidence_hash is not None:
            pred_result = (
                next((r for r in reliance_result["requirements"] if r["requirementId"] == "chain-predecessor"), None)
                if reliance_result is not None
                else None
            )
            if pred_result is None or not pred_result.get("satisfied"):
                raise StrixLocalChainPredecessorUnverified(
                    "chain_step declares a non-root predecessor (previousStepEvidenceId/Hash is not "
                    "null) but no independently-verified, satisfied 'chain-predecessor' reliance "
                    "requirement was found in this call's reliance evaluation. A chainRef predecessor "
                    "claim must always be backed by a re-verified requirement, never accepted as raw "
                    "chain_step input."
                )
            previous_evidence_id = pred_result.get("evidenceId")
            previous_evidence_hash = pred_result.get("evidenceHash")

        chain_ref = {
            "chainId": chain_step.chain_id,
            "stepIndex": chain_step.step_index,
            "previousStepEvidenceId": previous_evidence_id,
            "previousStepEvidenceHash": previous_evidence_hash,
            "agentAttestationRequired": chain_step.attestation_required,
            "agentId": agent_id,
        }

    # Chained Governed Autonomy v2: dagRef is DERIVED from the reliance
    # evaluation that just cleared above — never accepted as raw input.
    # Same "derive, never trust raw input" treatment as chainRef, extended
    # to a list of zero or more parents: every declared parent index must
    # be backed by its own independently-verified, satisfied
    # "dag-parent-{i}" requirement in THIS call's evaluation, and the
    # SIGNED dagRef embeds that requirement's own verified
    # evidenceId/evidenceHash — never the caller's raw dag_step claim.
    dag_ref: dict[str, Any] | None = None
    if dag_step is not None:
        if len(set(dag_step.parent_evidence_ids)) != len(dag_step.parent_evidence_ids):
            raise StrixLocalDagParentUnverified(
                "dag_step declares a duplicate parent evidence id — a DAG step cannot depend on the "
                "same parent twice."
            )

        dag_agent_id: str | None = None
        if dag_step.attestation_required and reliance_result is not None:
            dag_att_result = next(
                (r for r in reliance_result["requirements"] if r["requirementId"] == "dag-attestation"), None
            )
            if dag_att_result is not None:
                dag_agent_id = dag_att_result.get("attestationAgentId")

        parent_refs: list[dict[str, Any]] = []
        for parent_index in range(len(dag_step.parent_evidence_ids)):
            requirement_id = f"dag-parent-{parent_index}"
            parent_result = (
                next((r for r in reliance_result["requirements"] if r["requirementId"] == requirement_id), None)
                if reliance_result is not None
                else None
            )
            if parent_result is None or not parent_result.get("satisfied"):
                raise StrixLocalDagParentUnverified(
                    f"dag_step declares parent index {parent_index} but no independently-verified, "
                    f"satisfied {requirement_id!r} reliance requirement was found in this call's "
                    "reliance evaluation. A dagRef parent claim must always be backed by a "
                    "re-verified requirement, never accepted as raw dag_step input."
                )
            parent_refs.append(
                {"evidenceId": parent_result.get("evidenceId"), "evidenceHash": parent_result.get("evidenceHash")}
            )

        # Canonical order, NOT declaration order: parentEvidenceRefs is
        # semantically an unordered SET (every verify_local_dag check already
        # resolves it by evidenceId/stepIndex value, never list position —
        # see CGA2-13). Sorting by (evidenceId, evidenceHash) before signing
        # means two logically-identical parent sets declared in different
        # orders ([A, B] vs [B, A]) always produce the same canonical bytes
        # and signature. This is a construction-time-only guarantee —
        # verify_local_dag deliberately stays order-agnostic when reading.
        parent_refs.sort(key=lambda ref: (ref["evidenceId"], ref["evidenceHash"]))

        dag_ref = {
            "dagId": dag_step.dag_id,
            "stepIndex": dag_step.step_index,
            "parentEvidenceRefs": parent_refs,
            "agentAttestationRequired": dag_step.attestation_required,
            "agentId": dag_agent_id,
        }

    key = generate_or_load_key(state_dir)
    ref = policy_ref()
    evidence_dir, chain_path = _chain_paths(state_dir)
    prev_hash, chain_seq = _last_hash_and_seq(chain_path)

    try:
        result = operation()
    except Exception:
        try:
            failed_payload = _build_payload(
                evidence_id=f"local_ev_{uuid.uuid4().hex}",
                capability_id=capability_id,
                action_name=action_name,
                params=payload,
                ref=ref,
                decision=decision,
                execution_status="FAILED",
                workspace_root=workspace_root,
                key=key,
                chain_seq=chain_seq,
                prev_hash=prev_hash,
                reliance_ref=reliance_ref,
                chain_ref=chain_ref,
                dag_ref=dag_ref,
            )
            _append_and_export(state_dir, _sign(failed_payload, key))
        except Exception as receipt_exc:  # noqa: BLE001 - never mask the operation's own exception
            warnings.warn(
                f"failed to record a FAILED receipt after the operation itself failed: {receipt_exc}",
                stacklevel=2,
            )
        raise

    try:
        success_payload = _build_payload(
            evidence_id=f"local_ev_{uuid.uuid4().hex}",
            capability_id=capability_id,
            action_name=action_name,
            params=payload,
            ref=ref,
            decision=decision,
            execution_status="SUCCEEDED",
            workspace_root=workspace_root,
            key=key,
            chain_seq=chain_seq,
            prev_hash=prev_hash,
            reliance_ref=reliance_ref,
            chain_ref=chain_ref,
            dag_ref=dag_ref,
        )
        record = _sign(success_payload, key)
        receipt_path = _append_and_export(state_dir, record)
    except Exception as exc:  # noqa: BLE001
        raise StrixLocalReceiptPersistenceError(
            f"{capability_id} executed successfully, but the signed receipt could not be persisted: "
            f"{exc}. The mutation is NOT undone. Inspect {evidence_dir} before retrying."
        ) from exc

    evidence_id = record["payload"]["evidenceId"]
    return LocalGovernedActionResult(result=result, evidence_id=evidence_id, receipt_path=receipt_path, record=record)


# ---------------------------------------------------------------------------
# Chained Governed Autonomy v1 — ChainSession + verify_local_chain
# ---------------------------------------------------------------------------


class LocalChainError(StrixLocalError):
    """Chain misconfiguration or misuse — always fail-closed, never a
    silent no-op."""


class ChainAttestationPolicy:
    """The identity policy every step of a chain must satisfy, applied
    uniformly by :class:`ChainSession`. ``permitted_issuers`` has no
    default: an attestation policy with no issuer trust boundary at all is
    not a fail-closed identity check."""

    __slots__ = (
        "permitted_issuers",
        "required_class",
        "capability_scope_must_include_subject",
        "agent_id_from_request",
        "expected_agent_id",
        "max_age_seconds",
        "allow_unresolved_key",
    )

    def __init__(
        self,
        permitted_issuers: tuple[str, ...],
        *,
        required_class: str | None = None,
        capability_scope_must_include_subject: bool = True,
        agent_id_from_request: bool = True,
        expected_agent_id: str | None = None,
        max_age_seconds: int | None = None,
        allow_unresolved_key: bool = False,
    ) -> None:
        if not permitted_issuers:
            raise LocalChainError(
                "ChainAttestationPolicy.permitted_issuers must be non-empty — trusting any issuer by "
                "default is not a fail-closed identity boundary"
            )
        if agent_id_from_request and expected_agent_id is not None:
            raise LocalChainError("agent_id_from_request and expected_agent_id are mutually exclusive")
        self.permitted_issuers = permitted_issuers
        self.required_class = required_class
        self.capability_scope_must_include_subject = capability_scope_must_include_subject
        self.agent_id_from_request = agent_id_from_request
        self.expected_agent_id = expected_agent_id
        self.max_age_seconds = max_age_seconds
        self.allow_unresolved_key = allow_unresolved_key


class ChainSession:
    """The sanctioned API for a Chained Governed Autonomy v1 sequence — the
    standalone-helper mirror of ``solo_builder.strix_wire_local_chain.ChainSession``.

    There is no lower-level way to mint a valid ``local-receipt-v3`` chain
    step: ``receipt_path``, ``previousStepEvidenceId/Hash``, and
    ``stepIndex`` are all derived from this session's own internal state,
    updated ONLY after a step's receipt is actually minted. A denial or a
    failed operation leaves the "last known good" pointer untouched, so a
    retried step reuses the same predecessor and the same stepIndex.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        state_dir: Path,
        attestation_policy: ChainAttestationPolicy | None = None,
        chain_id: str | None = None,
        same_signing_key: bool = True,
        step_max_age_seconds: int | None = None,
    ) -> None:
        self.chain_id = chain_id or f"local_chain_{uuid.uuid4().hex}"
        self.workspace_root = workspace_root
        self.state_dir = state_dir
        self.attestation_policy = attestation_policy
        self.same_signing_key = same_signing_key
        self.step_max_age_seconds = step_max_age_seconds

        self._step_index = 0
        self._last_capability_id: str | None = None
        self._last_receipt_path: Path | None = None
        self._last_evidence_id: str | None = None
        self._last_evidence_hash: str | None = None

    @property
    def next_step_index(self) -> int:
        return self._step_index

    def step(
        self,
        capability_id: str,
        action_name: str,
        params: dict[str, Any],
        operation: Callable[[], T],
        *,
        approval_granted: bool = False,
        requesting_agent_id: str | None = None,
        attestation_path: Path | str | None = None,
        extra_reliance: Sequence[RelianceRequirement] = (),
    ) -> LocalGovernedActionResult[T]:
        if self.attestation_policy is not None and attestation_path is None:
            raise LocalChainError(
                "this chain declares an attestation_policy — every step must supply attestation_path "
                "(the applicable agent attestation for THIS step); it cannot be silently skipped"
            )
        if (
            self.attestation_policy is not None
            and self.attestation_policy.agent_id_from_request
            and requesting_agent_id is None
        ):
            raise LocalChainError(
                "this chain's attestation_policy binds agent_id_from_request — every step must supply "
                "requesting_agent_id"
            )

        reliance_reqs: list[RelianceRequirement] = []
        if self._step_index > 0:
            assert self._last_capability_id is not None
            assert self._last_receipt_path is not None
            reliance_reqs.append(
                RelianceRequirement(
                    self._last_capability_id,
                    str(self._last_receipt_path),
                    requirement_id="chain-predecessor",
                    receipt_type=RECORD_MODE,
                    execution_status="SUCCEEDED",
                    same_workspace=True,
                    same_signing_key=self.same_signing_key,
                    max_age_seconds=self.step_max_age_seconds,
                )
            )
        if self.attestation_policy is not None:
            reliance_reqs.append(
                RelianceRequirement(
                    "",
                    str(attestation_path),
                    requirement_id="chain-attestation",
                    receipt_type=ATTESTATION_RECORD_MODE,
                    agent_id_from_request=self.attestation_policy.agent_id_from_request,
                    expected_agent_id=self.attestation_policy.expected_agent_id,
                    required_class=self.attestation_policy.required_class,
                    permitted_issuers=self.attestation_policy.permitted_issuers,
                    capability_scope_must_include_subject=self.attestation_policy.capability_scope_must_include_subject,
                    max_age_seconds=self.attestation_policy.max_age_seconds,
                    allow_unresolved_key=self.attestation_policy.allow_unresolved_key,
                )
            )
        reliance_reqs.extend(extra_reliance)

        chain_step = LocalChainStep(
            chain_id=self.chain_id,
            step_index=self._step_index,
            previous_evidence_id=self._last_evidence_id,
            previous_evidence_hash=self._last_evidence_hash,
            attestation_required=self.attestation_policy is not None,
        )

        result = governed_action_local(
            capability_id,
            action_name,
            params,
            operation,
            approval_granted=approval_granted,
            workspace_root=self.workspace_root,
            state_dir=self.state_dir,
            # None (not []) when there is nothing to require yet — step 0 of
            # a chain with no attestation_policy has no predecessor and no
            # identity check; evaluate_reliance_local refuses an
            # empty-requirement list by construction.
            reliance=reliance_reqs or None,
            requesting_agent_id=requesting_agent_id,
            chain_step=chain_step,
        )

        # Advance ONLY on success — a denial or a failed operation raises
        # out of governed_action_local before this line.
        self._step_index += 1
        self._last_capability_id = capability_id
        self._last_receipt_path = result.receipt_path
        self._last_evidence_id = result.evidence_id
        self._last_evidence_hash = result.record["payload"]["evidenceHash"]
        return result


_STATUS_RANK = {"VERIFIED": 0, "UNVERIFIABLE": 1, "INVALID": 2}


def verify_local_chain(records: Sequence[dict[str, Any]], *, state_dir: Path) -> dict[str, Any]:
    """Independently re-verify an ORDERED sequence of ``local-receipt-v3``
    records claiming membership in the same chain. Mirrors
    ``solo_builder.strix_wire_local_chain.verify_local_chain`` — callers are
    responsible for CURATING the sequence (every receipt under a
    workspace's evidence directory whose ``chainRef.chainId`` matches the
    chain of interest and whose ``executionStatus`` is ``SUCCEEDED``,
    sorted by ``chainRef.stepIndex``).

    Checks: (1) every record independently verified via the EXISTING,
    unchanged ``_verify_local_record_for_reliance`` — no new crypto path;
    (2) every record declares schemaVersion local-receipt-v3 with a
    structured chainRef; (3) chainId identical across every record;
    (4) stepIndex dense and strictly monotonic starting at 0; (5) for
    every record at stepIndex > 0, chainRef.previousStepEvidenceId/Hash
    equal the ACTUAL evidenceId/evidenceHash of the record at
    stepIndex - 1, byte-for-byte. Worst-of roll-up: the overall
    verificationStatus is the worst individual record status.
    """
    if not records:
        return {
            "ok": False,
            "chainId": None,
            "steps": 0,
            "stepsValid": 0,
            "sequenceLinked": False,
            "verificationStatus": "UNVERIFIABLE",
            "reason": "EMPTY_CHAIN: no records presented",
            "results": [],
        }

    results: list[dict[str, Any]] = []
    chain_ids: set[Any] = set()
    seen_step_indices: list[Any] = []
    sequence_linked = True
    worst_status = "VERIFIED"
    steps_valid = 0
    reasons: list[str] = []

    prev_evidence_id: str | None = None
    prev_evidence_hash: str | None = None

    for idx, record in enumerate(records):
        crypto_result = _verify_local_record_for_reliance(record, state_dir)
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        chain_ref = payload.get("chainRef") if isinstance(payload.get("chainRef"), dict) else None

        entry: dict[str, Any] = {
            "index": idx,
            "evidenceId": payload.get("evidenceId"),
            "verification": crypto_result,
        }

        step_ok = crypto_result["status"] == "VERIFIED"
        step_reason_parts: list[str] = []

        if payload.get("schemaVersion") != SCHEMA_VERSION_V3 or chain_ref is None:
            step_ok = False
            sequence_linked = False
            step_reason_parts.append(
                f"record at index {idx} is not a local-receipt-v3 chain step (missing/wrong chainRef)"
            )
        else:
            chain_ids.add(chain_ref.get("chainId"))
            seen_step_indices.append(chain_ref.get("stepIndex"))
            claimed_prev_id = chain_ref.get("previousStepEvidenceId")
            claimed_prev_hash = chain_ref.get("previousStepEvidenceHash")
            if idx == 0:
                if claimed_prev_id is not None or claimed_prev_hash is not None:
                    step_ok = False
                    sequence_linked = False
                    step_reason_parts.append("first record in the set claims a predecessor")
            else:
                if claimed_prev_id != prev_evidence_id or claimed_prev_hash != prev_evidence_hash:
                    step_ok = False
                    sequence_linked = False
                    step_reason_parts.append(
                        f"record at index {idx} claims a predecessor that does not match the actual "
                        "prior record in this set"
                    )
            prev_evidence_id = payload.get("evidenceId")
            prev_evidence_hash = payload.get("evidenceHash")

        entry["chainRef"] = chain_ref
        entry["stepOk"] = step_ok
        if step_reason_parts:
            entry["reason"] = "; ".join(step_reason_parts)
        results.append(entry)

        if step_ok:
            steps_valid += 1
        rank = _STATUS_RANK.get(crypto_result["status"], 2)
        if rank > _STATUS_RANK[worst_status]:
            worst_status = crypto_result["status"]
        if not step_ok and not step_reason_parts:
            reasons.append(f"index {idx}: {crypto_result.get('cryptoCode')}")
        elif step_reason_parts:
            reasons.append(f"index {idx}: {'; '.join(step_reason_parts)}")

    if len(chain_ids) > 1:
        sequence_linked = False
        reasons.append(f"records claim {len(chain_ids)} distinct chainIds — not one chain")
    expected_indices = list(range(len(records)))
    if seen_step_indices != expected_indices:
        sequence_linked = False
        reasons.append(
            f"stepIndex sequence {seen_step_indices} is not dense/strictly-monotonic from 0 "
            f"(expected {expected_indices})"
        )

    ok = sequence_linked and steps_valid == len(records) and worst_status == "VERIFIED"
    reason = (
        "ALL_STEPS_VERIFIED_AND_LINKED: every record verified and the sequence is intact"
        if ok
        else (" | ".join(reasons) if reasons else "one or more steps failed verification")
    )

    return {
        "ok": ok,
        "chainId": next(iter(chain_ids), None) if len(chain_ids) == 1 else None,
        "steps": len(records),
        "stepsValid": steps_valid,
        "sequenceLinked": sequence_linked,
        "verificationStatus": worst_status,
        "reason": reason,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Chained Governed Autonomy v2 — DagSession + verify_local_dag
# ---------------------------------------------------------------------------


class DagSessionError(StrixLocalError):
    """DAG misconfiguration or misuse — always fail-closed, never a silent
    no-op."""


class DagSession:
    """The sanctioned API for a Chained Governed Autonomy v2 DAG — the
    standalone-helper mirror of ``solo_builder.strix_wire_local_dag.DagSession``.

    There is no lower-level way to mint a valid ``local-receipt-v4`` DAG
    node: every declared parent must be an evidence id this session has
    itself already produced, duplicates are rejected, and ``stepIndex`` is
    this session's own creation-order counter — none of these are
    caller-suppliable. A denial or a failed operation leaves the tracked
    node dict and step counter untouched, so a retried step reuses the
    same ``stepIndex`` and the same declared parent set.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        state_dir: Path,
        attestation_policy: ChainAttestationPolicy | None = None,
        dag_id: str | None = None,
        same_signing_key: bool = True,
        step_max_age_seconds: int | None = None,
    ) -> None:
        self.dag_id = dag_id or f"local_dag_{uuid.uuid4().hex}"
        self.workspace_root = workspace_root
        self.state_dir = state_dir
        self.attestation_policy = attestation_policy
        self.same_signing_key = same_signing_key
        self.step_max_age_seconds = step_max_age_seconds

        self._step_index = 0
        self._nodes: dict[str, tuple[Path, str]] = {}  # evidenceId -> (receipt_path, capability_id)

    @property
    def next_step_index(self) -> int:
        return self._step_index

    def step(
        self,
        capability_id: str,
        action_name: str,
        params: dict[str, Any],
        operation: Callable[[], T],
        *,
        parent_evidence_ids: Sequence[str] = (),
        approval_granted: bool = False,
        requesting_agent_id: str | None = None,
        attestation_path: Path | str | None = None,
        extra_reliance: Sequence[RelianceRequirement] = (),
    ) -> LocalGovernedActionResult[T]:
        parent_ids = tuple(parent_evidence_ids)

        if len(set(parent_ids)) != len(parent_ids):
            raise DagSessionError(
                "parent_evidence_ids contains a duplicate — a DAG step cannot depend on the same "
                "parent twice"
            )
        unknown = [pid for pid in parent_ids if pid not in self._nodes]
        if unknown:
            raise DagSessionError(
                f"parent_evidence_ids references evidence id(s) {unknown!r} that this DagSession "
                "has not itself produced — a step's declared parents must all originate from a "
                "prior, successful .step() call on this SAME session"
            )

        if self.attestation_policy is not None and attestation_path is None:
            raise DagSessionError(
                "this DAG declares an attestation_policy — every step must supply attestation_path "
                "(the applicable agent attestation for THIS step); it cannot be silently skipped"
            )
        if (
            self.attestation_policy is not None
            and self.attestation_policy.agent_id_from_request
            and requesting_agent_id is None
        ):
            raise DagSessionError(
                "this DAG's attestation_policy binds agent_id_from_request — every step must supply "
                "requesting_agent_id"
            )

        reliance_reqs: list[RelianceRequirement] = []
        for i, parent_id in enumerate(parent_ids):
            receipt_path, parent_capability_id = self._nodes[parent_id]
            reliance_reqs.append(
                RelianceRequirement(
                    parent_capability_id,
                    str(receipt_path),
                    requirement_id=f"dag-parent-{i}",
                    receipt_type=RECORD_MODE,
                    execution_status="SUCCEEDED",
                    same_workspace=True,
                    same_signing_key=self.same_signing_key,
                    max_age_seconds=self.step_max_age_seconds,
                )
            )
        if self.attestation_policy is not None:
            reliance_reqs.append(
                RelianceRequirement(
                    "",
                    str(attestation_path),
                    requirement_id="dag-attestation",
                    receipt_type=ATTESTATION_RECORD_MODE,
                    agent_id_from_request=self.attestation_policy.agent_id_from_request,
                    expected_agent_id=self.attestation_policy.expected_agent_id,
                    required_class=self.attestation_policy.required_class,
                    permitted_issuers=self.attestation_policy.permitted_issuers,
                    capability_scope_must_include_subject=self.attestation_policy.capability_scope_must_include_subject,
                    max_age_seconds=self.attestation_policy.max_age_seconds,
                    allow_unresolved_key=self.attestation_policy.allow_unresolved_key,
                )
            )
        reliance_reqs.extend(extra_reliance)

        dag_step = LocalDagStep(
            dag_id=self.dag_id,
            step_index=self._step_index,
            parent_evidence_ids=parent_ids,
            attestation_required=self.attestation_policy is not None,
        )

        result = governed_action_local(
            capability_id,
            action_name,
            params,
            operation,
            approval_granted=approval_granted,
            workspace_root=self.workspace_root,
            state_dir=self.state_dir,
            # None (not []) when there is nothing to require yet — a source
            # node with no attestation_policy has no parents and no
            # identity check; evaluate_reliance_local refuses an
            # empty-requirement list by construction.
            reliance=reliance_reqs or None,
            requesting_agent_id=requesting_agent_id,
            dag_step=dag_step,
        )

        # Advance ONLY on success — a denial or a failed operation raises
        # out of governed_action_local before this line.
        self._nodes[result.evidence_id] = (result.receipt_path, capability_id)
        self._step_index += 1
        return result


def _dag_index_and_schema_flags(
    records: Sequence[dict[str, Any]], state_dir: Path
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[bool],
    dict[str, tuple[int, Any, Any]],
    set[str],
]:
    crypto_results: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    schema_ok_flags: list[bool] = []
    index: dict[str, tuple[int, Any, Any]] = {}
    # A record's evidenceId is supposed to be globally unique (uuid4-generated
    # at mint time) — two records sharing one in the curated set is either a
    # curation bug or an adversarial splice, and letting the LAST one silently
    # win the index would make parent-resolution dependent on incidental list
    # order/duplication, exactly the property this whole verifier exists to
    # NOT have (see CGA2-14). Track collisions so BOTH records, and anyone
    # referencing the ambiguous id as a parent, fail closed rather than
    # resolving to an arbitrary winner.
    duplicate_evidence_ids: set[str] = set()

    for record in records:
        crypto_result = _verify_local_record_for_reliance(record, state_dir)
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        dag_ref = payload.get("dagRef")
        schema_ok = payload.get("schemaVersion") == SCHEMA_VERSION_V4 and _dag_ref_well_formed(dag_ref)

        crypto_results.append(crypto_result)
        payloads.append(payload)
        schema_ok_flags.append(schema_ok)

        if schema_ok:
            evidence_id = payload.get("evidenceId")
            if isinstance(evidence_id, str):
                if evidence_id in index:
                    duplicate_evidence_ids.add(evidence_id)
                index[evidence_id] = (dag_ref["stepIndex"], payload.get("evidenceHash"), dag_ref["dagId"])

    return crypto_results, payloads, schema_ok_flags, index, duplicate_evidence_ids


def verify_local_dag(records: Sequence[dict[str, Any]], *, state_dir: Path) -> dict[str, Any]:
    """Independently re-verify a curated set of ``local-receipt-v4``
    records claiming membership in the same DAG. Mirrors
    ``solo_builder.strix_wire_local_dag.verify_local_dag`` — callers are
    responsible for CURATING the set (every receipt under a workspace's
    evidence directory whose ``dagRef.dagId`` matches the DAG of interest
    and whose ``executionStatus`` is ``SUCCEEDED``).

    **Presentation order carries no meaning here** (a DAG has no single
    "next" record) — every check resolves cross-record references by
    ``evidenceId``/``stepIndex`` VALUE, never by list position (a
    deliberate difference from ``verify_local_chain``'s linear chain,
    where order IS part of the claim).

    Checks: (1) every record independently verified via the EXISTING,
    unchanged ``_verify_local_record_for_reliance`` — no new crypto path;
    (2) every record declares schemaVersion local-receipt-v4 with a
    well-formed dagRef; (3) an index evidenceId -> (stepIndex,
    evidenceHash, dagId) is built from records passing check 2 — a second
    record claiming an evidenceId already seen is a DUPLICATE NODE
    IDENTITY, flagged rather than silently overwritten; (3.5) any record
    whose OWN evidenceId is duplicated in the curated set is invalid
    (ambiguous node identity), and any record declaring a parent whose
    evidenceId is duplicated fails closed (an ambiguous parent can never
    be resolved to a specific evidenceHash/stepIndex — it is never
    treated as "whichever one was seen last"; this is what makes
    order-independence, check 6, safe); (4) dagId identical across every
    record; (5) stepIndex values are a set of distinct non-negative
    integers, dense from 0; (6) every parentEvidenceRefs entry must have
    an evidenceId present in the index and NOT duplicated, match its
    actual evidenceHash exactly, and have a stepIndex strictly less than
    the referencing record's own (the cycle-exclusion rule). Worst-of
    roll-up: the overall verificationStatus is the worst individual
    record status.

    **What this does NOT prove:** that the curated set is the DAG's
    complete history — same honesty boundary as ``verify_local_chain``.
    """
    if not records:
        return {
            "ok": False,
            "dagId": None,
            "nodes": 0,
            "nodesValid": 0,
            "graphLinked": False,
            "verificationStatus": "UNVERIFIABLE",
            "reason": "EMPTY_DAG: no records presented",
            "results": [],
        }

    crypto_results, payloads, schema_ok_flags, index, duplicate_evidence_ids = _dag_index_and_schema_flags(
        records, state_dir
    )

    results: list[dict[str, Any]] = []
    dag_ids: set[Any] = set()
    step_indices: list[Any] = []
    worst_status = "VERIFIED"
    nodes_valid = 0
    graph_linked = True
    reasons: list[str] = []

    for idx in range(len(records)):
        crypto_result = crypto_results[idx]
        payload = payloads[idx]
        schema_ok = schema_ok_flags[idx]
        dag_ref = payload.get("dagRef") if schema_ok else None

        node_ok = crypto_result["status"] == "VERIFIED"
        reason_parts: list[str] = []

        if not schema_ok:
            node_ok = False
            graph_linked = False
            reason_parts.append(
                f"record at index {idx} is not a local-receipt-v4 DAG node (missing/malformed dagRef)"
            )
        else:
            dag_ids.add(dag_ref["dagId"])
            step_indices.append(dag_ref["stepIndex"])
            own_evidence_id = payload.get("evidenceId")
            if isinstance(own_evidence_id, str) and own_evidence_id in duplicate_evidence_ids:
                node_ok = False
                graph_linked = False
                reason_parts.append(
                    f"record at index {idx} has evidenceId {own_evidence_id!r} which appears on "
                    "more than one record in the curated set — ambiguous node identity"
                )
            for parent_position, parent_ref in enumerate(dag_ref["parentEvidenceRefs"]):
                parent_id = parent_ref["evidenceId"]
                if parent_id in duplicate_evidence_ids:
                    node_ok = False
                    graph_linked = False
                    reason_parts.append(
                        f"record at index {idx} declares parent {parent_id!r} (position "
                        f"{parent_position}) whose evidenceId is ambiguous — it appears on more "
                        "than one record in the curated set, so it cannot be resolved"
                    )
                    continue
                parent_entry = index.get(parent_id)
                if parent_entry is None:
                    node_ok = False
                    graph_linked = False
                    reason_parts.append(
                        f"record at index {idx} declares parent {parent_id!r} (position "
                        f"{parent_position}) that is not present in the curated set"
                    )
                    continue
                parent_step_index, parent_evidence_hash, _parent_dag_id = parent_entry
                if parent_ref["evidenceHash"] != parent_evidence_hash:
                    node_ok = False
                    graph_linked = False
                    reason_parts.append(
                        f"record at index {idx} declares parent {parent_id!r} with an evidenceHash "
                        "that does not match that parent's actual evidenceHash in the curated set"
                    )
                if not (isinstance(parent_step_index, int) and parent_step_index < dag_ref["stepIndex"]):
                    node_ok = False
                    graph_linked = False
                    reason_parts.append(
                        f"record at index {idx} declares parent {parent_id!r} whose stepIndex does "
                        "not precede this record's own stepIndex — a cycle or a fabricated stepIndex"
                    )

        entry: dict[str, Any] = {
            "index": idx,
            "evidenceId": payload.get("evidenceId"),
            "dagRef": dag_ref,
            "verification": crypto_result,
            "nodeOk": node_ok,
        }
        if reason_parts:
            entry["reason"] = "; ".join(reason_parts)
        results.append(entry)

        if node_ok:
            nodes_valid += 1
        rank = _STATUS_RANK.get(crypto_result["status"], 2)
        if rank > _STATUS_RANK[worst_status]:
            worst_status = crypto_result["status"]
        if not node_ok:
            reasons.append(
                f"index {idx}: {'; '.join(reason_parts)}" if reason_parts else f"index {idx}: {crypto_result.get('cryptoCode')}"
            )

    if len(dag_ids) > 1:
        graph_linked = False
        reasons.append(f"records claim {len(dag_ids)} distinct dagIds — not one DAG")

    expected_indices = list(range(len(records)))
    if sorted(step_indices) != expected_indices:
        graph_linked = False
        reasons.append(
            f"stepIndex set {sorted(step_indices)} is not dense/distinct from 0 (expected "
            f"{expected_indices})"
        )

    ok = graph_linked and nodes_valid == len(records) and worst_status == "VERIFIED"
    reason = (
        "ALL_NODES_VERIFIED_AND_LINKED: every record verified and the DAG is intact"
        if ok
        else (" | ".join(reasons) if reasons else "one or more nodes failed verification")
    )

    return {
        "ok": ok,
        "dagId": next(iter(dag_ids), None) if len(dag_ids) == 1 else None,
        "nodes": len(records),
        "nodesValid": nodes_valid,
        "graphLinked": graph_linked,
        "verificationStatus": worst_status,
        "reason": reason,
        "results": results,
    }


__all__ = [
    "ATTESTATION_RECORD_MODE",
    "ATTESTATION_SCHEMA_VERSION",
    "ChainAttestationPolicy",
    "ChainSession",
    "DEFAULT_STATE_DIR",
    "DagSession",
    "DagSessionError",
    "LocalChainError",
    "LocalChainStep",
    "LocalDagStep",
    "LocalGovernedActionResult",
    "LocalSigningKey",
    "RelianceRequirement",
    "SCHEMA_VERSION_V3",
    "SCHEMA_VERSION_V4",
    "StrixLocalApprovalRequired",
    "StrixLocalChainPredecessorUnverified",
    "StrixLocalDagParentUnverified",
    "StrixLocalDenied",
    "StrixLocalError",
    "StrixLocalKeyError",
    "StrixLocalReceiptPersistenceError",
    "StrixLocalRelianceDenied",
    "evaluate_policy",
    "evaluate_reliance_local",
    "generate_or_load_key",
    "governed_action_local",
    "resolve_public_key",
    "verify_local_chain",
    "verify_local_dag",
]
