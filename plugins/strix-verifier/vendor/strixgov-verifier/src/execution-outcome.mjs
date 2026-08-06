import crypto from "node:crypto";

export const EXECUTION_OUTCOME_SCHEMA_VERSION = "1";
export const EXECUTION_OUTCOME_SIGNATURE_ALGORITHM = "Ed25519";

export const EXECUTION_OUTCOME_CORE_FIELD_ORDER = Object.freeze([
  "schemaVersion",
  "outcomeId",
  "authorizationReceiptId",
  "authorizationProofChainHash",
  "capabilityId",
  "action",
  "decision",
  "executionAttempted",
  "executionStatus",
  "invocationHash",
  "resultHash",
  "errorCode",
  "policyVersion",
  "tenantId",
  "environment",
  "completedAt",
  "signingKeyId",
  "signatureAlgorithm",
]);

export const EXECUTION_OUTCOME_FIELD_ORDER = Object.freeze([
  ...EXECUTION_OUTCOME_CORE_FIELD_ORDER,
  "outcomeHash",
]);

export const EXECUTION_OUTCOME_ALLOWED_FIELDS = Object.freeze([
  ...EXECUTION_OUTCOME_FIELD_ORDER,
  "signature",
]);

const STRING_FIELDS = Object.freeze([
  ...EXECUTION_OUTCOME_FIELD_ORDER.filter((field) => field !== "executionAttempted"),
]);

function orderedPayload(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label}: payload must be an object`);
  }
  return `{${fields
    .map((field) => {
      const fieldValue = value[field];
      if (fieldValue === undefined || fieldValue === null) {
        throw new Error(`${label}: required field '${field}' is missing`);
      }
      return `${JSON.stringify(field)}:${JSON.stringify(fieldValue)}`;
    })
    .join(",")}}`;
}

function matches(value, pattern) {
  return typeof value === "string" && pattern.test(value);
}

export function validateExecutionOutcomeRecord(outcome, opts = {}) {
  if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)) {
    throw new TypeError("validateExecutionOutcomeRecord: outcome must be an object");
  }

  const allowed = new Set(EXECUTION_OUTCOME_ALLOWED_FIELDS);
  for (const field of Object.keys(outcome)) {
    if (!allowed.has(field)) {
      throw new Error(
        `validateExecutionOutcomeRecord: unsupported field '${field}' is not signed by execution-outcome-v1`,
      );
    }
  }

  const required =
    opts.requireSignature === false
      ? EXECUTION_OUTCOME_FIELD_ORDER
      : EXECUTION_OUTCOME_ALLOWED_FIELDS;
  for (const field of required) {
    if (!(field in outcome) || outcome[field] === null || outcome[field] === undefined) {
      throw new Error(`validateExecutionOutcomeRecord: required field '${field}' is missing`);
    }
  }
  for (const field of STRING_FIELDS) {
    if (typeof outcome[field] !== "string") {
      throw new Error(`validateExecutionOutcomeRecord: field '${field}' must be a string`);
    }
  }
  if ("signature" in outcome && typeof outcome.signature !== "string") {
    throw new Error("validateExecutionOutcomeRecord: field 'signature' must be a string");
  }
  if (outcome.executionAttempted !== true) {
    throw new Error("validateExecutionOutcomeRecord: executionAttempted must be true");
  }
  if (outcome.schemaVersion !== EXECUTION_OUTCOME_SCHEMA_VERSION) {
    throw new Error(
      `validateExecutionOutcomeRecord: unsupported schemaVersion '${outcome.schemaVersion}'`,
    );
  }
  if (outcome.signatureAlgorithm !== EXECUTION_OUTCOME_SIGNATURE_ALGORITHM) {
    throw new Error(
      `validateExecutionOutcomeRecord: unsupported signatureAlgorithm '${outcome.signatureAlgorithm}'`,
    );
  }
  if (!matches(outcome.outcomeId, /^out_[A-Za-z0-9._-]+$/)) {
    throw new Error("validateExecutionOutcomeRecord: outcomeId is malformed");
  }
  for (const field of ["authorizationReceiptId", "capabilityId", "action", "policyVersion", "tenantId", "environment", "signingKeyId"]) {
    if (outcome[field].length === 0) {
      throw new Error(`validateExecutionOutcomeRecord: field '${field}' must not be empty`);
    }
  }
  if (!matches(outcome.authorizationProofChainHash, /^[0-9a-f]{64}$/)) {
    throw new Error(
      "validateExecutionOutcomeRecord: authorizationProofChainHash must be lowercase SHA-256 hex",
    );
  }
  if (!matches(outcome.invocationHash, /^[0-9a-f]{64}$/)) {
    throw new Error(
      "validateExecutionOutcomeRecord: invocationHash must be lowercase SHA-256 hex",
    );
  }
  if (!matches(outcome.outcomeHash, /^sha256:[0-9a-f]{64}$/)) {
    throw new Error(
      "validateExecutionOutcomeRecord: outcomeHash must use sha256:<lowercase-hex>",
    );
  }
  if (!matches(outcome.resultHash, /^(|sha256:[0-9a-f]{64})$/)) {
    throw new Error("validateExecutionOutcomeRecord: resultHash is malformed");
  }
  if (!Number.isFinite(Date.parse(outcome.completedAt))) {
    throw new Error("validateExecutionOutcomeRecord: completedAt must be an ISO-compatible date-time");
  }
  if ("signature" in outcome && !matches(outcome.signature, /^[A-Za-z0-9_-]+$/)) {
    throw new Error("validateExecutionOutcomeRecord: signature must be base64url text");
  }
  return true;
}

export function buildExecutionOutcomeCanonicalCore(outcome) {
  return orderedPayload(
    outcome,
    EXECUTION_OUTCOME_CORE_FIELD_ORDER,
    "buildExecutionOutcomeCanonicalCore",
  );
}

export function buildExecutionOutcomeCanonicalPayload(outcome) {
  return orderedPayload(
    outcome,
    EXECUTION_OUTCOME_FIELD_ORDER,
    "buildExecutionOutcomeCanonicalPayload",
  );
}

export function executionOutcomeHash(outcome) {
  return `sha256:${crypto
    .createHash("sha256")
    .update(buildExecutionOutcomeCanonicalCore(outcome))
    .digest("hex")}`;
}

function publicKeyFromJwk(jwk) {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error(`Unexpected key type: ${jwk?.kty}/${jwk?.crv}`);
  }
  const rawBytes = Buffer.from(jwk.x, "base64url");
  if (rawBytes.length !== 32) {
    throw new Error(`Unexpected Ed25519 public-key length: ${rawBytes.length}`);
  }
  const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({
    key: Buffer.concat([spkiHeader, rawBytes]),
    format: "der",
    type: "spki",
  });
}

function resolvePublicKeys(outcome, options) {
  if (options.publicKey) return [options.publicKey];
  const keys = options.jwks?.keys ?? [];
  const matches = keys.filter(
    (jwk) =>
      typeof jwk.kid === "string" &&
      jwk.kid.toLowerCase() === String(outcome.signingKeyId).toLowerCase(),
  );
  return matches.map(publicKeyFromJwk);
}

/**
 * Offline verifier for a signed post-execution outcome.
 *
 * Checks are reported independently: schema, outcome hash, key resolution,
 * signature, execution-state consistency, and authorization-receipt linkage.
 */
export function verifyExecutionOutcomeRecord(outcome, options = {}) {
  const result = {
    outcomeId: outcome?.outcomeId,
    schemaValid: false,
    hashValid: false,
    signaturePresent: !!outcome?.signature,
    signatureValid: false,
    keyResolved: false,
    linkValid: options.authorizationReceipt ? false : null,
    consistencyValid: false,
    verificationStatus: "ERROR",
    error: null,
  };

  try {
    validateExecutionOutcomeRecord(outcome, { requireSignature: false });
    result.schemaValid = true;

    result.hashValid = executionOutcomeHash(outcome) === outcome.outcomeHash;
    result.consistencyValid =
      outcome.decision === "ALLOW" &&
      outcome.executionAttempted === true &&
      ["SUCCEEDED", "FAILED", "UNKNOWN"].includes(outcome.executionStatus) &&
      (outcome.executionStatus !== "SUCCEEDED" ||
        matches(outcome.resultHash, /^sha256:[0-9a-f]{64}$/)) &&
      (outcome.executionStatus !== "FAILED" || outcome.errorCode.length > 0) &&
      (outcome.executionStatus === "FAILED" || outcome.errorCode === "") &&
      (outcome.executionStatus === "SUCCEEDED" || outcome.resultHash === "");

    const authorization = options.authorizationReceipt;
    if (authorization) {
      result.linkValid =
        authorization.decision === "ALLOW" &&
        outcome.authorizationReceiptId === authorization.receiptId &&
        outcome.authorizationProofChainHash === authorization.proofChainHash &&
        outcome.capabilityId === authorization.capabilityId &&
        outcome.action === authorization.action &&
        outcome.invocationHash === authorization.invocationHash &&
        outcome.policyVersion === authorization.policyVersion &&
        outcome.tenantId === authorization.tenantId &&
        outcome.environment === authorization.environment;
    }

    if (!outcome.signature) {
      result.verificationStatus = "UNSIGNED";
      return result;
    }

    const publicKeys = resolvePublicKeys(outcome, options);
    result.keyResolved = publicKeys.length > 0;
    if (!result.keyResolved) {
      result.verificationStatus = "KEY_NOT_FOUND";
      return result;
    }

    const payload = Buffer.from(buildExecutionOutcomeCanonicalPayload(outcome), "utf8");
    const signature = Buffer.from(outcome.signature, "base64url");
    result.signatureValid = publicKeys.some((key) =>
      crypto.verify(null, payload, key, signature),
    );

    const linkOk = result.linkValid === null || result.linkValid === true;
    if (
      result.schemaValid &&
      result.hashValid &&
      result.signatureValid &&
      result.consistencyValid &&
      linkOk
    ) {
      result.verificationStatus = "VERIFIED";
    } else if (!result.hashValid) {
      result.verificationStatus = "HASH_MISMATCH";
    } else if (!result.signatureValid) {
      result.verificationStatus = "SIGNATURE_INVALID";
    } else if (!result.consistencyValid) {
      result.verificationStatus = "INCONSISTENT";
    } else {
      result.verificationStatus = "AUTHORIZATION_LINK_INVALID";
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    result.verificationStatus = "ERROR";
  }

  return result;
}
