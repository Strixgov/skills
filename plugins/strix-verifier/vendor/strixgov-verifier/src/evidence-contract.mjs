export const SE_V1_SIGNATURE_ALGORITHM = "Ed25519";
export const EVIDENCE_VERIFICATION_CONTRACT_VERSION = 2;

const c = (status, performed, valid, reason) => ({ status, performed, valid, reason });
const pass = (reason) => c("PASS", true, true, reason);
const fail = (reason) => c("FAIL", true, false, reason);
const np = (reason) => c("NOT_PERFORMED", false, null, reason);
const na = (reason) => c("NOT_APPLICABLE", false, null, reason);

export function buildEvidenceVerificationContract(input) {
  const present = Boolean(input.signaturePresent);
  const declaredAlgorithm = present ? (input.signatureAlgorithm ?? SE_V1_SIGNATURE_ALGORITHM) : null;
  const algorithm = present
    ? (declaredAlgorithm === SE_V1_SIGNATURE_ALGORITHM
      ? { ...pass("The record algorithm is Ed25519, the algorithm fixed by Signed Evidence v1."), declared: declaredAlgorithm, expected: SE_V1_SIGNATURE_ALGORITHM }
      : { ...fail(`Unsupported Signed Evidence algorithm: ${declaredAlgorithm ?? "missing"}.`), declared: declaredAlgorithm, expected: SE_V1_SIGNATURE_ALGORITHM })
    : { ...na("Unsigned records do not declare a signature algorithm."), declared: null, expected: SE_V1_SIGNATURE_ALGORITHM };

  const countKnown = typeof input.resolvedKeyCandidateCount === "number";
  const keyResolution = !present
    ? { ...na("Unsigned records do not require public-key resolution."), keyId: input.signingKeyId ?? null, candidateCount: null }
    : !countKnown
      ? { ...np("Public-key resolution outcome was not independently supplied."), keyId: input.signingKeyId ?? null, candidateCount: null }
      : input.resolvedKeyCandidateCount > 0
        ? { ...pass("At least one trusted public-key candidate was resolved for the declared key ID."), keyId: input.signingKeyId ?? null, candidateCount: input.resolvedKeyCandidateCount }
        : { ...fail("No trusted public key was resolved for the declared key ID."), keyId: input.signingKeyId ?? null, candidateCount: 0 };

  const signature = !present
    ? { ...na("No signature is present on this record."), present: false, algorithm: null, keyId: input.signingKeyId ?? null }
    : algorithm.status !== "PASS" || keyResolution.status !== "PASS"
      ? { ...np("Signature verification cannot be asserted until algorithm and key resolution pass."), present: true, algorithm: declaredAlgorithm === SE_V1_SIGNATURE_ALGORITHM ? SE_V1_SIGNATURE_ALGORITHM : null, keyId: input.signingKeyId ?? null }
      : { ...(input.signatureValid ? pass("Ed25519 verification succeeded against a resolved public key.") : fail("Ed25519 verification did not succeed against any resolved public key.")), present: true, algorithm: SE_V1_SIGNATURE_ALGORITHM, keyId: input.signingKeyId ?? null };

  const authenticated = signature.status === "PASS";
  const signedEnvelope = present ? (authenticated ? pass("The frozen Signed Evidence v1 canonical envelope is authenticated by the signature.") : fail("The frozen Signed Evidence v1 canonical envelope is not authenticated.")) : na("No signed envelope exists for an unsigned record.");
  const evidenceHashAuthenticated = present ? (authenticated ? pass("The stored evidenceHash value is authenticated as a field inside the signed envelope.") : fail("The stored evidenceHash value is not authenticated.")) : na("An unsigned record cannot authenticate its evidenceHash field.");
  const evidenceHashValid = typeof input.recomputedEvidenceHash === "string" && typeof input.evidenceHash === "string"
    ? (input.recomputedEvidenceHash === input.evidenceHash ? pass("The underlying evidence content was independently hashed and matches the committed evidenceHash.") : fail("The independently recomputed evidence hash does not match the committed evidenceHash."))
    : np("The underlying decision-content inputs were not supplied, so evidenceHash derivation was not independently recomputed.");
  const carriesChain = typeof input.proofChainHash === "string" && input.proofChainHash.length > 0;
  const chainLinkAuthenticated = carriesChain ? (authenticated ? pass("The proofChainHash value is authenticated as a field inside the signed envelope.") : fail("The proofChainHash value is not authenticated.")) : na("This record does not carry a proof-chain link.");
  const chainLinkValid = carriesChain && typeof input.expectedProofChainHash === "string"
    ? (input.proofChainHash === input.expectedProofChainHash ? pass("The stored proofChainHash matches the independently derived predecessor link.") : fail("The stored proofChainHash does not match the independently derived predecessor link."))
    : carriesChain ? np("The predecessor-derived chain hash was not supplied, so chain-link continuity was not checked.") : na("This record does not participate in a proof chain.");
  const fullChainValid = typeof input.fullChainValid === "boolean"
    ? (input.fullChainValid ? pass("The evidence chain was traversed and verified for the requested scope.") : fail("Evidence-chain traversal detected a broken, missing, or invalid link."))
    : np("A genesis-to-record evidence-chain traversal was not performed.");

  const checks = { keyResolution, algorithm, signature, signedEnvelope, evidenceHashAuthenticated, evidenceHashValid, chainLinkAuthenticated, chainLinkValid, fullChainValid };
  const out = (verificationStatus, recordType, verificationReason) => ({ contractVersion: EVIDENCE_VERIFICATION_CONTRACT_VERSION, recordType, verificationStatus, verificationReason, checks });
  if (input.status === "NOT_FOUND") return out("NOT_FOUND", "legacy_unsigned_evidence", "No evidence record was found.");
  if (input.status === "LEGACY_UNSIGNED") return out("LEGACY_UNSIGNED", "legacy_unsigned_evidence", "The record is retained as legacy evidence but has no cryptographic signature.");
  if (input.status === "UNAVAILABLE_RUNTIME") return out("UNAVAILABLE_RUNTIME", "unavailable_runtime_evidence", "Runtime signing was unavailable. No signature, hash-derivation, or chain-continuity claim is implied.");
  if (algorithm.status === "FAIL") return out("UNSUPPORTED_ALGORITHM", "signed_evidence_v1", "The record declares an algorithm outside the Signed Evidence v1 contract.");
  if (keyResolution.status === "FAIL") return out("SIGNING_KEY_UNKNOWN", "signed_evidence_v1", "No trusted public key could be resolved for the declared key ID.");
  if (Object.values(checks).some((x) => x.status === "FAIL")) return out("INVALID", "signed_evidence_v1", "One or more performed verification layers failed.");
  const full = evidenceHashValid.status === "PASS" && (chainLinkValid.status === "PASS" || chainLinkValid.status === "NOT_APPLICABLE") && fullChainValid.status === "PASS";
  if (full) return out("FULLY_VERIFIED", "signed_evidence_v1", "Key resolution, algorithm, signature, independent evidence-hash derivation, and evidence-chain verification all passed.");
  if (authenticated) return out("ENVELOPE_VERIFIED", "signed_evidence_v1", "The Signed Evidence v1 envelope is authentic. Independent evidence-hash derivation and/or chain traversal were not performed.");
  return out("INVALID", "signed_evidence_v1", "The signed evidence record could not be cryptographically authenticated.");
}
