import {
  fetchEvidence,
  fetchPublicKeys,
  buildCanonicalPayload,
  verifySignature,
} from "./index.mjs";
import {
  buildEvidenceVerificationContract,
  SE_V1_SIGNATURE_ALGORITHM,
} from "./evidence-contract.mjs";

/**
 * Truthful Signed Evidence v1 verifier.
 *
 * This function performs record retrieval, JWKS key resolution, canonical
 * envelope reconstruction, and Ed25519 verification. It does not claim to
 * recompute the underlying decision-content hash or traverse the evidence
 * chain unless callers independently supply those results.
 */
export async function verifyEvidenceV2(evidenceId, options = {}) {
  const proofBase = options.proofBase;
  const jwksBase = options.jwksBase;
  let record = null;

  try {
    record = await fetchEvidence(evidenceId, proofBase);
    const signaturePresent = Boolean(record.signature);
    const signingKeyId = typeof record.signingKeyId === "string" ? record.signingKeyId : null;

    if (!signaturePresent || !signingKeyId) {
      const status = record.signatureFailureReason ? "UNAVAILABLE_RUNTIME" : "LEGACY_UNSIGNED";
      return {
        evidenceId,
        record,
        verificationContract: buildEvidenceVerificationContract({
          status,
          signaturePresent,
          signatureValid: false,
          signingKeyId,
          signatureAlgorithm: null,
          resolvedKeyCandidateCount: null,
          evidenceHash: record.evidenceHash ?? null,
          proofChainHash: record.proofChainHash ?? null,
        }),
      };
    }

    let publicKeys;
    try {
      publicKeys = await fetchPublicKeys(signingKeyId, jwksBase);
    } catch (error) {
      return {
        evidenceId,
        record,
        error: error instanceof Error ? error.message : String(error),
        verificationContract: buildEvidenceVerificationContract({
          status: "SIGNING_KEY_UNKNOWN",
          signaturePresent: true,
          signatureValid: false,
          signingKeyId,
          signatureAlgorithm: SE_V1_SIGNATURE_ALGORITHM,
          resolvedKeyCandidateCount: 0,
          evidenceHash: record.evidenceHash ?? null,
          proofChainHash: record.proofChainHash ?? null,
        }),
      };
    }

    const canonical = buildCanonicalPayload(record);
    const signatureValid = publicKeys.some((publicKey) =>
      verifySignature(canonical, record.signature, publicKey),
    );

    const verificationContract = buildEvidenceVerificationContract({
      status: signatureValid ? "VERIFIED" : "SIGNATURE_INVALID",
      signaturePresent: true,
      signatureValid,
      signingKeyId,
      signatureAlgorithm: record.signatureAlgorithm ?? SE_V1_SIGNATURE_ALGORITHM,
      resolvedKeyCandidateCount: publicKeys.length,
      evidenceHash: record.evidenceHash ?? null,
      recomputedEvidenceHash: options.recomputedEvidenceHash ?? null,
      proofChainHash: record.proofChainHash ?? null,
      expectedProofChainHash: options.expectedProofChainHash ?? null,
      fullChainValid: options.fullChainValid ?? null,
    });

    return {
      evidenceId,
      record,
      canonicalPayload: canonical,
      verificationContract,
      verified: verificationContract.verificationStatus === "FULLY_VERIFIED",
      envelopeVerified: verificationContract.verificationStatus === "ENVELOPE_VERIFIED" || verificationContract.verificationStatus === "FULLY_VERIFIED",
    };
  } catch (error) {
    return {
      evidenceId,
      record,
      error: error instanceof Error ? error.message : String(error),
      verificationContract: buildEvidenceVerificationContract({
        status: "NOT_FOUND",
        signaturePresent: false,
        signatureValid: false,
        signingKeyId: null,
      }),
    };
  }
}
