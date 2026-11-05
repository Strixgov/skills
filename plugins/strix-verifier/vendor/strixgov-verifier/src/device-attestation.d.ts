/**
 * Type declarations for the AA-2 (Device Attestation v1) verifier.
 *
 * Hand-written rather than generated: the module is dependency-free ESM whose
 * runtime behaviour is pinned by the 15-vector conformance corpus, and adding
 * a build step to a package whose whole value is "you can read every line of
 * it" would be the wrong trade. These declarations describe the surface a
 * TypeScript consumer uses; the corpus is what proves the surface behaves.
 */

export type DeviceClass = 'browser' | 'mobile_ios' | 'mobile_android';
export type AttestationProtocol =
  | 'webauthn'
  | 'app_attest_ios'
  | 'play_integrity_android';

export interface DeviceAttestationRecord {
  payload: Record<string, unknown>;
  kid: string;
  signature: string;
  created_at?: string;
}

export interface DeviceAttestationVerification {
  /** `true`, `false`, or `null` — null means COULD NOT CHECK, never checked-and-wrong. */
  valid: boolean | null;
  failingRule: string | null;
  reason: string | null;
}

/**
 * What `renderDeviceClassBlock` ACTUALLY returns.
 *
 * CORRECTED 2026-09-06. This declaration previously read
 * `{ attested, verified, reason, deviceClass, attestationProtocol }` — a shape
 * the implementation has never produced. `device-attestation.mjs` returns
 * `claimedClass` / `verificationReason` and no `attested` field at all, and
 * because this `.d.ts` is hand-written alongside a `.mjs` module with nothing
 * keeping the two in step, the declaration was simply wrong and TypeScript
 * repeated it to every consumer as fact.
 *
 * The cost was real and downstream: strix-platform's console wrote its badge
 * against the declared shape (correctly, given what the types said), bridged
 * the two with an `as` assertion that looked like a same-shape cast, and so
 * read `attested` as `undefined` at runtime. `undefined` is falsy, the badge
 * branches on it, and a VERIFIED attestation and a REJECTED one both rendered
 * as "No device attestation" — the two outcomes AA-2 exists to distinguish,
 * collapsed into the one that says nothing happened.
 *
 * Two naming choices here are deliberate rather than cosmetic:
 *
 * - `claimedClass`, not `deviceClass`. It is the class the attestation
 *   payload CLAIMS. A consumer must not present it as established until
 *   `verified === true`.
 * - There is no `attested`. This function cannot know whether an attestation
 *   was present — it renders the same all-null block for "no record" and for
 *   "a record with nothing resolvable". Only a caller holding the record can
 *   tell those apart, so that field belongs to the caller's own type, never
 *   to this one.
 */
export interface DeviceClassBlock {
  claimedClass: DeviceClass | null;
  verified: boolean | null;
  verificationReason: string | null;
  attestationProtocol: AttestationProtocol | null;
}

export interface VerifyDeviceAttestationDeps {
  signatureVerifier?: (
    payloadBytes: Uint8Array,
    signatureBytes: Uint8Array,
    publicKeyBytes: Uint8Array,
  ) => boolean;
  jwks?: unknown;
  boundEvidenceTenant?: string;
  boundEvidenceOccurredAt?: string | null;
  freshnessWindowSeconds?: number;
  /**
   * Called as `resolver({ deviceId })` — an OBJECT, matching the
   * implementation. This declaration previously said `(deviceId: string)`,
   * which disagreed with the code it declares. Nothing caught it because no
   * caller supplied a resolver, so rule 9 was skipped everywhere: a wrong type
   * on a parameter nobody passes is invisible until the first real caller, and
   * then it fails as "substrate permanently unavailable" rather than as a
   * wiring error.
   *
   * Synchronous by design. Callers needing I/O resolve the status first and
   * hand in an already-known value.
   */
  deviceRevocationResolver?: ((args: { deviceId: string }) => string) | null;
  /** Defaults to 'reserved' — the fail-closed capability gate. */
  capabilityStatus?: 'reserved' | 'active' | 'retired';
}

export declare const DEVICE_CLASS: Readonly<Record<string, DeviceClass>>;
export declare const ATTESTATION_PROTOCOL: Readonly<Record<string, AttestationProtocol>>;
export declare const VERIFIER_RULE: Readonly<Record<string, string>>;
export declare const DEVICE_CLASS_REASON: Readonly<Record<string, string>>;
export declare const DEVICE_REVOCATION_STATUS: Readonly<Record<string, string>>;
export declare const REQUIRED_PAYLOAD_FIELDS: readonly string[];
export declare const AA_2: string;
export declare const VALID_DEVICE_PROTOCOL_PAIRS: readonly (readonly [DeviceClass, AttestationProtocol])[];
export declare const SUBSTRATE_ERROR_REASONS: readonly string[];

export declare function deviceClassMatchesProtocol(
  deviceClass: string,
  attestationProtocol: string,
): boolean;
export declare function canonicalPayloadBytes(payload: unknown): Uint8Array;
export declare function payloadHash(payload: unknown): string;
export declare function buildDeviceAttestationPayload(input: Record<string, unknown>): Record<string, unknown>;
export declare function verifyDeviceAttestation(
  record: DeviceAttestationRecord,
  deps?: VerifyDeviceAttestationDeps,
): DeviceAttestationVerification;
export declare function ed25519SignatureVerifier(
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
  publicKeyBytes: Uint8Array,
): boolean;
export declare function renderDeviceClassBlock(
  attestationRecord: DeviceAttestationRecord | null | undefined,
  verification: DeviceAttestationVerification | null | undefined,
): DeviceClassBlock;
