//! Canonical native Falcon-512 blind issuance for Bootle/Lantern credentials.
//!
//! The first-release lifecycle is deliberately closed: generate a concrete Falcon/NTRU issuer key,
//! derive its governed policy, prove a blinded holder request, verify and sign that request, then
//! let the holder independently finalize and validate the credential before any presentation proof
//! is produced. There is no direct or trusted-issuance shortcut.
#[cfg(any(test, feature = "test-utils"))]
pub use super::issuance_store::BootleLanternInMemoryIssuanceStoreV1;
pub use super::issuance_store::{
    BootleLanternFileIssuanceStoreV1, BootleLanternIssuanceClaimV1,
    BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreConfigV1,
    BootleLanternIssuanceStoreErrorV1, BootleLanternIssuanceStoreV1,
};
use super::{
    codec::{
        BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1, BLIND_ISSUANCE_REQUEST_BYTES_V1,
        BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1, BLIND_ISSUANCE_REQUEST_MAGIC_V1,
        BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1, BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1,
        BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1, BLIND_ISSUANCE_REQUEST_VERSION_V1,
        BLIND_ISSUANCE_RESPONSE_BYTES_V1, PROOF_BYTES_V1,
    },
    credential_sampling::{
        BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1, CredentialRandomnessErrorV1,
        sample_credential_randomness_v1,
    },
    falcon512::{self, DEGREE as FALCON_DEGREE_V1, Trapdoor},
    params::{APPLICATION_MODULUS_V1, APPLICATION_RING_DEGREE_V1, APPLICATION_ROWS_V1},
    proof::{
        PresentationProofErrorV1, prove_blind_issuance_request_v1, verify_blind_issuance_request_v1,
    },
    randomness::BootleLanternIssuanceRandomnessRootV1,
    relation::{
        BootleLanternApplicationRelationV1, BootleLanternPresentationWitnessV1, RelationErrorV1,
        compile_application_relation_v1, compile_blind_issuance_request_relation_v1,
        validate_presentation_witness_v1,
    },
    ring::ApplicationPolynomialV1,
    scope::{BootleLanternCredentialScopeV1, CredentialScopeErrorV1},
    transcript::{
        BlindIssuanceRequestChallengeBindingV1, BlindIssuanceRequestTranscriptV1, MatrixRoleV1,
        TranscriptErrorV1, expand_application_matrix_v1, matrix_seed_v1,
    },
};
use crate::privacy_engines::prover_randomness::{
    HealthCheckedCryptoRngV1, ProverRandomnessErrorV1,
};
use iroha_data_model::{
    NetworkId,
    privacy::{
        BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BootleLanternAllowedAttributeValuesV1,
        BootleLanternAttributeValueV1, BootleLanternDisclosedAttributeV1,
        BootleLanternIssuerPolicyLifecycleV1, BootleLanternIssuerPolicyV1,
        BootleLanternIssuerPublicMatrixV1, BootleLanternPolynomialV1,
        IrohaBootleLanternAnoncredStatementV1, PrivacyBootleLanternIssuerPolicyDigestV1,
        PrivacyIssuerIdV1, PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPolicyIdV1,
        PrivacyStatementContextV1,
    },
};
use rand_core_06::{CryptoRng, OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Exact concrete issuer profile committed by compiled privacy metadata.
pub const BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1: &[u8] = b"falcon512-ntru-r512-as-r64-rank8-interleaved|source:rust-fn-dsa-workspace-0.3-daf14859b5aa3f8d75c42966ba7de83e6eb59997-Unlicense|specialization:BLNS-specialization-no-main-construction-reduction|public-key:H_i[j]=h[8*j+i]|equation:s1+h*s2=t+A_tau*tau+credential-scope|keygen-seed:exact-nonzero-32-byte-secret-or-health-checked-CSPRNG|keygen-candidates:4096|authorization-id-draws:4|authorization-lifetime-blocks<=4096|authorization-state:Fresh-Processing-Completed-or-Failed|issuance-store:bounded-strict-ILS1-file-store+canonical-process-lease+held-unix-exclusive-flock+atomic-sync-rename+explicit-height-pruning|preimage-attempts:64|tau:one-purpose-derived-64-byte-stream-eight-R64-MSB-first|preimage-rng:purpose-derived-56-byte-Falcon-ChaCha20-word-major|issuance-rng:one-health-checked-master64-per-holder-or-issuer-operation+closed-context-bound-SHAKE256-substreams|canonical-flow:keygen-provider-prepare-ILA1+torii-only-register-request-ILQ1-with-ILB1-torii-preflight-public-P1+provider-key-validation-atomic-height-claim-provider-independent-revalidation-before-RNG-issue-local-ILR1-revalidation-durable-complete-or-fail-finalize-ILN1|broker-binding:exact-handle+revision+policy-digest+issuer-id+policy-id+lifetime+same-service-uid|completed-retry-before-provider-call-after-process-reopen-and-independent-of-expiry|no-direct-issuance";
/// Exact peer-1 Taira broker contract committed by provider qualification.
///
/// This descriptor is shared by the broker and the native release composer so
/// neither executable can silently redefine the slot, operations, custody,
/// authentication, RNG, replay, export, or lifecycle contract.
pub const TAIRA_BOOTLE_LANTERN_BROKER_CONTRACT_V1: &[u8] = b"binary:taira_bootle_lantern_broker|slot:55|operations:authenticate=119,prepare-authorization=120,validate-request=121,issue-validated=122|transport:stock-runtime-provider-broker-v1-same-service-uid|credentials:three-explicit-systemd-encrypted-or-container-read-only-bind-files+nofollow+effective-service-owner-or-exact-unit-systemd-root-owner+mode0400+single-link+bounded-read+immutable-opened-snapshot|authentication:opaque-bearer-domain-hash+constant-time-fixed-digest-compare+stable-principal-seed+bounded-nonzero-request-context+exact-height-lifetime|issuer:native-falcon512-key-from-exact-seed|rng:core-owned-rand_core_06-OsRng-per-prepare-or-issue|policy:epoch1-active+no-required-disclosures+eight-empty-allowlists|public-export:canonical-InstructionBox-registration-bytes+sha256+complete-public-policy-json|state:torii-only-preflight-claim-complete-fail|lifecycle:joined-SIGINT+SIGTERM-orderly-cleanup|first-release:no-legacy-or-direct-issuance";
/// Exact authorization/request/response wire contract owned by this implementation.
///
/// Header validation establishes the structural message purpose. Complete cryptographic purpose
/// separation additionally comes from the self-digest, request transcript, scope, policy, and
/// request-digest checks; a structurally valid same-shape splice is rejected by those bindings
/// rather than by a claim that structural decoding alone rejects every splice.
pub(crate) const BOOTLE_LANTERN_ISSUANCE_WIRE_DESCRIPTOR_V1: &[u8] = b"ILA1:fixed320|header:magic=ILA1,version-u8=1,flags-u8=0,reserved-u16be=0|fields:authorization-id[32],issuer-profile-digest[32],canonical-genesis-hash[32],credential-scope-digest[32],policy-record-digest[32],issuer-parameter-id[32],issuer-parameter-digest[32],policy-epoch-u64be,requester-authorization-digest[32],issued-at-height-u64be,expires-at-height-u64be,authorization-digest[32]|canonical:exact-length,nonzero-bindings,active-profile,lifetime=1..4096,self-digest=SHA256(domain+u64be-length-framed-fields);ILQ1:fixed71576|header:magic=ILQ1,version-u8=1,purpose-u8=1,reserved-u16be=0,target-count-u16be=8,ring-degree-u16be=64,proof-length-u32be=70344|fields:target[8][64]-u16be,target-digest[32],issuance-authorization-digest[32],scope-digest[32],issuer-profile-digest[32],policy-record-digest[32],proof[70344]=strict-ILB1,request-digest[32]|canonical:caller-cap-before-exact-length-before-allocation,exact-counts,target-residues<12289,nonzero-bindings,self-digests,no-trailing-bytes;ILR1:fixed3176|header:magic=ILR1,version-u8=1,flags-u8=0,reserved-u16be=0|fields:tag[8][64]-u16be,signature-one[8][64]-u16be,signature-two[8][64]-u16be,request-digest[32],scope-digest[32],policy-record-digest[32]|canonical:exact-length,tag-in-{0,1},signature-residues<12289,nonzero-bindings|purpose-separation:header-structural-plus-cryptographic-bound-digests-and-transcript";
/// Maximum complete Falcon/NTRU key candidates derived from one seed.
pub const MAX_BOOTLE_LANTERN_ISSUER_KEYGEN_CANDIDATES_V1: u32 =
    falcon512::BOOTLE_LANTERN_FALCON512_DEFAULT_KEYGEN_CANDIDATES_V1;
/// Maximum non-zero, collision-free authorization identifiers sampled.
pub const MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1: u32 = 4;
/// Maximum lifetime of one issuance authorization in block heights.
pub const MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1: u64 = 4_096;
/// Maximum independent Falcon sampler-coin draws for one fixed target.
pub const MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1: u32 = 64;
const ISSUER_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.issuer-profile-digest.v1";
const TAIRA_QUALIFICATION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.taira.privacy.bootle-lantern.provider-qualification.v1";
const TAIRA_CONTRACT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.taira.privacy.bootle-lantern.broker-contract-digest.v1";
const TAIRA_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.taira.privacy.bootle-lantern.issuer-profile-digest.v1";
const MASKED_TARGET_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.masked-target-digest.v1";
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.blind-request-digest.v1";
const AUTHORIZATION_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.issuance-authorization-digest.v1";
const AUTHORIZATION_MAGIC_V1: [u8; 4] = *b"ILA1";
const AUTHORIZATION_VERSION_V1: u8 = 1;
const AUTHORIZATION_HEADER_BYTES_V1: usize = 8;
const RESPONSE_MAGIC_V1: [u8; 4] = *b"ILR1";
const RESPONSE_VERSION_V1: u8 = 1;
const RESPONSE_HEADER_BYTES_V1: usize = 8;
const BLIND_ISSUANCE_REQUEST_BINDING_FIELDS_V1: usize = 5;
/// Public governance metadata used to derive one active issuer policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootleLanternIssuerPolicyMetadataV1 {
    /// Credential issuer governed by the new record.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Stable policy identity in the issuer namespace.
    pub policy_id: PrivacyPolicyIdV1,
    /// Exact non-zero policy/key epoch.
    pub epoch: u64,
    /// Attributes every presentation must disclose.
    pub required_disclosure_bitmap: u8,
    /// Fixed-order allowed public values for all eight attributes.
    pub allowed_values: Vec<BootleLanternAllowedAttributeValuesV1>,
}
/// Public inputs committed by the peer-1 Taira provider qualification digest.
#[derive(Clone, Copy, Debug)]
pub struct TairaBootleLanternBrokerQualificationInputsV1<'a> {
    /// Exact genesis-header-derived network identity advertised by the broker handshake.
    pub network_id: NetworkId,
    /// Exact production runtime-provider handle.
    pub runtime_provider_handle: &'a str,
    /// Non-zero provider-policy revision.
    pub runtime_provider_revision: u64,
    /// Governed issuer identity.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Governed issuer-policy identity.
    pub policy_id: PrivacyPolicyIdV1,
    /// Exact authorization lifetime in committed block heights.
    pub authorization_lifetime_blocks: u64,
    /// Complete canonical active epoch-one issuer policy.
    pub policy: &'a BootleLanternIssuerPolicyV1,
    /// Stable public requester-principal commitment, independent of bearer rotation.
    pub stable_principal_digest: [u8; 32],
}
/// Failure while deriving the shared peer-1 Taira provider qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TairaBootleLanternBrokerQualificationErrorV1 {
    /// A chain, provider, identity, lifetime, or principal binding was invalid.
    #[error("Taira Bootle/Lantern broker qualification binding is invalid")]
    InvalidPublicBinding,
    /// The governed issuer policy was not a valid active epoch-one record for the binding.
    #[error("Taira Bootle/Lantern broker qualification policy is invalid")]
    InvalidIssuerPolicy,
    /// Canonical encoding of the governed issuer policy failed.
    #[error("Taira Bootle/Lantern broker qualification policy encoding failed")]
    PolicyEncodingFailed,
    /// A derived public digest was structurally weak.
    #[error("Taira Bootle/Lantern broker qualification digest is degenerate")]
    DegenerateDigest,
}
/// Issuer-generated bearer authorization for exactly one blind issuance.
///
/// The authorization is integrity-bound to the issuer implementation, chain genesis, reusable
/// credential scope, active policy/key epoch, external requester authorization, and a bounded
/// block-height lifetime. Its fields are private so callers cannot fabricate or rewrite it.
#[derive(Clone, PartialEq, Eq)]
pub struct BootleLanternIssuanceAuthorizationV1 {
    authorization_id: [u8; 32],
    issuer_profile_digest: [u8; 32],
    canonical_genesis_hash: [u8; 32],
    credential_scope_digest: [u8; 32],
    policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
    issuer_parameter_id: PrivacyParameterIdV1,
    issuer_parameter_digest: PrivacyParameterDigestV1,
    policy_epoch: u64,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
    authorization_digest: [u8; 32],
}
impl core::fmt::Debug for BootleLanternIssuanceAuthorizationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootleLanternIssuanceAuthorizationV1")
            .field("authorization_digest", &self.authorization_digest)
            .field("issued_at_height", &self.issued_at_height)
            .field("expires_at_height", &self.expires_at_height)
            .finish_non_exhaustive()
    }
}
impl BootleLanternIssuanceAuthorizationV1 {
    /// Unique identifier used by the authoritative one-shot issuance store.
    #[must_use]
    pub const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
    /// Digest bound into the holder's request and P1 transcript.
    #[must_use]
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }
    /// Digest of the authenticated external requester principal.
    ///
    /// Issuers use this binding to require that the principal presenting an
    /// `ILA1` authorization is the same principal for which it was minted.
    #[must_use]
    pub const fn requester_authorization_digest(&self) -> [u8; 32] {
        self.requester_authorization_digest
    }
    /// First block height at which this authorization is valid.
    #[must_use]
    pub const fn issued_at_height(&self) -> u64 {
        self.issued_at_height
    }
    /// Inclusive last height at which an issuer may atomically claim it.
    #[must_use]
    pub const fn expires_at_height(&self) -> u64 {
        self.expires_at_height
    }
    /// Encode the unique fixed-width holder-facing `ILA1` wire.
    ///
    /// # Errors
    ///
    /// Rejects every internally inconsistent or non-canonical authorization.
    pub fn encode(&self) -> Result<Vec<u8>, BootleLanternIssuanceErrorV1> {
        validate_issuance_authorization_self_v1(self)?;
        let mut bytes = Vec::with_capacity(BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1);
        bytes.extend_from_slice(&AUTHORIZATION_MAGIC_V1);
        bytes.push(AUTHORIZATION_VERSION_V1);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        for field in [
            self.authorization_id.as_slice(),
            self.issuer_profile_digest.as_slice(),
            self.canonical_genesis_hash.as_slice(),
            self.credential_scope_digest.as_slice(),
            self.policy_record_digest.as_bytes().as_slice(),
            self.issuer_parameter_id.as_bytes().as_slice(),
            self.issuer_parameter_digest.as_bytes().as_slice(),
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&self.policy_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.requester_authorization_digest);
        bytes.extend_from_slice(&self.issued_at_height.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_height.to_be_bytes());
        bytes.extend_from_slice(&self.authorization_digest);
        if bytes.len() != BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1 {
            return Err(BootleLanternIssuanceErrorV1::InternalInvariant);
        }
        Ok(bytes)
    }
    /// Decode exactly one canonical fixed-width `ILA1` authorization.
    ///
    /// # Errors
    ///
    /// Rejects every wrong length, magic, version, flag/reserved byte, zero field, invalid
    /// lifetime, altered digest, trailing byte, or alternate representation.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, BootleLanternIssuanceErrorV1> {
        if bytes.len() != BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1
            || bytes[..4] != AUTHORIZATION_MAGIC_V1
            || bytes[4] != AUTHORIZATION_VERSION_V1
            || bytes[5] != 0
            || bytes[6..8] != [0, 0]
        {
            return Err(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid);
        }
        let mut offset = AUTHORIZATION_HEADER_BYTES_V1;
        let authorization_id = take_32_v1(bytes, &mut offset)?;
        let issuer_profile_digest = take_32_v1(bytes, &mut offset)?;
        let canonical_genesis_hash = take_32_v1(bytes, &mut offset)?;
        let credential_scope_digest = take_32_v1(bytes, &mut offset)?;
        let policy_record_digest =
            PrivacyBootleLanternIssuerPolicyDigestV1::new(take_32_v1(bytes, &mut offset)?);
        let issuer_parameter_id = PrivacyParameterIdV1::new(take_32_v1(bytes, &mut offset)?);
        let issuer_parameter_digest =
            PrivacyParameterDigestV1::new(take_32_v1(bytes, &mut offset)?);
        let policy_epoch = take_u64_v1(bytes, &mut offset)?;
        let requester_authorization_digest = take_32_v1(bytes, &mut offset)?;
        let issued_at_height = take_u64_v1(bytes, &mut offset)?;
        let expires_at_height = take_u64_v1(bytes, &mut offset)?;
        let authorization_digest = take_32_v1(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid);
        }
        let authorization = Self {
            authorization_id,
            issuer_profile_digest,
            canonical_genesis_hash,
            credential_scope_digest,
            policy_record_digest,
            issuer_parameter_id,
            issuer_parameter_digest,
            policy_epoch,
            requester_authorization_digest,
            issued_at_height,
            expires_at_height,
            authorization_digest,
        };
        validate_issuance_authorization_self_v1(&authorization)?;
        Ok(authorization)
    }
}
/// One native Falcon-512 issuer trapdoor and its exact public matrix.
pub struct BootleLanternIssuerKeyPairV1 {
    issuer_parameter_id: PrivacyParameterIdV1,
    public_matrix: BootleLanternIssuerPublicMatrixV1,
    trapdoor: Trapdoor,
}
impl core::fmt::Debug for BootleLanternIssuerKeyPairV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BootleLanternIssuerKeyPairV1(<redacted>)")
    }
}
impl BootleLanternIssuerKeyPairV1 {
    /// Reconstruct one genuine bounded issuer key from exact secret seed material.
    ///
    /// This is the stable sealed-credential provisioning boundary. The seed must be 32
    /// uniformly random secret bytes, never a password, label, public identifier, or test default.
    /// The caller retains ownership and must zeroize it immediately after this call.
    ///
    /// # Errors
    ///
    /// Rejects a zero parameter identity, an all-zero seed, bounded keygen
    /// exhaustion, or a public-key structural invariant failure.
    pub fn generate_from_secret_seed_v1(
        issuer_parameter_id: PrivacyParameterIdV1,
        secret_seed: &[u8; 32],
    ) -> Result<Self, BootleLanternIssuanceErrorV1> {
        if issuer_parameter_id.is_zero() {
            return Err(BootleLanternIssuanceErrorV1::InvalidIssuerParameterId);
        }
        if secret_seed.iter().all(|byte| *byte == 0) {
            return Err(BootleLanternIssuanceErrorV1::InvalidIssuerSecretSeed);
        }
        let trapdoor = falcon512::generate_from_seed(
            secret_seed,
            MAX_BOOTLE_LANTERN_ISSUER_KEYGEN_CANDIDATES_V1,
        )
        .ok_or(BootleLanternIssuanceErrorV1::IssuerKeyGenerationExhausted)?;
        let public_matrix = public_matrix_from_falcon_h_v1(&**trapdoor.h)?;
        public_matrix
            .validate_r512_multiplication_structure_v1()
            .map_err(|_| BootleLanternIssuanceErrorV1::InvalidIssuerPublicMatrix)?;
        Ok(Self {
            issuer_parameter_id,
            public_matrix,
            trapdoor,
        })
    }
    /// Generate one genuine bounded Falcon-512/NTRU issuer key.
    ///
    /// # Errors
    ///
    /// Rejects a zero parameter identity, unavailable or unhealthy cryptographic randomness,
    /// key-generation exhaustion, or a public-key structural invariant failure.
    pub fn generate_with_rng_v1<R: CryptoRng + RngCore>(
        issuer_parameter_id: PrivacyParameterIdV1,
        rng: &mut R,
    ) -> Result<Self, BootleLanternIssuanceErrorV1> {
        if issuer_parameter_id.is_zero() {
            return Err(BootleLanternIssuanceErrorV1::InvalidIssuerParameterId);
        }
        let mut checked = HealthCheckedCryptoRngV1::new(rng).map_err(map_randomness_error_v1)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        checked
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| BootleLanternIssuanceErrorV1::RandomnessUnavailable)?;
        let trapdoor =
            falcon512::generate_from_seed(&*seed, MAX_BOOTLE_LANTERN_ISSUER_KEYGEN_CANDIDATES_V1)
                .ok_or(BootleLanternIssuanceErrorV1::IssuerKeyGenerationExhausted)?;
        let public_matrix = public_matrix_from_falcon_h_v1(&**trapdoor.h)?;
        public_matrix
            .validate_r512_multiplication_structure_v1()
            .map_err(|_| BootleLanternIssuanceErrorV1::InvalidIssuerPublicMatrix)?;
        Ok(Self {
            issuer_parameter_id,
            public_matrix,
            trapdoor,
        })
    }
    /// Build the self-digested active governed policy for this exact key.
    ///
    /// # Errors
    ///
    /// Rejects malformed metadata or any matrix, parameter-digest, record,
    /// lifecycle, or initial-policy invariant failure.
    pub fn active_policy_v1(
        &self,
        metadata: BootleLanternIssuerPolicyMetadataV1,
    ) -> Result<BootleLanternIssuerPolicyV1, BootleLanternIssuanceErrorV1> {
        let mut policy = BootleLanternIssuerPolicyV1 {
            issuer_id: metadata.issuer_id,
            policy_id: metadata.policy_id,
            epoch: metadata.epoch,
            lifecycle: BootleLanternIssuerPolicyLifecycleV1::Active,
            issuer_parameter_id: self.issuer_parameter_id,
            issuer_parameter_digest: PrivacyParameterDigestV1::new([0; 32]),
            issuer_public_matrix: self.public_matrix.clone(),
            required_disclosure_bitmap: metadata.required_disclosure_bitmap,
            allowed_values: metadata.allowed_values,
            record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
        };
        policy.issuer_parameter_digest = policy
            .computed_issuer_parameter_digest()
            .map_err(|_| BootleLanternIssuanceErrorV1::PolicyEncodingFailed)?;
        policy.record_digest = policy
            .computed_record_digest()
            .map_err(|_| BootleLanternIssuanceErrorV1::PolicyEncodingFailed)?;
        policy
            .validate()
            .map_err(|_| BootleLanternIssuanceErrorV1::InvalidIssuerPolicy)?;
        Ok(policy)
    }
    fn matches_policy(&self, policy: &BootleLanternIssuerPolicyV1) -> bool {
        policy.lifecycle == BootleLanternIssuerPolicyLifecycleV1::Active
            && policy.issuer_parameter_id == self.issuer_parameter_id
            && policy.issuer_public_matrix == self.public_matrix
            && policy.validate().is_ok()
    }
}
/// Generate and atomically register one bounded blind-issuance authorization.
///
/// `requester_authorization_digest` is the issuer deployment's non-zero authorization decision (for
/// example, an authenticated account/session or approved enrollment record). The privacy engine
/// treats it as an opaque public commitment and never substitutes a holder-generated nonce for it.
///
/// # Errors
///
/// Rejects an invalid key/policy/scope, zero requester authorization, an invalid or overlong
/// lifetime, unhealthy randomness, identifier collision exhaustion, or any persistence failure.
pub fn issuer_authorize_blind_issuance_with_rng_v1<R: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
    store: &dyn BootleLanternIssuanceStoreV1,
    rng: &mut R,
) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceErrorV1> {
    let credential_scope_digest = validate_authorization_candidate_inputs_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        requester_authorization_digest,
        issued_at_height,
        expires_at_height,
    )?;
    let mut checked = HealthCheckedCryptoRngV1::new(rng).map_err(map_randomness_error_v1)?;
    for _ in 0..MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1 {
        let mut authorization_id = [0_u8; 32];
        checked
            .try_fill_bytes(&mut authorization_id)
            .map_err(|_| BootleLanternIssuanceErrorV1::RandomnessUnavailable)?;
        if authorization_id == [0; 32] {
            continue;
        }
        let authorization = build_authorization_candidate_v1(
            authorization_id,
            canonical_genesis_hash,
            credential_scope_digest,
            policy,
            requester_authorization_digest,
            issued_at_height,
            expires_at_height,
        )?;
        match store.register_fresh_v1(
            authorization.authorization_id,
            authorization.authorization_digest,
            authorization.issued_at_height,
            authorization.expires_at_height,
        ) {
            Ok(()) => return Ok(authorization),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists) => continue,
            Err(_) => return Err(BootleLanternIssuanceErrorV1::IssuanceStoreFailed),
        }
    }
    Err(BootleLanternIssuanceErrorV1::AuthorizationIdExhausted)
}
/// Prepare one native authorization candidate without mutating replay state.
///
/// This is the cryptographic-provider half of the issuance boundary. The caller is responsible for
/// atomically registering the returned identifier in the sole authoritative
/// [`BootleLanternIssuanceStoreV1`]. A collision must never be treated as success: callers may
/// request at most [`MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1`] independent candidates
/// before failing closed.
///
/// # Errors
///
/// Rejects an invalid key, policy, context, principal binding, lifetime, unhealthy randomness, a
/// zero identifier draw, or an inconsistent canonical authorization.
pub fn issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1<R: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
    rng: &mut R,
) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceErrorV1> {
    let credential_scope_digest = validate_authorization_candidate_inputs_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        requester_authorization_digest,
        issued_at_height,
        expires_at_height,
    )?;
    let mut checked = HealthCheckedCryptoRngV1::new(rng).map_err(map_randomness_error_v1)?;
    let mut authorization_id = [0_u8; 32];
    checked
        .try_fill_bytes(&mut authorization_id)
        .map_err(|_| BootleLanternIssuanceErrorV1::RandomnessUnavailable)?;
    if authorization_id == [0; 32] {
        return Err(BootleLanternIssuanceErrorV1::AuthorizationIdExhausted);
    }
    build_authorization_candidate_v1(
        authorization_id,
        canonical_genesis_hash,
        credential_scope_digest,
        policy,
        requester_authorization_digest,
        issued_at_height,
        expires_at_height,
    )
}
/// Prepare one native authorization candidate with fresh operating-system randomness.
///
/// This is the production provider entrypoint. Deterministic and fault- injected tests retain the
/// explicit-RNG variant, while deployment adapters cannot accidentally substitute the incompatible
/// `rand` 0.9 RNG traits or reuse one mutable RNG across independent provider operations.
///
/// # Errors
///
/// Returns the same closed failure set as
/// [`issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1`],
/// including unavailable or unhealthy OS randomness.
pub fn issuer_prepare_blind_issuance_authorization_candidate_v1(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceErrorV1> {
    let mut rng = OsRng;
    issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        requester_authorization_digest,
        issued_at_height,
        expires_at_height,
        &mut rng,
    )
}
/// Validate a provider-prepared authorization against exact public chain state.
///
/// This consumes no randomness and performs no store mutation. Callers must run it before
/// registering a provider-produced candidate in the sole authoritative issuance store.
///
/// # Errors
///
/// Rejects every malformed, inactive, or substituted context, genesis,
/// policy, parameter, epoch, scope, profile, lifetime, or self-digest binding.
pub fn issuer_validate_prepared_blind_issuance_authorization_v1(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    validate_issuance_authorization_v1(authorization, context, canonical_genesis_hash, policy, None)
}
fn validate_authorization_candidate_inputs_v1(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
) -> Result<[u8; 32], BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    if !issuer.matches_policy(policy) {
        return Err(BootleLanternIssuanceErrorV1::IssuerKeyPolicyMismatch);
    }
    if requester_authorization_digest == [0; 32] {
        return Err(BootleLanternIssuanceErrorV1::InvalidRequesterAuthorization);
    }
    validate_authorization_lifetime_v1(issued_at_height, expires_at_height)?;
    BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)
}
fn build_authorization_candidate_v1(
    authorization_id: [u8; 32],
    canonical_genesis_hash: [u8; 32],
    credential_scope_digest: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    requester_authorization_digest: [u8; 32],
    issued_at_height: u64,
    expires_at_height: u64,
) -> Result<BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceErrorV1> {
    if authorization_id == [0; 32] {
        return Err(BootleLanternIssuanceErrorV1::AuthorizationIdExhausted);
    }
    let mut authorization = BootleLanternIssuanceAuthorizationV1 {
        authorization_id,
        issuer_profile_digest: bootle_lantern_issuer_profile_digest_v1(),
        canonical_genesis_hash,
        credential_scope_digest,
        policy_record_digest: policy.record_digest,
        issuer_parameter_id: policy.issuer_parameter_id,
        issuer_parameter_digest: policy.issuer_parameter_digest,
        policy_epoch: policy.epoch,
        requester_authorization_digest,
        issued_at_height,
        expires_at_height,
        authorization_digest: [0; 32],
    };
    authorization.authorization_digest = issuance_authorization_digest_v1(&authorization);
    let _canonical_wire = authorization.encode()?;
    Ok(authorization)
}
/// Holder-to-issuer P1 request. All fields are exact and field-private.
pub struct BootleLanternBlindIssuanceRequestV1 {
    target: [ApplicationPolynomialV1; APPLICATION_ROWS_V1],
    target_digest: [u8; 32],
    issuance_authorization_digest: [u8; 32],
    scope_digest: [u8; 32],
    issuer_profile_digest: [u8; 32],
    policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
    proof: super::codec::BootleLanternBlindIssuanceRequestProofV1,
    request_digest: [u8; 32],
}
impl core::fmt::Debug for BootleLanternBlindIssuanceRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootleLanternBlindIssuanceRequestV1")
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}
impl BootleLanternBlindIssuanceRequestV1 {
    /// Digest of the complete canonical request, including its P1 wire.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[cfg(test)]
    pub(super) const fn issuance_authorization_digest_v1(&self) -> [u8; 32] {
        self.issuance_authorization_digest
    }
    #[cfg(test)]
    pub(super) const fn scope_digest_v1(&self) -> [u8; 32] {
        self.scope_digest
    }
    #[cfg(test)]
    pub(super) const fn policy_record_digest_v1(&self) -> [u8; 32] {
        *self.policy_record_digest.as_bytes()
    }
    /// Encode the unique fixed-width holder-to-issuer `ILQ1` request.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical target or any inconsistent, zero, or substituted request binding.
    pub fn encode(&self) -> Result<Vec<u8>, BootleLanternIssuanceErrorV1> {
        let proof_wire = self.proof.encode();
        self.validate_self_v1(&proof_wire)?;
        let mut bytes = Vec::with_capacity(BLIND_ISSUANCE_REQUEST_BYTES_V1);
        bytes.extend_from_slice(&BLIND_ISSUANCE_REQUEST_MAGIC_V1);
        bytes.push(BLIND_ISSUANCE_REQUEST_VERSION_V1);
        bytes.push(BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1.to_be_bytes());
        bytes.extend_from_slice(&BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(PROOF_BYTES_V1)
                .expect("fixed P1 proof length fits u32")
                .to_be_bytes(),
        );
        for polynomial in &self.target {
            for coefficient in polynomial.coefficients() {
                if *coefficient >= APPLICATION_MODULUS_V1 {
                    return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
                }
                bytes.extend_from_slice(&coefficient.to_be_bytes());
            }
        }
        for field in [
            self.target_digest.as_slice(),
            self.issuance_authorization_digest.as_slice(),
            self.scope_digest.as_slice(),
            self.issuer_profile_digest.as_slice(),
            self.policy_record_digest.as_bytes().as_slice(),
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&proof_wire);
        bytes.extend_from_slice(&self.request_digest);
        if bytes.len() != BLIND_ISSUANCE_REQUEST_BYTES_V1 {
            return Err(BootleLanternIssuanceErrorV1::InternalInvariant);
        }
        Ok(bytes)
    }
    /// Decode exactly one allocation-bounded canonical `ILQ1` request.
    ///
    /// The caller ceiling and exact outer length are checked before the sole variable-sized
    /// inner-proof allocation. The header fixes the target count, ring degree, and exact `ILB1`
    /// proof length, so no attacker-supplied count controls allocation or iteration.
    ///
    /// # Errors
    ///
    /// Rejects oversized input, every wrong length/header/count, non-canonical
    /// target coefficient, malformed inner proof, zero binding, altered digest,
    /// trailing byte, or alternate representation.
    pub fn decode_exact(
        bytes: &[u8],
        max_bytes: u32,
    ) -> Result<Self, BootleLanternIssuanceErrorV1> {
        let observed = u64::try_from(bytes.len())
            .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
        if observed > u64::from(max_bytes) {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestWireTooLarge {
                bytes: observed,
                max: max_bytes,
            });
        }
        if bytes.len() != BLIND_ISSUANCE_REQUEST_BYTES_V1 {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
        }
        let target_count = u16::from_be_bytes([bytes[8], bytes[9]]);
        let ring_degree = u16::from_be_bytes([bytes[10], bytes[11]]);
        let proof_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if bytes[..4] != BLIND_ISSUANCE_REQUEST_MAGIC_V1
            || bytes[4] != BLIND_ISSUANCE_REQUEST_VERSION_V1
            || bytes[5] != BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1
            || bytes[6..8] != [0, 0]
            || target_count != BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1
            || ring_degree != BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1
            || proof_length
                != u32::try_from(PROOF_BYTES_V1).expect("fixed P1 proof length fits u32")
        {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
        }
        let mut offset = BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1;
        let mut target = [ApplicationPolynomialV1::ZERO; APPLICATION_ROWS_V1];
        for polynomial in &mut target {
            let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
            for coefficient in &mut coefficients {
                let end = offset
                    .checked_add(2)
                    .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
                let encoded: [u8; 2] = bytes
                    .get(offset..end)
                    .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?
                    .try_into()
                    .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
                offset = end;
                *coefficient = u16::from_be_bytes(encoded);
                if *coefficient >= APPLICATION_MODULUS_V1 {
                    return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
                }
            }
            *polynomial = ApplicationPolynomialV1::new(coefficients)
                .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
        }
        let target_digest = take_blind_request_32_v1(bytes, &mut offset)?;
        let issuance_authorization_digest = take_blind_request_32_v1(bytes, &mut offset)?;
        let scope_digest = take_blind_request_32_v1(bytes, &mut offset)?;
        let issuer_profile_digest = take_blind_request_32_v1(bytes, &mut offset)?;
        let policy_record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new(
            take_blind_request_32_v1(bytes, &mut offset)?,
        );
        let proof_end = offset
            .checked_add(PROOF_BYTES_V1)
            .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
        let proof_wire = bytes
            .get(offset..proof_end)
            .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
        let proof = super::codec::BootleLanternBlindIssuanceRequestProofV1::decode_exact(
            proof_wire,
            proof_length,
        )
        .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
        offset = proof_end;
        let request_digest = take_blind_request_32_v1(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
        }
        let request = Self {
            target,
            target_digest,
            issuance_authorization_digest,
            scope_digest,
            issuer_profile_digest,
            policy_record_digest,
            proof,
            request_digest,
        };
        request.validate_self_v1(proof_wire)?;
        Ok(request)
    }
    fn validate_self_v1(&self, proof_wire: &[u8]) -> Result<(), BootleLanternIssuanceErrorV1> {
        if proof_wire.len() != PROOF_BYTES_V1
            || self.target_digest == [0; 32]
            || self.issuance_authorization_digest == [0; 32]
            || self.scope_digest == [0; 32]
            || self.issuer_profile_digest != bootle_lantern_issuer_profile_digest_v1()
            || self.policy_record_digest.is_zero()
            || self.request_digest == [0; 32]
            || self.target_digest
                != digest_application_vector_v1(MASKED_TARGET_DIGEST_DOMAIN_V1, &self.target)
            || self.request_digest
                != blind_request_digest_v1(
                    &self.target_digest,
                    &self.issuance_authorization_digest,
                    &self.scope_digest,
                    self.policy_record_digest.as_bytes(),
                    proof_wire,
                )
        {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) const fn proof_v1(&self) -> &super::codec::BootleLanternBlindIssuanceRequestProofV1 {
        &self.proof
    }
    fn validate_bindings_v1(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        authorization: &BootleLanternIssuanceAuthorizationV1,
    ) -> Result<BootleLanternCredentialScopeV1, BootleLanternIssuanceErrorV1> {
        require_active_policy_v1(policy)?;
        validate_issuance_authorization_v1(
            authorization,
            context,
            canonical_genesis_hash,
            policy,
            None,
        )?;
        let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
            .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
        let scope_digest = scope
            .digest()
            .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
        if self.scope_digest != scope_digest
            || self.issuer_profile_digest != bootle_lantern_issuer_profile_digest_v1()
            || self.policy_record_digest != policy.record_digest
            || self.issuance_authorization_digest != authorization.authorization_digest
            || self.target_digest
                != digest_application_vector_v1(MASKED_TARGET_DIGEST_DOMAIN_V1, &self.target)
            || self.request_digest
                != blind_request_digest_v1(
                    &self.target_digest,
                    &self.issuance_authorization_digest,
                    &self.scope_digest,
                    policy.record_digest.as_bytes(),
                    &self.proof.encode(),
                )
        {
            return Err(BootleLanternIssuanceErrorV1::BlindRequestBindingMismatch);
        }
        Ok(scope)
    }
    #[cfg(test)]
    pub(crate) fn compile_transcript_v1(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
        authorization: &BootleLanternIssuanceAuthorizationV1,
    ) -> Result<
        (
            BootleLanternApplicationRelationV1,
            BlindIssuanceRequestTranscriptV1,
        ),
        BootleLanternIssuanceErrorV1,
    > {
        self.validate_bindings_v1(context, canonical_genesis_hash, policy, authorization)?;
        self.compile_transcript_after_binding_v1(context, canonical_genesis_hash, policy)
    }
    fn compile_transcript_after_binding_v1(
        &self,
        context: &PrivacyStatementContextV1,
        canonical_genesis_hash: [u8; 32],
        policy: &BootleLanternIssuerPolicyV1,
    ) -> Result<
        (
            BootleLanternApplicationRelationV1,
            BlindIssuanceRequestTranscriptV1,
        ),
        BootleLanternIssuanceErrorV1,
    > {
        let matrix_seed = matrix_seed_v1(*context.parameter_digest.as_bytes())
            .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
        let relation = compile_blind_issuance_request_relation_v1(matrix_seed, &self.target)
            .map_err(|_| BootleLanternIssuanceErrorV1::RelationFailed)?;
        let transcript = BlindIssuanceRequestTranscriptV1::new(
            BlindIssuanceRequestChallengeBindingV1 {
                parameter_digest: *context.parameter_digest.as_bytes(),
                genesis_hash: canonical_genesis_hash,
                issuer_profile_digest: self.issuer_profile_digest,
                credential_scope_digest: self.scope_digest,
                issuer_policy_record_digest: *policy.record_digest.as_bytes(),
                masked_target_digest: self.target_digest,
                issuance_authorization_digest: self.issuance_authorization_digest,
            },
            matrix_seed,
            super::application_relation_digest_v1(&relation),
        )
        .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
        Ok((relation, transcript))
    }
}
/// Secret holder state consumed while finalizing exactly one request.
pub struct BootleLanternBlindIssuanceStateV1 {
    pub(super) randomness: [ApplicationPolynomialV1; 16],
    pub(super) attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
    pub(super) request_digest: [u8; 32],
    pub(super) scope: BootleLanternCredentialScopeV1,
}
impl core::fmt::Debug for BootleLanternBlindIssuanceStateV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BootleLanternBlindIssuanceStateV1(<redacted>)")
    }
}
impl Zeroize for BootleLanternBlindIssuanceStateV1 {
    fn zeroize(&mut self) {
        self.randomness.zeroize();
        self.attributes.zeroize();
        self.request_digest.zeroize();
    }
}
impl Drop for BootleLanternBlindIssuanceStateV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Exact issuer response to one verified P1 request.
pub struct BootleLanternBlindIssuanceResponseV1 {
    tag: [ApplicationPolynomialV1; 8],
    signature_one: [ApplicationPolynomialV1; 8],
    signature_two: [ApplicationPolynomialV1; 8],
    request_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
}
impl core::fmt::Debug for BootleLanternBlindIssuanceResponseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BootleLanternBlindIssuanceResponseV1(<redacted>)")
    }
}
impl BootleLanternBlindIssuanceResponseV1 {
    #[cfg(test)]
    pub(super) const fn request_digest_v1(&self) -> [u8; 32] {
        self.request_digest
    }
    #[cfg(test)]
    pub(super) const fn scope_digest_v1(&self) -> [u8; 32] {
        self.scope_digest
    }
    #[cfg(test)]
    pub(super) const fn policy_record_digest_v1(&self) -> [u8; 32] {
        *self.policy_record_digest.as_bytes()
    }
    /// Encode the unique fixed-width `ILR1` response persisted for retries.
    ///
    /// # Errors
    ///
    /// Rejects a non-binary tag, non-canonical polynomial, or zero binding.
    pub fn encode(&self) -> Result<Vec<u8>, BootleLanternIssuanceErrorV1> {
        if self.request_digest == [0; 32]
            || self.scope_digest == [0; 32]
            || self.policy_record_digest.is_zero()
        {
            return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
        }
        let mut bytes = Vec::with_capacity(BLIND_ISSUANCE_RESPONSE_BYTES_V1);
        bytes.extend_from_slice(&RESPONSE_MAGIC_V1);
        bytes.push(RESPONSE_VERSION_V1);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        for polynomial in &self.tag {
            for coefficient in polynomial.coefficients() {
                if *coefficient > 1 {
                    return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
                }
                bytes.extend_from_slice(&coefficient.to_be_bytes());
            }
        }
        for polynomial in self.signature_one.iter().chain(&self.signature_two) {
            for coefficient in polynomial.coefficients() {
                if *coefficient >= APPLICATION_MODULUS_V1 {
                    return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
                }
                bytes.extend_from_slice(&coefficient.to_be_bytes());
            }
        }
        bytes.extend_from_slice(&self.request_digest);
        bytes.extend_from_slice(&self.scope_digest);
        bytes.extend_from_slice(self.policy_record_digest.as_bytes());
        if bytes.len() != BLIND_ISSUANCE_RESPONSE_BYTES_V1 {
            return Err(BootleLanternIssuanceErrorV1::InternalInvariant);
        }
        Ok(bytes)
    }
    /// Decode exactly one canonical fixed-width `ILR1` response.
    ///
    /// # Errors
    ///
    /// Rejects every wrong length/header, non-binary tag, non-canonical
    /// residue, zero binding, trailing byte, or alternate representation.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, BootleLanternIssuanceErrorV1> {
        if bytes.len() != BLIND_ISSUANCE_RESPONSE_BYTES_V1
            || bytes[..4] != RESPONSE_MAGIC_V1
            || bytes[4] != RESPONSE_VERSION_V1
            || bytes[5] != 0
            || bytes[6..8] != [0, 0]
        {
            return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
        }
        let mut offset = RESPONSE_HEADER_BYTES_V1;
        let tag = decode_application_polynomials_v1::<8>(bytes, &mut offset, true)?;
        let signature_one = decode_application_polynomials_v1::<8>(bytes, &mut offset, false)?;
        let signature_two = decode_application_polynomials_v1::<8>(bytes, &mut offset, false)?;
        let request_digest = take_32_v1(bytes, &mut offset)
            .map_err(|_| BootleLanternIssuanceErrorV1::ResponseWireInvalid)?;
        let scope_digest = take_32_v1(bytes, &mut offset)
            .map_err(|_| BootleLanternIssuanceErrorV1::ResponseWireInvalid)?;
        let policy_record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new(
            take_32_v1(bytes, &mut offset)
                .map_err(|_| BootleLanternIssuanceErrorV1::ResponseWireInvalid)?,
        );
        if offset != bytes.len()
            || request_digest == [0; 32]
            || scope_digest == [0; 32]
            || policy_record_digest.is_zero()
        {
            return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
        }
        Ok(Self {
            tag: *tag,
            signature_one: *signature_one,
            signature_two: *signature_two,
            request_digest,
            scope_digest,
            policy_record_digest,
        })
    }
}
impl Zeroize for BootleLanternBlindIssuanceResponseV1 {
    fn zeroize(&mut self) {
        self.tag.zeroize();
        self.signature_one.zeroize();
        self.signature_two.zeroize();
        self.request_digest.zeroize();
        self.scope_digest.zeroize();
    }
}
impl Drop for BootleLanternBlindIssuanceResponseV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Reusable holder credential produced only by canonical finalization.
pub struct BootleLanternCredentialV1 {
    pub(super) randomness: [ApplicationPolynomialV1; 16],
    pub(super) tag: [ApplicationPolynomialV1; 8],
    pub(super) signature_one: [ApplicationPolynomialV1; 8],
    pub(super) signature_two: [ApplicationPolynomialV1; 8],
    pub(super) attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
    pub(super) scope: BootleLanternCredentialScopeV1,
}
impl core::fmt::Debug for BootleLanternCredentialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BootleLanternCredentialV1(<redacted>)")
    }
}
impl Zeroize for BootleLanternCredentialV1 {
    fn zeroize(&mut self) {
        self.randomness.zeroize();
        self.tag.zeroize();
        self.signature_one.zeroize();
        self.signature_two.zeroize();
        self.attributes.zeroize();
    }
}
impl Drop for BootleLanternCredentialV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl BootleLanternCredentialV1 {
    /// Build and independently validate the witness for one later statement.
    ///
    /// Action index and transaction intent may change between presentations; every reusable scope
    /// field and the exact active policy must remain the same.
    ///
    /// # Errors
    ///
    /// Rejects a policy/statement/scope substitution, disclosure violation,
    /// norm violation, or failed credential equation.
    pub fn presentation_witness_v1(
        &self,
        statement: &IrohaBootleLanternAnoncredStatementV1,
        policy: &BootleLanternIssuerPolicyV1,
        canonical_genesis_hash: [u8; 32],
    ) -> Result<BootleLanternPresentationWitnessV1, BootleLanternIssuanceErrorV1> {
        if !self
            .scope
            .matches(&statement.context, canonical_genesis_hash, policy)
        {
            return Err(BootleLanternIssuanceErrorV1::CredentialScopeMismatch);
        }
        let matrix_seed = matrix_seed_v1(*statement.context.parameter_digest.as_bytes())
            .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
        let relation =
            compile_application_relation_v1(statement, policy, matrix_seed, canonical_genesis_hash)
                .map_err(|_| BootleLanternIssuanceErrorV1::RelationFailed)?;
        let witness = BootleLanternPresentationWitnessV1 {
            randomness: self.randomness,
            tag: self.tag,
            signature_one: self.signature_one,
            signature_two: self.signature_two,
            attributes: self.attributes,
        };
        validate_presentation_witness_v1(&relation, &witness)
            .map_err(|_| BootleLanternIssuanceErrorV1::CredentialValidationFailed)?;
        Ok(witness)
    }
}
/// Prepare the only canonical holder P1 request.
///
/// # Errors
///
/// Rejects an invalid/non-active policy or scope, unavailable/unhealthy
/// randomness, holder-sampler exhaustion, matrix expansion, invalid request
/// authorization, transcript construction, or P1 proof failure.
pub fn holder_prepare_blind_issuance_with_rng_v1<R: CryptoRng + RngCore>(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
    rng: &mut R,
) -> Result<
    (
        BootleLanternBlindIssuanceRequestV1,
        BootleLanternBlindIssuanceStateV1,
    ),
    BootleLanternIssuanceErrorV1,
> {
    require_active_policy_v1(policy)?;
    validate_issuance_authorization_v1(
        authorization,
        context,
        canonical_genesis_hash,
        policy,
        None,
    )?;
    let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    let issuer_profile_digest = bootle_lantern_issuer_profile_digest_v1();
    let matrix_seed = matrix_seed_v1(*context.parameter_digest.as_bytes())
        .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
    let (mut mask_rng, mut proof_rng) = BootleLanternIssuanceRandomnessRootV1::from_rng_v1(rng)
        .map_err(map_randomness_error_v1)?
        .split_holder_v1(authorization.authorization_digest);
    let randomness = sample_credential_randomness_v1(&mut mask_rng)
        .map_err(map_credential_randomness_error_v1)?;
    let randomness = randomness.into_polynomials();
    let target = masked_target_v1(matrix_seed, &randomness, &attributes)?;
    let target_digest = digest_application_vector_v1(MASKED_TARGET_DIGEST_DOMAIN_V1, &target);
    let relation = compile_blind_issuance_request_relation_v1(matrix_seed, &target)
        .map_err(|_| BootleLanternIssuanceErrorV1::RelationFailed)?;
    let transcript = BlindIssuanceRequestTranscriptV1::new(
        BlindIssuanceRequestChallengeBindingV1 {
            parameter_digest: *context.parameter_digest.as_bytes(),
            genesis_hash: canonical_genesis_hash,
            issuer_profile_digest,
            credential_scope_digest: scope_digest,
            issuer_policy_record_digest: *policy.record_digest.as_bytes(),
            masked_target_digest: target_digest,
            issuance_authorization_digest: authorization.authorization_digest,
        },
        matrix_seed,
        super::application_relation_digest_v1(&relation),
    )
    .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
    let p1_witness = BootleLanternPresentationWitnessV1 {
        randomness,
        tag: [ApplicationPolynomialV1::ZERO; 8],
        signature_one: [ApplicationPolynomialV1::ZERO; 8],
        signature_two: [ApplicationPolynomialV1::ZERO; 8],
        attributes,
    };
    let proof = prove_blind_issuance_request_v1(&relation, &p1_witness, transcript, &mut proof_rng)
        .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestProofFailed)?;
    let request_digest = blind_request_digest_v1(
        &target_digest,
        &authorization.authorization_digest,
        &scope_digest,
        policy.record_digest.as_bytes(),
        &proof.encode(),
    );
    let request = BootleLanternBlindIssuanceRequestV1 {
        target,
        target_digest,
        issuance_authorization_digest: authorization.authorization_digest,
        scope_digest,
        issuer_profile_digest,
        policy_record_digest: policy.record_digest,
        proof,
        request_digest,
    };
    let _canonical_wire = request.encode()?;
    let state = BootleLanternBlindIssuanceStateV1 {
        randomness,
        attributes,
        request_digest,
        scope,
    };
    Ok((request, state))
}
#[cfg(any(test, feature = "test-utils"))]
/// Prepare the canonical holder P1 request with fresh operating-system randomness.
///
/// This is the production holder entrypoint. Deterministic and fault-injected
/// tests retain [`holder_prepare_blind_issuance_with_rng_v1`], while production
/// callers cannot accidentally reuse a mutable RNG across holder operations.
///
/// # Errors
///
/// Returns the same closed failure set as [`holder_prepare_blind_issuance_with_rng_v1`], including
/// unavailable or unhealthy operating-system randomness.
pub fn holder_prepare_blind_issuance_v1(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    attributes: [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
) -> Result<
    (
        BootleLanternBlindIssuanceRequestV1,
        BootleLanternBlindIssuanceStateV1,
    ),
    BootleLanternIssuanceErrorV1,
> {
    let mut rng = OsRng;
    holder_prepare_blind_issuance_with_rng_v1(
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        attributes,
        &mut rng,
    )
}
/// Decode one canonical holder request and verify its public bindings and P1 proof.
///
/// # Errors
///
/// Rejects any non-canonical, truncated, trailing, substituted, or oversized
/// request wire before delegating to the typed issuance lifecycle.
pub fn issuer_validate_blind_issuance_request_encoded_v1(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
) -> Result<[u8; 32], BootleLanternIssuanceErrorV1> {
    let validated = validate_encoded_request_v1(
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        request_bytes,
        current_height,
    )?;
    Ok(validated.request.request_digest)
}
/// Verify one canonical holder request against the exact issuer trapdoor.
///
/// This is the cryptographic provider's non-random validation phase. It repeats all public P1 and
/// binding checks and additionally proves that the provider's private key corresponds to the
/// governed public issuer policy. It performs no replay-state mutation and consumes no randomness.
///
/// # Errors
///
/// Rejects every malformed or substituted wire, context, genesis, policy,
/// authorization, proof, height, or issuer-key binding.
pub fn issuer_validate_blind_issuance_request_for_issuer_encoded_v1(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
) -> Result<[u8; 32], BootleLanternIssuanceErrorV1> {
    let validated = validate_encoded_request_for_issuer_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        request_bytes,
        current_height,
    )?;
    Ok(validated.request.request_digest)
}
/// Validate and cryptographically issue one request without touching replay state.
///
/// The caller must first run the non-mutating replay preflight, invoke
/// [`issuer_validate_blind_issuance_request_encoded_v1`], and atomically claim the exact request in
/// the authoritative issuance store. This function then independently repeats every canonical
/// binding and P1 verification before obtaining issuer randomness. The caller must durably complete
/// or irreversibly fail the claim on every return path.
///
/// # Errors
///
/// Rejects any non-canonical wire, key/policy/context/authorization/request substitution, invalid
/// P1 proof, unhealthy randomness, sampling failure, or response invariant failure.
pub fn issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1<R: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
    rng: &mut R,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    let validated = validate_encoded_request_for_issuer_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        request_bytes,
        current_height,
    )?;
    let (mut tag_rng, mut preimage_rng) = BootleLanternIssuanceRandomnessRootV1::from_rng_v1(rng)
        .map_err(map_randomness_error_v1)?
        .split_issuer_v1(validated.request.request_digest);
    let response = issue_claimed_request_v1(
        issuer,
        validated.matrix_seed,
        &validated.scope,
        validated.scope_digest,
        policy,
        &validated.request,
        &mut tag_rng,
        &mut preimage_rng,
    )?;
    let _canonical_wire = response.encode()?;
    Ok(response)
}
/// Revalidate and issue one claimed request with fresh operating-system randomness.
///
/// This production provider entrypoint creates a new `OsRng` value for every
/// operation. All canonical/key/policy/P1 checks still run before the generic
/// implementation first consumes randomness.
///
/// # Errors
///
/// Returns the same closed failure set as
/// [`issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1`].
pub fn issuer_issue_validated_blind_issuance_request_encoded_v1(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    let mut rng = OsRng;
    issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        request_bytes,
        current_height,
        &mut rng,
    )
}
/// Decode and bind a cached response to the exact completed request.
///
/// This performs no issuer operation and consumes no randomness. It is the only accepted path for
/// returning a durable completed retry after the authorization lifetime has elapsed.
///
/// # Errors
///
/// Rejects malformed or substituted authorization, request, scope, policy, or response bytes.
pub fn issuer_validate_cached_blind_issuance_response_encoded_v1(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
        request_bytes,
        u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed ILQ1 request length fits u32"),
    )?;
    let scope =
        request.validate_bindings_v1(context, canonical_genesis_hash, policy, authorization)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    decode_cached_response_v1(response_bytes, &request, scope_digest, policy)
}
struct ValidatedIssuerRequestV1 {
    request: BootleLanternBlindIssuanceRequestV1,
    scope: BootleLanternCredentialScopeV1,
    scope_digest: [u8; 32],
    matrix_seed: super::transcript::MatrixSeedV1,
}
fn validate_encoded_request_for_issuer_v1(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
) -> Result<ValidatedIssuerRequestV1, BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    if !issuer.matches_policy(policy) {
        return Err(BootleLanternIssuanceErrorV1::IssuerKeyPolicyMismatch);
    }
    validate_encoded_request_v1(
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        request_bytes,
        current_height,
    )
}
fn validate_encoded_request_v1(
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
) -> Result<ValidatedIssuerRequestV1, BootleLanternIssuanceErrorV1> {
    let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
        request_bytes,
        u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed ILQ1 request length fits u32"),
    )?;
    require_active_policy_v1(policy)?;
    validate_issuance_authorization_v1(
        authorization,
        context,
        canonical_genesis_hash,
        policy,
        Some(current_height),
    )?;
    let scope =
        request.validate_bindings_v1(context, canonical_genesis_hash, policy, authorization)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    let (relation, transcript) =
        request.compile_transcript_after_binding_v1(context, canonical_genesis_hash, policy)?;
    let matrix_seed = matrix_seed_v1(*context.parameter_digest.as_bytes())
        .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
    verify_blind_issuance_request_v1(&relation, transcript, &request.proof)
        .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestProofFailed)?;
    Ok(ValidatedIssuerRequestV1 {
        request,
        scope,
        scope_digest,
        matrix_seed,
    })
}
/// Decode one canonical `ILQ1` request, atomically claim it, and issue at most once.
///
/// This explicit-RNG entrypoint retains the authoritative store-backed lifecycle for deterministic
/// tests and deployment-owned fault injection. Production providers should prefer
/// [`issuer_issue_validated_blind_issuance_request_encoded_v1`] after Torii has performed the sole
/// durable preflight and claim transition.
///
/// # Errors
///
/// Rejects a malformed, truncated, trailing, or oversized request wire; every key, policy, context,
/// genesis, authorization, request, height, or proof substitution; replay-store failures; unhealthy
/// randomness; sampling exhaustion; and response-invariant failures. A completed retry returns its
/// exact cached response without consuming the supplied RNG.
pub fn issuer_blind_issue_once_encoded_with_rng_v1<R: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_bytes: &[u8],
    current_height: u64,
    store: &dyn BootleLanternIssuanceStoreV1,
    rng: &mut R,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    let request = BootleLanternBlindIssuanceRequestV1::decode_exact(
        request_bytes,
        u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1).expect("fixed ILQ1 request length fits u32"),
    )?;
    issuer_blind_issue_once_with_rng_v1(
        issuer,
        context,
        canonical_genesis_hash,
        policy,
        authorization,
        &request,
        current_height,
        store,
        rng,
    )
}
/// Verify a decoded P1 request, atomically claim its authorization, and issue once.
///
/// # Errors
///
/// Rejects key/policy/context/authorization/request substitution and expiry before randomness. A
/// completed retry of the same request returns the exact cached `ILR1` response without touching
/// either RNG. Once a fresh claim succeeds, every later failure is terminal and can never reset the
/// authorization to fresh.
pub(crate) fn issuer_blind_issue_once_with_rng_v1<R: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request: &BootleLanternBlindIssuanceRequestV1,
    current_height: u64,
    store: &dyn BootleLanternIssuanceStoreV1,
    rng: &mut R,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    if !issuer.matches_policy(policy) {
        return Err(BootleLanternIssuanceErrorV1::IssuerKeyPolicyMismatch);
    }
    let scope =
        request.validate_bindings_v1(context, canonical_genesis_hash, policy, authorization)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    match store.preflight_v1(
        authorization.authorization_id,
        authorization.authorization_digest,
        request.request_digest,
        current_height,
    ) {
        Ok(BootleLanternIssuancePreflightV1::Completed(response_bytes)) => {
            return decode_cached_response_v1(&response_bytes, request, scope_digest, policy);
        }
        Ok(BootleLanternIssuancePreflightV1::Fresh) => {}
        Err(error) => return Err(map_store_claim_error_v1(error)),
    }
    let (relation, transcript) =
        request.compile_transcript_after_binding_v1(context, canonical_genesis_hash, policy)?;
    let matrix_seed = matrix_seed_v1(*context.parameter_digest.as_bytes())
        .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
    verify_blind_issuance_request_v1(&relation, transcript, &request.proof)
        .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestProofFailed)?;
    match store.claim_v1(
        authorization.authorization_id,
        authorization.authorization_digest,
        request.request_digest,
        current_height,
    ) {
        Ok(BootleLanternIssuanceClaimV1::Completed(response_bytes)) => {
            return decode_cached_response_v1(&response_bytes, request, scope_digest, policy);
        }
        Ok(BootleLanternIssuanceClaimV1::Fresh) => {}
        Err(error) => return Err(map_store_claim_error_v1(error)),
    }
    let (mut tag_rng, mut preimage_rng) =
        match BootleLanternIssuanceRandomnessRootV1::from_rng_v1(rng) {
            Ok(root) => root.split_issuer_v1(request.request_digest),
            Err(error) => {
                fail_claim_v1(store, authorization, request.request_digest, current_height)?;
                return Err(map_randomness_error_v1(error));
            }
        };
    let issue_result = issue_claimed_request_v1(
        issuer,
        matrix_seed,
        &scope,
        scope_digest,
        policy,
        request,
        &mut tag_rng,
        &mut preimage_rng,
    );
    let response = match issue_result {
        Ok(response) => response,
        Err(error) => {
            fail_claim_v1(store, authorization, request.request_digest, current_height)?;
            return Err(error);
        }
    };
    let response_bytes = match response.encode() {
        Ok(bytes) => bytes,
        Err(error) => {
            fail_claim_v1(store, authorization, request.request_digest, current_height)?;
            return Err(error);
        }
    };
    if store
        .complete_v1(
            authorization.authorization_id,
            authorization.authorization_digest,
            request.request_digest,
            &response_bytes,
            current_height,
        )
        .is_err()
    {
        let _ = store.fail_v1(
            authorization.authorization_id,
            authorization.authorization_digest,
            request.request_digest,
            current_height,
        );
        return Err(BootleLanternIssuanceErrorV1::IssuanceStoreFailed);
    }
    Ok(response)
}
fn issue_claimed_request_v1<RTag: CryptoRng + RngCore, RPreimage: CryptoRng + RngCore>(
    issuer: &BootleLanternIssuerKeyPairV1,
    matrix_seed: super::transcript::MatrixSeedV1,
    scope: &BootleLanternCredentialScopeV1,
    scope_digest: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    request: &BootleLanternBlindIssuanceRequestV1,
    tag_rng: &mut RTag,
    preimage_rng: &mut RPreimage,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    let mut checked_tag_rng =
        HealthCheckedCryptoRngV1::new(tag_rng).map_err(map_randomness_error_v1)?;
    let tag = sample_tag_v1(&mut checked_tag_rng)?;
    let a_tau = expand_application_matrix_v1(matrix_seed, MatrixRoleV1::ApplicationTag)
        .map_err(|_| BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
    let scope_term = scope
        .application_term()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    let mut signing_target = Zeroizing::new(request.target);
    for row in 0..APPLICATION_ROWS_V1 {
        signing_target[row] = signing_target[row].add(scope_term[row]);
        for column in 0..8 {
            let coefficient = a_tau
                .get(
                    u16::try_from(row).expect("fixed row fits u16"),
                    u16::try_from(column).expect("fixed column fits u16"),
                )
                .ok_or(BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
            signing_target[row] = signing_target[row].add(coefficient.multiply(tag[column]));
        }
    }
    let falcon_target = r64_rank8_to_r512_v1(&signing_target);
    let preimage = sample_preimage_bounded_v1(preimage_rng, |seed| {
        falcon512::sample_preimage_from_seed(&issuer.trapdoor, &falcon_target, seed)
    })?;
    let signature_one = centered_r512_to_r64_rank8_v1(&**preimage.first)?;
    let signature_two = centered_r512_to_r64_rank8_v1(&**preimage.second)?;
    Ok(BootleLanternBlindIssuanceResponseV1 {
        tag: *tag,
        signature_one: *signature_one,
        signature_two: *signature_two,
        request_digest: request.request_digest,
        scope_digest,
        policy_record_digest: policy.record_digest,
    })
}
fn sample_preimage_bounded_v1<T, R, Sample>(
    rng: &mut R,
    mut sample: Sample,
) -> Result<T, BootleLanternIssuanceErrorV1>
where
    R: CryptoRng + RngCore,
    Sample: FnMut(&[u8; 56]) -> Option<T>,
{
    let mut checked_rng = HealthCheckedCryptoRngV1::new(rng).map_err(map_randomness_error_v1)?;
    for _ in 0..MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1 {
        let mut seed = Zeroizing::new([0_u8; 56]);
        checked_rng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| BootleLanternIssuanceErrorV1::RandomnessUnavailable)?;
        if let Some(preimage) = sample(&seed) {
            return Ok(preimage);
        }
    }
    Err(BootleLanternIssuanceErrorV1::PreimageSamplingExhausted)
}
fn fail_claim_v1(
    store: &dyn BootleLanternIssuanceStoreV1,
    authorization: &BootleLanternIssuanceAuthorizationV1,
    request_digest: [u8; 32],
    failed_at_height: u64,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    store
        .fail_v1(
            authorization.authorization_id,
            authorization.authorization_digest,
            request_digest,
            failed_at_height,
        )
        .map_err(|_| BootleLanternIssuanceErrorV1::IssuanceStoreFailed)
}
fn decode_cached_response_v1(
    response_bytes: &[u8],
    request: &BootleLanternBlindIssuanceRequestV1,
    scope_digest: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
) -> Result<BootleLanternBlindIssuanceResponseV1, BootleLanternIssuanceErrorV1> {
    let response = BootleLanternBlindIssuanceResponseV1::decode_exact(response_bytes)
        .map_err(|_| BootleLanternIssuanceErrorV1::CachedIssuanceResponseInvalid)?;
    if response.request_digest != request.request_digest
        || response.scope_digest != scope_digest
        || response.policy_record_digest != policy.record_digest
    {
        return Err(BootleLanternIssuanceErrorV1::CachedIssuanceResponseInvalid);
    }
    Ok(response)
}
fn map_store_claim_error_v1(
    error: BootleLanternIssuanceStoreErrorV1,
) -> BootleLanternIssuanceErrorV1 {
    match error {
        BootleLanternIssuanceStoreErrorV1::AuthorizationNotYetValid => {
            BootleLanternIssuanceErrorV1::AuthorizationNotYetValid
        }
        BootleLanternIssuanceStoreErrorV1::AuthorizationExpired => {
            BootleLanternIssuanceErrorV1::AuthorizationExpired
        }
        BootleLanternIssuanceStoreErrorV1::Busy => BootleLanternIssuanceErrorV1::AuthorizationBusy,
        BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed => {
            BootleLanternIssuanceErrorV1::AuthorizationConsumed
        }
        BootleLanternIssuanceStoreErrorV1::InvalidInput
        | BootleLanternIssuanceStoreErrorV1::ConfigurationInvalid
        | BootleLanternIssuanceStoreErrorV1::AuthorizationExists
        | BootleLanternIssuanceStoreErrorV1::CapacityExceeded
        | BootleLanternIssuanceStoreErrorV1::StoreAlreadyOpen
        | BootleLanternIssuanceStoreErrorV1::UnsupportedPlatform
        | BootleLanternIssuanceStoreErrorV1::Corrupt
        | BootleLanternIssuanceStoreErrorV1::Backend => {
            BootleLanternIssuanceErrorV1::IssuanceStoreFailed
        }
    }
}
/// Consume holder state, validate the complete credential equation, and
/// finalize one reusable credential.
///
/// # Errors
///
/// Rejects response, policy, scope, disclosure, norm, or application-equation
/// mismatch. Holder state is consumed and wiped on every path.
pub fn holder_finalize_blind_issuance_v1(
    state: BootleLanternBlindIssuanceStateV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    response: BootleLanternBlindIssuanceResponseV1,
) -> Result<BootleLanternCredentialV1, BootleLanternIssuanceErrorV1> {
    require_active_policy_v1(policy)?;
    let authoritative_policy_record_digest = policy.record_digest;
    if response.request_digest != state.request_digest
        || response.policy_record_digest != authoritative_policy_record_digest
        || response.scope_digest
            != state
                .scope
                .digest()
                .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?
        || !state.scope.matches(context, canonical_genesis_hash, policy)
    {
        return Err(BootleLanternIssuanceErrorV1::IssuanceResponseMismatch);
    }
    let witness = BootleLanternPresentationWitnessV1 {
        randomness: state.randomness,
        tag: response.tag,
        signature_one: response.signature_one,
        signature_two: response.signature_two,
        attributes: state.attributes,
    };
    let statement = validation_statement_v1(context.clone(), policy, &state.attributes);
    let matrix_seed = matrix_seed_v1(*context.parameter_digest.as_bytes())
        .map_err(|_| BootleLanternIssuanceErrorV1::TranscriptFailed)?;
    let relation =
        compile_application_relation_v1(&statement, policy, matrix_seed, canonical_genesis_hash)
            .map_err(|_| BootleLanternIssuanceErrorV1::RelationFailed)?;
    validate_presentation_witness_v1(&relation, &witness)
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialValidationFailed)?;
    Ok(BootleLanternCredentialV1 {
        randomness: witness.randomness,
        tag: witness.tag,
        signature_one: witness.signature_one,
        signature_two: witness.signature_two,
        attributes: witness.attributes,
        scope: state.scope.clone(),
    })
}
/// Digest of the exact native issuer implementation profile.
#[must_use]
pub fn bootle_lantern_issuer_profile_digest_v1() -> [u8; 32] {
    issuer_profile_digest_from_fields_v1(&[
        BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1,
        BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1,
        falcon512::BOOTLE_LANTERN_FALCON512_PROFILE_DESCRIPTOR_V1,
        falcon512::BOOTLE_LANTERN_FALCON512_MAPPING_DESCRIPTOR_V1,
        falcon512::BOOTLE_LANTERN_FALCON512_IMPLEMENTATION_PROVENANCE_V1,
    ])
}
fn issuer_profile_digest_from_fields_v1(fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ISSUER_PROFILE_DIGEST_DOMAIN_V1);
    hash.update(
        u64::try_from(fields.len())
            .expect("fixed issuer profile field count fits u64")
            .to_be_bytes(),
    );
    for field in fields {
        hash.update(
            u64::try_from(field.len())
                .expect("fixed issuer profile field length fits u64")
                .to_be_bytes(),
        );
        hash.update(field);
    }
    hash.finalize().into()
}
/// BLAKE3 digest of the exact issuer profile as committed by Taira provider qualification.
#[must_use]
pub fn taira_bootle_lantern_issuer_profile_contract_digest_v1() -> [u8; 32] {
    taira_length_framed_digest_v1(
        TAIRA_PROFILE_DIGEST_DOMAIN_V1,
        &[BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1],
    )
}
/// BLAKE3 digest of the exact peer-1 broker executable contract.
#[must_use]
pub fn taira_bootle_lantern_broker_contract_digest_v1() -> [u8; 32] {
    taira_length_framed_digest_v1(
        TAIRA_CONTRACT_DIGEST_DOMAIN_V1,
        &[TAIRA_BOOTLE_LANTERN_BROKER_CONTRACT_V1],
    )
}
/// Derive the one canonical peer-1 Taira provider qualification digest.
///
/// # Errors
///
/// Rejects empty or zero public bindings, an out-of-range lifetime, a policy whose identities do
/// not match the advertised binding, a policy other than the valid active epoch-one record,
/// canonical encoding failure, or a weak derived digest.
pub fn derive_taira_bootle_lantern_broker_qualification_digest_v1(
    inputs: &TairaBootleLanternBrokerQualificationInputsV1<'_>,
) -> Result<[u8; 32], TairaBootleLanternBrokerQualificationErrorV1> {
    if inputs.runtime_provider_handle.is_empty()
        || inputs.runtime_provider_revision == 0
        || inputs.issuer_id.is_zero()
        || inputs.policy_id.is_zero()
        || inputs.authorization_lifetime_blocks == 0
        || inputs.authorization_lifetime_blocks
            > MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1
        || inputs.policy.issuer_id != inputs.issuer_id
        || inputs.policy.policy_id != inputs.policy_id
        || !taira_strong_public_digest_v1(&inputs.stable_principal_digest)
    {
        return Err(TairaBootleLanternBrokerQualificationErrorV1::InvalidPublicBinding);
    }
    inputs
        .policy
        .validate_initial()
        .map_err(|_| TairaBootleLanternBrokerQualificationErrorV1::InvalidIssuerPolicy)?;
    let canonical_policy_bytes = norito::to_bytes(inputs.policy)
        .map_err(|_| TairaBootleLanternBrokerQualificationErrorV1::PolicyEncodingFailed)?;
    let digest = taira_length_framed_digest_v1(
        TAIRA_QUALIFICATION_DIGEST_DOMAIN_V1,
        &[
            inputs.network_id.as_bytes(),
            inputs.runtime_provider_handle.as_bytes(),
            &inputs.runtime_provider_revision.to_be_bytes(),
            inputs.issuer_id.as_bytes(),
            inputs.policy_id.as_bytes(),
            &inputs.authorization_lifetime_blocks.to_be_bytes(),
            inputs.policy.issuer_parameter_id.as_bytes(),
            inputs.policy.issuer_parameter_digest.as_bytes(),
            inputs.policy.record_digest.as_bytes(),
            &inputs.stable_principal_digest,
            &canonical_policy_bytes,
            BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1,
            TAIRA_BOOTLE_LANTERN_BROKER_CONTRACT_V1,
        ],
    );
    if !taira_strong_public_digest_v1(&digest) {
        return Err(TairaBootleLanternBrokerQualificationErrorV1::DegenerateDigest);
    }
    Ok(digest)
}
fn taira_length_framed_digest_v1(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(
        &u64::try_from(domain.len())
            .expect("slice length fits u64 on supported targets")
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        &u64::try_from(fields.len())
            .expect("slice length fits u64 on supported targets")
            .to_be_bytes(),
    );
    for field in fields {
        hasher.update(
            &u64::try_from(field.len())
                .expect("slice length fits u64 on supported targets")
                .to_be_bytes(),
        );
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}
fn taira_strong_public_digest_v1(bytes: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    let mut unique = 0_usize;
    for byte in bytes {
        let slot = &mut seen[usize::from(*byte)];
        if !*slot {
            *slot = true;
            unique += 1;
        }
    }
    unique >= 8
}
fn public_matrix_from_falcon_h_v1(
    h: &[u16],
) -> Result<BootleLanternIssuerPublicMatrixV1, BootleLanternIssuanceErrorV1> {
    if h.len() != FALCON_DEGREE_V1 {
        return Err(BootleLanternIssuanceErrorV1::InvalidIssuerPublicMatrix);
    }
    let first_column = core::array::from_fn(|row| BootleLanternPolynomialV1 {
        coefficients: (0..APPLICATION_RING_DEGREE_V1)
            .map(|coefficient| h[8 * coefficient + row])
            .collect(),
    });
    BootleLanternIssuerPublicMatrixV1::from_r512_first_column_blocks_v1(&first_column)
        .map_err(|_| BootleLanternIssuanceErrorV1::InvalidIssuerPublicMatrix)
}
fn masked_target_v1(
    matrix_seed: super::transcript::MatrixSeedV1,
    randomness: &[ApplicationPolynomialV1; 16],
    attributes: &[[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
) -> Result<[ApplicationPolynomialV1; APPLICATION_ROWS_V1], BootleLanternIssuanceErrorV1> {
    let a_r = expand_application_matrix_v1(matrix_seed, MatrixRoleV1::ApplicationRandomness)
        .map_err(|_| BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
    let a_m = expand_application_matrix_v1(matrix_seed, MatrixRoleV1::ApplicationAttributes)
        .map_err(|_| BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
    let attribute_polynomials = attributes.map(ApplicationPolynomialV1::from_direct_attribute);
    let mut target = [ApplicationPolynomialV1::ZERO; APPLICATION_ROWS_V1];
    for row in 0..APPLICATION_ROWS_V1 {
        for column in 0..randomness.len() {
            let coefficient = a_r
                .get(
                    u16::try_from(row).expect("fixed row fits u16"),
                    u16::try_from(column).expect("fixed column fits u16"),
                )
                .ok_or(BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
            target[row] = target[row].add(coefficient.multiply(randomness[column]));
        }
        for column in 0..attribute_polynomials.len() {
            let coefficient = a_m
                .get(
                    u16::try_from(row).expect("fixed row fits u16"),
                    u16::try_from(column).expect("fixed column fits u16"),
                )
                .ok_or(BootleLanternIssuanceErrorV1::MatrixExpansionFailed)?;
            target[row] = target[row].add(coefficient.multiply(attribute_polynomials[column]));
        }
    }
    Ok(target)
}
fn sample_tag_v1<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<Zeroizing<[ApplicationPolynomialV1; 8]>, BootleLanternIssuanceErrorV1> {
    let mut bytes = Zeroizing::new([0_u8; 64]);
    rng.try_fill_bytes(bytes.as_mut())
        .map_err(|_| BootleLanternIssuanceErrorV1::RandomnessUnavailable)?;
    let mut tag = Zeroizing::new([ApplicationPolynomialV1::ZERO; 8]);
    for row in 0..tag.len() {
        let mut coefficients = Zeroizing::new([0_u16; APPLICATION_RING_DEGREE_V1]);
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = u16::from((bytes[row * 8 + index / 8] >> (7 - index % 8)) & 1);
        }
        tag[row] = ApplicationPolynomialV1::new(*coefficients)
            .expect("binary tag coefficients are canonical");
    }
    Ok(tag)
}
fn r64_rank8_to_r512_v1(
    input: &[ApplicationPolynomialV1; APPLICATION_ROWS_V1],
) -> Zeroizing<[u16; FALCON_DEGREE_V1]> {
    let mut output = Zeroizing::new([0_u16; FALCON_DEGREE_V1]);
    for row in 0..APPLICATION_ROWS_V1 {
        for coefficient in 0..APPLICATION_RING_DEGREE_V1 {
            output[8 * coefficient + row] = input[row].coefficients()[coefficient];
        }
    }
    output
}
fn centered_r512_to_r64_rank8_v1(
    input: &[i16],
) -> Result<Zeroizing<[ApplicationPolynomialV1; APPLICATION_ROWS_V1]>, BootleLanternIssuanceErrorV1>
{
    if input.len() != FALCON_DEGREE_V1 {
        return Err(BootleLanternIssuanceErrorV1::InternalInvariant);
    }
    let mut output = Zeroizing::new([ApplicationPolynomialV1::ZERO; APPLICATION_ROWS_V1]);
    for row in 0..APPLICATION_ROWS_V1 {
        let mut coefficients = Zeroizing::new([0_i64; APPLICATION_RING_DEGREE_V1]);
        for (coefficient, output_coefficient) in coefficients.iter_mut().enumerate() {
            *output_coefficient = i64::from(input[8 * coefficient + row]);
        }
        output[row] = ApplicationPolynomialV1::from_centered_coefficients(*coefficients);
    }
    Ok(output)
}
fn validation_statement_v1(
    context: PrivacyStatementContextV1,
    policy: &BootleLanternIssuerPolicyV1,
    attributes: &[[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1],
) -> IrohaBootleLanternAnoncredStatementV1 {
    let disclosures = attributes
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| policy.required_disclosure_bitmap & (1_u8 << index) != 0)
        .map(|(index, attribute)| BootleLanternDisclosedAttributeV1 {
            index: u8::try_from(index).expect("fixed attribute index fits u8"),
            value: BootleLanternAttributeValueV1::new(attribute),
        })
        .collect();
    IrohaBootleLanternAnoncredStatementV1 {
        context,
        issuer_id: policy.issuer_id,
        policy_id: policy.policy_id,
        issuer_policy_epoch: policy.epoch,
        issuer_policy_record_digest: policy.record_digest,
        issuer_parameter_id: policy.issuer_parameter_id,
        issuer_parameter_digest: policy.issuer_parameter_digest,
        disclosures,
    }
}
fn digest_application_vector_v1(
    domain: &[u8],
    vector: &[ApplicationPolynomialV1; APPLICATION_ROWS_V1],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for polynomial in vector {
        for coefficient in polynomial.coefficients() {
            hash.update(coefficient.to_be_bytes());
        }
    }
    hash.finalize().into()
}
fn blind_request_digest_v1(
    target_digest: &[u8; 32],
    issuance_authorization_digest: &[u8; 32],
    scope_digest: &[u8; 32],
    policy_record_digest: &[u8; 32],
    proof_wire: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REQUEST_DIGEST_DOMAIN_V1);
    for field in [
        target_digest.as_slice(),
        issuance_authorization_digest.as_slice(),
        scope_digest.as_slice(),
        policy_record_digest.as_slice(),
        proof_wire,
    ] {
        hash.update(
            u64::try_from(field.len())
                .expect("bounded request field length fits u64")
                .to_be_bytes(),
        );
        hash.update(field);
    }
    hash.finalize().into()
}
fn validate_authorization_lifetime_v1(
    issued_at_height: u64,
    expires_at_height: u64,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    let lifetime = expires_at_height
        .checked_sub(issued_at_height)
        .ok_or(BootleLanternIssuanceErrorV1::InvalidAuthorizationLifetime)?;
    if lifetime == 0 || lifetime > MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1 {
        return Err(BootleLanternIssuanceErrorV1::InvalidAuthorizationLifetime);
    }
    Ok(())
}
fn validate_issuance_authorization_self_v1(
    authorization: &BootleLanternIssuanceAuthorizationV1,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    if authorization.authorization_id == [0; 32]
        || authorization.issuer_profile_digest != bootle_lantern_issuer_profile_digest_v1()
        || authorization.canonical_genesis_hash == [0; 32]
        || authorization.credential_scope_digest == [0; 32]
        || authorization.policy_record_digest.is_zero()
        || authorization.issuer_parameter_id.is_zero()
        || authorization.issuer_parameter_digest.is_zero()
        || authorization.policy_epoch == 0
        || authorization.requester_authorization_digest == [0; 32]
        || authorization.authorization_digest == [0; 32]
    {
        return Err(BootleLanternIssuanceErrorV1::InvalidIssuanceAuthorization);
    }
    validate_authorization_lifetime_v1(
        authorization.issued_at_height,
        authorization.expires_at_height,
    )?;
    if authorization.authorization_digest != issuance_authorization_digest_v1(authorization) {
        return Err(BootleLanternIssuanceErrorV1::InvalidIssuanceAuthorization);
    }
    Ok(())
}
fn validate_issuance_authorization_v1(
    authorization: &BootleLanternIssuanceAuthorizationV1,
    context: &PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    policy: &BootleLanternIssuerPolicyV1,
    current_height: Option<u64>,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    validate_issuance_authorization_self_v1(authorization)?;
    let scope = BootleLanternCredentialScopeV1::new(context, canonical_genesis_hash, policy)
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    let scope_digest = scope
        .digest()
        .map_err(|_| BootleLanternIssuanceErrorV1::CredentialScopeFailed)?;
    if authorization.canonical_genesis_hash != canonical_genesis_hash
        || authorization.credential_scope_digest != scope_digest
        || authorization.policy_record_digest != policy.record_digest
        || authorization.issuer_parameter_id != policy.issuer_parameter_id
        || authorization.issuer_parameter_digest != policy.issuer_parameter_digest
        || authorization.policy_epoch != policy.epoch
    {
        return Err(BootleLanternIssuanceErrorV1::AuthorizationBindingMismatch);
    }
    if let Some(current_height) = current_height {
        if current_height < authorization.issued_at_height {
            return Err(BootleLanternIssuanceErrorV1::AuthorizationNotYetValid);
        }
        if current_height > authorization.expires_at_height {
            return Err(BootleLanternIssuanceErrorV1::AuthorizationExpired);
        }
    }
    Ok(())
}
fn issuance_authorization_digest_v1(
    authorization: &BootleLanternIssuanceAuthorizationV1,
) -> [u8; 32] {
    let policy_epoch = authorization.policy_epoch.to_be_bytes();
    let issued_at_height = authorization.issued_at_height.to_be_bytes();
    let expires_at_height = authorization.expires_at_height.to_be_bytes();
    let mut hash = Sha256::new();
    hash.update(AUTHORIZATION_DIGEST_DOMAIN_V1);
    for field in [
        authorization.authorization_id.as_slice(),
        authorization.issuer_profile_digest.as_slice(),
        authorization.canonical_genesis_hash.as_slice(),
        authorization.credential_scope_digest.as_slice(),
        authorization.policy_record_digest.as_bytes().as_slice(),
        authorization.issuer_parameter_id.as_bytes().as_slice(),
        authorization.issuer_parameter_digest.as_bytes().as_slice(),
        policy_epoch.as_slice(),
        authorization.requester_authorization_digest.as_slice(),
        issued_at_height.as_slice(),
        expires_at_height.as_slice(),
    ] {
        hash.update(
            u64::try_from(field.len())
                .expect("fixed authorization field length fits u64")
                .to_be_bytes(),
        );
        hash.update(field);
    }
    hash.finalize().into()
}
fn take_32_v1(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], BootleLanternIssuanceErrorV1> {
    let end = offset
        .checked_add(32)
        .ok_or(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?;
    let output = bytes
        .get(*offset..end)
        .ok_or(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?
        .try_into()
        .map_err(|_| BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?;
    *offset = end;
    Ok(output)
}
fn take_blind_request_32_v1(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; 32], BootleLanternIssuanceErrorV1> {
    let end = offset
        .checked_add(32)
        .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
    let output = bytes
        .get(*offset..end)
        .ok_or(BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?
        .try_into()
        .map_err(|_| BootleLanternIssuanceErrorV1::BlindRequestWireInvalid)?;
    *offset = end;
    Ok(output)
}
fn take_u64_v1(bytes: &[u8], offset: &mut usize) -> Result<u64, BootleLanternIssuanceErrorV1> {
    let end = offset
        .checked_add(8)
        .ok_or(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?;
    let encoded: [u8; 8] = bytes
        .get(*offset..end)
        .ok_or(BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?
        .try_into()
        .map_err(|_| BootleLanternIssuanceErrorV1::AuthorizationWireInvalid)?;
    *offset = end;
    Ok(u64::from_be_bytes(encoded))
}
fn decode_application_polynomials_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
    require_binary: bool,
) -> Result<Zeroizing<[ApplicationPolynomialV1; N]>, BootleLanternIssuanceErrorV1> {
    let mut polynomials = Zeroizing::new([ApplicationPolynomialV1::ZERO; N]);
    for polynomial in polynomials.iter_mut() {
        let mut coefficients = Zeroizing::new([0_u16; APPLICATION_RING_DEGREE_V1]);
        for coefficient in coefficients.iter_mut() {
            let end = offset
                .checked_add(2)
                .ok_or(BootleLanternIssuanceErrorV1::ResponseWireInvalid)?;
            let encoded: [u8; 2] = bytes
                .get(*offset..end)
                .ok_or(BootleLanternIssuanceErrorV1::ResponseWireInvalid)?
                .try_into()
                .map_err(|_| BootleLanternIssuanceErrorV1::ResponseWireInvalid)?;
            *offset = end;
            *coefficient = u16::from_be_bytes(encoded);
            if *coefficient >= APPLICATION_MODULUS_V1 || (require_binary && *coefficient > 1) {
                return Err(BootleLanternIssuanceErrorV1::ResponseWireInvalid);
            }
        }
        *polynomial = ApplicationPolynomialV1::new(*coefficients)
            .map_err(|_| BootleLanternIssuanceErrorV1::ResponseWireInvalid)?;
    }
    Ok(polynomials)
}
fn require_active_policy_v1(
    policy: &BootleLanternIssuerPolicyV1,
) -> Result<(), BootleLanternIssuanceErrorV1> {
    policy
        .validate()
        .map_err(|_| BootleLanternIssuanceErrorV1::InvalidIssuerPolicy)?;
    if policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
        return Err(BootleLanternIssuanceErrorV1::IssuerPolicyNotActive);
    }
    Ok(())
}
fn map_randomness_error_v1(error: ProverRandomnessErrorV1) -> BootleLanternIssuanceErrorV1 {
    match error {
        ProverRandomnessErrorV1::Unavailable => BootleLanternIssuanceErrorV1::RandomnessUnavailable,
        ProverRandomnessErrorV1::Unhealthy => BootleLanternIssuanceErrorV1::RandomnessUnhealthy,
    }
}
fn map_credential_randomness_error_v1(
    error: CredentialRandomnessErrorV1,
) -> BootleLanternIssuanceErrorV1 {
    match error {
        CredentialRandomnessErrorV1::RandomnessUnavailable => {
            BootleLanternIssuanceErrorV1::RandomnessUnavailable
        }
        CredentialRandomnessErrorV1::CoefficientSamplingExhausted
        | CredentialRandomnessErrorV1::SamplingExhausted => {
            BootleLanternIssuanceErrorV1::HolderRandomnessSamplingExhausted
        }
        CredentialRandomnessErrorV1::InternalInvariant => {
            BootleLanternIssuanceErrorV1::InternalInvariant
        }
    }
}
/// Failure in the closed native issuance lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BootleLanternIssuanceErrorV1 {
    /// Issuer parameter identity was zero.
    #[error("Bootle/Lantern issuer parameter id is invalid")]
    InvalidIssuerParameterId,
    /// Stable issuer key seed was all zero or otherwise forbidden.
    #[error("Bootle/Lantern issuer secret seed is invalid")]
    InvalidIssuerSecretSeed,
    /// Cryptographic randomness became unavailable.
    #[error("Bootle/Lantern issuance randomness is unavailable")]
    RandomnessUnavailable,
    /// Cryptographic randomness failed the canonical health check.
    #[error("Bootle/Lantern issuance randomness failed its health check")]
    RandomnessUnhealthy,
    /// Bounded Falcon/NTRU key generation exhausted its candidates.
    #[error("Bootle/Lantern Falcon issuer key generation exhausted")]
    IssuerKeyGenerationExhausted,
    /// Generated issuer public matrix failed its exact structure.
    #[error("Bootle/Lantern issuer public matrix is invalid")]
    InvalidIssuerPublicMatrix,
    /// Policy canonical encoding failed.
    #[error("Bootle/Lantern issuer policy encoding failed")]
    PolicyEncodingFailed,
    /// Governed issuer policy was malformed.
    #[error("Bootle/Lantern issuer policy is invalid")]
    InvalidIssuerPolicy,
    /// A revoked policy was selected for issuance or presentation.
    #[error("Bootle/Lantern issuer policy is not active")]
    IssuerPolicyNotActive,
    /// Issuer trapdoor and governed public policy differ.
    #[error("Bootle/Lantern issuer key does not match policy")]
    IssuerKeyPolicyMismatch,
    /// External issuer-side requester authorization was zero.
    #[error("Bootle/Lantern requester authorization digest is invalid")]
    InvalidRequesterAuthorization,
    /// Authorization expiry was empty, reversed, or exceeded its public cap.
    #[error("Bootle/Lantern issuance authorization lifetime is invalid")]
    InvalidAuthorizationLifetime,
    /// Bounded non-zero collision-free authorization-id sampling exhausted.
    #[error("Bootle/Lantern issuance authorization id sampling exhausted")]
    AuthorizationIdExhausted,
    /// Authorization fields or their self-digest were malformed.
    #[error("Bootle/Lantern issuance authorization is invalid")]
    InvalidIssuanceAuthorization,
    /// Holder-facing `ILA1` bytes were not the unique canonical encoding.
    #[error("Bootle/Lantern issuance authorization wire is invalid")]
    AuthorizationWireInvalid,
    /// Authorization selected another chain, scope, policy, key, or epoch.
    #[error("Bootle/Lantern issuance authorization binding mismatch")]
    AuthorizationBindingMismatch,
    /// Issuance was attempted before the authorization's issued height.
    #[error("Bootle/Lantern issuance authorization is not yet valid")]
    AuthorizationNotYetValid,
    /// Issuance was attempted after the authorization's inclusive expiry.
    #[error("Bootle/Lantern issuance authorization expired")]
    AuthorizationExpired,
    /// Another worker owns the same in-flight request.
    #[error("Bootle/Lantern issuance authorization is busy")]
    AuthorizationBusy,
    /// Authorization was absent, substituted, spent, or terminally failed.
    #[error("Bootle/Lantern issuance authorization is consumed")]
    AuthorizationConsumed,
    /// Atomic authorization persistence or durable completion failed.
    #[error("Bootle/Lantern issuance store failed")]
    IssuanceStoreFailed,
    /// Reusable credential scope construction failed.
    #[error("Bootle/Lantern credential scope construction failed")]
    CredentialScopeFailed,
    /// Later presentation selected another reusable scope.
    #[error("Bootle/Lantern credential scope mismatch")]
    CredentialScopeMismatch,
    /// Exact holder randomness sampling exhausted its bound.
    #[error("Bootle/Lantern holder randomness sampling exhausted")]
    HolderRandomnessSamplingExhausted,
    /// Matrix expansion failed.
    #[error("Bootle/Lantern application matrix expansion failed")]
    MatrixExpansionFailed,
    /// Public relation construction failed.
    #[error("Bootle/Lantern issuance relation construction failed")]
    RelationFailed,
    /// Transcript construction failed.
    #[error("Bootle/Lantern issuance transcript construction failed")]
    TranscriptFailed,
    /// P1 construction or verification failed.
    #[error("Bootle/Lantern blind-request proof failed")]
    BlindRequestProofFailed,
    /// Complete holder request exceeded the caller's byte ceiling.
    #[error("Bootle/Lantern blind-request wire has {bytes} bytes, exceeding limit {max}")]
    BlindRequestWireTooLarge {
        /// Exact received request length.
        bytes: u64,
        /// Caller-supplied admission ceiling.
        max: u32,
    },
    /// `ILQ1` bytes were not the unique canonical complete holder request.
    #[error("Bootle/Lantern blind-request wire is invalid")]
    BlindRequestWireInvalid,
    /// Request fields, target, policy, or proof digest were substituted.
    #[error("Bootle/Lantern blind-request binding mismatch")]
    BlindRequestBindingMismatch,
    /// Bounded Falcon preimage sampling exhausted for the fixed target.
    #[error("Bootle/Lantern Falcon preimage sampling exhausted")]
    PreimageSamplingExhausted,
    /// `ILR1` bytes were not the unique canonical issuer response.
    #[error("Bootle/Lantern issuance response wire is invalid")]
    ResponseWireInvalid,
    /// Durable completed response bytes did not match the claimed request.
    #[error("Bootle/Lantern cached issuance response is invalid")]
    CachedIssuanceResponseInvalid,
    /// Holder state and issuer response differ.
    #[error("Bootle/Lantern issuance response mismatch")]
    IssuanceResponseMismatch,
    /// Final credential equation or norm check failed.
    #[error("Bootle/Lantern finalized credential validation failed")]
    CredentialValidationFailed,
    /// A closed implementation invariant failed.
    #[error("Bootle/Lantern issuance internal invariant failed")]
    InternalInvariant,
}
impl From<CredentialScopeErrorV1> for BootleLanternIssuanceErrorV1 {
    fn from(_: CredentialScopeErrorV1) -> Self {
        Self::CredentialScopeFailed
    }
}
impl From<RelationErrorV1> for BootleLanternIssuanceErrorV1 {
    fn from(_: RelationErrorV1) -> Self {
        Self::RelationFailed
    }
}
impl From<TranscriptErrorV1> for BootleLanternIssuanceErrorV1 {
    fn from(_: TranscriptErrorV1) -> Self {
        Self::TranscriptFailed
    }
}
impl From<PresentationProofErrorV1> for BootleLanternIssuanceErrorV1 {
    fn from(_: PresentationProofErrorV1) -> Self {
        Self::BlindRequestProofFailed
    }
}
const _: () = {
    assert!(APPLICATION_ROWS_V1 == 8);
    assert!(APPLICATION_RING_DEGREE_V1 * APPLICATION_ROWS_V1 == FALCON_DEGREE_V1);
    assert!(APPLICATION_MODULUS_V1 == 12_289);
    assert!(BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1 as usize == APPLICATION_ROWS_V1);
    assert!(BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1 as usize == APPLICATION_RING_DEGREE_V1);
    assert!(BLIND_ISSUANCE_REQUEST_BINDING_FIELDS_V1 == 5);
    assert!(BLIND_ISSUANCE_REQUEST_BYTES_V1 == 71_576);
};
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        block::BlockHeader,
        privacy::{
            PrivacyEngineManifestDigestV1, PrivacyStatementSchemaDigestV1,
            PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
        },
    };
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    use std::sync::{
        OnceLock,
        atomic::{AtomicU32, Ordering},
    };
    #[test]
    fn issuer_profile_digest_binds_every_exact_native_subprofile_in_order() {
        let canonical_fields = [
            BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1,
            BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1,
            falcon512::BOOTLE_LANTERN_FALCON512_PROFILE_DESCRIPTOR_V1,
            falcon512::BOOTLE_LANTERN_FALCON512_MAPPING_DESCRIPTOR_V1,
            falcon512::BOOTLE_LANTERN_FALCON512_IMPLEMENTATION_PROVENANCE_V1,
        ];
        let canonical = bootle_lantern_issuer_profile_digest_v1();
        assert_eq!(
            canonical,
            issuer_profile_digest_from_fields_v1(&canonical_fields)
        );
        assert_ne!(canonical, [0; 32]);
        for changed_index in 0..canonical_fields.len() {
            let mut changed_fields = canonical_fields
                .iter()
                .map(|field| field.to_vec())
                .collect::<Vec<_>>();
            changed_fields[changed_index][0] ^= 1;
            let changed_refs = changed_fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_ne!(
                canonical,
                issuer_profile_digest_from_fields_v1(&changed_refs),
                "field {changed_index} must be bound"
            );
        }
        let reordered = [
            canonical_fields[1],
            canonical_fields[0],
            canonical_fields[2],
            canonical_fields[3],
            canonical_fields[4],
        ];
        assert_ne!(canonical, issuer_profile_digest_from_fields_v1(&reordered));
    }
    struct TestRng {
        state: u64,
    }
    impl TestRng {
        const fn healthy(seed: u64) -> Self {
            Self { state: seed }
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("infallible deterministic test RNG");
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for byte in destination {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                *byte = self.state as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("issuer RNG was touched before a successful fresh claim")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("issuer RNG was touched before a successful fresh claim")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("issuer RNG was touched before a successful fresh claim")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
            panic!("issuer RNG was touched before a successful fresh claim")
        }
    }
    impl CryptoRng for PanicRng {}
    struct FailingRng;
    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            panic!("fallible path must use try_fill_bytes")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("fallible path must use try_fill_bytes")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("fallible path must use try_fill_bytes")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
            Err(RngError::new("injected issuer RNG failure"))
        }
    }
    impl CryptoRng for FailingRng {}
    struct IssuanceFixture {
        issuer: BootleLanternIssuerKeyPairV1,
        context: PrivacyStatementContextV1,
        genesis_hash: [u8; 32],
        policy: BootleLanternIssuerPolicyV1,
        authorization: BootleLanternIssuanceAuthorizationV1,
        request: BootleLanternBlindIssuanceRequestV1,
        credential: BootleLanternCredentialV1,
    }
    fn raw(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn network_id(byte: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(raw(byte)),
        ))
    }
    fn statement_context_v1() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: network_id(0x32),
            action_index: 3,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(1)),
            parameter_id: PrivacyParameterIdV1::new(raw(2)),
            parameter_digest: PrivacyParameterDigestV1::new([0x31; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new(raw(4)),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(5)),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(6)),
        }
    }
    fn policy_metadata_v1(epoch: u64) -> BootleLanternIssuerPolicyMetadataV1 {
        BootleLanternIssuerPolicyMetadataV1 {
            issuer_id: PrivacyIssuerIdV1::new(raw(11)),
            policy_id: PrivacyPolicyIdV1::new(raw(12)),
            epoch,
            required_disclosure_bitmap: 0b0000_0010,
            allowed_values: (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
                .map(|index| BootleLanternAllowedAttributeValuesV1 {
                    values: if index == 1 {
                        vec![BootleLanternAttributeValueV1::new([1; 8])]
                    } else {
                        Vec::new()
                    },
                })
                .collect(),
        }
    }
    fn attributes_v1() -> [[u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1] {
        let mut attributes = [[0_u8; 8]; BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1];
        attributes[1] = [1; 8];
        attributes
    }
    fn presentation_statement_v1(
        context: PrivacyStatementContextV1,
        policy: &BootleLanternIssuerPolicyV1,
    ) -> IrohaBootleLanternAnoncredStatementV1 {
        IrohaBootleLanternAnoncredStatementV1 {
            context,
            issuer_id: policy.issuer_id,
            policy_id: policy.policy_id,
            issuer_policy_epoch: policy.epoch,
            issuer_policy_record_digest: policy.record_digest,
            issuer_parameter_id: policy.issuer_parameter_id,
            issuer_parameter_digest: policy.issuer_parameter_digest,
            disclosures: vec![BootleLanternDisclosedAttributeV1 {
                index: 1,
                value: BootleLanternAttributeValueV1::new([1; 8]),
            }],
        }
    }
    fn clone_request_v1(
        request: &BootleLanternBlindIssuanceRequestV1,
    ) -> BootleLanternBlindIssuanceRequestV1 {
        BootleLanternBlindIssuanceRequestV1 {
            target: request.target,
            target_digest: request.target_digest,
            issuance_authorization_digest: request.issuance_authorization_digest,
            scope_digest: request.scope_digest,
            issuer_profile_digest: request.issuer_profile_digest,
            policy_record_digest: request.policy_record_digest,
            proof: request.proof.clone(),
            request_digest: request.request_digest,
        }
    }
    fn issuance_fixture_v1() -> &'static IssuanceFixture {
        static FIXTURE: OnceLock<IssuanceFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let mut keygen_rng = TestRng::healthy(0x6a09_e667_f3bc_c908);
            let issuer = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                PrivacyParameterIdV1::new(raw(13)),
                &mut keygen_rng,
            )
            .expect("native issuer key generation");
            let policy = issuer
                .active_policy_v1(policy_metadata_v1(1))
                .expect("active native issuer policy");
            let context = statement_context_v1();
            let genesis_hash = *context.network_id.as_bytes();
            let store = BootleLanternInMemoryIssuanceStoreV1::new();
            let mut authorization_rng = TestRng::healthy(0x1f83_d9ab_fb41_bd6b);
            let authorization = issuer_authorize_blind_issuance_with_rng_v1(
                &issuer,
                &context,
                genesis_hash,
                &policy,
                [0x71; 32],
                10,
                20,
                &store,
                &mut authorization_rng,
            )
            .expect("one-shot issuer authorization");
            let mut holder_issuance_rng = TestRng::healthy(0xbb67_ae85_84ca_a73b);
            let (request, state) = holder_prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes_v1(),
                &mut holder_issuance_rng,
            )
            .expect("holder blind-issuance request");
            let request_wire = request.encode().expect("canonical ILQ1 request");
            let mut issuer_issuance_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
            let response = issuer_blind_issue_once_encoded_with_rng_v1(
                &issuer,
                &context,
                genesis_hash,
                &policy,
                &authorization,
                &request_wire,
                11,
                &store,
                &mut issuer_issuance_rng,
            )
            .expect("native blind issuance");
            let credential =
                holder_finalize_blind_issuance_v1(state, &context, genesis_hash, &policy, response)
                    .expect("holder finalization");
            IssuanceFixture {
                issuer,
                context,
                genesis_hash,
                policy,
                authorization,
                request,
                credential,
            }
        })
    }
    fn fresh_store_v1(fixture: &IssuanceFixture) -> BootleLanternInMemoryIssuanceStoreV1 {
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        store
            .register_fresh_v1(
                fixture.authorization.authorization_id,
                fixture.authorization.authorization_digest,
                fixture.authorization.issued_at_height,
                fixture.authorization.expires_at_height,
            )
            .expect("fresh fixture authorization");
        store
    }
    fn assert_store_remained_fresh_v1(
        fixture: &IssuanceFixture,
        store: &BootleLanternInMemoryIssuanceStoreV1,
    ) {
        assert_eq!(
            store.preflight_v1(
                fixture.authorization.authorization_id,
                fixture.authorization.authorization_digest,
                fixture.request.request_digest,
                fixture.authorization.issued_at_height,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
    }
    fn valid_authorization_v1() -> BootleLanternIssuanceAuthorizationV1 {
        let mut authorization = BootleLanternIssuanceAuthorizationV1 {
            authorization_id: raw(1),
            issuer_profile_digest: bootle_lantern_issuer_profile_digest_v1(),
            canonical_genesis_hash: raw(2),
            credential_scope_digest: raw(3),
            policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new(raw(4)),
            issuer_parameter_id: PrivacyParameterIdV1::new(raw(5)),
            issuer_parameter_digest: PrivacyParameterDigestV1::new(raw(6)),
            policy_epoch: 7,
            requester_authorization_digest: raw(8),
            issued_at_height: 9,
            expires_at_height: 10,
            authorization_digest: [0; 32],
        };
        authorization.authorization_digest = issuance_authorization_digest_v1(&authorization);
        authorization
    }
    fn valid_response_v1() -> BootleLanternBlindIssuanceResponseV1 {
        BootleLanternBlindIssuanceResponseV1 {
            tag: [ApplicationPolynomialV1::ZERO; 8],
            signature_one: [ApplicationPolynomialV1::ZERO; 8],
            signature_two: [ApplicationPolynomialV1::ZERO; 8],
            request_digest: raw(1),
            scope_digest: raw(2),
            policy_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new(raw(3)),
        }
    }
    fn decode_ilq1_error_v1(bytes: &[u8], cap: u32) -> BootleLanternIssuanceErrorV1 {
        BootleLanternBlindIssuanceRequestV1::decode_exact(bytes, cap)
            .expect_err("malformed ILQ1 must fail")
    }
    #[test]
    fn secret_seed_key_reconstruction_is_exact_and_rejects_defaults() {
        let parameter_id = PrivacyParameterIdV1::new(raw(0x13));
        let secret_seed = raw(0xA7);
        let first =
            BootleLanternIssuerKeyPairV1::generate_from_secret_seed_v1(parameter_id, &secret_seed)
                .expect("first stable issuer key");
        let second =
            BootleLanternIssuerKeyPairV1::generate_from_secret_seed_v1(parameter_id, &secret_seed)
                .expect("second stable issuer key");
        assert_eq!(
            first
                .active_policy_v1(policy_metadata_v1(1))
                .expect("first governed policy"),
            second
                .active_policy_v1(policy_metadata_v1(1))
                .expect("second governed policy")
        );
        assert!(matches!(
            BootleLanternIssuerKeyPairV1::generate_from_secret_seed_v1(parameter_id, &[0; 32]),
            Err(BootleLanternIssuanceErrorV1::InvalidIssuerSecretSeed)
        ));
        assert!(matches!(
            BootleLanternIssuerKeyPairV1::generate_from_secret_seed_v1(
                PrivacyParameterIdV1::new([0; 32]),
                &secret_seed,
            ),
            Err(BootleLanternIssuanceErrorV1::InvalidIssuerParameterId)
        ));
    }
    #[test]
    fn provider_authorization_candidate_is_store_free_and_fully_publicly_bound() {
        let fixture = issuance_fixture_v1();
        let mut rng = TestRng::healthy(0x510e_527f_ade6_82d1);
        let authorization = issuer_prepare_blind_issuance_authorization_candidate_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            [0x81; 32],
            21,
            31,
            &mut rng,
        )
        .expect("provider candidate");
        issuer_validate_prepared_blind_issuance_authorization_v1(
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &authorization,
        )
        .expect("exact public candidate binding");
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        assert_eq!(
            store.preflight_v1(
                authorization.authorization_id(),
                authorization.authorization_digest(),
                [0x91; 32],
                21,
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationConsumed),
            "provider preparation must not mutate Torii-owned replay state"
        );
        store
            .register_fresh_v1(
                authorization.authorization_id(),
                authorization.authorization_digest(),
                authorization.issued_at_height(),
                authorization.expires_at_height(),
            )
            .expect("sole authoritative registration");
        assert_eq!(
            store.register_fresh_v1(
                authorization.authorization_id(),
                authorization.authorization_digest(),
                authorization.issued_at_height(),
                authorization.expires_at_height(),
            ),
            Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists)
        );
        let mut substituted_context = fixture.context.clone();
        substituted_context.parameter_digest = PrivacyParameterDigestV1::new(raw(0x87));
        assert_eq!(
            issuer_validate_prepared_blind_issuance_authorization_v1(
                &substituted_context,
                fixture.genesis_hash,
                &fixture.policy,
                &authorization,
            ),
            Err(BootleLanternIssuanceErrorV1::AuthorizationBindingMismatch)
        );
    }
    #[test]
    fn pure_provider_issue_split_revalidates_before_rng_and_binds_cached_response() {
        let fixture = issuance_fixture_v1();
        let request_wire = fixture.request.encode().expect("canonical ILQ1");
        assert_eq!(
            issuer_validate_blind_issuance_request_encoded_v1(
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                11,
            ),
            Ok(fixture.request.request_digest())
        );
        assert_eq!(
            issuer_validate_blind_issuance_request_for_issuer_encoded_v1(
                &fixture.issuer,
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                11,
            ),
            Ok(fixture.request.request_digest())
        );
        assert_eq!(
            issuer_validate_blind_issuance_request_encoded_v1(
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                9,
            ),
            Err(BootleLanternIssuanceErrorV1::AuthorizationNotYetValid)
        );
        let mut substituted_request = request_wire.clone();
        *substituted_request
            .last_mut()
            .expect("fixed request is non-empty") ^= 1;
        assert!(
            issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
                &fixture.issuer,
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &substituted_request,
                11,
                &mut PanicRng,
            )
            .is_err(),
            "request substitution must fail before issuer RNG"
        );
        assert!(
            issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
                &fixture.issuer,
                &fixture.context,
                [0; 32],
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                11,
                &mut PanicRng,
            )
            .is_err(),
            "genesis substitution must fail before issuer RNG"
        );
        let mut issue_rng = TestRng::healthy(0x9b05_688c_2b3e_6c1f);
        let response = issuer_issue_validated_blind_issuance_request_encoded_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &request_wire,
            11,
            &mut issue_rng,
        )
        .expect("pure provider issue");
        let response_wire = response.encode().expect("canonical ILR1");
        assert_eq!(
            issuer_validate_cached_blind_issuance_response_encoded_v1(
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                &response_wire,
            )
            .expect("exact cached response")
            .encode()
            .expect("canonical cached response"),
            response_wire
        );
        let mut substituted_response = response_wire;
        *substituted_response
            .last_mut()
            .expect("fixed response is non-empty") ^= 1;
        assert_eq!(
            issuer_validate_cached_blind_issuance_response_encoded_v1(
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                &substituted_response,
            )
            .expect_err("response substitution must fail"),
            BootleLanternIssuanceErrorV1::CachedIssuanceResponseInvalid
        );
    }
    #[test]
    fn production_provider_wrappers_use_fresh_os_randomness_and_preserve_exact_bindings() {
        let fixture = issuance_fixture_v1();
        let authorization = issuer_prepare_blind_issuance_authorization_candidate_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            [0xD1; 32],
            21,
            31,
        )
        .expect("prepare provider authorization with OS randomness");
        issuer_validate_prepared_blind_issuance_authorization_v1(
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &authorization,
        )
        .expect("validate OS-random authorization candidate");
        assert_ne!(
            authorization.authorization_id(),
            [0; 32],
            "production preparation must return a non-zero identifier"
        );
        let request_wire = fixture.request.encode().expect("canonical ILQ1");
        let response = issuer_issue_validated_blind_issuance_request_encoded_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &request_wire,
            11,
        )
        .expect("issue provider response with OS randomness");
        let response_wire = response.encode().expect("canonical OS-random ILR1");
        issuer_validate_cached_blind_issuance_response_encoded_v1(
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &request_wire,
            &response_wire,
        )
        .expect("validate exact OS-random response binding");
    }
    #[test]
    fn ilq1_wire_roundtrips_and_rejects_every_non_exact_outer_length() {
        let wire = issuance_fixture_v1()
            .request
            .encode()
            .expect("canonical ILQ1 request");
        let cap = u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1)
            .expect("fixed ILQ1 request length fits u32");
        assert_eq!(wire.len(), BLIND_ISSUANCE_REQUEST_BYTES_V1);
        assert_eq!(wire.len(), 71_576);
        assert_eq!(
            &wire[..BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1],
            &[
                b'I', b'L', b'Q', b'1', 1, 1, 0, 0, 0, 8, 0, 64, 0, 1, 18, 200
            ]
        );
        assert_eq!(
            BootleLanternBlindIssuanceRequestV1::decode_exact(&wire, cap)
                .expect("strict ILQ1 decode")
                .encode()
                .expect("canonical ILQ1 re-encoding"),
            wire
        );
        for length in 0..wire.len() {
            assert_eq!(
                BootleLanternBlindIssuanceRequestV1::decode_exact(&wire[..length], cap)
                    .expect_err("every ILQ1 truncation must fail"),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid,
                "ILQ1 truncation at length {length} was misclassified"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_ilq1_error_v1(&trailing, cap),
            BootleLanternIssuanceErrorV1::BlindRequestWireTooLarge {
                bytes: u64::from(cap) + 1,
                max: cap,
            }
        );
        assert_eq!(
            decode_ilq1_error_v1(&trailing, cap + 1),
            BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
        );
        assert_eq!(
            decode_ilq1_error_v1(&wire, cap - 1),
            BootleLanternIssuanceErrorV1::BlindRequestWireTooLarge {
                bytes: u64::from(cap),
                max: cap - 1,
            }
        );
    }
    #[test]
    fn ilq1_decoder_rejects_header_count_length_and_payload_substitutions() {
        let canonical = issuance_fixture_v1()
            .request
            .encode()
            .expect("canonical ILQ1 request");
        let cap = u32::try_from(BLIND_ISSUANCE_REQUEST_BYTES_V1)
            .expect("fixed ILQ1 request length fits u32");
        for magic_byte in 0..4 {
            for bit in 0..8 {
                let mut malformed = canonical.clone();
                malformed[magic_byte] ^= 1_u8 << bit;
                assert_eq!(
                    decode_ilq1_error_v1(&malformed, cap),
                    BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
                );
            }
        }
        for version in 0..=u8::MAX {
            if version == BLIND_ISSUANCE_REQUEST_VERSION_V1 {
                continue;
            }
            let mut malformed = canonical.clone();
            malformed[4] = version;
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        for purpose in 0..=u8::MAX {
            if purpose == BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1 {
                continue;
            }
            let mut malformed = canonical.clone();
            malformed[5] = purpose;
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        for bit in 0..16 {
            let mut malformed = canonical.clone();
            malformed[6..8].copy_from_slice(&(1_u16 << bit).to_be_bytes());
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        for target_count in [0_u16, 7, 9, u16::MAX] {
            let mut malformed = canonical.clone();
            malformed[8..10].copy_from_slice(&target_count.to_be_bytes());
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        for ring_degree in [0_u16, 63, 65, u16::MAX] {
            let mut malformed = canonical.clone();
            malformed[10..12].copy_from_slice(&ring_degree.to_be_bytes());
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        for proof_length in [0_u32, 70_343, 70_345, u32::MAX] {
            let mut malformed = canonical.clone();
            malformed[12..16].copy_from_slice(&proof_length.to_be_bytes());
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
            );
        }
        let target_bytes = APPLICATION_ROWS_V1 * APPLICATION_RING_DEGREE_V1 * 2;
        let bindings_offset = BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1 + target_bytes;
        let proof_offset = bindings_offset + BLIND_ISSUANCE_REQUEST_BINDING_FIELDS_V1 * 32;
        let mut noncanonical_target = canonical.clone();
        noncanonical_target
            [BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1..BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1 + 2]
            .copy_from_slice(&APPLICATION_MODULUS_V1.to_be_bytes());
        assert_eq!(
            decode_ilq1_error_v1(&noncanonical_target, cap),
            BootleLanternIssuanceErrorV1::BlindRequestWireInvalid
        );
        for binding in 0..BLIND_ISSUANCE_REQUEST_BINDING_FIELDS_V1 {
            let mut zero_binding = canonical.clone();
            let start = bindings_offset + binding * 32;
            zero_binding[start..start + 32].fill(0);
            assert_eq!(
                decode_ilq1_error_v1(&zero_binding, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid,
                "zero ILQ1 binding {binding} was accepted"
            );
        }
        for inner_header_byte in 0..8 {
            let mut malformed = canonical.clone();
            malformed[proof_offset + inner_header_byte] ^= 1;
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid,
                "inner ILB1 header substitution at {inner_header_byte} was accepted"
            );
        }
        for offset in [bindings_offset, proof_offset + 8, canonical.len() - 1] {
            let mut malformed = canonical.clone();
            malformed[offset] ^= 1;
            assert_eq!(
                decode_ilq1_error_v1(&malformed, cap),
                BootleLanternIssuanceErrorV1::BlindRequestWireInvalid,
                "ILQ1 bound payload substitution at {offset} was accepted"
            );
        }
    }
    #[test]
    fn encoded_issuer_ingress_rejects_before_store_or_rng() {
        let fixture = issuance_fixture_v1();
        let mut malformed = fixture.request.encode().expect("canonical ILQ1 request");
        malformed[0] ^= 1;
        let store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_encoded_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &malformed,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("malformed ILQ1 must fail before store or RNG");
        assert_eq!(error, BootleLanternIssuanceErrorV1::BlindRequestWireInvalid);
        assert_store_remained_fresh_v1(fixture, &store);
    }
    #[test]
    fn ila1_every_single_byte_mutation_is_rejected() {
        let wire = valid_authorization_v1().encode().expect("valid ILA1");
        assert_eq!(wire.len(), BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1);
        assert_eq!(
            BootleLanternIssuanceAuthorizationV1::decode_exact(&wire)
                .expect("canonical ILA1")
                .encode()
                .expect("canonical re-encoding"),
            wire
        );
        for index in 0..wire.len() {
            let mut mutated = wire.clone();
            mutated[index] ^= 1;
            assert!(
                BootleLanternIssuanceAuthorizationV1::decode_exact(&mutated).is_err(),
                "single-byte ILA1 mutation at offset {index} was accepted"
            );
        }
        for length in 0..wire.len() {
            assert!(BootleLanternIssuanceAuthorizationV1::decode_exact(&wire[..length]).is_err());
        }
        let mut trailing = wire;
        trailing.push(0);
        assert!(BootleLanternIssuanceAuthorizationV1::decode_exact(&trailing).is_err());
    }
    #[test]
    fn authorization_id_collisions_stop_at_the_exact_public_attempt_cap() {
        struct AlwaysCollidingStore {
            registrations: AtomicU32,
        }
        impl BootleLanternIssuanceStoreV1 for AlwaysCollidingStore {
            fn register_fresh_v1(
                &self,
                _: [u8; 32],
                _: [u8; 32],
                _: u64,
                _: u64,
            ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
                self.registrations.fetch_add(1, Ordering::Relaxed);
                Err(BootleLanternIssuanceStoreErrorV1::AuthorizationExists)
            }
            fn preflight_v1(
                &self,
                _: [u8; 32],
                _: [u8; 32],
                _: [u8; 32],
                _: u64,
            ) -> Result<BootleLanternIssuancePreflightV1, BootleLanternIssuanceStoreErrorV1>
            {
                unreachable!("authorization collision exhaustion cannot preflight")
            }
            fn claim_v1(
                &self,
                _: [u8; 32],
                _: [u8; 32],
                _: [u8; 32],
                _: u64,
            ) -> Result<BootleLanternIssuanceClaimV1, BootleLanternIssuanceStoreErrorV1>
            {
                unreachable!("authorization collision exhaustion cannot claim")
            }
            fn complete_v1(
                &self,
                _: [u8; 32],
                _: [u8; 32],
                _: [u8; 32],
                _: &[u8],
                _: u64,
            ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
                unreachable!("authorization collision exhaustion cannot complete")
            }
            fn fail_v1(
                &self,
                _: [u8; 32],
                _: [u8; 32],
                _: [u8; 32],
                _: u64,
            ) -> Result<(), BootleLanternIssuanceStoreErrorV1> {
                unreachable!("authorization collision exhaustion cannot fail")
            }
            fn prune_v1(&self, _: u64) -> Result<usize, BootleLanternIssuanceStoreErrorV1> {
                unreachable!("authorization collision exhaustion cannot prune")
            }
        }
        let fixture = issuance_fixture_v1();
        let store = AlwaysCollidingStore {
            registrations: AtomicU32::new(0),
        };
        let mut rng = TestRng::healthy(0x9b05_688c_2b3e_6c1f);
        assert_eq!(
            issuer_authorize_blind_issuance_with_rng_v1(
                &fixture.issuer,
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                raw(0x93),
                10,
                20,
                &store,
                &mut rng,
            )
            .expect_err("every generated authorization identifier collides"),
            BootleLanternIssuanceErrorV1::AuthorizationIdExhausted
        );
        assert_eq!(
            store.registrations.load(Ordering::Relaxed),
            MAX_BOOTLE_LANTERN_AUTHORIZATION_ID_ATTEMPTS_V1
        );
    }
    #[test]
    fn issuer_preimage_sampler_fails_after_exact_public_attempt_cap() {
        let mut attempts = 0_u32;
        let mut rng = TestRng::healthy(0x510e_527f_ade6_82d1);
        let result: Result<(), BootleLanternIssuanceErrorV1> =
            sample_preimage_bounded_v1(&mut rng, |_| {
                attempts += 1;
                None
            });
        assert_eq!(
            result,
            Err(BootleLanternIssuanceErrorV1::PreimageSamplingExhausted)
        );
        assert_eq!(attempts, MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1);
    }
    #[test]
    fn issuer_preimage_sampler_accepts_the_final_allowed_attempt() {
        let mut attempts = 0_u32;
        let mut rng = TestRng::healthy(0x1f83_d9ab_fb41_bd6b);
        let result = sample_preimage_bounded_v1(&mut rng, |_| {
            attempts += 1;
            (attempts == MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1).then_some(attempts)
        });
        assert_eq!(result, Ok(MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1));
        assert_eq!(attempts, MAX_BOOTLE_LANTERN_PREIMAGE_ATTEMPTS_V1);
    }
    #[test]
    fn ilr1_wire_is_exact_and_rejects_noncanonical_fields() {
        let wire = valid_response_v1().encode().expect("valid ILR1");
        assert_eq!(wire.len(), BLIND_ISSUANCE_RESPONSE_BYTES_V1);
        assert_eq!(
            BootleLanternBlindIssuanceResponseV1::decode_exact(&wire)
                .expect("canonical ILR1")
                .encode()
                .expect("canonical re-encoding"),
            wire
        );
        for length in 0..wire.len() {
            assert!(BootleLanternBlindIssuanceResponseV1::decode_exact(&wire[..length]).is_err());
        }
        for index in 0..RESPONSE_HEADER_BYTES_V1 {
            let mut mutated = wire.clone();
            mutated[index] ^= 1;
            assert!(BootleLanternBlindIssuanceResponseV1::decode_exact(&mutated).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(BootleLanternBlindIssuanceResponseV1::decode_exact(&trailing).is_err());
        let mut non_binary_tag = wire.clone();
        non_binary_tag[RESPONSE_HEADER_BYTES_V1..RESPONSE_HEADER_BYTES_V1 + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(BootleLanternBlindIssuanceResponseV1::decode_exact(&non_binary_tag).is_err());
        let signature_one_offset = RESPONSE_HEADER_BYTES_V1 + 8 * APPLICATION_RING_DEGREE_V1 * 2;
        let mut noncanonical_signature = wire.clone();
        noncanonical_signature[signature_one_offset..signature_one_offset + 2]
            .copy_from_slice(&APPLICATION_MODULUS_V1.to_be_bytes());
        assert!(
            BootleLanternBlindIssuanceResponseV1::decode_exact(&noncanonical_signature).is_err()
        );
        for binding in 0..3 {
            let mut zero_binding = wire.clone();
            let start = wire.len() - 3 * 32 + binding * 32;
            zero_binding[start..start + 32].fill(0);
            assert!(BootleLanternBlindIssuanceResponseV1::decode_exact(&zero_binding).is_err());
        }
    }
    #[test]
    fn authorization_input_and_lifetime_failures_precede_rng_and_registration() {
        let fixture = issuance_fixture_v1();
        for (requester_digest, issued_at_height, expires_at_height, expected) in [
            (
                [0; 32],
                10,
                20,
                BootleLanternIssuanceErrorV1::InvalidRequesterAuthorization,
            ),
            (
                raw(0xA0),
                10,
                10,
                BootleLanternIssuanceErrorV1::InvalidAuthorizationLifetime,
            ),
            (
                raw(0xA0),
                11,
                10,
                BootleLanternIssuanceErrorV1::InvalidAuthorizationLifetime,
            ),
            (
                raw(0xA0),
                10,
                10 + MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1 + 1,
                BootleLanternIssuanceErrorV1::InvalidAuthorizationLifetime,
            ),
        ] {
            let store = BootleLanternInMemoryIssuanceStoreV1::new();
            let error = issuer_authorize_blind_issuance_with_rng_v1(
                &fixture.issuer,
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                requester_digest,
                issued_at_height,
                expires_at_height,
                &store,
                &mut PanicRng,
            )
            .expect_err("invalid authorization input must fail before entropy");
            assert_eq!(error, expected);
        }
    }
    #[test]
    fn action_and_intent_change_reuses_credential_and_existing_p1() {
        let fixture = issuance_fixture_v1();
        let mut context = fixture.context.clone();
        context.action_index = context.action_index.wrapping_add(19);
        context.transaction_intent_digest = PrivacyTransactionIntentDigestV1::new(raw(0xA1));
        let statement = presentation_statement_v1(context.clone(), &fixture.policy);
        fixture
            .credential
            .presentation_witness_v1(&statement, &fixture.policy, fixture.genesis_hash)
            .expect("action and intent are presentation-specific");
        let (relation, transcript) = fixture
            .request
            .compile_transcript_v1(
                &context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
            )
            .expect("same P1 reusable across action and intent");
        verify_blind_issuance_request_v1(&relation, transcript, &fixture.request.proof)
            .expect("existing P1 remains valid");
    }
    #[test]
    fn every_reusable_scope_change_fails_before_claim_or_rng() {
        let fixture = issuance_fixture_v1();
        let mut contexts = Vec::new();
        let mut network = fixture.context.clone();
        network.network_id = network_id(0x33);
        contexts.push(network);
        let mut parameter_id = fixture.context.clone();
        parameter_id.parameter_id = PrivacyParameterIdV1::new(raw(0x81));
        contexts.push(parameter_id);
        let mut parameter_digest = fixture.context.clone();
        parameter_digest.parameter_digest = PrivacyParameterDigestV1::new(raw(0x82));
        contexts.push(parameter_digest);
        let mut verifier = fixture.context.clone();
        verifier.verifier_digest = PrivacyVerifierDigestV1::new(raw(0x83));
        contexts.push(verifier);
        let mut schema = fixture.context.clone();
        schema.statement_schema_digest = PrivacyStatementSchemaDigestV1::new(raw(0x84));
        contexts.push(schema);
        let mut manifest = fixture.context.clone();
        manifest.engine_manifest_digest = PrivacyEngineManifestDigestV1::new(raw(0x85));
        contexts.push(manifest);
        for context in contexts {
            let canonical_genesis_hash = *context.network_id.as_bytes();
            let store = fresh_store_v1(fixture);
            let error = issuer_blind_issue_once_with_rng_v1(
                &fixture.issuer,
                &context,
                canonical_genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &fixture.request,
                11,
                &store,
                &mut PanicRng,
            )
            .expect_err("scope substitution must fail before issuer RNG");
            assert_eq!(
                error,
                BootleLanternIssuanceErrorV1::AuthorizationBindingMismatch
            );
            assert_store_remained_fresh_v1(fixture, &store);
            let statement = presentation_statement_v1(context, &fixture.policy);
            assert_eq!(
                fixture.credential.presentation_witness_v1(
                    &statement,
                    &fixture.policy,
                    canonical_genesis_hash,
                ),
                Err(BootleLanternIssuanceErrorV1::CredentialScopeMismatch)
            );
        }
        let other_genesis = raw(0x86);
        let store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            other_genesis,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("genesis substitution must fail before issuer RNG");
        assert_eq!(error, BootleLanternIssuanceErrorV1::CredentialScopeFailed);
        assert_store_remained_fresh_v1(fixture, &store);
        let statement = presentation_statement_v1(fixture.context.clone(), &fixture.policy);
        assert_eq!(
            fixture
                .credential
                .presentation_witness_v1(&statement, &fixture.policy, other_genesis,),
            Err(BootleLanternIssuanceErrorV1::CredentialScopeMismatch)
        );
    }
    #[test]
    fn expired_rotated_and_wrong_key_requests_fail_before_claim_or_rng() {
        let fixture = issuance_fixture_v1();
        let expired_store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            fixture.authorization.expires_at_height + 1,
            &expired_store,
            &mut PanicRng,
        )
        .expect_err("expired authorization must fail before issuer RNG");
        assert_eq!(error, BootleLanternIssuanceErrorV1::AuthorizationExpired);
        assert_store_remained_fresh_v1(fixture, &expired_store);
        let rotated_policy = fixture
            .issuer
            .active_policy_v1(policy_metadata_v1(fixture.policy.epoch + 1))
            .expect("valid rotated policy");
        let rotated_store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &rotated_policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &rotated_store,
            &mut PanicRng,
        )
        .expect_err("rotated policy must fail before issuer RNG");
        assert_eq!(
            error,
            BootleLanternIssuanceErrorV1::AuthorizationBindingMismatch
        );
        assert_store_remained_fresh_v1(fixture, &rotated_store);
        let rotated_statement = presentation_statement_v1(fixture.context.clone(), &rotated_policy);
        assert_eq!(
            fixture.credential.presentation_witness_v1(
                &rotated_statement,
                &rotated_policy,
                fixture.genesis_hash,
            ),
            Err(BootleLanternIssuanceErrorV1::CredentialScopeMismatch)
        );
        let wrong_key = {
            let mut keygen_rng = TestRng::healthy(0x243f_6a88_85a3_08d3);
            BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                PrivacyParameterIdV1::new(raw(0x91)),
                &mut keygen_rng,
            )
            .expect("independent native issuer key")
        };
        let wrong_key_store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_with_rng_v1(
            &wrong_key,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &wrong_key_store,
            &mut PanicRng,
        )
        .expect_err("wrong issuer key must fail before issuer RNG");
        assert_eq!(error, BootleLanternIssuanceErrorV1::IssuerKeyPolicyMismatch);
        assert_store_remained_fresh_v1(fixture, &wrong_key_store);
    }
    #[test]
    fn a_new_authorization_rejects_the_old_p1_before_claim_or_rng() {
        let fixture = issuance_fixture_v1();
        let store = BootleLanternInMemoryIssuanceStoreV1::new();
        let mut authorization_rng = TestRng::healthy(0x1319_8a2e_0370_7344);
        let new_authorization = issuer_authorize_blind_issuance_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            raw(0x92),
            10,
            20,
            &store,
            &mut authorization_rng,
        )
        .expect("second authorization");
        assert_ne!(
            new_authorization.authorization_digest,
            fixture.authorization.authorization_digest
        );
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &new_authorization,
            &fixture.request,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("old P1 must not authorize a new bearer authorization");
        assert_eq!(
            error,
            BootleLanternIssuanceErrorV1::BlindRequestBindingMismatch
        );
        assert_eq!(
            store.preflight_v1(
                new_authorization.authorization_id,
                new_authorization.authorization_digest,
                fixture.request.request_digest,
                11,
            ),
            Ok(BootleLanternIssuancePreflightV1::Fresh)
        );
    }
    #[test]
    fn completed_retry_returns_exact_bytes_without_rng() {
        let fixture = issuance_fixture_v1();
        let store = fresh_store_v1(fixture);
        let request_wire = fixture.request.encode().expect("canonical ILQ1 request");
        let mut issuer_issuance_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
        let response = issuer_blind_issue_once_encoded_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &request_wire,
            11,
            &store,
            &mut issuer_issuance_rng,
        )
        .expect("first completed issuance");
        let expected = response.encode().expect("canonical response");
        let cached = issuer_blind_issue_once_encoded_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &request_wire,
            fixture.authorization.expires_at_height + 1,
            &store,
            &mut PanicRng,
        )
        .expect("completed retry after expiry must not touch RNG");
        assert_eq!(
            cached.encode().expect("canonical cached response"),
            expected
        );
        for binding_index in 0..3 {
            let mut substituted = expected.clone();
            let binding_offset = substituted.len() - 3 * 32 + binding_index * 32;
            substituted[binding_offset] ^= 1;
            let substituted_store = fresh_store_v1(fixture);
            assert_eq!(
                substituted_store.claim_v1(
                    fixture.authorization.authorization_id,
                    fixture.authorization.authorization_digest,
                    fixture.request.request_digest,
                    11,
                ),
                Ok(BootleLanternIssuanceClaimV1::Fresh)
            );
            let completion = substituted_store.complete_v1(
                fixture.authorization.authorization_id,
                fixture.authorization.authorization_digest,
                fixture.request.request_digest,
                &substituted,
                11,
            );
            if binding_index == 0 {
                assert_eq!(
                    completion,
                    Err(BootleLanternIssuanceStoreErrorV1::InvalidInput),
                    "the store must reject a cached ILR1 whose request digest is substituted"
                );
                continue;
            }
            completion.expect("scope/policy substitution reaches issuer cache validation");
            let error = issuer_blind_issue_once_encoded_with_rng_v1(
                &fixture.issuer,
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
                &request_wire,
                11,
                &substituted_store,
                &mut PanicRng,
            )
            .expect_err("cached ILR1 digest substitution must fail without issuer RNG");
            assert_eq!(
                error,
                BootleLanternIssuanceErrorV1::CachedIssuanceResponseInvalid
            );
        }
    }
    #[test]
    fn post_claim_rng_failure_is_terminal() {
        let fixture = issuance_fixture_v1();
        let store = fresh_store_v1(fixture);
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut FailingRng,
        )
        .expect_err("post-claim RNG failure must fail issuance");
        assert_eq!(error, BootleLanternIssuanceErrorV1::RandomnessUnavailable);
        let retry_error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("failed claim must be terminal without touching RNG");
        assert_eq!(
            retry_error,
            BootleLanternIssuanceErrorV1::AuthorizationConsumed
        );
    }
    #[test]
    fn crash_after_claim_remains_busy_and_never_reaches_rng() {
        let fixture = issuance_fixture_v1();
        let store = fresh_store_v1(fixture);
        assert_eq!(
            store.claim_v1(
                fixture.authorization.authorization_id,
                fixture.authorization.authorization_digest,
                fixture.request.request_digest,
                11,
            ),
            Ok(BootleLanternIssuanceClaimV1::Fresh)
        );
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("a restarted worker must observe the persisted processing claim");
        assert_eq!(error, BootleLanternIssuanceErrorV1::AuthorizationBusy);
    }
    #[test]
    fn completion_failure_is_terminal_and_never_reissues() {
        let fixture = issuance_fixture_v1();
        let store = fresh_store_v1(fixture);
        store.inject_next_completion_failure_v1();
        let mut issuer_issuance_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
        let error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut issuer_issuance_rng,
        )
        .expect_err("injected completion failure must fail issuance");
        assert_eq!(error, BootleLanternIssuanceErrorV1::IssuanceStoreFailed);
        let retry_error = issuer_blind_issue_once_with_rng_v1(
            &fixture.issuer,
            &fixture.context,
            fixture.genesis_hash,
            &fixture.policy,
            &fixture.authorization,
            &fixture.request,
            11,
            &store,
            &mut PanicRng,
        )
        .expect_err("completion failure must be terminal without touching RNG");
        assert_eq!(
            retry_error,
            BootleLanternIssuanceErrorV1::AuthorizationConsumed
        );
    }
    #[test]
    fn cloned_request_helper_preserves_the_exact_p1_binding() {
        let fixture = issuance_fixture_v1();
        let cloned = clone_request_v1(&fixture.request);
        assert_eq!(cloned.request_digest, fixture.request.request_digest);
        assert_eq!(cloned.proof.encode(), fixture.request.proof.encode());
        let (relation, transcript) = cloned
            .compile_transcript_v1(
                &fixture.context,
                fixture.genesis_hash,
                &fixture.policy,
                &fixture.authorization,
            )
            .expect("cloned exact request binding");
        verify_blind_issuance_request_v1(&relation, transcript, &cloned.proof)
            .expect("cloned exact P1");
    }
    #[test]
    fn taira_qualification_is_one_shared_exact_profile_and_contract_binding() {
        let fixture = issuance_fixture_v1();
        let stable_principal_digest: [u8; 32] =
            Sha256::digest(b"taira-shared-stable-principal-fixture").into();
        let inputs = TairaBootleLanternBrokerQualificationInputsV1 {
            network_id: network_id(0x32),
            runtime_provider_handle: "runtime://privacy/bootle-lantern/taira-primary",
            runtime_provider_revision: 1,
            issuer_id: fixture.policy.issuer_id,
            policy_id: fixture.policy.policy_id,
            authorization_lifetime_blocks: 300,
            policy: &fixture.policy,
            stable_principal_digest,
        };
        let exact = derive_taira_bootle_lantern_broker_qualification_digest_v1(&inputs)
            .expect("derive exact shared Taira qualification");
        let canonical_policy = norito::to_bytes(&fixture.policy).expect("canonical policy");
        let revision_bytes = inputs.runtime_provider_revision.to_be_bytes();
        let lifetime_bytes = inputs.authorization_lifetime_blocks.to_be_bytes();
        let fields = [
            inputs.network_id.as_bytes(),
            inputs.runtime_provider_handle.as_bytes(),
            revision_bytes.as_slice(),
            inputs.issuer_id.as_bytes(),
            inputs.policy_id.as_bytes(),
            lifetime_bytes.as_slice(),
            inputs.policy.issuer_parameter_id.as_bytes(),
            inputs.policy.issuer_parameter_digest.as_bytes(),
            inputs.policy.record_digest.as_bytes(),
            inputs.stable_principal_digest.as_slice(),
            canonical_policy.as_slice(),
            BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1,
            TAIRA_BOOTLE_LANTERN_BROKER_CONTRACT_V1,
        ];
        assert_eq!(
            exact,
            taira_length_framed_digest_v1(TAIRA_QUALIFICATION_DIGEST_DOMAIN_V1, &fields)
        );
        let mut substituted_fields = fields;
        substituted_fields[11] = b"substituted-issuer-profile";
        assert_ne!(
            exact,
            taira_length_framed_digest_v1(
                TAIRA_QUALIFICATION_DIGEST_DOMAIN_V1,
                &substituted_fields
            )
        );
        substituted_fields = fields;
        substituted_fields[12] = b"substituted-broker-contract";
        assert_ne!(
            exact,
            taira_length_framed_digest_v1(
                TAIRA_QUALIFICATION_DIGEST_DOMAIN_V1,
                &substituted_fields
            )
        );
        assert_eq!(
            taira_bootle_lantern_issuer_profile_contract_digest_v1(),
            taira_length_framed_digest_v1(
                TAIRA_PROFILE_DIGEST_DOMAIN_V1,
                &[BOOTLE_LANTERN_ISSUER_PROFILE_DESCRIPTOR_V1]
            )
        );
        assert_eq!(
            taira_bootle_lantern_broker_contract_digest_v1(),
            taira_length_framed_digest_v1(
                TAIRA_CONTRACT_DIGEST_DOMAIN_V1,
                &[TAIRA_BOOTLE_LANTERN_BROKER_CONTRACT_V1]
            )
        );
    }
    #[test]
    fn taira_qualification_rejects_weak_or_mismatched_public_inputs() {
        let fixture = issuance_fixture_v1();
        let mut inputs = TairaBootleLanternBrokerQualificationInputsV1 {
            network_id: network_id(0x32),
            runtime_provider_handle: "runtime://privacy/bootle-lantern/taira-primary",
            runtime_provider_revision: 1,
            issuer_id: fixture.policy.issuer_id,
            policy_id: fixture.policy.policy_id,
            authorization_lifetime_blocks: 300,
            policy: &fixture.policy,
            stable_principal_digest: Sha256::digest(
                b"taira-shared-stable-principal-negative-fixture",
            )
            .into(),
        };
        inputs.stable_principal_digest = [7; 32];
        assert_eq!(
            derive_taira_bootle_lantern_broker_qualification_digest_v1(&inputs),
            Err(TairaBootleLanternBrokerQualificationErrorV1::InvalidPublicBinding)
        );
        inputs.stable_principal_digest =
            Sha256::digest(b"taira-shared-stable-principal-negative-fixture").into();
        inputs.authorization_lifetime_blocks =
            MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1 + 1;
        assert_eq!(
            derive_taira_bootle_lantern_broker_qualification_digest_v1(&inputs),
            Err(TairaBootleLanternBrokerQualificationErrorV1::InvalidPublicBinding)
        );
        inputs.authorization_lifetime_blocks = 300;
        inputs.policy_id = PrivacyPolicyIdV1::new([0x5a; 32]);
        assert_eq!(
            derive_taira_bootle_lantern_broker_qualification_digest_v1(&inputs),
            Err(TairaBootleLanternBrokerQualificationErrorV1::InvalidPublicBinding)
        );
    }
}
