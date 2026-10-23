//! Exhaustive native privacy proof verification boundary.
//!
//! An admitted envelope must pass the locally compiled governance manifest,
//! intrinsic typed validation, execution-context binding, the typed dispatch
//! registry, strict native wire decoding, and the role's cryptographic verifier
//! in that order. [`verify_privacy_envelope_v1`] is the single dispatch of all
//! Exact12 roles: it resolves the one role of the envelope, refuses a role the
//! registry (`crate::privacy_dispatch`) records as unsupported with a typed
//! error, runs that role's one native verifier and seals only an effect of
//! that role. Only this module can construct [`VerifiedPrivacyEffectsV1`], so
//! state handlers cannot derive ledger effects from unverified
//! caller-controlled bytes.
#[cfg(feature = "zk-stark")]
use crate::privacy_engines::zk_ace::{ZkAceNativeErrorV1, verify_zk_ace_privacy_v1};
use crate::{
    privacy_dispatch::{PrivacyUnsupportedOperationV1, require_supported_privacy_action_role_v1},
    privacy_engines::{
        anonymous_pgc::{
            AnonymousPgcParametersV1, AnonymousPgcPoolInvariantV1, AnonymousPgcReadError,
            TwistedElGamalCiphertextV1, TwistedElGamalPublicKeyV1,
            payment::{AnonymousPgcPaymentStatementV1, verify_payment_encoded},
        },
        bootle_lantern::{
            BoundPresentationEncodedErrorV1, BoundPresentationErrorV1, codec::ProofCodecErrorV1,
            proof::PresentationProofErrorV1, relation::RelationErrorV1,
            transcript::TranscriptErrorV1, verify_bound_presentation_encoded_v1,
        },
        fcmp_plus_plus::{
            FcmpNativeErrorV1, FcmpOutputTupleV1, FcmpProofInputPublicV1,
            FcmpRuntimeContextBindingV1, FcmpTreeRootV1, derive_fcmp_runtime_context_hash_v1,
            validate_fcmp_encrypted_output_v1, verify_fcmp_transaction_v1,
        },
        ivm_private_note::{
            IvmPrivateNoteWalletErrorV1, validate_ivm_private_encrypted_output_v1,
            verify_private_note_stark_v1,
        },
        jindo::{JindoErrorV1, jindo_crs_digest_v1, verify_batched_evaluation_v1},
        orchard::{
            OrchardActionPublicV1, OrchardBundlePublicV1, OrchardNativeErrorV1,
            verify_orchard_bundle_v1,
        },
        p256::{CompressedPointV1, TranscriptBindingV1},
        pq_masp::{
            stark::verify_pq_masp_stark_v1,
            wire::{
                PqMaspWireErrorV1, validate_pq_masp_note_encryption_key_digest_v1,
                verify_pq_masp_authorization_v1,
            },
        },
        proof_managed_note_stark::ProofManagedNoteStarkErrorV1,
        vega::{VegaMdlConsensusBindingV1, VegaMdlError, verify_mdl_figure9_v1},
        verange::{
            VeRangeBitLengthV1, VeRangeError, VeRangeParametersV1, VeRangeType1BatchStatementV1,
            verify_batch_encoded,
        },
        zk_ams::{
            VerifiedZkAmsBatchAdmissionV1, VerifiedZkAmsProvisionAccountV1, ZkAmsErrorV1,
            verify_zk_ams_batch_admission_v1, verify_zk_ams_provision_statement_v1,
            zk_ams_generator_digest_v1,
        },
        zk_x509::engine::{ZkX509EngineErrorV1, verify_zk_x509_credential_proof_v1},
    },
    privacy_profiles::{
        CompiledPrivacyProfileValidationErrorV1, validate_compiled_privacy_activation_v1,
    },
    privacy_state::{
        PrivacyFcmpAccumulatorStateV1, PrivacyOrchardPoolSnapshotV1, PrivacyOrchardPoolStateV1,
        PrivacyProofManagedAccumulatorStateV1, PrivacyProofManagedPoolSnapshotV1,
        PrivacyZkX509AuthoritativeStateV1, derive_privacy_pgc_account_state_root_v1,
        validate_privacy_zk_x509_statement_state_v1,
    },
};
#[cfg(feature = "zk-stark")]
use iroha_data_model::zk::ZkAcePrivacyPublicInputsV1;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    privacy::{
        AnonymousPgcKOutOfNStatementV1, BootleLanternIssuerPolicyLifecycleV1,
        BootleLanternIssuerPolicyV1, IrohaBootleLanternAnoncredStatementV1,
        IrohaIvmPrivateNoteStarkStatementV1, IrohaJindoPolynomialCommitmentStatementV1,
        IrohaZkAmsStatementV1, MoneroFcmpPlusPlusStatementV1, OrchardHalo2ActionsStatementV1,
        PqMaspStarkStatementV1, PrivacyActionRoleV1, PrivacyCommitmentV1, PrivacyConsensusLimitsV1,
        PrivacyFcmpKeyImageV1, PrivacyFcmpOutputTupleV1, PrivacyNamespaceV1,
        PrivacyNativeConsensusBindingV1, PrivacyNativeConsensusBindingValidationErrorV1,
        PrivacyNullifierV1, PrivacyP256CiphertextV1, PrivacyP256PointV1,
        PrivacyPgcAccountBootstrapDigestV1, PrivacyPgcAccountV1, PrivacyPgcBootstrapProofDigestV1,
        PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyProofBytesV1, PrivacyProofEnvelopeV1,
        PrivacyProofEnvelopeValidationError, PrivacyProtocolActivationRecordV1,
        PrivacyProtocolIdV1, PrivacyRootRoleV1, PrivacyRootV1, PrivacyStatementDigestV1,
        PrivacyStatementV1, PrivacyValueBalanceDirectionV1, PrivacyValueBalanceV1,
        PrivacyVeRangeBitLengthV1, PrivacyVegaIssuerRecordLifecycleV1, PrivacyVegaIssuerRecordV1,
        PrivacyZkAceIdentityCommitmentV1, PrivacyZkAceReplayNullifierV1, PrivacyZkAmsActionV1,
        VegaExistingCredentialStatementV1,
    },
};
use thiserror::Error;
/// Complete trusted PGC pool state selected before native verification.
///
/// The submit handler constructs this only after its bounded state loader has
/// validated the persisted invariant, head, retained history, account epochs,
/// provenance, and complete strict account order.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct PrivacyPgcVerificationStateV1<'a> {
    /// Exact protocol/pool namespace selected by the statement.
    pub namespace: PrivacyNamespaceV1,
    /// Immutable public supply established by bootstrap.
    pub total_supply: u32,
    /// Digest of the canonical bootstrap public input.
    pub bootstrap_digest: PrivacyPgcAccountBootstrapDigestV1,
    /// Digest of the exact canonical bootstrap proof admitted by core.
    pub bootstrap_proof_digest: PrivacyPgcBootstrapProofDigestV1,
    /// Current account-state root from the persisted head.
    pub current_root: PrivacyRootV1,
    /// Current account-state epoch from the persisted head.
    pub current_epoch: u64,
    /// Exact retained-history membership record for the current head.
    pub retained_current_root: Option<(u64, PrivacyRootV1)>,
    /// Complete account table in strict public-key order.
    pub accounts: &'a [PrivacyPgcAccountV1],
}
/// Trusted X.509 governance/root snapshot and replay status selected by core.
///
/// The replay bit is derived from the role-separated nullifier map before native proof
/// verification, so an already consumed certificate cannot force another H20 proof verification.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct PrivacyZkX509VerificationStateV1<'a> {
    /// Fully joined active trust-anchor, policy, CRL, and root-head state.
    pub authoritative_state: &'a PrivacyZkX509AuthoritativeStateV1,
    /// Whether the exact policy-scoped certificate nullifier already exists.
    pub certificate_nullifier_consumed: bool,
}
/// Consensus context not supplied by the proof submitter.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct PrivacyVerificationContextV1<'a> {
    /// Exact locally stored active record selected by protocol id.
    pub activation: &'a PrivacyProtocolActivationRecordV1,
    /// Singleton chain-wide limits effective for this incoming block.
    pub consensus_limits: &'a PrivacyConsensusLimitsV1,
    /// Exact genesis-header-derived network identity.
    pub network_id: &'a NetworkId,
    /// Hash of the committed genesis block.
    pub genesis_hash: [u8; 32],
    /// Height of the block executing this proof.
    pub current_height: u64,
    /// Next zero-based privacy action index in this transaction.
    pub expected_action_index: u32,
    /// Canonical current block timestamp in Unix milliseconds.
    ///
    /// `VeRange` does not use time, but credential profiles consume this same
    /// trusted field rather than accepting a prover-selected clock.
    pub block_timestamp_ms: u64,
    /// Complete trusted PGC state, required only by Anonymous-PGC payments.
    pub pgc_state: Option<PrivacyPgcVerificationStateV1<'a>>,
    /// Complete trusted Orchard pool state, required only by Orchard bundles.
    pub orchard_state: Option<&'a PrivacyOrchardPoolSnapshotV1>,
    /// Complete trusted FCMP++/IVM/PQ pool state.
    pub proof_managed_state: Option<&'a PrivacyProofManagedPoolSnapshotV1>,
    /// Complete trusted X.509 state and pre-proof replay lookup.
    pub zk_x509_state: Option<PrivacyZkX509VerificationStateV1<'a>>,
    /// Exact current governed Bootle/Lantern issuer policy.
    pub bootle_lantern_policy: Option<&'a BootleLanternIssuerPolicyV1>,
    /// Exact current governed Vega issuer-key/policy revision.
    pub vega_issuer_record: Option<&'a PrivacyVegaIssuerRecordV1>,
}
/// Complete successor account-table transition derived by the native verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedAnonymousPgcLedgerEffectV1 {
    namespace: PrivacyNamespaceV1,
    total_supply: u32,
    current_root: PrivacyRootV1,
    current_epoch: u64,
    next_root: PrivacyRootV1,
    next_epoch: u64,
    accounts: Vec<PrivacyPgcAccountV1>,
}
impl VerifiedAnonymousPgcLedgerEffectV1 {
    /// Exact pool namespace whose complete table must change.
    #[must_use]
    #[inline]
    pub const fn namespace(&self) -> PrivacyNamespaceV1 {
        self.namespace
    }
    /// Immutable verified total supply.
    #[must_use]
    #[inline]
    pub const fn total_supply(&self) -> u32 {
        self.total_supply
    }
    /// Persisted head root consumed by this transition.
    #[must_use]
    #[inline]
    pub const fn current_root(&self) -> PrivacyRootV1 {
        self.current_root
    }
    /// Persisted head epoch consumed by this transition.
    #[must_use]
    #[inline]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    /// Canonical successor root derived from every successor ciphertext.
    #[must_use]
    #[inline]
    pub const fn next_root(&self) -> PrivacyRootV1 {
        self.next_root
    }
    /// Canonical successor epoch.
    #[must_use]
    #[inline]
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    /// Complete successor account table in unchanged strict key order.
    #[must_use]
    #[inline]
    pub fn accounts(&self) -> &[PrivacyPgcAccountV1] {
        &self.accounts
    }
}
/// Exact transparent mutation produced by the disabled native ZK-ACE candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedZkAceAuthorizationV1 {
    pub policy_id: PrivacyPolicyIdV1,
    pub policy_digest: PrivacyPolicyDigestV1,
    pub identity_commitment: PrivacyZkAceIdentityCommitmentV1,
    pub authorization_epoch: u64,
    pub source: AccountId,
    pub destination: AccountId,
    pub asset_definition_id: AssetDefinitionId,
    pub public_balance_scope: AssetBalanceScope,
    pub amount: u128,
    pub replay_nullifier: PrivacyZkAceReplayNullifierV1,
}
/// Exact durable replay effect authorized by one native X.509 proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
#[non_exhaustive]
pub struct VerifiedZkX509CertificateEffectV1 {
    /// Exact trust-anchor/policy namespace selected by trusted state.
    pub namespace: PrivacyNamespaceV1,
    /// Certificate-and-policy-derived nonzero replay nullifier.
    pub certificate_nullifier: PrivacyNullifierV1,
    /// Exact authoritative trust-anchor revision used by verification.
    pub trust_anchor_record_digest:
        iroha_data_model::privacy::PrivacyZkX509TrustAnchorRecordDigestV1,
    /// Exact authoritative trust-anchor revision epoch.
    pub trust_anchor_record_epoch: u64,
    /// Exact authoritative certificate-policy revision used by verification.
    pub certificate_policy_record_digest:
        iroha_data_model::privacy::PrivacyZkX509CertificatePolicyRecordDigestV1,
    /// Exact authoritative certificate-policy revision epoch.
    pub certificate_policy_record_epoch: u64,
    /// Exact authoritative signed-CRL revision used by verification.
    pub crl_record_digest: iroha_data_model::privacy::PrivacyZkX509CrlRecordDigestV1,
    /// Exact authoritative signed-CRL revision epoch.
    pub crl_record_epoch: u64,
}
/// Complete Orchard state transition and public bridge authorized by one proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedOrchardLedgerEffectV1 {
    namespace: PrivacyNamespaceV1,
    bootstrap_digest: iroha_data_model::privacy::PrivacyOrchardPoolBootstrapDigestV1,
    asset_definition_id: AssetDefinitionId,
    public_balance_scope: AssetBalanceScope,
    reserve_account: AccountId,
    anchor: PrivacyRootV1,
    anchor_epoch: u64,
    current_root: PrivacyRootV1,
    current_epoch: u64,
    successor_state: PrivacyOrchardPoolStateV1,
    nullifiers: Vec<[u8; 32]>,
    value_balance: PrivacyValueBalanceV1,
    expiry_height: u64,
}
impl VerifiedOrchardLedgerEffectV1 {
    #[must_use]
    #[inline]
    pub const fn namespace(&self) -> PrivacyNamespaceV1 {
        self.namespace
    }
    #[must_use]
    #[inline]
    pub const fn bootstrap_digest(
        &self,
    ) -> iroha_data_model::privacy::PrivacyOrchardPoolBootstrapDigestV1 {
        self.bootstrap_digest
    }
    #[must_use]
    #[inline]
    pub const fn asset_definition_id(&self) -> &AssetDefinitionId {
        &self.asset_definition_id
    }
    #[must_use]
    #[inline]
    pub const fn public_balance_scope(&self) -> AssetBalanceScope {
        self.public_balance_scope
    }
    #[must_use]
    #[inline]
    pub const fn reserve_account(&self) -> &AccountId {
        &self.reserve_account
    }
    #[must_use]
    #[inline]
    pub const fn anchor(&self) -> PrivacyRootV1 {
        self.anchor
    }
    #[must_use]
    #[inline]
    pub const fn anchor_epoch(&self) -> u64 {
        self.anchor_epoch
    }
    #[must_use]
    #[inline]
    pub const fn current_root(&self) -> PrivacyRootV1 {
        self.current_root
    }
    #[must_use]
    #[inline]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    #[must_use]
    #[inline]
    pub const fn successor_state(&self) -> &PrivacyOrchardPoolStateV1 {
        &self.successor_state
    }
    #[must_use]
    #[inline]
    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }
    #[must_use]
    #[inline]
    pub const fn value_balance(&self) -> PrivacyValueBalanceV1 {
        self.value_balance
    }
    #[must_use]
    #[inline]
    pub const fn expiry_height(&self) -> u64 {
        self.expiry_height
    }
}
/// Complete proof-managed pool mutation authorized by a native verifier.
///
/// The closed transition enum carries exactly one protocol-native successor, so an FCMP++ curve
/// frontier cannot be confused with an IVM/PQ note frontier and the handler never reconstructs
/// effects from caller-controlled roots.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum VerifiedProofManagedPoolTransitionV1 {
    /// FCMP++ key images, complete output tuples, and curve-tree successor.
    Fcmp {
        key_images: Vec<PrivacyFcmpKeyImageV1>,
        outputs: Vec<PrivacyFcmpOutputTupleV1>,
        successor_state: PrivacyFcmpAccumulatorStateV1,
    },
    /// Private-IVM nullifiers, note commitments, and SHA-256 successor.
    IvmPrivateNote {
        nullifiers: Vec<PrivacyNullifierV1>,
        output_commitments: Vec<PrivacyCommitmentV1>,
        successor_state: PrivacyProofManagedAccumulatorStateV1,
    },
    /// PQ-MASP nullifiers, note commitments, and SHA-256 successor.
    PqMasp {
        nullifiers: Vec<PrivacyNullifierV1>,
        output_commitments: Vec<PrivacyCommitmentV1>,
        successor_state: PrivacyProofManagedAccumulatorStateV1,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
#[non_exhaustive]
pub struct VerifiedProofManagedPoolLedgerEffectV1 {
    namespace: PrivacyNamespaceV1,
    bootstrap_digest: iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1,
    asset_definition_id: AssetDefinitionId,
    current_root: PrivacyRootV1,
    current_epoch: u64,
    next_root: PrivacyRootV1,
    next_epoch: u64,
    transition: VerifiedProofManagedPoolTransitionV1,
    value_balance: Option<PrivacyValueBalanceV1>,
    public_balance_scope: Option<AssetBalanceScope>,
}
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub struct VerifiedProofManagedPoolLedgerEffectTestPartsV1 {
    pub namespace: PrivacyNamespaceV1,
    pub bootstrap_digest: iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1,
    pub asset_definition_id: AssetDefinitionId,
    pub current_root: PrivacyRootV1,
    pub current_epoch: u64,
    pub next_root: PrivacyRootV1,
    pub next_epoch: u64,
    pub transition: VerifiedProofManagedPoolTransitionV1,
    pub value_balance: Option<PrivacyValueBalanceV1>,
    pub public_balance_scope: Option<AssetBalanceScope>,
}
impl VerifiedProofManagedPoolLedgerEffectV1 {
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_test_parts(parts: VerifiedProofManagedPoolLedgerEffectTestPartsV1) -> Self {
        let VerifiedProofManagedPoolLedgerEffectTestPartsV1 {
            namespace,
            bootstrap_digest,
            asset_definition_id,
            current_root,
            current_epoch,
            next_root,
            next_epoch,
            transition,
            value_balance,
            public_balance_scope,
        } = parts;
        Self {
            namespace,
            bootstrap_digest,
            asset_definition_id,
            current_root,
            current_epoch,
            next_root,
            next_epoch,
            transition,
            value_balance,
            public_balance_scope,
        }
    }
    #[must_use]
    #[inline]
    pub const fn namespace(&self) -> PrivacyNamespaceV1 {
        self.namespace
    }
    #[must_use]
    #[inline]
    pub const fn bootstrap_digest(
        &self,
    ) -> iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1 {
        self.bootstrap_digest
    }
    #[must_use]
    #[inline]
    pub const fn asset_definition_id(&self) -> &AssetDefinitionId {
        &self.asset_definition_id
    }
    #[must_use]
    #[inline]
    pub const fn current_root(&self) -> PrivacyRootV1 {
        self.current_root
    }
    #[must_use]
    #[inline]
    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    #[must_use]
    #[inline]
    pub const fn next_root(&self) -> PrivacyRootV1 {
        self.next_root
    }
    #[must_use]
    #[inline]
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    #[must_use]
    #[inline]
    pub const fn transition(&self) -> &VerifiedProofManagedPoolTransitionV1 {
        &self.transition
    }
    #[must_use]
    #[inline]
    pub const fn value_balance(&self) -> Option<PrivacyValueBalanceV1> {
        self.value_balance
    }
    #[must_use]
    #[inline]
    pub const fn public_balance_scope(&self) -> Option<AssetBalanceScope> {
        self.public_balance_scope
    }
}
/// Ledger mutation class produced only after successful native verification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum VerifiedPrivacyLedgerEffectsV1 {
    /// Reusable proof component with no replay marker, output, or root update.
    None,
    /// Complete Anonymous-PGC encrypted account-table transition.
    AnonymousPgcPayment(VerifiedAnonymousPgcLedgerEffectV1),
    /// Atomic Orchard nullifier, compact-frontier, root, and public bridge transition.
    OrchardActions(VerifiedOrchardLedgerEffectV1),
    /// Atomic FCMP++/private-IVM/PQ-MASP nullifier, commitment, and root transition.
    ProofManagedPool(VerifiedProofManagedPoolLedgerEffectV1),
    /// Atomic ZK-AMS PHC/seed admission and `AccountRegistry` successor.
    ZkAmsBatchAdmission(VerifiedZkAmsBatchAdmissionV1),
    /// Atomic ZK-AMS provisioning key image and fresh account creation.
    ZkAmsProvisionAccount(VerifiedZkAmsProvisionAccountV1),
    /// Atomic policy-scoped replay insertion and transparent asset transfer.
    #[cfg_attr(not(feature = "zk-stark"), allow(dead_code))]
    ZkAceAuthorization(VerifiedZkAceAuthorizationV1),
    /// Atomic policy-scoped certificate-nullifier insertion.
    ZkX509Certificate(VerifiedZkX509CertificateEffectV1),
}
/// Fully verified, statement-derived effects ready for atomic admission.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedPrivacyEffectsV1 {
    role: PrivacyActionRoleV1,
    protocol_id: PrivacyProtocolIdV1,
    statement_digest: PrivacyStatementDigestV1,
    action_index: u32,
    encoded_action_bytes: u64,
    ledger: VerifiedPrivacyLedgerEffectsV1,
}
impl VerifiedPrivacyEffectsV1 {
    /// Seal the effect of one verified role.
    ///
    /// This is the only constructor. It refuses a ledger effect that is not the
    /// registered effect of `role`, so every value of this type carries an
    /// effect its own role may hand to the state executor.
    fn seal_v1(
        role: PrivacyActionRoleV1,
        statement_digest: PrivacyStatementDigestV1,
        action_index: u32,
        encoded_action_bytes: u64,
        ledger: VerifiedPrivacyLedgerEffectsV1,
    ) -> Result<Self, PrivacyVerificationErrorV1> {
        if !ledger.discharges_role_v1(role) {
            return Err(PrivacyVerificationErrorV1::EffectRoleMismatch(Box::new(
                PrivacyEffectRoleMismatchFailureV1 { role },
            )));
        }
        Ok(Self {
            role,
            protocol_id: role.protocol_id(),
            statement_digest,
            action_index,
            encoded_action_bytes,
            ledger,
        })
    }
    /// Return the one Exact12 role that was verified.
    #[must_use]
    #[inline]
    pub const fn role(&self) -> PrivacyActionRoleV1 {
        self.role
    }
    /// Return the cryptographically verified protocol.
    #[must_use]
    #[inline]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        self.protocol_id
    }
    /// Return the digest of the exact verified typed statement.
    #[must_use]
    #[inline]
    pub const fn statement_digest(&self) -> PrivacyStatementDigestV1 {
        self.statement_digest
    }
    /// Return the verified transaction-local privacy action index.
    #[must_use]
    #[inline]
    pub const fn action_index(&self) -> u32 {
        self.action_index
    }
    /// Return the canonical envelope byte charge.
    #[must_use]
    #[inline]
    pub const fn encoded_action_bytes(&self) -> u64 {
        self.encoded_action_bytes
    }
    /// Return the exact verified ledger mutation class.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    #[inline]
    pub const fn ledger(&self) -> &VerifiedPrivacyLedgerEffectsV1 {
        &self.ledger
    }
    /// Consume this verified action and return its opaque ledger transition.
    #[must_use]
    #[inline]
    pub fn into_ledger(self) -> VerifiedPrivacyLedgerEffectsV1 {
        self.ledger
    }
}
/// Verify one envelope and derive its exact atomic effects.
///
/// This is the single dispatch of every Exact12 role. No other function selects
/// a native verifier for an envelope.
///
/// # Errors
///
/// Rejects a missing/altered compiled profile, malformed or inactive
/// activation, envelope inconsistency, wrong execution context, a role the
/// dispatch registry records as unsupported, non-canonical native wire value,
/// or failed proof equation.
///
/// Failure precedence is consensus-critical: compiled activation is checked first, governed and
/// intrinsic envelope validity second, trusted execution context third, canonical byte charging
/// fourth, the typed dispatch registry fifth, and the selected native verifier last.
#[doc(hidden)]
pub fn verify_privacy_envelope_v1(
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyEffectsV1, PrivacyVerificationErrorV1> {
    validate_compiled_privacy_activation_v1(context.activation).map_err(|source| {
        PrivacyVerificationErrorV1::CompiledActivation(Box::new(
            PrivacyCompiledActivationFailureV1 { source },
        ))
    })?;
    verify_privacy_envelope_after_compiled_activation_v1(envelope, context)
}
fn verify_privacy_envelope_after_compiled_activation_v1(
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyEffectsV1, PrivacyVerificationErrorV1> {
    envelope
        .validate_against_activation(
            context.activation,
            context.consensus_limits,
            context.current_height,
        )
        .map_err(|source| {
            PrivacyVerificationErrorV1::Envelope(Box::new(PrivacyEnvelopeFailureV1 { source }))
        })?;
    if context.genesis_hash == [0; 32] {
        return Err(PrivacyVerificationErrorV1::Context(Box::new(
            PrivacyVerificationContextFailureV1::new(
                PrivacyVerificationContextFailureCodeV1::ZeroGenesisHash,
                "non-zero committed genesis hash",
                "all-zero digest",
            ),
        )));
    }
    if context.network_id.as_bytes() != &context.genesis_hash {
        return Err(PrivacyVerificationErrorV1::Context(Box::new(
            PrivacyVerificationContextFailureV1::new(
                PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch,
                context.network_id.to_string(),
                format!("{:02x?}", context.genesis_hash),
            ),
        )));
    }
    let statement_context = envelope.statement.context();
    if statement_context.network_id != *context.network_id {
        return Err(PrivacyVerificationErrorV1::Context(Box::new(
            PrivacyVerificationContextFailureV1::new(
                PrivacyVerificationContextFailureCodeV1::NetworkIdMismatch,
                context.network_id.to_string(),
                statement_context.network_id.to_string(),
            ),
        )));
    }
    if statement_context.action_index != context.expected_action_index {
        return Err(PrivacyVerificationErrorV1::Context(Box::new(
            PrivacyVerificationContextFailureV1::new(
                PrivacyVerificationContextFailureCodeV1::ActionIndexMismatch,
                context.expected_action_index.to_string(),
                statement_context.action_index.to_string(),
            ),
        )));
    }
    // Canonical encoding is repeated here deliberately: the validated exact
    // bytes become the rollback-safe budget charge returned with the effects.
    let encoded_action_bytes = norito::canonical_frame_len(envelope)
        .ok()
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| {
            PrivacyVerificationErrorV1::CanonicalEncoding(Box::new(
                PrivacyCanonicalEncodingFailureV1,
            ))
        })?;
    // Envelope admission above established an exact protocol match between the envelope, statement,
    // and proof (including the ZK-AMS action tag); the single resolver names the one role.
    let role = envelope.action_role_v1().map_err(|source| {
        PrivacyVerificationErrorV1::Envelope(Box::new(PrivacyEnvelopeFailureV1 { source }))
    })?;
    // A role without usable verification is refused here with its typed limitation, before any
    // proof byte is examined. This refusal does not depend on an activation record.
    require_supported_privacy_action_role_v1(role)
        .map_err(|source| PrivacyVerificationErrorV1::UnsupportedOperation(Box::new(source)))?;
    // Route only on the closed statement enum so adding a protocol cannot compile until this
    // dispatcher has an explicit native-verifier arm.
    let proof = envelope.proof.bytes();
    let ledger = match &envelope.statement {
        #[cfg(feature = "zk-stark")]
        PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) => {
            let public_inputs =
                ZkAcePrivacyPublicInputsV1::new(statement.clone(), context.genesis_hash);
            verify_zk_ace_privacy_v1(
                &public_inputs,
                proof.as_bytes(),
                context.consensus_limits.max_proof_bytes_per_action,
            )
            .map_err(|source| {
                PrivacyVerificationErrorV1::NativeZkAce(Box::new(
                    PrivacyZkAceVerificationFailureV1 { source },
                ))
            })?;
            VerifiedPrivacyLedgerEffectsV1::ZkAceAuthorization(VerifiedZkAceAuthorizationV1 {
                policy_id: statement.policy_id,
                policy_digest: statement.policy_digest,
                identity_commitment: statement.identity_commitment,
                authorization_epoch: statement.authorization_epoch,
                source: statement.source.clone(),
                destination: statement.destination.clone(),
                asset_definition_id: statement.asset_definition_id.clone(),
                public_balance_scope: statement.public_balance_scope,
                amount: statement.amount,
                replay_nullifier: statement.replay_nullifier,
            })
        }
        #[cfg(not(feature = "zk-stark"))]
        PrivacyStatementV1::ZkAcePqAuthorizationV1(_) => {
            return Err(PrivacyVerificationErrorV1::UnsupportedOperation(Box::new(
                PrivacyUnsupportedOperationV1::new(
                    role,
                    crate::privacy_dispatch::PrivacyRoleLimitationV1::NativeEngineNotCompiled,
                ),
            )));
        }
        PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) => {
            verify_anonymous_pgc_payment_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::VeRangeTransparentRangeV1(statement) => {
            let profile = match statement.bit_length {
                PrivacyVeRangeBitLengthV1::Bits32 => VeRangeBitLengthV1::Bits32,
                PrivacyVeRangeBitLengthV1::Bits64 => VeRangeBitLengthV1::Bits64,
            };
            let parameters = VeRangeParametersV1::for_profile(profile).map_err(|source| {
                PrivacyVerificationErrorV1::NativeVeRange(Box::new(
                    PrivacyVeRangeVerificationFailureV1 { source },
                ))
            })?;
            let commitments = statement
                .value_commitments
                .iter()
                .map(|point| CompressedPointV1::from_slice(point.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| {
                    PrivacyVerificationErrorV1::NativeVeRange(Box::new(
                        PrivacyVeRangeVerificationFailureV1 {
                            source: source.into(),
                        },
                    ))
                })?;
            let transcript = TranscriptBindingV1 {
                network_id: context.network_id.as_bytes(),
                genesis_hash: context.genesis_hash,
                action_index: context.expected_action_index,
                statement_digest: *envelope.statement_digest.as_bytes(),
                parameter_id: *envelope.parameter_id.as_bytes(),
                parameter_digest: *envelope.parameter_digest.as_bytes(),
                verifier_digest: *envelope.verifier_digest.as_bytes(),
                statement_schema_digest: *envelope.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *envelope.engine_manifest_digest.as_bytes(),
                generator_digest: parameters.generator_digest(),
            };
            let native_statement =
                VeRangeType1BatchStatementV1::new(profile, commitments, transcript).map_err(
                    |source| {
                        PrivacyVerificationErrorV1::NativeVeRange(Box::new(
                            PrivacyVeRangeVerificationFailureV1 { source },
                        ))
                    },
                )?;
            verify_batch_encoded(&native_statement, proof.as_bytes()).map_err(|source| {
                PrivacyVerificationErrorV1::NativeVeRange(Box::new(
                    PrivacyVeRangeVerificationFailureV1 { source },
                ))
            })?;
            VerifiedPrivacyLedgerEffectsV1::None
        }
        PrivacyStatementV1::IrohaZkAmsV1(statement) => {
            verify_zk_ams_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::VegaExistingCredentialZkV1(statement) => {
            verify_vega_existing_credential_v1(statement, proof, context)?
        }
        PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) => {
            verify_zk_x509_certificate_v1(statement, proof, context)?
        }
        PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) => {
            verify_jindo_batched_evaluation_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) => {
            verify_bootle_lantern_presentation_v1(statement, proof, context)?
        }
        PrivacyStatementV1::OrchardHalo2ActionsV1(statement) => {
            verify_orchard_actions_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) => {
            verify_fcmp_plus_plus_action_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) => {
            verify_ivm_private_note_action_v1(statement, proof, envelope, context)?
        }
        PrivacyStatementV1::PqMaspStarkV1(statement) => {
            verify_pq_masp_action_v1(statement, proof, envelope, context)?
        }
    };
    VerifiedPrivacyEffectsV1::seal_v1(
        role,
        envelope.statement_digest,
        context.expected_action_index,
        encoded_action_bytes,
        ledger,
    )
}
fn verify_zk_x509_certificate_v1(
    statement: &iroha_data_model::privacy::IrohaZkX509StarkP256StatementV1,
    proof: &PrivacyProofBytesV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let verification_state = context
        .zk_x509_state
        .ok_or_else(|| zk_x509_state_error(PrivacyZkX509StateFailureCodeV1::MissingTrustedState))?;
    validate_privacy_zk_x509_statement_state_v1(
        statement,
        verification_state.authoritative_state,
        context.block_timestamp_ms,
        context.consensus_limits,
    )
    .map_err(|_| {
        zk_x509_state_error(PrivacyZkX509StateFailureCodeV1::AuthoritativeStateMismatch)
    })?;
    if verification_state.certificate_nullifier_consumed {
        return Err(zk_x509_state_error(
            PrivacyZkX509StateFailureCodeV1::DuplicateCertificateNullifier,
        ));
    }
    verify_zk_x509_credential_proof_v1(
        statement,
        verification_state.authoritative_state,
        context.genesis_hash,
        proof.as_bytes(),
    )
    .map_err(|source| {
        PrivacyVerificationErrorV1::NativeZkX509(Box::new(PrivacyZkX509VerificationFailureV1 {
            source,
        }))
    })?;
    let authoritative_state = verification_state.authoritative_state;
    let trust_anchor = authoritative_state.trust_anchor();
    let certificate_policy = authoritative_state.certificate_policy();
    let crl = authoritative_state.crl_record();
    Ok(VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(
        VerifiedZkX509CertificateEffectV1 {
            namespace: authoritative_state.namespace(),
            certificate_nullifier: statement.certificate_nullifier,
            trust_anchor_record_digest: trust_anchor.record_digest,
            trust_anchor_record_epoch: trust_anchor.record_epoch,
            certificate_policy_record_digest: certificate_policy.record_digest,
            certificate_policy_record_epoch: certificate_policy.record_epoch,
            crl_record_digest: crl.record_digest,
            crl_record_epoch: crl.record_epoch,
        },
    ))
}
fn zk_x509_state_error(code: PrivacyZkX509StateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::ZkX509State(Box::new(PrivacyZkX509StateFailureV1 { code }))
}
fn verify_bootle_lantern_presentation_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    proof: &PrivacyProofBytesV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let policy = context.bootle_lantern_policy.ok_or_else(|| {
        PrivacyVerificationErrorV1::BootleLanternState(Box::new(
            PrivacyBootleLanternStateFailureV1 {
                code: PrivacyBootleLanternStateFailureCodeV1::MissingTrustedPolicy,
            },
        ))
    })?;
    policy.validate().map_err(|_| {
        PrivacyVerificationErrorV1::BootleLanternState(Box::new(
            PrivacyBootleLanternStateFailureV1 {
                code: PrivacyBootleLanternStateFailureCodeV1::InvalidTrustedPolicy,
            },
        ))
    })?;
    if policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
        return Err(PrivacyVerificationErrorV1::BootleLanternState(Box::new(
            PrivacyBootleLanternStateFailureV1 {
                code: PrivacyBootleLanternStateFailureCodeV1::PolicyRevoked,
            },
        )));
    }
    verify_bound_presentation_encoded_v1(
        statement,
        policy,
        context.genesis_hash,
        proof.as_bytes(),
        context.consensus_limits.max_proof_bytes_per_action,
    )
    .map_err(|source| match source {
        BoundPresentationEncodedErrorV1::Codec(source) => {
            PrivacyBootleLanternNativeFailureSourceV1::Codec(source)
        }
        BoundPresentationEncodedErrorV1::Presentation(
            BoundPresentationErrorV1::EngineUnavailable,
        ) => PrivacyBootleLanternNativeFailureSourceV1::EngineUnavailable,
        BoundPresentationEncodedErrorV1::Presentation(
            BoundPresentationErrorV1::StatementDigest,
        ) => PrivacyBootleLanternNativeFailureSourceV1::StatementDigest,
        BoundPresentationEncodedErrorV1::Presentation(BoundPresentationErrorV1::Relation(
            source,
        )) => PrivacyBootleLanternNativeFailureSourceV1::Relation(source),
        BoundPresentationEncodedErrorV1::Presentation(BoundPresentationErrorV1::Transcript(
            source,
        )) => PrivacyBootleLanternNativeFailureSourceV1::Transcript(source),
        BoundPresentationEncodedErrorV1::Presentation(BoundPresentationErrorV1::Proof(source)) => {
            PrivacyBootleLanternNativeFailureSourceV1::Proof(source)
        }
    })
    .map_err(native_bootle_lantern_error)?;
    Ok(VerifiedPrivacyLedgerEffectsV1::None)
}
fn native_bootle_lantern_error(
    source: PrivacyBootleLanternNativeFailureSourceV1,
) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::NativeBootleLantern(Box::new(
        PrivacyBootleLanternVerificationFailureV1 { source },
    ))
}
fn orchard_state_error(code: PrivacyOrchardStateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::OrchardState(Box::new(PrivacyOrchardStateFailureV1 { code }))
}
fn fcmp_state_error(code: PrivacyFcmpStateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::FcmpState(Box::new(PrivacyFcmpStateFailureV1 { code }))
}
fn native_fcmp_error(source: FcmpNativeErrorV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::NativeFcmp(Box::new(PrivacyFcmpVerificationFailureV1 { source }))
}
fn ivm_private_note_state_error(
    code: PrivacyIvmPrivateNoteStateFailureCodeV1,
) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::IvmPrivateNoteState(Box::new(PrivacyIvmPrivateNoteStateFailureV1 {
        code,
    }))
}
fn native_ivm_private_note_error(
    source: PrivacyIvmPrivateNoteNativeFailureSourceV1,
) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::NativeIvmPrivateNote(Box::new(
        PrivacyIvmPrivateNoteVerificationFailureV1 { source },
    ))
}
fn pq_masp_state_error(code: PrivacyPqMaspStateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::PqMaspState(Box::new(PrivacyPqMaspStateFailureV1 { code }))
}
fn native_pq_masp_error(source: PrivacyPqMaspNativeFailureSourceV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::NativePqMasp(Box::new(PrivacyPqMaspVerificationFailureV1 {
        source,
    }))
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedIvmPrivateNoteTransitionV1 {
    namespace: PrivacyNamespaceV1,
    bootstrap_digest: iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1,
    asset_definition_id: AssetDefinitionId,
    current_root: PrivacyRootV1,
    current_epoch: u64,
    successor_state: PrivacyProofManagedAccumulatorStateV1,
}
fn prepare_ivm_private_note_transition_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    expected_namespace: PrivacyNamespaceV1,
    snapshot: Option<&PrivacyProofManagedPoolSnapshotV1>,
) -> Result<PreparedIvmPrivateNoteTransitionV1, PrivacyVerificationErrorV1> {
    let snapshot = snapshot.ok_or_else(|| {
        ivm_private_note_state_error(PrivacyIvmPrivateNoteStateFailureCodeV1::MissingTrustedState)
    })?;
    if snapshot.namespace() != expected_namespace {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::NamespaceMismatch,
        ));
    }
    if snapshot.bootstrap().protocol_id() != PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1
        || snapshot.root_role() != PrivacyRootRoleV1::ProgramState
    {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::ProtocolOrRoleMismatch,
        ));
    }
    if snapshot.bootstrap().asset_definition_id() != &statement.asset_definition_id {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::AssetMismatch,
        ));
    }
    if snapshot.bootstrap().public_balance_scope() != Some(statement.public_balance_scope) {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::PublicBalanceScopeMismatch,
        ));
    }
    if snapshot.bootstrap().program_id() != Some(statement.program_id) {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::ProgramMismatch,
        ));
    }
    let accumulator = snapshot.accumulator_state().ok_or_else(|| {
        ivm_private_note_state_error(PrivacyIvmPrivateNoteStateFailureCodeV1::MissingNoteFrontier)
    })?;
    if accumulator.namespace() != snapshot.namespace() {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::FrontierMismatch,
        ));
    }
    let accumulator_epoch = accumulator.epoch();
    let mutation_head_epoch = snapshot.current_epoch();
    let mutation_head_root = snapshot.current_root();
    if accumulator_epoch != mutation_head_epoch
        || accumulator.root() != mutation_head_root
        || accumulator.tree_size() != snapshot.output_count()
    {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::FrontierMismatch,
        ));
    }
    if snapshot.retained_current_root().is_none() {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::CurrentRootNotRetained,
        ));
    }
    // Membership may use any exactly retained append-only note root. Mutation
    // always starts from the current trusted compact frontier above.
    if !snapshot.contains_retained_root(statement.root_epoch, statement.state_root) {
        return Err(ivm_private_note_state_error(
            PrivacyIvmPrivateNoteStateFailureCodeV1::AnchorNotRetained,
        ));
    }
    if statement.encrypted_outputs.len() != statement.output_commitments.len() {
        return Err(native_ivm_private_note_error(
            PrivacyIvmPrivateNoteNativeFailureSourceV1::Ciphertext(
                IvmPrivateNoteWalletErrorV1::Binding,
            ),
        ));
    }
    for (commitment, encrypted) in statement
        .output_commitments
        .iter()
        .copied()
        .zip(&statement.encrypted_outputs)
    {
        validate_ivm_private_encrypted_output_v1(
            statement.pool_id,
            statement.program_id,
            commitment,
            encrypted,
        )
        .map_err(PrivacyIvmPrivateNoteNativeFailureSourceV1::Ciphertext)
        .map_err(native_ivm_private_note_error)?;
    }
    let successor_state = snapshot
        .derive_note_successor(&statement.output_commitments)
        .map_err(|_| {
            ivm_private_note_state_error(
                PrivacyIvmPrivateNoteStateFailureCodeV1::SuccessorDerivation,
            )
        })?;
    Ok(PreparedIvmPrivateNoteTransitionV1 {
        namespace: snapshot.namespace(),
        bootstrap_digest: snapshot.bootstrap_digest(),
        asset_definition_id: statement.asset_definition_id.clone(),
        current_root: snapshot.current_root(),
        current_epoch: snapshot.current_epoch(),
        successor_state,
    })
}
fn verify_ivm_private_note_action_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let prepared = prepare_ivm_private_note_transition_v1(
        statement,
        PrivacyNamespaceV1::from_statement(&envelope.statement),
        context.proof_managed_state,
    )?;
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        context.genesis_hash,
        context.consensus_limits,
    )
    .map_err(PrivacyIvmPrivateNoteNativeFailureSourceV1::ConsensusBinding)
    .map_err(native_ivm_private_note_error)?;
    verify_private_note_stark_v1(
        statement,
        &consensus_binding,
        context.consensus_limits,
        proof.as_bytes(),
    )
    .map_err(PrivacyIvmPrivateNoteNativeFailureSourceV1::Proof)
    .map_err(native_ivm_private_note_error)?;
    Ok(VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(
        VerifiedProofManagedPoolLedgerEffectV1 {
            namespace: prepared.namespace,
            bootstrap_digest: prepared.bootstrap_digest,
            asset_definition_id: prepared.asset_definition_id,
            current_root: prepared.current_root,
            current_epoch: prepared.current_epoch,
            next_root: prepared.successor_state.root(),
            next_epoch: prepared.successor_state.epoch(),
            transition: VerifiedProofManagedPoolTransitionV1::IvmPrivateNote {
                nullifiers: statement.nullifiers.clone(),
                output_commitments: statement.output_commitments.clone(),
                successor_state: prepared.successor_state,
            },
            value_balance: Some(statement.value_balance),
            public_balance_scope: Some(statement.public_balance_scope),
        },
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedPqMaspTransitionV1 {
    namespace: PrivacyNamespaceV1,
    bootstrap_digest: iroha_data_model::privacy::PrivacyProofManagedPoolBootstrapDigestV1,
    asset_definition_id: AssetDefinitionId,
    current_root: PrivacyRootV1,
    current_epoch: u64,
    successor_state: PrivacyProofManagedAccumulatorStateV1,
}
fn prepare_pq_masp_transition_v1(
    statement: &PqMaspStarkStatementV1,
    expected_namespace: PrivacyNamespaceV1,
    snapshot: Option<&PrivacyProofManagedPoolSnapshotV1>,
) -> Result<PreparedPqMaspTransitionV1, PrivacyVerificationErrorV1> {
    let snapshot = snapshot
        .ok_or_else(|| pq_masp_state_error(PrivacyPqMaspStateFailureCodeV1::MissingTrustedState))?;
    if snapshot.namespace() != expected_namespace {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::NamespaceMismatch,
        ));
    }
    if snapshot.bootstrap().protocol_id() != PrivacyProtocolIdV1::PqMaspStarkV1
        || snapshot.root_role() != PrivacyRootRoleV1::NoteCommitmentAnchor
    {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::ProtocolOrRoleMismatch,
        ));
    }
    if snapshot.bootstrap().asset_definition_id() != &statement.asset_definition_id {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::AssetMismatch,
        ));
    }
    let accumulator = snapshot
        .accumulator_state()
        .ok_or_else(|| pq_masp_state_error(PrivacyPqMaspStateFailureCodeV1::MissingNoteFrontier))?;
    if accumulator.namespace() != snapshot.namespace() {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::FrontierMismatch,
        ));
    }
    let accumulator_epoch = accumulator.epoch();
    let mutation_head_epoch = snapshot.current_epoch();
    let mutation_head_root = snapshot.current_root();
    if accumulator_epoch != mutation_head_epoch
        || accumulator.root() != mutation_head_root
        || accumulator.tree_size() != snapshot.output_count()
    {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::FrontierMismatch,
        ));
    }
    if snapshot.retained_current_root().is_none() {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::CurrentRootNotRetained,
        ));
    }
    // Membership is valid under any exactly retained append-only root. The
    // successor is nevertheless derived only from the trusted current
    // frontier above, never from a prover-selected anchor.
    if !snapshot.contains_retained_root(statement.anchor_epoch, statement.anchor) {
        return Err(pq_masp_state_error(
            PrivacyPqMaspStateFailureCodeV1::AnchorNotRetained,
        ));
    }
    if statement.encrypted_outputs.len() != statement.output_commitments.len()
        || statement
            .encrypted_outputs
            .iter()
            .zip(&statement.output_commitments)
            .any(|(encrypted, commitment)| encrypted.commitment != *commitment)
    {
        return Err(native_pq_masp_error(
            PrivacyPqMaspNativeFailureSourceV1::Ciphertext(
                PqMaspWireErrorV1::EncryptedOutputBinding,
            ),
        ));
    }
    validate_pq_masp_note_encryption_key_digest_v1(statement)
        .map_err(PrivacyPqMaspNativeFailureSourceV1::Ciphertext)
        .map_err(native_pq_masp_error)?;
    let successor_state = snapshot
        .derive_note_successor(&statement.output_commitments)
        .map_err(|_| pq_masp_state_error(PrivacyPqMaspStateFailureCodeV1::SuccessorDerivation))?;
    Ok(PreparedPqMaspTransitionV1 {
        namespace: snapshot.namespace(),
        bootstrap_digest: snapshot.bootstrap_digest(),
        asset_definition_id: statement.asset_definition_id.clone(),
        current_root: snapshot.current_root(),
        current_epoch: snapshot.current_epoch(),
        successor_state,
    })
}
fn verify_pq_masp_action_v1(
    statement: &PqMaspStarkStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let prepared = prepare_pq_masp_transition_v1(
        statement,
        PrivacyNamespaceV1::from_statement(&envelope.statement),
        context.proof_managed_state,
    )?;
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        context.genesis_hash,
        context.consensus_limits,
    )
    .map_err(PrivacyPqMaspNativeFailureSourceV1::ConsensusBinding)
    .map_err(native_pq_masp_error)?;
    let consensus_binding_digest = consensus_binding
        .digest()
        .map_err(|_| PrivacyPqMaspNativeFailureSourceV1::ConsensusBindingEncoding)
        .map_err(native_pq_masp_error)?;
    let authorization = verify_pq_masp_authorization_v1(
        envelope.statement_digest,
        consensus_binding_digest,
        statement.authorization_key_digest,
        proof.as_bytes(),
    )
    .map_err(PrivacyPqMaspNativeFailureSourceV1::Authorization)
    .map_err(native_pq_masp_error)?;
    verify_pq_masp_stark_v1(
        statement,
        &consensus_binding,
        context.consensus_limits,
        authorization.stark_proof,
    )
    .map_err(PrivacyPqMaspNativeFailureSourceV1::Proof)
    .map_err(native_pq_masp_error)?;
    Ok(VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(
        VerifiedProofManagedPoolLedgerEffectV1 {
            namespace: prepared.namespace,
            bootstrap_digest: prepared.bootstrap_digest,
            asset_definition_id: prepared.asset_definition_id,
            current_root: prepared.current_root,
            current_epoch: prepared.current_epoch,
            next_root: prepared.successor_state.root(),
            next_epoch: prepared.successor_state.epoch(),
            transition: VerifiedProofManagedPoolTransitionV1::PqMasp {
                nullifiers: statement.nullifiers.clone(),
                output_commitments: statement.output_commitments.clone(),
                successor_state: prepared.successor_state,
            },
            value_balance: None,
            public_balance_scope: None,
        },
    ))
}
fn fcmp_runtime_context_hash_v1(
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> [u8; 32] {
    derive_fcmp_runtime_context_hash_v1(&FcmpRuntimeContextBindingV1 {
        network_id: context.network_id,
        action_index: context.expected_action_index,
        statement_digest: envelope.statement_digest,
        parameter_id: envelope.parameter_id,
        parameter_digest: envelope.parameter_digest,
        verifier_digest: envelope.verifier_digest,
        statement_schema_digest: envelope.statement_schema_digest,
        engine_manifest_digest: envelope.engine_manifest_digest,
    })
}
fn verify_fcmp_plus_plus_action_v1(
    statement: &MoneroFcmpPlusPlusStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let snapshot = context
        .proof_managed_state
        .ok_or_else(|| fcmp_state_error(PrivacyFcmpStateFailureCodeV1::MissingTrustedState))?;
    let expected_namespace = PrivacyNamespaceV1::from_statement(&envelope.statement);
    if snapshot.namespace() != expected_namespace {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::NamespaceMismatch,
        ));
    }
    if snapshot.bootstrap().protocol_id() != PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1
        || snapshot.root_role() != PrivacyRootRoleV1::OutputSet
    {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::ProtocolOrRoleMismatch,
        ));
    }
    if snapshot.bootstrap().asset_definition_id() != &statement.asset_definition_id {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::AssetMismatch,
        ));
    }
    let accumulator = snapshot
        .fcmp_accumulator_state()
        .ok_or_else(|| fcmp_state_error(PrivacyFcmpStateFailureCodeV1::MissingCurveFrontier))?;
    if accumulator.namespace() != snapshot.namespace() {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::FrontierMismatch,
        ));
    }
    let accumulator_epoch = accumulator.epoch();
    let mutation_head_epoch = snapshot.current_epoch();
    if accumulator_epoch != mutation_head_epoch
        || accumulator.root().history_commitment() != snapshot.current_root()
        || accumulator.tree_size() != snapshot.output_count()
    {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::FrontierMismatch,
        ));
    }
    if snapshot.retained_current_root().is_none() {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::CurrentRootNotRetained,
        ));
    }
    // The proof anchor and mutation head are deliberately distinct. FCMP++'s output set is
    // append-only, so membership under any exactly retained historical root remains sound.
    // Key-image uniqueness prevents replay, while newly created outputs are always appended to the
    // current trusted frontier below.
    let statement_root = statement.output_set_root.history_commitment();
    if !snapshot.contains_retained_root(statement.root_epoch, statement_root) {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::AnchorNotRetained,
        ));
    }
    if statement.root_epoch == snapshot.current_epoch()
        && statement_root == snapshot.current_root()
        && statement.output_set_root != accumulator.root()
    {
        return Err(fcmp_state_error(
            PrivacyFcmpStateFailureCodeV1::CurrentTypedRootMismatch,
        ));
    }
    let native_root = FcmpTreeRootV1::new(
        statement.output_set_root.layers,
        statement.output_set_root.point,
    )
    .map_err(native_fcmp_error)?;
    let native_inputs = statement
        .inputs
        .iter()
        .map(|input| {
            FcmpProofInputPublicV1::new(
                input.output_key_tilde,
                input.linking_tag_generator_tilde,
                input.rerandomization_commitment,
                input.pseudo_out,
                input.key_image.into_bytes(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(native_fcmp_error)?;
    let native_outputs = statement
        .outputs
        .iter()
        .map(|output| {
            FcmpOutputTupleV1::new(
                output.output_key,
                output.linking_tag_generator,
                output.amount_commitment,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(native_fcmp_error)?;
    for (output, encrypted) in statement
        .outputs
        .iter()
        .copied()
        .zip(&statement.encrypted_outputs)
    {
        validate_fcmp_encrypted_output_v1(statement.pool_id, output, encrypted)
            .map_err(native_fcmp_error)?;
    }
    let successor_state = snapshot
        .derive_fcmp_successor(&statement.outputs)
        .map_err(|_| fcmp_state_error(PrivacyFcmpStateFailureCodeV1::SuccessorDerivation))?;
    let runtime_context = fcmp_runtime_context_hash_v1(envelope, context);
    verify_fcmp_transaction_v1(
        runtime_context,
        proof.as_bytes(),
        &native_inputs,
        &native_outputs,
        native_root,
    )
    .map_err(native_fcmp_error)?;
    Ok(VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(
        VerifiedProofManagedPoolLedgerEffectV1 {
            namespace: snapshot.namespace(),
            bootstrap_digest: snapshot.bootstrap_digest(),
            asset_definition_id: statement.asset_definition_id.clone(),
            current_root: snapshot.current_root(),
            current_epoch: snapshot.current_epoch(),
            next_root: successor_state.root().history_commitment(),
            next_epoch: successor_state.epoch(),
            transition: VerifiedProofManagedPoolTransitionV1::Fcmp {
                key_images: statement
                    .inputs
                    .iter()
                    .map(|input| input.key_image)
                    .collect(),
                outputs: statement.outputs.clone(),
                successor_state,
            },
            value_balance: None,
            public_balance_scope: None,
        },
    ))
}
fn verify_orchard_actions_v1(
    statement: &OrchardHalo2ActionsStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let snapshot = context.orchard_state.ok_or_else(|| {
        orchard_state_error(PrivacyOrchardStateFailureCodeV1::MissingTrustedState)
    })?;
    let expected_namespace = PrivacyNamespaceV1::from_statement(&envelope.statement);
    if snapshot.namespace() != expected_namespace {
        return Err(orchard_state_error(
            PrivacyOrchardStateFailureCodeV1::NamespaceMismatch,
        ));
    }
    if snapshot.state().asset_definition_id() != &statement.asset_definition_id {
        return Err(orchard_state_error(
            PrivacyOrchardStateFailureCodeV1::AssetMismatch,
        ));
    }
    if snapshot.state().public_balance_scope() != statement.public_balance_scope {
        return Err(orchard_state_error(
            PrivacyOrchardStateFailureCodeV1::PublicBalanceScopeMismatch,
        ));
    }
    if !snapshot.contains_retained_anchor(statement.anchor_epoch, statement.anchor) {
        return Err(orchard_state_error(
            PrivacyOrchardStateFailureCodeV1::AnchorNotRetained,
        ));
    }
    if context.current_height > statement.expiry_height {
        return Err(orchard_state_error(
            PrivacyOrchardStateFailureCodeV1::Expired,
        ));
    }
    let magnitude = i64::try_from(statement.value_balance.amount).map_err(|_| {
        orchard_state_error(PrivacyOrchardStateFailureCodeV1::ValueBalanceOutOfRange)
    })?;
    let value_balance = match statement.value_balance.direction {
        PrivacyValueBalanceDirectionV1::Balanced => 0,
        PrivacyValueBalanceDirectionV1::IntoPool => magnitude.checked_neg().ok_or_else(|| {
            orchard_state_error(PrivacyOrchardStateFailureCodeV1::ValueBalanceOutOfRange)
        })?,
        PrivacyValueBalanceDirectionV1::OutOfPool => magnitude,
    };
    let mut public_actions = Vec::with_capacity(statement.actions.len());
    let mut note_commitments = Vec::with_capacity(statement.actions.len());
    let mut nullifiers = Vec::with_capacity(statement.actions.len());
    for action in &statement.actions {
        let encrypted_note =
            action.encrypted_note.as_slice().try_into().map_err(|_| {
                orchard_state_error(PrivacyOrchardStateFailureCodeV1::CiphertextWidth)
            })?;
        let outgoing_ciphertext = action
            .outgoing_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| orchard_state_error(PrivacyOrchardStateFailureCodeV1::CiphertextWidth))?;
        public_actions.push(OrchardActionPublicV1 {
            nullifier: action.nullifier,
            randomized_key: action.randomized_key,
            note_commitment: action.note_commitment,
            ephemeral_key: action.ephemeral_key,
            encrypted_note,
            outgoing_ciphertext,
            value_commitment: action.value_commitment,
        });
        note_commitments.push(action.note_commitment);
        nullifiers.push(action.nullifier);
    }
    let successor_state = snapshot
        .derive_successor(&note_commitments)
        .map_err(|_| orchard_state_error(PrivacyOrchardStateFailureCodeV1::SuccessorDerivation))?;
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        context.genesis_hash,
        context.consensus_limits,
    )
    .map_err(|_| {
        PrivacyVerificationErrorV1::NativeOrchard(Box::new(PrivacyOrchardVerificationFailureV1 {
            source: OrchardNativeErrorV1::ConsensusBinding,
        }))
    })?;
    let native_public = OrchardBundlePublicV1 {
        consensus_binding,
        anchor: statement.anchor.into_bytes(),
        value_balance,
        actions: public_actions,
    };
    verify_orchard_bundle_v1(&native_public, proof.as_bytes(), context.consensus_limits).map_err(
        |source| {
            PrivacyVerificationErrorV1::NativeOrchard(Box::new(
                PrivacyOrchardVerificationFailureV1 { source },
            ))
        },
    )?;
    Ok(VerifiedPrivacyLedgerEffectsV1::OrchardActions(
        VerifiedOrchardLedgerEffectV1 {
            namespace: snapshot.namespace(),
            bootstrap_digest: snapshot.bootstrap_digest(),
            asset_definition_id: statement.asset_definition_id.clone(),
            public_balance_scope: statement.public_balance_scope,
            reserve_account: snapshot.state().reserve_account().clone(),
            anchor: statement.anchor,
            anchor_epoch: statement.anchor_epoch,
            current_root: snapshot.current_root(),
            current_epoch: snapshot.current_epoch(),
            successor_state,
            nullifiers,
            value_balance: statement.value_balance,
            expiry_height: statement.expiry_height,
        },
    ))
}
fn verify_zk_ams_v1(
    statement: &IrohaZkAmsStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let binding = TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: context.genesis_hash,
        action_index: context.expected_action_index,
        statement_digest: *envelope.statement_digest.as_bytes(),
        parameter_id: *envelope.parameter_id.as_bytes(),
        parameter_digest: *envelope.parameter_digest.as_bytes(),
        verifier_digest: *envelope.verifier_digest.as_bytes(),
        statement_schema_digest: *envelope.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *envelope.engine_manifest_digest.as_bytes(),
        generator_digest: zk_ams_generator_digest_v1(),
    };
    match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(_) => {
            verify_zk_ams_batch_admission_v1(statement, &binding, proof.as_bytes())
                .map(VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission)
        }
        PrivacyZkAmsActionV1::ProvisionAccount(_) => {
            verify_zk_ams_provision_statement_v1(statement, &binding, proof.as_bytes())
                .map(VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount)
        }
    }
    .map_err(|source| {
        PrivacyVerificationErrorV1::NativeZkAms(Box::new(PrivacyZkAmsVerificationFailureV1 {
            source,
        }))
    })
}
fn verify_vega_existing_credential_v1(
    statement: &VegaExistingCredentialStatementV1,
    proof: &PrivacyProofBytesV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let record = context
        .vega_issuer_record
        .ok_or_else(|| vega_state_error(PrivacyVegaStateFailureCodeV1::MissingTrustedIssuer))?;
    validate_vega_authoritative_issuer_binding_v1(statement, record).map_err(vega_state_error)?;
    let binding = VegaMdlConsensusBindingV1::from_context(&statement.context, context.genesis_hash);
    verify_mdl_figure9_v1(
        statement,
        &binding,
        context.block_timestamp_ms,
        proof.as_bytes(),
    )
    .map_err(|source| {
        PrivacyVerificationErrorV1::NativeVega(Box::new(PrivacyVegaVerificationFailureV1 {
            source,
        }))
    })?;
    Ok(VerifiedPrivacyLedgerEffectsV1::None)
}
/// Validate the exact current Vega issuer revision selected by a statement.
///
/// This is the production trusted-state boundary shared by ledger admission and the non-shipping
/// release-evidence harness. It deliberately performs no proof work: malformed, revoked, stale, or
/// policy-substituted authoritative state must fail before the native verifier is invoked.
#[doc(hidden)]
pub fn validate_vega_authoritative_issuer_binding_v1(
    statement: &VegaExistingCredentialStatementV1,
    record: &PrivacyVegaIssuerRecordV1,
) -> Result<(), PrivacyVegaStateFailureCodeV1> {
    record
        .validate()
        .map_err(|_| PrivacyVegaStateFailureCodeV1::InvalidTrustedIssuer)?;
    CompressedPointV1::from_slice(record.issuer_public_key.as_bytes())
        .map_err(|_| PrivacyVegaStateFailureCodeV1::InvalidTrustedIssuer)?;
    if record.lifecycle != PrivacyVegaIssuerRecordLifecycleV1::Active {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerRevoked);
    }
    if statement.issuer_id != record.issuer_id {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerIdMismatch);
    }
    if statement.issuer_record_epoch != record.record_epoch {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerEpochMismatch);
    }
    if statement.issuer_record_digest != record.record_digest {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerRecordDigestMismatch);
    }
    if statement.issuer_public_key != record.issuer_public_key {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerPublicKeyMismatch);
    }
    if statement.document_type != record.document_type {
        return Err(PrivacyVegaStateFailureCodeV1::DocumentPolicyMismatch);
    }
    if statement.namespace != record.namespace {
        return Err(PrivacyVegaStateFailureCodeV1::NamespacePolicyMismatch);
    }
    if statement.digest_algorithm != record.digest_algorithm {
        return Err(PrivacyVegaStateFailureCodeV1::DigestAlgorithmPolicyMismatch);
    }
    if statement.issuer_authentication_algorithm != record.issuer_authentication_algorithm {
        return Err(PrivacyVegaStateFailureCodeV1::IssuerAuthenticationPolicyMismatch);
    }
    if statement.device_authentication_algorithm != record.device_authentication_algorithm {
        return Err(PrivacyVegaStateFailureCodeV1::DeviceAuthenticationPolicyMismatch);
    }
    Ok(())
}
fn vega_state_error(code: PrivacyVegaStateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::VegaState(Box::new(PrivacyVegaStateFailureV1 { code }))
}
fn verify_jindo_batched_evaluation_v1(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let transcript = TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: context.genesis_hash,
        action_index: context.expected_action_index,
        statement_digest: *envelope.statement_digest.as_bytes(),
        parameter_id: *envelope.parameter_id.as_bytes(),
        parameter_digest: *envelope.parameter_digest.as_bytes(),
        verifier_digest: *envelope.verifier_digest.as_bytes(),
        statement_schema_digest: *envelope.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *envelope.engine_manifest_digest.as_bytes(),
        generator_digest: jindo_crs_digest_v1(),
    };
    verify_batched_evaluation_v1(
        statement,
        proof.as_bytes(),
        &transcript,
        context.consensus_limits.max_proof_bytes_per_action,
    )
    .map_err(|source| {
        PrivacyVerificationErrorV1::NativeJindo(Box::new(PrivacyJindoVerificationFailureV1 {
            source,
        }))
    })?;
    Ok(VerifiedPrivacyLedgerEffectsV1::None)
}
fn verify_anonymous_pgc_payment_v1(
    statement: &AnonymousPgcKOutOfNStatementV1,
    proof: &PrivacyProofBytesV1,
    envelope: &PrivacyProofEnvelopeV1,
    context: &PrivacyVerificationContextV1<'_>,
) -> Result<VerifiedPrivacyLedgerEffectsV1, PrivacyVerificationErrorV1> {
    let state = context.pgc_state.ok_or_else(|| {
        pgc_state_error(PrivacyAnonymousPgcStateFailureCodeV1::MissingTrustedState)
    })?;
    let expected_namespace = PrivacyNamespaceV1::from_statement(&envelope.statement);
    if state.namespace != expected_namespace {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::NamespaceMismatch,
        ));
    }
    if statement.account_state_root != state.current_root
        || statement.account_state_root_epoch != state.current_epoch
    {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::StaleHead,
        ));
    }
    if state.retained_current_root != Some((state.current_epoch, state.current_root)) {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootNotRetained,
        ));
    }
    if state.accounts.len() != statement.anonymity_set_public_keys.len()
        || state
            .accounts
            .iter()
            .zip(&statement.anonymity_set_public_keys)
            .any(|(account, statement_key)| account.public_key != *statement_key)
    {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch,
        ));
    }
    let computed_current_root = derive_privacy_pgc_account_state_root_v1(
        state.namespace,
        state.current_epoch,
        state.total_supply,
        state.accounts,
    )
    .map_err(|source| PrivacyVerificationErrorV1::AnonymousPgcRoot {
        code: PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootRecomputationFailed,
        source,
    })?;
    if computed_current_root != state.current_root {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootMismatch,
        ));
    }
    let parameters = AnonymousPgcParametersV1::get().map_err(native_pgc_error)?;
    let pool_invariant = AnonymousPgcPoolInvariantV1::new(
        state.total_supply,
        *state.bootstrap_digest.as_bytes(),
        *state.bootstrap_proof_digest.as_bytes(),
    )
    .map_err(|_| pgc_state_error(PrivacyAnonymousPgcStateFailureCodeV1::InvalidPoolInvariant))?;
    let public_keys = statement
        .anonymity_set_public_keys
        .iter()
        .map(|point| TwistedElGamalPublicKeyV1::from_sec1_bytes(point.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(native_pgc_error)?;
    let transfer_ciphertexts = statement
        .transfer_ciphertexts
        .iter()
        .map(|ciphertext| {
            TwistedElGamalCiphertextV1::from_sec1_bytes(
                ciphertext.left.as_bytes(),
                ciphertext.right.as_bytes(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(native_pgc_error)?;
    let current_balance_ciphertexts = state
        .accounts
        .iter()
        .map(|account| {
            TwistedElGamalCiphertextV1::from_sec1_bytes(
                account.encrypted_balance.left.as_bytes(),
                account.encrypted_balance.right.as_bytes(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(native_pgc_error)?;
    let transcript = TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: context.genesis_hash,
        action_index: context.expected_action_index,
        statement_digest: *envelope.statement_digest.as_bytes(),
        parameter_id: *envelope.parameter_id.as_bytes(),
        parameter_digest: *envelope.parameter_digest.as_bytes(),
        verifier_digest: *envelope.verifier_digest.as_bytes(),
        statement_schema_digest: *envelope.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *envelope.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    };
    let recipient_count = usize::try_from(statement.recipient_count).map_err(|_| {
        pgc_state_error(PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch)
    })?;
    let native_statement = AnonymousPgcPaymentStatementV1::new(
        &public_keys,
        &transfer_ciphertexts,
        &current_balance_ciphertexts,
        recipient_count,
        pool_invariant,
        transcript,
    )
    .map_err(native_pgc_error)?;
    let verified =
        verify_payment_encoded(&native_statement, proof.as_bytes()).map_err(native_pgc_error)?;
    if verified.next_balance_ciphertexts().len() != state.accounts.len() {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::SuccessorTableMismatch,
        ));
    }
    let accounts = state
        .accounts
        .iter()
        .zip(verified.next_balance_ciphertexts())
        .map(|(current, ciphertext)| PrivacyPgcAccountV1 {
            public_key: current.public_key,
            encrypted_balance: PrivacyP256CiphertextV1 {
                left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
                right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
            },
        })
        .collect::<Vec<_>>();
    let computed_next_root = derive_privacy_pgc_account_state_root_v1(
        state.namespace,
        statement.next_account_state_root_epoch,
        state.total_supply,
        &accounts,
    )
    .map_err(|source| PrivacyVerificationErrorV1::AnonymousPgcRoot {
        code: PrivacyAnonymousPgcStateFailureCodeV1::NextRootRecomputationFailed,
        source,
    })?;
    if computed_next_root != statement.next_account_state_root {
        return Err(pgc_state_error(
            PrivacyAnonymousPgcStateFailureCodeV1::NextRootMismatch,
        ));
    }
    Ok(VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(
        VerifiedAnonymousPgcLedgerEffectV1 {
            namespace: state.namespace,
            total_supply: state.total_supply,
            current_root: state.current_root,
            current_epoch: state.current_epoch,
            next_root: computed_next_root,
            next_epoch: statement.next_account_state_root_epoch,
            accounts,
        },
    ))
}
fn native_pgc_error(source: impl Into<AnonymousPgcReadError>) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::NativeAnonymousPgc(Box::new(source.into()))
}
fn pgc_state_error(code: PrivacyAnonymousPgcStateFailureCodeV1) -> PrivacyVerificationErrorV1 {
    PrivacyVerificationErrorV1::AnonymousPgcState(Box::new(PrivacyAnonymousPgcStateFailureV1 {
        code,
    }))
}
/// Exhaustive privacy-verification failure.
///
/// Ordinary diagnostics retain their boxed details. The original PGC root/codec
/// refusal stays inline so reporting a local capacity failure needs no new
/// allocation.
#[derive(Debug, Error)]
#[doc(hidden)]
#[expect(
    variant_size_differences,
    reason = "retain original root/codec refusal without allocating on failure"
)]
pub enum PrivacyVerificationErrorV1 {
    /// The execution context differs from the statement or is incomplete.
    #[error(transparent)]
    Context(Box<PrivacyVerificationContextFailureV1>),
    /// The active governance record differs from executable consensus code.
    #[error(transparent)]
    CompiledActivation(Box<PrivacyCompiledActivationFailureV1>),
    /// Typed envelope or governed lifecycle validation failed.
    #[error(transparent)]
    Envelope(Box<PrivacyEnvelopeFailureV1>),
    /// The selected role has no usable native verification in this source tree.
    ///
    /// This typed refusal carries the role and its concrete limitation. It is
    /// returned before any proof byte is examined and is never a success.
    #[error(transparent)]
    UnsupportedOperation(Box<PrivacyUnsupportedOperationV1>),
    /// A native verifier returned the ledger effect of another role.
    #[error(transparent)]
    EffectRoleMismatch(Box<PrivacyEffectRoleMismatchFailureV1>),
    /// Native `VeRange` decoding or verification failed.
    #[error(transparent)]
    NativeVeRange(Box<PrivacyVeRangeVerificationFailureV1>),
    /// Native Jindo decoding or verification failed.
    #[error(transparent)]
    NativeJindo(Box<PrivacyJindoVerificationFailureV1>),
    /// Trusted Vega issuer-key/policy state was absent or inconsistent.
    #[error(transparent)]
    VegaState(Box<PrivacyVegaStateFailureV1>),
    /// Native Vega decoding or verification failed.
    #[error(transparent)]
    NativeVega(Box<PrivacyVegaVerificationFailureV1>),
    /// Direct native ZK-ACE decoding or verification failed.
    #[cfg(feature = "zk-stark")]
    #[error(transparent)]
    NativeZkAce(Box<PrivacyZkAceVerificationFailureV1>),
    /// Native ZK-AMS decoding or verification failed.
    #[error(transparent)]
    NativeZkAms(Box<PrivacyZkAmsVerificationFailureV1>),
    /// Trusted X.509 governance/root/replay state was absent or inconsistent.
    #[error(transparent)]
    ZkX509State(Box<PrivacyZkX509StateFailureV1>),
    /// Native canonical X5S1 proof decoding or verification failed.
    #[error(transparent)]
    NativeZkX509(Box<PrivacyZkX509VerificationFailureV1>),
    /// Trusted persisted Orchard state was absent or inconsistent with the statement.
    #[error(transparent)]
    OrchardState(Box<PrivacyOrchardStateFailureV1>),
    /// Native Orchard decoding or verification failed.
    #[error(transparent)]
    NativeOrchard(Box<PrivacyOrchardVerificationFailureV1>),
    /// Trusted persisted FCMP++ state was absent or inconsistent with the statement.
    #[error(transparent)]
    FcmpState(Box<PrivacyFcmpStateFailureV1>),
    /// Native FCMP++ decoding, conservation, or proof verification failed.
    #[error(transparent)]
    NativeFcmp(Box<PrivacyFcmpVerificationFailureV1>),
    /// Trusted persisted private-IVM state was absent or inconsistent.
    #[error(transparent)]
    IvmPrivateNoteState(Box<PrivacyIvmPrivateNoteStateFailureV1>),
    /// Native private-IVM ciphertext or proof verification failed.
    #[error(transparent)]
    NativeIvmPrivateNote(Box<PrivacyIvmPrivateNoteVerificationFailureV1>),
    /// Trusted persisted PQ-MASP state was absent or inconsistent.
    #[error(transparent)]
    PqMaspState(Box<PrivacyPqMaspStateFailureV1>),
    /// Native PQ-MASP ciphertext, authorization, or proof verification failed.
    #[error(transparent)]
    NativePqMasp(Box<PrivacyPqMaspVerificationFailureV1>),
    /// Trusted persisted Anonymous-PGC state was absent or inconsistent.
    #[error(transparent)]
    AnonymousPgcState(Box<PrivacyAnonymousPgcStateFailureV1>),
    /// Canonical trusted PGC root derivation failed without losing its allocation owner.
    #[error("trusted Anonymous-PGC root derivation {code:?}: {source}")]
    AnonymousPgcRoot {
        /// Whether the current or verified successor root was being derived.
        code: PrivacyAnonymousPgcStateFailureCodeV1,
        /// Original typed structural or local encoding failure.
        #[source]
        source: crate::privacy_state::PrivacyPgcAccountStateRootErrorV1,
    },
    /// Native Anonymous-PGC decoding or verification failed.
    #[error("native Anonymous-PGC verification failed: {0}")]
    NativeAnonymousPgc(#[source] Box<AnonymousPgcReadError>),
    /// Trusted Bootle/Lantern issuer policy was absent, invalid, or revoked.
    #[error(transparent)]
    BootleLanternState(Box<PrivacyBootleLanternStateFailureV1>),
    /// Native Bootle/Lantern relation, decoding, transcript, or proof verification failed.
    #[error(transparent)]
    NativeBootleLantern(Box<PrivacyBootleLanternVerificationFailureV1>),
    /// Canonical envelope encoding or length conversion failed.
    #[error(transparent)]
    CanonicalEncoding(Box<PrivacyCanonicalEncodingFailureV1>),
}
/// Stable execution-context mismatch category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyVerificationContextFailureCodeV1 {
    /// No committed genesis digest was available.
    ZeroGenesisHash,
    /// Prover-selected and node-configured networks differ.
    NetworkIdMismatch,
    /// The typed network identity and explicit trusted genesis hash differ.
    NetworkGenesisMismatch,
    /// Prover-selected and transaction-local action indexes differ.
    ActionIndexMismatch,
}
#[derive(Debug, Error)]
#[error("privacy verification context {code:?}: expected {expected}, observed {actual}")]
pub struct PrivacyVerificationContextFailureV1 {
    pub code: PrivacyVerificationContextFailureCodeV1,
    expected: Box<str>,
    actual: Box<str>,
}
impl PrivacyVerificationContextFailureV1 {
    fn new(
        code: PrivacyVerificationContextFailureCodeV1,
        expected: impl Into<Box<str>>,
        actual: impl Into<Box<str>>,
    ) -> Self {
        Self {
            code,
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}
#[derive(Debug, Error, Clone, Copy)]
#[error("privacy activation does not match the compiled native profile: {source}")]
pub struct PrivacyCompiledActivationFailureV1 {
    source: CompiledPrivacyProfileValidationErrorV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("privacy envelope admission failed: {source}")]
pub struct PrivacyEnvelopeFailureV1 {
    source: PrivacyProofEnvelopeValidationError,
}
/// Internal dispatch fault: a verified ledger effect did not belong to its role.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("native privacy verifier returned an effect that does not belong to role {role}")]
pub struct PrivacyEffectRoleMismatchFailureV1 {
    /// The role whose verifier produced the foreign effect.
    pub role: PrivacyActionRoleV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native VeRange verification failed: {source}")]
pub struct PrivacyVeRangeVerificationFailureV1 {
    source: VeRangeError,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native Jindo verification failed: {source}")]
pub struct PrivacyJindoVerificationFailureV1 {
    source: JindoErrorV1,
}
/// Stable trusted-state failure detected before native Vega proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyVegaStateFailureCodeV1 {
    /// The submit path did not resolve a governed issuer lineage.
    MissingTrustedIssuer,
    /// Persisted issuer bytes or P-256 key failed canonical validation.
    InvalidTrustedIssuer,
    /// The current issuer lineage is terminal-revoked.
    IssuerRevoked,
    /// The statement selected a different stable issuer identity.
    IssuerIdMismatch,
    /// The statement selected a stale or future issuer revision.
    IssuerEpochMismatch,
    /// The statement substituted the authoritative revision self-digest.
    IssuerRecordDigestMismatch,
    /// The statement substituted the authoritative P-256 issuer key.
    IssuerPublicKeyMismatch,
    /// The statement selected a different credential document policy.
    DocumentPolicyMismatch,
    /// The statement selected a different mDL namespace policy.
    NamespacePolicyMismatch,
    /// The statement selected a different digest algorithm policy.
    DigestAlgorithmPolicyMismatch,
    /// The statement selected a different issuer-authentication policy.
    IssuerAuthenticationPolicyMismatch,
    /// The statement selected a different device-authentication policy.
    DeviceAuthenticationPolicyMismatch,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted Vega issuer state failed validation: {code:?}")]
pub struct PrivacyVegaStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyVegaStateFailureCodeV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native Vega verification failed: {source}")]
pub struct PrivacyVegaVerificationFailureV1 {
    source: VegaMdlError,
}
#[derive(Debug, Error)]
#[error("native ZK-ACE verification failed: {source}")]
#[cfg(feature = "zk-stark")]
pub struct PrivacyZkAceVerificationFailureV1 {
    source: ZkAceNativeErrorV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native ZK-AMS verification failed: {source}")]
pub struct PrivacyZkAmsVerificationFailureV1 {
    source: ZkAmsErrorV1,
}
/// Stable trusted-state failure detected before native X.509 proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyZkX509StateFailureCodeV1 {
    /// The submit path did not supply the fully joined authoritative snapshot.
    MissingTrustedState,
    /// Statement revisions, roots, predicates, or trusted time differ from state.
    AuthoritativeStateMismatch,
    /// The exact policy-scoped certificate nullifier was already consumed.
    DuplicateCertificateNullifier,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted X.509 state failed validation: {code:?}")]
pub struct PrivacyZkX509StateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyZkX509StateFailureCodeV1,
}
#[derive(Debug, Error)]
#[cfg_attr(
    not(any(test, feature = "privacy-release-evidence")),
    derive(Clone, Copy)
)]
#[error("native X.509 verification failed: {source}")]
pub struct PrivacyZkX509VerificationFailureV1 {
    source: ZkX509EngineErrorV1,
}
/// Stable trusted-state failure detected before or after native Orchard proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyOrchardStateFailureCodeV1 {
    /// The submit path did not supply a trusted pool snapshot.
    MissingTrustedState,
    /// Trusted state belongs to another protocol/pool namespace.
    NamespaceMismatch,
    /// The statement selected a different public asset.
    AssetMismatch,
    /// The statement selected a different transparent reserve partition.
    PublicBalanceScopeMismatch,
    /// The statement anchor is not in the exact retained root window.
    AnchorNotRetained,
    /// The current block is later than the statement expiry.
    Expired,
    /// The public value balance cannot be represented by the native API.
    ValueBalanceOutOfRange,
    /// A fixed-width Orchard ciphertext did not retain its canonical width.
    CiphertextWidth,
    /// The authoritative compact frontier could not derive a successor.
    SuccessorDerivation,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted Orchard state failed validation: {code:?}")]
pub struct PrivacyOrchardStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyOrchardStateFailureCodeV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native Orchard verification failed: {source}")]
pub struct PrivacyOrchardVerificationFailureV1 {
    source: OrchardNativeErrorV1,
}
/// Stable trusted-state failure detected before native FCMP++ verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyFcmpStateFailureCodeV1 {
    /// The submit path did not supply a trusted pool snapshot.
    MissingTrustedState,
    /// Trusted state belongs to another protocol/pool namespace.
    NamespaceMismatch,
    /// Trusted bootstrap protocol or root role is not FCMP++ output-set state.
    ProtocolOrRoleMismatch,
    /// The statement selected a different public asset.
    AssetMismatch,
    /// The trusted snapshot has no FCMP++ curve frontier.
    MissingCurveFrontier,
    /// The curve frontier differs from the authoritative head or output count.
    FrontierMismatch,
    /// The authoritative current head is absent from retained history.
    CurrentRootNotRetained,
    /// The exact statement epoch/root pair is absent from retained history.
    AnchorNotRetained,
    /// The full typed current Selene/Helios root differs despite the same
    /// authoritative current history key.
    CurrentTypedRootMismatch,
    /// Complete output tuples could not derive a canonical successor frontier.
    SuccessorDerivation,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted FCMP++ state failed validation: {code:?}")]
pub struct PrivacyFcmpStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyFcmpStateFailureCodeV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native FCMP++ verification failed: {source}")]
pub struct PrivacyFcmpVerificationFailureV1 {
    source: FcmpNativeErrorV1,
}
/// Stable trusted-state failure detected before private-IVM proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyIvmPrivateNoteStateFailureCodeV1 {
    /// The submit path did not supply a trusted pool snapshot.
    MissingTrustedState,
    /// Trusted state belongs to another pool/program namespace.
    NamespaceMismatch,
    /// Trusted bootstrap protocol or root role is not private-IVM state.
    ProtocolOrRoleMismatch,
    /// The statement selected a different public asset.
    AssetMismatch,
    /// The statement selected a different transparent reserve partition.
    PublicBalanceScopeMismatch,
    /// The statement selected a different governed private program.
    ProgramMismatch,
    /// The trusted snapshot has no SHA-256 note frontier.
    MissingNoteFrontier,
    /// The note frontier differs from the authoritative head or output count.
    FrontierMismatch,
    /// The authoritative current head is absent from retained history.
    CurrentRootNotRetained,
    /// The exact statement epoch/root pair is absent from retained history.
    AnchorNotRetained,
    /// New note commitments could not derive a canonical successor frontier.
    SuccessorDerivation,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted private-IVM state failed validation: {code:?}")]
pub struct PrivacyIvmPrivateNoteStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyIvmPrivateNoteStateFailureCodeV1,
}
/// Native private-IVM failure boundary.
#[derive(Debug, Error, Clone, Copy)]
pub enum PrivacyIvmPrivateNoteNativeFailureSourceV1 {
    /// The fixed authenticated ciphertext shape or public binding is invalid.
    #[error("ciphertext validation failed: {0}")]
    Ciphertext(IvmPrivateNoteWalletErrorV1),
    /// The trusted chain/genesis/profile binding was invalid.
    #[error("consensus binding validation failed: {0}")]
    ConsensusBinding(PrivacyNativeConsensusBindingValidationErrorV1),
    /// The exact STARK proof failed verification.
    #[error("proof verification failed: {0}")]
    Proof(ProofManagedNoteStarkErrorV1),
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native private-IVM verification failed: {source}")]
pub struct PrivacyIvmPrivateNoteVerificationFailureV1 {
    source: PrivacyIvmPrivateNoteNativeFailureSourceV1,
}
/// Stable trusted-state failure detected before PQ-MASP authorization and proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyPqMaspStateFailureCodeV1 {
    /// The submit path did not supply a trusted pool snapshot.
    MissingTrustedState,
    /// Trusted state belongs to another pool namespace.
    NamespaceMismatch,
    /// Trusted bootstrap protocol or root role is not PQ-MASP note state.
    ProtocolOrRoleMismatch,
    /// The statement selected a different public asset.
    AssetMismatch,
    /// The trusted snapshot has no SHA-256 note frontier.
    MissingNoteFrontier,
    /// The note frontier differs from the authoritative head or output count.
    FrontierMismatch,
    /// The authoritative current head is absent from retained history.
    CurrentRootNotRetained,
    /// The exact statement epoch/root pair is absent from retained history.
    AnchorNotRetained,
    /// New note commitments could not derive a canonical successor frontier.
    SuccessorDerivation,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted PQ-MASP state failed validation: {code:?}")]
pub struct PrivacyPqMaspStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyPqMaspStateFailureCodeV1,
}
/// Native PQ-MASP failure boundary.
#[derive(Debug, Error, Clone, Copy)]
pub enum PrivacyPqMaspNativeFailureSourceV1 {
    /// Fixed ML-KEM/XChaCha ciphertext shape or ordered key binding is invalid.
    #[error("ciphertext validation failed: {0}")]
    Ciphertext(PqMaspWireErrorV1),
    /// The trusted chain/genesis/profile binding was invalid.
    #[error("consensus binding validation failed: {0}")]
    ConsensusBinding(PrivacyNativeConsensusBindingValidationErrorV1),
    /// The validated binding could not be canonically digested.
    #[error("consensus binding canonical encoding failed")]
    ConsensusBindingEncoding,
    /// The exact PQA1 ML-DSA-65 authorization wrapper failed verification.
    #[error("authorization verification failed: {0}")]
    Authorization(PqMaspWireErrorV1),
    /// The exact inner PQS1 STARK proof failed verification.
    #[error("proof verification failed: {0}")]
    Proof(ProofManagedNoteStarkErrorV1),
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native PQ-MASP verification failed: {source}")]
pub struct PrivacyPqMaspVerificationFailureV1 {
    source: PrivacyPqMaspNativeFailureSourceV1,
}
/// Stable trusted-state failure detected before or after native PGC proof verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyAnonymousPgcStateFailureCodeV1 {
    /// The submit path did not supply a trusted pool snapshot.
    MissingTrustedState,
    /// Trusted state belongs to another namespace.
    NamespaceMismatch,
    /// The statement does not reference the current persisted head.
    StaleHead,
    /// The current head has no exact retained-history record.
    CurrentRootNotRetained,
    /// The statement keys differ from the complete persisted account table.
    AccountTableMismatch,
    /// Persisted supply or bootstrap audit digests are invalid.
    InvalidPoolInvariant,
    /// The current account table could not be hashed canonically.
    CurrentRootRecomputationFailed,
    /// The recomputed current account root differs from the persisted head.
    CurrentRootMismatch,
    /// Native verification returned a non-complete successor table.
    SuccessorTableMismatch,
    /// The successor account table could not be hashed canonically.
    NextRootRecomputationFailed,
    /// The recomputed successor root differs from the statement.
    NextRootMismatch,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted Anonymous-PGC state failed validation: {code:?}")]
pub struct PrivacyAnonymousPgcStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyAnonymousPgcStateFailureCodeV1,
}
/// Stable trusted-state failure for a Bootle/Lantern presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum PrivacyBootleLanternStateFailureCodeV1 {
    /// The submit path did not resolve the statement-selected policy.
    MissingTrustedPolicy,
    /// Persisted policy bytes failed canonical intrinsic validation.
    InvalidTrustedPolicy,
    /// The selected policy lineage is terminal-revoked.
    PolicyRevoked,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("trusted Bootle/Lantern issuer policy failed validation: {code:?}")]
pub struct PrivacyBootleLanternStateFailureV1 {
    /// Exact stable failure category.
    pub code: PrivacyBootleLanternStateFailureCodeV1,
}
#[derive(Debug, Error, Clone, Copy)]
pub enum PrivacyBootleLanternNativeFailureSourceV1 {
    /// The complete native relation is deliberately fail-closed.
    #[error("complete native engine is unavailable")]
    EngineUnavailable,
    /// The typed statement could not be canonically hashed for transcript binding.
    #[error("statement digest construction failed")]
    StatementDigest,
    /// Trusted record and statement could not compile one canonical relation.
    #[error("relation compilation failed: {0}")]
    Relation(RelationErrorV1),
    /// Transparent setup or transcript binding failed.
    #[error("transcript construction failed: {0}")]
    Transcript(TranscriptErrorV1),
    /// Proof bytes were not the one canonical fixed-width wire value.
    #[error("proof decoding failed: {0}")]
    Codec(ProofCodecErrorV1),
    /// Native Lantern/LNP22 proof verification failed.
    #[error("proof verification failed: {0}")]
    Proof(PresentationProofErrorV1),
}
#[derive(Debug, Error, Clone, Copy)]
#[error("native Bootle/Lantern verification failed: {source}")]
pub struct PrivacyBootleLanternVerificationFailureV1 {
    source: PrivacyBootleLanternNativeFailureSourceV1,
}
#[derive(Debug, Error, Clone, Copy)]
#[error("canonical privacy envelope encoding failed")]
pub struct PrivacyCanonicalEncodingFailureV1;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub use test_fixtures::{
    FcmpRuntimeFixtureForTest, ZkAmsRuntimeFixtureForTest, fcmp_runtime_fixture_for_test,
    zk_ams_runtime_fixture_for_test,
};
#[cfg(test)]
mod tests {
    type FcmpStatementMutation = (&'static str, fn(&mut MoneroFcmpPlusPlusStatementV1));
    use super::test_fixtures::*;
    use super::*;
    use crate::{
        privacy_engines::{
            anonymous_pgc::{
                TwistedElGamalKeyPairV1, add_ciphertexts, encrypt_with_randomness,
                payment::{
                    AnonymousPgcPaymentWitnessV1, encrypt_signed_with_randomness, prove_payment,
                },
            },
            bootle_lantern::{
                codec::PROOF_BYTES_V1 as BOOTLE_LANTERN_PROOF_BYTES_V1,
                issuer::{
                    BootleLanternInMemoryIssuanceStoreV1, BootleLanternIssuerKeyPairV1,
                    BootleLanternIssuerPolicyMetadataV1, holder_finalize_blind_issuance_v1,
                    holder_prepare_blind_issuance_with_rng_v1,
                    issuer_authorize_blind_issuance_with_rng_v1,
                    issuer_blind_issue_once_with_rng_v1,
                },
                prove_bound_presentation_v1,
            },
            fcmp_plus_plus::{build_fcmp_frontier_v1, fcmp_test_spendable_output_v1},
            ivm_private_note::private_note_statement_fixture_v1,
            jindo::{
                JINDO_NATIVE_PROOF_BYTES_V1, commit_polynomial_v1, evaluate_polynomial_v1,
                prove_batched_evaluation_v1,
            },
            orchard::tests::build_fixture as orchard_native_fixture,
            p256::SecretScalarV1,
            pq_masp::{
                relation::{
                    derive_pq_masp_note_commitment_v1,
                    derive_pq_masp_note_encryption_keys_digest_v1,
                    test_fixtures::valid_fixture as pq_masp_fixture,
                },
                wire::{
                    authorize_pq_masp_stark_proof_v1, derive_pq_masp_authorization_key_digest_v1,
                },
            },
            verange::{commit, prove_batch},
        },
        privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        asset::AssetDefinitionId,
        privacy::{
            BootleLanternAllowedAttributeValuesV1, BootleLanternAttributeValueV1,
            BootleLanternDisclosedAttributeV1, IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1,
            PrivacyActiveLifecycleV1, PrivacyBootleLanternIssuerPolicyDigestV1,
            PrivacyEncryptionKeyV1, PrivacyEngineIdV1, PrivacyFcmpInputPublicV1,
            PrivacyFcmpKeyImageV1, PrivacyFcmpPoolBootstrapV1, PrivacyFcmpTreeRootV1,
            PrivacyIssuerIdV1, PrivacyIvmPrivateNotePoolBootstrapV1, PrivacyJindoFieldElementV1,
            PrivacyNamespaceScopeV1, PrivacyNoteEncryptionKeyDigestV1, PrivacyOrchardActionV1,
            PrivacyP256PointV1, PrivacyParameterIdV1, PrivacyPgcAccountBootstrapDigestV1,
            PrivacyPgcBootstrapProofDigestV1, PrivacyPolicyIdV1, PrivacyPoolIdV1,
            PrivacyPoolNamespaceV1, PrivacyPqMaspPoolBootstrapV1,
            PrivacyProofManagedPoolBootstrapV1, PrivacyProofSystemIdV1, PrivacyProofV1,
            PrivacyProposedLifecycleV1, PrivacyProtocolLifecycleV1, PrivacyRecipientIdV1,
            PrivacyStatementContextV1, PrivacyStatementValidationError,
            PrivacyTransactionIntentDigestV1, PrivacyValueBalanceDirectionV1,
            PrivacyValueBalanceV1, VeRangeTransparentRangeStatementV1,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use soranet_pq::{HedgedRngSeed, MlDsaSuite, generate_mldsa_keypair_from_seed};
    use std::{str::FromStr as _, sync::OnceLock};
    const TEST_CONSENSUS_LIMITS: PrivacyConsensusLimitsV1 =
        PrivacyConsensusLimitsV1::taira_default();
    fn secret(value: u8) -> SecretScalarV1 {
        let mut bytes = [0; 32];
        bytes[31] = value;
        SecretScalarV1::from_bytes(bytes).expect("canonical non-zero scalar")
    }
    fn active_profile() -> (CompiledPrivacyProfileV1, PrivacyProtocolActivationRecordV1) {
        let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("compiled VeRange");
        let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
            PrivacyActiveLifecycleV1 {
                proposed_at_height: 1,
                activated_at_height: 2,
                state_since_height: 2,
            },
        ));
        (profile, activation)
    }
    fn valid_envelope() -> (
        PrivacyProofEnvelopeV1,
        PrivacyProtocolActivationRecordV1,
        NetworkId,
    ) {
        let (compiled, activation) = active_profile();
        let network_id = network_id(0xA7);
        let native_profile = VeRangeBitLengthV1::Bits32;
        let values = [7_u64, 19_u64];
        let blindings = [secret(3), secret(5)];
        let native_commitments = values
            .iter()
            .zip(&blindings)
            .map(|(value, blinding)| {
                commit(native_profile, *value, blinding).expect("valid commitment")
            })
            .collect::<Vec<_>>();
        let value_commitments = native_commitments
            .iter()
            .map(|point| PrivacyP256PointV1::new(*point.as_bytes()))
            .collect();
        let context = PrivacyStatementContextV1 {
            network_id,
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xD1; 32]),
            parameter_id: compiled.parameter_id,
            parameter_digest: compiled.parameter_digest,
            verifier_digest: compiled.verifier_digest,
            statement_schema_digest: compiled.statement_schema_digest,
            engine_manifest_digest: compiled.engine_manifest_digest,
        };
        let statement =
            PrivacyStatementV1::VeRangeTransparentRangeV1(VeRangeTransparentRangeStatementV1 {
                context,
                asset_definition_id: AssetDefinitionId::derive_from_components(
                    DomainId::try_new("privacy", "universal").expect("domain"),
                    Name::from_str("asset").expect("name"),
                ),
                policy_id: PrivacyPolicyIdV1::new([0x91; 32]),
                value_commitments,
                bit_length: PrivacyVeRangeBitLengthV1::Bits32,
                aggregation_count: 2,
            });
        let statement_digest = statement.digest().expect("statement digest");
        let parameters =
            VeRangeParametersV1::for_profile(native_profile).expect("VeRange parameters");
        let transcript = TranscriptBindingV1 {
            network_id: network_id.as_bytes(),
            genesis_hash: *network_id.as_bytes(),
            action_index: 0,
            statement_digest: *statement_digest.as_bytes(),
            parameter_id: *compiled.parameter_id.as_bytes(),
            parameter_digest: *compiled.parameter_digest.as_bytes(),
            verifier_digest: *compiled.verifier_digest.as_bytes(),
            statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
            engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
            generator_digest: parameters.generator_digest(),
        };
        let native_statement =
            VeRangeType1BatchStatementV1::new(native_profile, native_commitments, transcript)
                .expect("native statement");
        let proof = prove_batch(
            &native_statement,
            &values,
            &blindings,
            &mut KatRng::new([0x62; 32]),
        )
        .expect("proof")
        .encode();
        (
            PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest,
                statement,
                proof: PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(proof)),
            },
            activation,
            network_id,
        )
    }
    fn jindo_field(value: u64) -> PrivacyJindoFieldElementV1 {
        let mut encoding = [0_u8; 32];
        encoding[..8].copy_from_slice(&value.to_le_bytes());
        PrivacyJindoFieldElementV1::new(encoding)
    }
    struct JindoFixture {
        envelope: PrivacyProofEnvelopeV1,
        activation: PrivacyProtocolActivationRecordV1,
        network_id: NetworkId,
    }
    impl JindoFixture {
        fn new() -> Self {
            let compiled =
                compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
                    .expect("compiled Jindo");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let polynomials = vec![
                vec![
                    jindo_field(3),
                    jindo_field(5),
                    jindo_field(7),
                    jindo_field(11),
                ],
                vec![jindo_field(13), jindo_field(17)],
                vec![jindo_field(19), jindo_field(23)],
                vec![jindo_field(29), jindo_field(31)],
            ];
            let evaluation_point = jindo_field(13);
            let claimed_evaluations = polynomials
                .iter()
                .map(|polynomial| {
                    evaluate_polynomial_v1(polynomial, evaluation_point)
                        .expect("canonical Jindo evaluation")
                })
                .collect();
            let mut commitment_rng = KatRng::new([0x6a; 32]);
            let (polynomial_commitments, openings): (Vec<_>, Vec<_>) = polynomials
                .iter()
                .map(|polynomial| {
                    commit_polynomial_v1(polynomial, &mut commitment_rng).expect("Jindo commitment")
                })
                .unzip();
            let statement = IrohaJindoPolynomialCommitmentStatementV1 {
                context: PrivacyStatementContextV1 {
                    network_id,
                    action_index: 0,
                    transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xd2; 32]),
                    parameter_id: compiled.parameter_id,
                    parameter_digest: compiled.parameter_digest,
                    verifier_digest: compiled.verifier_digest,
                    statement_schema_digest: compiled.statement_schema_digest,
                    engine_manifest_digest: compiled.engine_manifest_digest,
                },
                polynomial_commitments,
                evaluation_point,
                claimed_evaluations,
            };
            let typed_statement =
                PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement.clone());
            let statement_digest = typed_statement.digest().expect("Jindo statement digest");
            let transcript = TranscriptBindingV1 {
                network_id: network_id.as_bytes(),
                genesis_hash: [0xa7; 32],
                action_index: 0,
                statement_digest: *statement_digest.as_bytes(),
                parameter_id: *compiled.parameter_id.as_bytes(),
                parameter_digest: *compiled.parameter_digest.as_bytes(),
                verifier_digest: *compiled.verifier_digest.as_bytes(),
                statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                generator_digest: jindo_crs_digest_v1(),
            };
            let proof =
                prove_batched_evaluation_v1(&statement, &polynomials, &openings, &transcript)
                    .expect("Jindo proof");
            assert_eq!(proof.len(), JINDO_NATIVE_PROOF_BYTES_V1);
            Self {
                envelope: PrivacyProofEnvelopeV1 {
                    wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                    catalog_commitment:
                        iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                    protocol_id: compiled.protocol_id,
                    proof_system_id: compiled.proof_system_id,
                    engine_id: compiled.engine_id,
                    parameter_id: compiled.parameter_id,
                    parameter_digest: compiled.parameter_digest,
                    verifier_digest: compiled.verifier_digest,
                    statement_schema_digest: compiled.statement_schema_digest,
                    engine_manifest_digest: compiled.engine_manifest_digest,
                    statement_digest,
                    statement: typed_statement,
                    proof: PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(
                        PrivacyProofBytesV1::new(proof),
                    ),
                },
                activation,
                network_id,
            }
        }
        fn verification_context<'a>(
            &'a self,
            consensus_limits: &'a PrivacyConsensusLimitsV1,
        ) -> PrivacyVerificationContextV1<'a> {
            PrivacyVerificationContextV1 {
                activation: &self.activation,
                consensus_limits,
                network_id: &self.network_id,
                genesis_hash: [0xa7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: None,
                orchard_state: None,
                proof_managed_state: None,
                zk_x509_state: None,
                bootle_lantern_policy: None,
                vega_issuer_record: None,
            }
        }
    }
    fn jindo_fixture() -> &'static JindoFixture {
        static FIXTURE: OnceLock<JindoFixture> = OnceLock::new();
        FIXTURE.get_or_init(JindoFixture::new)
    }
    struct BootleLanternFixture {
        envelope: PrivacyProofEnvelopeV1,
        activation: PrivacyProtocolActivationRecordV1,
        network_id: NetworkId,
        policy: BootleLanternIssuerPolicyV1,
    }
    impl BootleLanternFixture {
        fn new() -> Self {
            let compiled =
                compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1)
                    .expect("compiled Bootle/Lantern");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let genesis_hash = [0xA7; 32];
            let context = PrivacyStatementContextV1 {
                network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xB4; 32]),
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
            };
            let mut keygen_rng = KatRng::new([0xB3; 32]);
            let issuer_key_pair = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                PrivacyParameterIdV1::new([0xB3; 32]),
                &mut keygen_rng,
            )
            .expect("native issuer key generation");
            let policy = issuer_key_pair
                .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
                    issuer_id: PrivacyIssuerIdV1::new([0xB1; 32]),
                    policy_id: PrivacyPolicyIdV1::new([0xB2; 32]),
                    epoch: 1,
                    required_disclosure_bitmap: 0b0000_0010,
                    allowed_values: (0..8)
                        .map(|index| BootleLanternAllowedAttributeValuesV1 {
                            values: if index == 1 {
                                vec![BootleLanternAttributeValueV1::new([1; 8])]
                            } else {
                                Vec::new()
                            },
                        })
                        .collect(),
                })
                .expect("canonical initial native issuer policy");
            let issuance_store = BootleLanternInMemoryIssuanceStoreV1::new();
            let mut authorization_rng = KatRng::new([0xB9; 32]);
            let authorization = issuer_authorize_blind_issuance_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                [0xBA; 32],
                10,
                20,
                &issuance_store,
                &mut authorization_rng,
            )
            .expect("issuer one-shot authorization");
            let mut attributes = [[0_u8; 8]; 8];
            attributes[1] = [1; 8];
            let mut holder_issuance_rng = KatRng::new([0xB4; 32]);
            let (issuance_request, issuance_state) = holder_prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes,
                &mut holder_issuance_rng,
            )
            .expect("holder blind-issuance request");
            let mut issuer_issuance_rng = KatRng::new([0xB6; 32]);
            let issuance_response = issuer_blind_issue_once_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                &authorization,
                &issuance_request,
                10,
                &issuance_store,
                &mut issuer_issuance_rng,
            )
            .expect("native blind issuance");
            let credential = holder_finalize_blind_issuance_v1(
                issuance_state,
                &context,
                genesis_hash,
                &policy,
                issuance_response,
            )
            .expect("holder issuance finalization");
            let statement = IrohaBootleLanternAnoncredStatementV1 {
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
            };
            let typed_statement =
                PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone());
            let statement_digest = typed_statement
                .digest()
                .expect("Bootle/Lantern statement digest");
            let witness = credential
                .presentation_witness_v1(&statement, &policy, genesis_hash)
                .expect("issued Bootle/Lantern witness");
            let proof = prove_bound_presentation_v1(
                &statement,
                &policy,
                genesis_hash,
                &witness,
                &mut KatRng::new([0xB8; 32]),
            )
            .expect("Bootle/Lantern proof")
            .encode();
            assert_eq!(proof.len(), BOOTLE_LANTERN_PROOF_BYTES_V1);
            Self {
                envelope: PrivacyProofEnvelopeV1 {
                    wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                    catalog_commitment:
                        iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                    protocol_id: compiled.protocol_id,
                    proof_system_id: compiled.proof_system_id,
                    engine_id: compiled.engine_id,
                    parameter_id: compiled.parameter_id,
                    parameter_digest: compiled.parameter_digest,
                    verifier_digest: compiled.verifier_digest,
                    statement_schema_digest: compiled.statement_schema_digest,
                    engine_manifest_digest: compiled.engine_manifest_digest,
                    statement_digest,
                    statement: typed_statement,
                    proof: PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(
                        proof,
                    )),
                },
                activation,
                network_id,
                policy,
            }
        }
        fn verification_context<'a>(
            &'a self,
            consensus_limits: &'a PrivacyConsensusLimitsV1,
        ) -> PrivacyVerificationContextV1<'a> {
            PrivacyVerificationContextV1 {
                activation: &self.activation,
                consensus_limits,
                network_id: &self.network_id,
                genesis_hash: [0xA7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: None,
                orchard_state: None,
                proof_managed_state: None,
                zk_x509_state: None,
                bootle_lantern_policy: Some(&self.policy),
                vega_issuer_record: None,
            }
        }
    }
    fn bootle_lantern_fixture() -> &'static BootleLanternFixture {
        static FIXTURE: OnceLock<BootleLanternFixture> = OnceLock::new();
        FIXTURE.get_or_init(BootleLanternFixture::new)
    }
    fn bootle_lantern_statement_mut(
        envelope: &mut PrivacyProofEnvelopeV1,
    ) -> &mut IrohaBootleLanternAnoncredStatementV1 {
        let PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) = &mut envelope.statement
        else {
            unreachable!("Bootle/Lantern fixture")
        };
        statement
    }
    fn redigest_bootle_lantern_policy(policy: &mut BootleLanternIssuerPolicyV1) {
        policy.issuer_parameter_digest = policy
            .computed_issuer_parameter_digest()
            .expect("issuer parameter digest");
        policy.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        policy.record_digest = policy.computed_record_digest().expect("policy digest");
    }
    struct OrchardFixture {
        envelope: PrivacyProofEnvelopeV1,
        activation: PrivacyProtocolActivationRecordV1,
        network_id: NetworkId,
        namespace: PrivacyNamespaceV1,
        snapshot: PrivacyOrchardPoolSnapshotV1,
    }
    impl OrchardFixture {
        fn new() -> Self {
            let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
                .expect("compiled Orchard");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let pool_id = PrivacyPoolIdV1::new([0xB6; 32]);
            let namespace = PrivacyNamespaceV1::new(
                PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
                PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 { pool_id }),
            );
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("orchard_asset").expect("name"),
            );
            let reserve_key = KeyPair::try_from_seed(vec![0xB7; 32], Algorithm::Ed25519)
                .expect("reserve keypair");
            let snapshot = PrivacyOrchardPoolSnapshotV1::canonical_bootstrap_for_test(
                namespace,
                asset_definition_id.clone(),
                AssetBalanceScope::Global,
                AccountId::new(reserve_key.public_key().clone()),
            );
            let statement_context = PrivacyStatementContextV1 {
                network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x44; 32]),
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
            };
            let consensus_binding = PrivacyNativeConsensusBindingV1::new(
                &statement_context,
                [0xA7; 32],
                &TEST_CONSENSUS_LIMITS,
            )
            .expect("canonical Orchard runtime consensus binding");
            let (public, authorization) = orchard_native_fixture(1, [0xA7; 32], consensus_binding);
            assert_eq!(
                public.anchor,
                snapshot.current_root().into_bytes(),
                "native fixture uses the canonical empty Orchard anchor"
            );
            let value_balance = match public.value_balance.cmp(&0) {
                core::cmp::Ordering::Equal => PrivacyValueBalanceV1::balanced(),
                core::cmp::Ordering::Less => PrivacyValueBalanceV1 {
                    direction: PrivacyValueBalanceDirectionV1::IntoPool,
                    amount: u128::from(public.value_balance.unsigned_abs()),
                },
                core::cmp::Ordering::Greater => PrivacyValueBalanceV1 {
                    direction: PrivacyValueBalanceDirectionV1::OutOfPool,
                    amount: u128::from(public.value_balance.unsigned_abs()),
                },
            };
            let statement =
                PrivacyStatementV1::OrchardHalo2ActionsV1(OrchardHalo2ActionsStatementV1 {
                    context: statement_context,
                    asset_definition_id,
                    public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
                    pool_id,
                    anchor: snapshot.current_root(),
                    anchor_epoch: snapshot.current_epoch(),
                    actions: public
                        .actions
                        .iter()
                        .map(|action| PrivacyOrchardActionV1 {
                            nullifier: action.nullifier,
                            randomized_key: action.randomized_key,
                            note_commitment: action.note_commitment,
                            ephemeral_key: action.ephemeral_key,
                            encrypted_note: action.encrypted_note.to_vec(),
                            outgoing_ciphertext: action.outgoing_ciphertext.to_vec(),
                            value_commitment: action.value_commitment,
                        })
                        .collect(),
                    value_balance,
                    expiry_height: 100,
                });
            let statement_digest = statement.digest().expect("Orchard statement digest");
            let envelope = PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest,
                statement,
                proof: PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(
                    authorization.clone(),
                )),
            };
            Self {
                envelope,
                activation,
                network_id,
                namespace,
                snapshot,
            }
        }
        fn verification_context(&self) -> PrivacyVerificationContextV1<'_> {
            PrivacyVerificationContextV1 {
                activation: &self.activation,
                consensus_limits: &TEST_CONSENSUS_LIMITS,
                network_id: &self.network_id,
                genesis_hash: [0xA7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: None,
                orchard_state: Some(&self.snapshot),
                proof_managed_state: None,
                zk_x509_state: None,
                bootle_lantern_policy: None,
                vega_issuer_record: None,
            }
        }
    }
    fn orchard_fixture() -> &'static OrchardFixture {
        static FIXTURE: OnceLock<OrchardFixture> = OnceLock::new();
        FIXTURE.get_or_init(OrchardFixture::new)
    }
    fn orchard_statement_mut(
        envelope: &mut PrivacyProofEnvelopeV1,
    ) -> &mut OrchardHalo2ActionsStatementV1 {
        let PrivacyStatementV1::OrchardHalo2ActionsV1(statement) = &mut envelope.statement else {
            unreachable!("Orchard fixture")
        };
        statement
    }
    struct IvmPrivateNotePreflightFixture {
        statement: IrohaIvmPrivateNoteStarkStatementV1,
        snapshot: PrivacyProofManagedPoolSnapshotV1,
        input_commitment: PrivacyCommitmentV1,
        reserve_account: AccountId,
    }
    impl IvmPrivateNotePreflightFixture {
        fn new() -> Self {
            let (mut statement, input_commitment) = private_note_statement_fixture_v1();
            let reserve_key = KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519)
                .expect("private-IVM reserve keypair");
            let reserve_account = AccountId::new(reserve_key.public_key().clone());
            let bootstrap = PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
                PrivacyIvmPrivateNotePoolBootstrapV1 {
                    pool_id: statement.pool_id,
                    asset_definition_id: statement.asset_definition_id.clone(),
                    public_balance_scope: statement.public_balance_scope,
                    reserve_account: reserve_account.clone(),
                    program_id: statement.program_id,
                    initial_note_commitments: vec![input_commitment],
                },
            );
            let snapshot =
                PrivacyProofManagedPoolSnapshotV1::canonical_private_note_bootstrap_for_test(
                    bootstrap,
                );
            statement.state_root = snapshot.current_root();
            statement.root_epoch = snapshot.current_epoch();
            statement.execution_epoch = snapshot.current_epoch();
            statement.action_digest =
                iroha_data_model::privacy::PrivacyActionDigestV1::new([0; 32]);
            statement.action_digest = statement
                .computed_action_digest()
                .expect("canonical private-IVM action digest");
            Self {
                statement,
                snapshot,
                input_commitment,
                reserve_account,
            }
        }
        fn expected_namespace(&self) -> PrivacyNamespaceV1 {
            PrivacyNamespaceV1::from_statement(&PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(
                self.statement.clone(),
            ))
        }
    }
    struct PqMaspPreflightFixture {
        statement: PqMaspStarkStatementV1,
        snapshot: PrivacyProofManagedPoolSnapshotV1,
        input_commitment: PrivacyCommitmentV1,
    }
    impl PqMaspPreflightFixture {
        fn new() -> Self {
            let (statement, witness) = pq_masp_fixture();
            let input_commitment =
                derive_pq_masp_note_commitment_v1(&statement, &witness.inputs[0].note)
                    .expect("canonical PQ-MASP input commitment");
            let snapshot = PrivacyProofManagedPoolSnapshotV1::canonical_pq_masp_bootstrap_for_test(
                PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(PrivacyPqMaspPoolBootstrapV1 {
                    pool_id: statement.pool_id,
                    asset_definition_id: statement.asset_definition_id.clone(),
                    initial_note_commitments: vec![input_commitment],
                }),
            );
            assert_eq!(statement.anchor, snapshot.current_root());
            assert_eq!(statement.anchor_epoch, snapshot.current_epoch());
            Self {
                statement,
                snapshot,
                input_commitment,
            }
        }
        fn expected_namespace(&self) -> PrivacyNamespaceV1 {
            PrivacyNamespaceV1::from_statement(&PrivacyStatementV1::PqMaspStarkV1(
                self.statement.clone(),
            ))
        }
        fn envelope(statement: &PqMaspStarkStatementV1, proof: Vec<u8>) -> PrivacyProofEnvelopeV1 {
            let typed_statement = PrivacyStatementV1::PqMaspStarkV1(statement.clone());
            let statement_digest = typed_statement.digest().expect("PQ-MASP statement digest");
            PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: PrivacyProtocolIdV1::PqMaspStarkV1,
                proof_system_id: PrivacyProofSystemIdV1::StarkFriSha3_384Goldilocks,
                engine_id: PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri,
                parameter_id: statement.context.parameter_id,
                parameter_digest: statement.context.parameter_digest,
                verifier_digest: statement.context.verifier_digest,
                statement_schema_digest: statement.context.statement_schema_digest,
                engine_manifest_digest: statement.context.engine_manifest_digest,
                statement_digest,
                statement: typed_statement,
                proof: PrivacyProofV1::PqMaspStarkV1(PrivacyProofBytesV1::new(proof)),
            }
        }
    }
    fn fcmp_statement_mut(
        envelope: &mut PrivacyProofEnvelopeV1,
    ) -> &mut MoneroFcmpPlusPlusStatementV1 {
        let PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) = &mut envelope.statement else {
            unreachable!("FCMP++ fixture")
        };
        statement
    }
    struct PgcFixture {
        envelope: PrivacyProofEnvelopeV1,
        activation: PrivacyProtocolActivationRecordV1,
        network_id: NetworkId,
        namespace: PrivacyNamespaceV1,
        total_supply: u32,
        bootstrap_digest: PrivacyPgcAccountBootstrapDigestV1,
        bootstrap_proof_digest: PrivacyPgcBootstrapProofDigestV1,
        current_root: PrivacyRootV1,
        current_epoch: u64,
        accounts: Vec<PrivacyPgcAccountV1>,
    }
    impl PgcFixture {
        fn new() -> Self {
            Self::with_declared_transition(None, None)
        }
        fn with_declared_transition(
            next_root_override: Option<PrivacyRootV1>,
            next_epoch_override: Option<u64>,
        ) -> Self {
            let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
                .expect("compiled Anonymous PGC");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let pool_id = PrivacyPoolIdV1::new([0xb1; 32]);
            let namespace = PrivacyNamespaceV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 { pool_id }),
            );
            let total_supply = 1_600;
            let bootstrap_digest = PrivacyPgcAccountBootstrapDigestV1::new([0xb2; 32]);
            let bootstrap_proof_digest = PrivacyPgcBootstrapProofDigestV1::new([0xb3; 32]);
            let current_epoch = 1;
            let mut key_pairs = (2_u8..18)
                .map(|value| {
                    TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("PGC key pair")
                })
                .collect::<Vec<_>>();
            key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
            let public_keys = key_pairs
                .iter()
                .map(TwistedElGamalKeyPairV1::public_key)
                .collect::<Vec<_>>();
            let public_key_wires = public_keys
                .iter()
                .map(|key| PrivacyP256PointV1::new(*key.as_point().as_bytes()))
                .collect::<Vec<_>>();
            let current_randomness = (0_u8..16)
                .map(|index| secret(100 + index))
                .collect::<Vec<_>>();
            let current_ciphertexts = public_keys
                .iter()
                .copied()
                .zip(&current_randomness)
                .map(|(key, randomness)| {
                    encrypt_with_randomness(key, 100, randomness).expect("current balance")
                })
                .collect::<Vec<_>>();
            let accounts = public_key_wires
                .iter()
                .copied()
                .zip(current_ciphertexts.iter().copied())
                .map(|(public_key, encrypted_balance)| PrivacyPgcAccountV1 {
                    public_key,
                    encrypted_balance: pgc_ciphertext_wire(encrypted_balance),
                })
                .collect::<Vec<_>>();
            let current_root = derive_privacy_pgc_account_state_root_v1(
                namespace,
                current_epoch,
                total_supply,
                &accounts,
            )
            .expect("current account root");
            let sender_index = 7;
            let recipient_count = 2;
            let mut transfer_values = vec![0_i64; 16];
            transfer_values[2] = 20;
            transfer_values[12] = 30;
            transfer_values[sender_index] = -50;
            let transfer_randomness = (0_u8..16)
                .map(|index| secret(40 + index))
                .collect::<Vec<_>>();
            let transfer_ciphertexts = public_keys
                .iter()
                .copied()
                .zip(&transfer_values)
                .zip(&transfer_randomness)
                .map(|((key, value), randomness)| {
                    encrypt_signed_with_randomness(key, *value, randomness)
                        .expect("transfer ciphertext")
                })
                .collect::<Vec<_>>();
            let next_accounts = public_key_wires
                .iter()
                .copied()
                .zip(
                    current_ciphertexts
                        .iter()
                        .copied()
                        .zip(transfer_ciphertexts.iter().copied())
                        .map(|(current, transfer)| {
                            add_ciphertexts(current, transfer).expect("successor ciphertext")
                        }),
                )
                .map(|(public_key, encrypted_balance)| PrivacyPgcAccountV1 {
                    public_key,
                    encrypted_balance: pgc_ciphertext_wire(encrypted_balance),
                })
                .collect::<Vec<_>>();
            let next_epoch = current_epoch + 1;
            let next_root = derive_privacy_pgc_account_state_root_v1(
                namespace,
                next_epoch,
                total_supply,
                &next_accounts,
            )
            .expect("next account root");
            let declared_next_root = next_root_override.unwrap_or(next_root);
            let declared_next_epoch = next_epoch_override.unwrap_or(next_epoch);
            let statement_context = PrivacyStatementContextV1 {
                network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xD2; 32]),
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
            };
            let statement =
                PrivacyStatementV1::AnonymousPgcKOutOfNV1(AnonymousPgcKOutOfNStatementV1 {
                    context: statement_context,
                    asset_definition_id: AssetDefinitionId::derive_from_components(
                        DomainId::try_new("privacy", "universal").expect("domain"),
                        Name::from_str("asset").expect("name"),
                    ),
                    pool_id,
                    account_state_root: current_root,
                    account_state_root_epoch: current_epoch,
                    next_account_state_root: declared_next_root,
                    next_account_state_root_epoch: declared_next_epoch,
                    anonymity_set_public_keys: public_key_wires,
                    transfer_ciphertexts: transfer_ciphertexts
                        .iter()
                        .copied()
                        .map(pgc_ciphertext_wire)
                        .collect(),
                    recipient_count,
                });
            let statement_digest = statement.digest().expect("PGC statement digest");
            let parameters = AnonymousPgcParametersV1::get().expect("PGC parameters");
            let transcript = TranscriptBindingV1 {
                network_id: network_id.as_bytes(),
                genesis_hash: [0xa7; 32],
                action_index: 0,
                statement_digest: *statement_digest.as_bytes(),
                parameter_id: *compiled.parameter_id.as_bytes(),
                parameter_digest: *compiled.parameter_digest.as_bytes(),
                verifier_digest: *compiled.verifier_digest.as_bytes(),
                statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                generator_digest: parameters.generator_digest(),
            };
            let native_invariant = AnonymousPgcPoolInvariantV1::new(
                total_supply,
                *bootstrap_digest.as_bytes(),
                *bootstrap_proof_digest.as_bytes(),
            )
            .expect("native invariant");
            let native_statement = AnonymousPgcPaymentStatementV1::new(
                &public_keys,
                &transfer_ciphertexts,
                &current_ciphertexts,
                usize::try_from(recipient_count).expect("recipient count"),
                native_invariant,
                transcript,
            )
            .expect("native PGC statement");
            let witness = AnonymousPgcPaymentWitnessV1 {
                transfer_values: &transfer_values,
                transfer_randomness: &transfer_randomness,
                sender_index,
                sender_secret: key_pairs[sender_index].secret_scalar(),
            };
            let proof = prove_payment(&native_statement, &witness, &mut KatRng::new([0xb4; 32]))
                .expect("PGC payment proof")
                .encode();
            let envelope = PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest,
                statement,
                proof: PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(proof)),
            };
            Self {
                envelope,
                activation,
                network_id,
                namespace,
                total_supply,
                bootstrap_digest,
                bootstrap_proof_digest,
                current_root,
                current_epoch,
                accounts,
            }
        }
        fn verification_context(&self) -> PrivacyVerificationContextV1<'_> {
            PrivacyVerificationContextV1 {
                activation: &self.activation,
                consensus_limits: &TEST_CONSENSUS_LIMITS,
                network_id: &self.network_id,
                genesis_hash: [0xa7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: Some(self.pgc_state(&self.accounts)),
                orchard_state: None,
                proof_managed_state: None,
                zk_x509_state: None,
                bootle_lantern_policy: None,
                vega_issuer_record: None,
            }
        }
        fn pgc_state<'a>(
            &self,
            accounts: &'a [PrivacyPgcAccountV1],
        ) -> PrivacyPgcVerificationStateV1<'a> {
            PrivacyPgcVerificationStateV1 {
                namespace: self.namespace,
                total_supply: self.total_supply,
                bootstrap_digest: self.bootstrap_digest,
                bootstrap_proof_digest: self.bootstrap_proof_digest,
                current_root: self.current_root,
                current_epoch: self.current_epoch,
                retained_current_root: Some((self.current_epoch, self.current_root)),
                accounts,
            }
        }
    }
    fn pgc_ciphertext_wire(ciphertext: TwistedElGamalCiphertextV1) -> PrivacyP256CiphertextV1 {
        PrivacyP256CiphertextV1 {
            left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
            right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
        }
    }
    fn verification_context<'a>(
        activation: &'a PrivacyProtocolActivationRecordV1,
        network_id: &'a NetworkId,
    ) -> PrivacyVerificationContextV1<'a> {
        PrivacyVerificationContextV1 {
            activation,
            consensus_limits: &TEST_CONSENSUS_LIMITS,
            network_id,
            genesis_hash: *network_id.as_bytes(),
            current_height: 10,
            expected_action_index: 0,
            block_timestamp_ms: 1_800_000_000_000,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        }
    }
    fn verange_statement_mut(
        envelope: &mut PrivacyProofEnvelopeV1,
    ) -> &mut VeRangeTransparentRangeStatementV1 {
        let PrivacyStatementV1::VeRangeTransparentRangeV1(statement) = &mut envelope.statement
        else {
            unreachable!("VeRange fixture")
        };
        statement
    }
    fn refresh_statement_digest(envelope: &mut PrivacyProofEnvelopeV1) {
        envelope.statement_digest = envelope
            .statement
            .digest()
            .expect("mutated statement remains canonically encodable");
    }
    fn jindo_statement_mut(
        envelope: &mut PrivacyProofEnvelopeV1,
    ) -> &mut IrohaJindoPolynomialCommitmentStatementV1 {
        let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) =
            &mut envelope.statement
        else {
            unreachable!("Jindo fixture")
        };
        statement
    }
    fn assert_rejected(
        envelope: &PrivacyProofEnvelopeV1,
        activation: &PrivacyProtocolActivationRecordV1,
        network_id: &NetworkId,
        label: &str,
    ) {
        assert!(
            verify_privacy_envelope_v1(envelope, &verification_context(activation, network_id))
                .is_err(),
            "adversarial envelope `{label}` was accepted"
        );
    }
    fn assert_native_jindo_rejected(
        envelope: &PrivacyProofEnvelopeV1,
        context: &PrivacyVerificationContextV1<'_>,
        label: &str,
    ) {
        assert!(
            matches!(
                verify_privacy_envelope_v1(envelope, context),
                Err(PrivacyVerificationErrorV1::NativeJindo(_))
            ),
            "Jindo adversarial envelope `{label}` did not reach and fail the native verifier"
        );
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn zk_ace_production_dispatch_has_no_activatable_profile() {
        let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
    }
    #[test]
    #[ignore = "release gate: generates and verifies a full masked ZK-AMS batch proof"]
    fn zk_ams_production_dispatch_covers_batch_and_successor_provisioning() {
        let fixture = zk_ams_runtime_fixture_for_test();
        let context = |expected_action_index| PrivacyVerificationContextV1 {
            activation: &fixture.activation,
            consensus_limits: &TEST_CONSENSUS_LIMITS,
            network_id: &fixture.network_id,
            genesis_hash: fixture.genesis_hash,
            current_height: fixture.current_height,
            expected_action_index,
            block_timestamp_ms: fixture.block_timestamp_ms,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        };
        let batch_effects = verify_privacy_envelope_v1(&fixture.batch_envelope, &context(0))
            .expect("native ZK-AMS batch dispatch");
        let PrivacyStatementV1::IrohaZkAmsV1(batch_statement) = &fixture.batch_envelope.statement
        else {
            unreachable!("ZK-AMS batch fixture")
        };
        let PrivacyZkAmsActionV1::BatchAdmission(batch) = &batch_statement.action else {
            unreachable!("ZK-AMS batch action")
        };
        let VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission(effect) = batch_effects.ledger()
        else {
            panic!("ZK-AMS batch dispatch returned the wrong ledger effect")
        };
        assert_eq!(effect.current_root, batch.account_registry_root);
        assert_eq!(effect.current_epoch, batch.account_registry_root_epoch);
        assert_eq!(effect.next_root, batch.next_account_registry_root);
        assert_eq!(effect.next_epoch, batch.next_account_registry_root_epoch);
        assert_eq!(effect.anchors, batch.anchors);
        assert_eq!(
            effect.registry_record_digest,
            batch_statement.registry_record_digest
        );
        let provision_effects =
            verify_privacy_envelope_v1(&fixture.provision_envelope, &context(0))
                .expect("native ZK-AMS provision dispatch");
        let PrivacyStatementV1::IrohaZkAmsV1(provision_statement) =
            &fixture.provision_envelope.statement
        else {
            unreachable!("ZK-AMS provision fixture")
        };
        let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &provision_statement.action else {
            unreachable!("ZK-AMS provision action")
        };
        let VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount(effect) =
            provision_effects.ledger()
        else {
            panic!("ZK-AMS provision dispatch returned the wrong ledger effect")
        };
        assert_eq!(effect.current_root, batch.next_account_registry_root);
        assert_eq!(effect.current_epoch, batch.next_account_registry_root_epoch);
        assert_eq!(effect.ring, provision.admitted_seed_key_ring);
        assert_eq!(effect.account_id, provision.account_id);
        assert_eq!(effect.key_image, provision.key_image);
        assert_eq!(
            effect.registry_record_digest,
            provision_statement.registry_record_digest
        );
        let mut corrupt_batch = fixture.batch_envelope.clone();
        let PrivacyProofV1::IrohaZkAmsV1(proof) = &mut corrupt_batch.proof else {
            unreachable!("ZK-AMS batch proof")
        };
        let proof = proof.bytes_mut();
        let middle = proof.bytes.len() / 2;
        proof.bytes[middle] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&corrupt_batch, &context(0)),
            Err(PrivacyVerificationErrorV1::NativeZkAms(_))
        ));
        let mut rebound = fixture.provision_envelope.clone();
        let PrivacyStatementV1::IrohaZkAmsV1(statement) = &mut rebound.statement else {
            unreachable!("ZK-AMS provision fixture")
        };
        let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &mut statement.action else {
            unreachable!("ZK-AMS provision action")
        };
        let mut changed_root = *provision.account_registry_root.as_bytes();
        changed_root[0] ^= 1;
        provision.account_registry_root = PrivacyRootV1::new(changed_root);
        rebound.statement_digest = rebound
            .statement
            .digest()
            .expect("mutated ZK-AMS statement remains canonical");
        assert!(matches!(
            verify_privacy_envelope_v1(&rebound, &context(0)),
            Err(PrivacyVerificationErrorV1::NativeZkAms(_))
        ));
        let mut wrong_action_proof = fixture.batch_envelope.clone();
        wrong_action_proof.proof = fixture.provision_envelope.proof.clone();
        assert!(matches!(
            verify_privacy_envelope_v1(&wrong_action_proof, &context(0)),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    #[test]
    fn verified_verange_effects_are_exact_and_non_mutating() {
        let (envelope, activation, network_id) = valid_envelope();
        let canonical_bytes = u64::try_from(
            norito::encode_canonical(&envelope)
                .expect("canonical envelope")
                .len(),
        )
        .expect("length");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _layout = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_ne!(
            u64::try_from(
                norito::to_bytes(&envelope)
                    .expect("alternate envelope")
                    .len()
            )
            .expect("length"),
            canonical_bytes
        );
        let effects =
            verify_privacy_envelope_v1(&envelope, &verification_context(&activation, &network_id))
                .expect("valid proof");
        assert_eq!(
            effects.protocol_id(),
            PrivacyProtocolIdV1::VeRangeTransparentRangeV1
        );
        assert_eq!(effects.statement_digest(), envelope.statement_digest);
        assert_eq!(effects.action_index(), 0);
        assert_eq!(effects.ledger(), &VerifiedPrivacyLedgerEffectsV1::None);
        assert_eq!(effects.encoded_action_bytes(), canonical_bytes);
    }
    #[test]
    fn pgc_payment_native_decoder_retains_original_refusal_through_verifier() {
        let fixture = PgcFixture::new();
        let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) = &fixture.envelope.statement
        else {
            panic!("PGC statement")
        };
        let PrivacyProofV1::AnonymousPgcKOutOfNV1(proof) = &fixture.envelope.proof else {
            panic!("PGC proof")
        };
        let context = fixture.verification_context();
        let state = context.pgc_state.expect("trusted PGC state");
        let unbounded =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128);
        let (root, usage) = norito::core::with_decode_limits_measured(unbounded, || {
            derive_privacy_pgc_account_state_root_v1(
                state.namespace,
                state.current_epoch,
                state.total_supply,
                state.accounts,
            )
        });
        root.expect("current root");
        let limits = norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usage.total_allocated_bytes(),
            128,
        );
        let verify =
            || verify_anonymous_pgc_payment_v1(statement, proof, &fixture.envelope, &context);
        let refusal = norito::with_decode_limits_scope(limits, verify).unwrap_err();
        assert!(
            std::error::Error::source(&refusal)
                .expect("native read remains the standard error source")
                .downcast_ref::<AnonymousPgcReadError>()
                .is_some()
        );
        let PrivacyVerificationErrorV1::NativeAnonymousPgc(read) = refusal else {
            panic!("quota permits current root but refuses the actual native payment decoder");
        };
        let AnonymousPgcReadError::Codec(original) = *read else {
            panic!("original decoder")
        };
        let owner = original
            .local_refusal()
            .expect("original scope survives verification boundary");
        assert_eq!(
            owner.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert_eq!(
            owner.resource_error(),
            original.error().decode_resource_error().unwrap()
        );
        verify().expect("the original unchanged payment retries after local scope retires");
    }
    #[test]
    fn pgc_payment_current_and_successor_root_refusals_keep_original_owner() {
        let fixture = PgcFixture::new();
        let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) = &fixture.envelope.statement
        else {
            panic!("PGC statement");
        };
        let PrivacyProofV1::AnonymousPgcKOutOfNV1(proof) = &fixture.envelope.proof else {
            panic!("PGC proof");
        };
        let context = fixture.verification_context();
        let verify =
            || verify_anonymous_pgc_payment_v1(statement, proof, &fixture.envelope, &context);
        let unbounded =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128);
        let (baseline, usage) = norito::core::with_decode_limits_measured(unbounded, verify);
        baseline.expect("actual valid native payment");
        let allocation = usage.total_allocated_bytes();
        assert!(
            allocation > 0,
            "both canonical roots charge their namespace frame"
        );
        for (limit, expected_code) in [
            (
                0,
                PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootRecomputationFailed,
            ),
            (
                allocation - 1,
                PrivacyAnonymousPgcStateFailureCodeV1::NextRootRecomputationFailed,
            ),
        ] {
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 128);
            let original = norito::with_decode_limits_scope(limits, verify).unwrap_err();
            let PrivacyVerificationErrorV1::AnonymousPgcRoot {
                code,
                source:
                    crate::privacy_state::PrivacyPgcAccountStateRootErrorV1::NamespaceEncoding(original),
            } = original
            else {
                panic!("the actual selected root must retain its original local encoding cause");
            };
            assert_eq!(code, expected_code);
            let origin = original
                .local_refusal()
                .expect("original enclosing budget owner");
            assert_eq!(
                origin.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert_eq!(
                origin.resource_error(),
                original.error().decode_resource_error().unwrap()
            );
        }
        verify().expect("unchanged original payment retries after local scopes retire");
    }
    #[test]
    fn verified_pgc_effect_is_complete_exact_and_replay_becomes_stale() {
        let fixture = PgcFixture::new();
        let effects =
            verify_privacy_envelope_v1(&fixture.envelope, &fixture.verification_context())
                .expect("valid PGC payment");
        assert_eq!(
            effects.protocol_id(),
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1
        );
        assert_eq!(
            effects.statement_digest(),
            fixture.envelope.statement_digest
        );
        let effect = match effects.ledger() {
            VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(effect) => effect,
            VerifiedPrivacyLedgerEffectsV1::None => panic!("missing PGC ledger effect"),
            VerifiedPrivacyLedgerEffectsV1::OrchardActions(_)
            | VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAceAuthorization(_) => {
                panic!("unexpected non-PGC ledger effect")
            }
        };
        assert_eq!(effect.namespace(), fixture.namespace);
        assert_eq!(effect.total_supply(), fixture.total_supply);
        assert_eq!(effect.current_root(), fixture.current_root);
        assert_eq!(effect.current_epoch(), fixture.current_epoch);
        assert_eq!(effect.next_epoch(), fixture.current_epoch + 1);
        assert_eq!(effect.accounts().len(), fixture.accounts.len());
        assert!(
            effect
                .accounts()
                .iter()
                .zip(&fixture.accounts)
                .all(|(next, current)| next.public_key == current.public_key)
        );
        assert_eq!(
            derive_privacy_pgc_account_state_root_v1(
                effect.namespace(),
                effect.next_epoch(),
                effect.total_supply(),
                effect.accounts(),
            )
            .expect("recompute verified next root"),
            effect.next_root()
        );
        let next_accounts = effect.accounts().to_vec();
        let next_root = effect.next_root();
        let next_epoch = effect.next_epoch();
        assert!(matches!(
            effects.into_ledger(),
            VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(_)
        ));
        let mut replay_state = fixture.pgc_state(&next_accounts);
        replay_state.current_root = next_root;
        replay_state.current_epoch = next_epoch;
        replay_state.retained_current_root = Some((next_epoch, next_root));
        let mut replay_context = fixture.verification_context();
        replay_context.pgc_state = Some(replay_state);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &replay_context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::StaleHead
        ));
    }
    #[test]
    fn pgc_trusted_state_memo_and_proof_tampering_fail_closed() {
        let fixture = PgcFixture::new();
        let mut missing = fixture.verification_context();
        missing.pgc_state = None;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &missing),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::MissingTrustedState
        ));
        let mut state = fixture.pgc_state(&fixture.accounts);
        state.retained_current_root = None;
        let mut context = fixture.verification_context();
        context.pgc_state = Some(state);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code
                    == PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootNotRetained
        ));
        let mut state = fixture.pgc_state(&fixture.accounts);
        state.current_epoch += 1;
        let mut context = fixture.verification_context();
        context.pgc_state = Some(state);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::StaleHead
        ));
        let mut reordered = fixture.accounts.clone();
        reordered.swap(0, 1);
        let mut context = fixture.verification_context();
        context.pgc_state = Some(fixture.pgc_state(&reordered));
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch
        ));
        let mut context = fixture.verification_context();
        context.pgc_state = Some(fixture.pgc_state(&fixture.accounts[..15]));
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch
        ));
        let mut duplicate = fixture.accounts.clone();
        duplicate[1].public_key = duplicate[0].public_key;
        let mut context = fixture.verification_context();
        context.pgc_state = Some(fixture.pgc_state(&duplicate));
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch
        ));
        let mut changed_ciphertext = fixture.accounts.clone();
        changed_ciphertext[0].encrypted_balance = changed_ciphertext[1].encrypted_balance;
        let mut context = fixture.verification_context();
        context.pgc_state = Some(fixture.pgc_state(&changed_ciphertext));
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootMismatch
        ));
        let mut state = fixture.pgc_state(&fixture.accounts);
        state.total_supply += 1;
        let mut context = fixture.verification_context();
        context.pgc_state = Some(state);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::CurrentRootMismatch
        ));
        let mut changed_provenance = fixture.pgc_state(&fixture.accounts);
        changed_provenance.bootstrap_proof_digest =
            PrivacyPgcBootstrapProofDigestV1::new([0xb5; 32]);
        let mut context = fixture.verification_context();
        context.pgc_state = Some(changed_provenance);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::NativeAnonymousPgc(_))
        ));
        let mut altered_proof = fixture.envelope.clone();
        let PrivacyProofV1::AnonymousPgcKOutOfNV1(proof) = &altered_proof.proof else {
            unreachable!("PGC proof")
        };
        let mut proof_bytes = proof.as_bytes().to_vec();
        let proof_middle = proof_bytes.len() / 2;
        proof_bytes[proof_middle] ^= 1;
        altered_proof.proof =
            PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(proof_bytes));
        assert!(matches!(
            verify_privacy_envelope_v1(&altered_proof, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::NativeAnonymousPgc(_))
        ));
        let PrivacyProofV1::AnonymousPgcKOutOfNV1(valid_proof) = &fixture.envelope.proof else {
            unreachable!("PGC proof")
        };
        for invalid_bytes in [
            valid_proof.as_bytes()[..valid_proof.as_bytes().len() - 1].to_vec(),
            {
                let mut trailing = valid_proof.as_bytes().to_vec();
                trailing.push(0);
                trailing
            },
        ] {
            let mut invalid = fixture.envelope.clone();
            invalid.proof =
                PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(invalid_bytes));
            assert!(matches!(
                verify_privacy_envelope_v1(&invalid, &fixture.verification_context()),
                Err(PrivacyVerificationErrorV1::NativeAnonymousPgc(_))
            ));
        }
        let mut empty = fixture.envelope.clone();
        empty.proof = PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(Vec::new()));
        assert!(matches!(
            verify_privacy_envelope_v1(&empty, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut all_zero = fixture.envelope.clone();
        all_zero.proof = PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(vec![
            0;
            valid_proof.as_bytes().len()
        ]));
        assert!(matches!(
            verify_privacy_envelope_v1(&all_zero, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut duplicate_statement = fixture.envelope.clone();
        let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) =
            &mut duplicate_statement.statement
        else {
            unreachable!("PGC statement")
        };
        statement.anonymity_set_public_keys[1] = statement.anonymity_set_public_keys[0];
        refresh_statement_digest(&mut duplicate_statement);
        assert!(matches!(
            verify_privacy_envelope_v1(&duplicate_statement, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let forged_next_root =
            PgcFixture::with_declared_transition(Some(PrivacyRootV1::new([0xc1; 32])), None);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &forged_next_root.envelope,
                &forged_next_root.verification_context(),
            ),
            Err(PrivacyVerificationErrorV1::AnonymousPgcState(detail))
                if detail.code == PrivacyAnonymousPgcStateFailureCodeV1::NextRootMismatch
        ));
        let forged_next_epoch =
            PgcFixture::with_declared_transition(None, Some(fixture.current_epoch + 2));
        assert!(matches!(
            verify_privacy_envelope_v1(
                &forged_next_epoch.envelope,
                &forged_next_epoch.verification_context(),
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    include!("privacy_verifier/cross_suite_replay_test.rs");
    #[test]
    fn verified_orchard_effect_is_complete_and_derived_from_authoritative_frontier() {
        let fixture = orchard_fixture();
        let effects =
            verify_privacy_envelope_v1(&fixture.envelope, &fixture.verification_context())
                .expect("valid Orchard action");
        assert_eq!(
            effects.protocol_id(),
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1
        );
        assert_eq!(
            effects.statement_digest(),
            fixture.envelope.statement_digest
        );
        assert_eq!(effects.action_index(), 0);
        assert_eq!(
            effects.encoded_action_bytes(),
            u64::try_from(
                norito::to_bytes(&fixture.envelope)
                    .expect("encode Orchard envelope")
                    .len()
            )
            .expect("bounded envelope length")
        );
        let statement = match &fixture.envelope.statement {
            PrivacyStatementV1::OrchardHalo2ActionsV1(statement) => statement,
            _ => unreachable!("Orchard fixture"),
        };
        let effect = match effects.ledger() {
            VerifiedPrivacyLedgerEffectsV1::OrchardActions(effect) => effect,
            VerifiedPrivacyLedgerEffectsV1::None
            | VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(_)
            | VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount(_)
            | VerifiedPrivacyLedgerEffectsV1::ZkAceAuthorization(_) => {
                panic!("missing Orchard ledger effect")
            }
        };
        assert_eq!(effect.namespace(), fixture.namespace);
        assert_eq!(
            effect.bootstrap_digest(),
            fixture.snapshot.bootstrap_digest()
        );
        assert_eq!(
            effect.asset_definition_id(),
            fixture.snapshot.state().asset_definition_id()
        );
        assert_eq!(
            effect.reserve_account(),
            fixture.snapshot.state().reserve_account()
        );
        assert_eq!(effect.anchor(), statement.anchor);
        assert_eq!(effect.anchor_epoch(), statement.anchor_epoch);
        assert_eq!(effect.current_root(), fixture.snapshot.current_root());
        assert_eq!(effect.current_epoch(), fixture.snapshot.current_epoch());
        assert_eq!(
            effect.successor_state().epoch(),
            fixture.snapshot.current_epoch() + 1
        );
        assert_eq!(effect.successor_state().tree_size(), 1);
        assert_ne!(
            effect.successor_state().root(),
            fixture.snapshot.current_root()
        );
        assert_eq!(
            effect.nullifiers(),
            statement
                .actions
                .iter()
                .map(|action| action.nullifier)
                .collect::<Vec<_>>()
        );
        assert_eq!(effect.value_balance(), statement.value_balance);
        assert_eq!(effect.expiry_height(), statement.expiry_height);
    }
    #[test]
    fn orchard_exact_envelope_rejects_changed_nonzero_authoritative_genesis_natively() {
        let fixture = orchard_fixture();
        let original_context = fixture.verification_context();
        let original_genesis = original_context.genesis_hash;
        assert_ne!(original_genesis, [0; 32]);
        verify_privacy_envelope_v1(&fixture.envelope, &original_context)
            .expect("Orchard fixture is valid under its proving genesis");
        let mut changed_context = fixture.verification_context();
        changed_context.genesis_hash[0] ^= 1;
        assert_ne!(changed_context.genesis_hash, [0; 32]);
        assert_ne!(changed_context.genesis_hash, original_genesis);
        let error = verify_privacy_envelope_v1(&fixture.envelope, &changed_context)
            .expect_err("the exact Orchard envelope must not replay across genesis");
        assert!(
            matches!(
                error,
                PrivacyVerificationErrorV1::Context(ref detail)
                    if detail.code
                        == PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch
            ),
            "changed genesis must fail the typed network binding: {error:?}"
        );
    }
    #[test]
    fn orchard_trusted_state_statement_and_authorization_tampering_fail_closed() {
        let fixture = orchard_fixture();
        let mut context = fixture.verification_context();
        context.orchard_state = None;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::MissingTrustedState
        ));
        let other_namespace = PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0xC1; 32]),
            }),
        );
        let other_pool = PrivacyOrchardPoolSnapshotV1::canonical_bootstrap_for_test(
            other_namespace,
            fixture.snapshot.state().asset_definition_id().clone(),
            fixture.snapshot.state().public_balance_scope(),
            fixture.snapshot.state().reserve_account().clone(),
        );
        let mut context = fixture.verification_context();
        context.orchard_state = Some(&other_pool);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::NamespaceMismatch
        ));
        let wrong_asset = PrivacyOrchardPoolSnapshotV1::canonical_bootstrap_for_test(
            fixture.namespace,
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("wrong_orchard_asset").expect("name"),
            ),
            fixture.snapshot.state().public_balance_scope(),
            fixture.snapshot.state().reserve_account().clone(),
        );
        let mut context = fixture.verification_context();
        context.orchard_state = Some(&wrong_asset);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::AssetMismatch
        ));
        let wrong_scope = PrivacyOrchardPoolSnapshotV1::canonical_bootstrap_for_test(
            fixture.namespace,
            fixture.snapshot.state().asset_definition_id().clone(),
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::new(7)),
            fixture.snapshot.state().reserve_account().clone(),
        );
        let mut context = fixture.verification_context();
        context.orchard_state = Some(&wrong_scope);
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::PublicBalanceScopeMismatch
        ));
        let mut stale_anchor = fixture.envelope.clone();
        let statement = orchard_statement_mut(&mut stale_anchor);
        statement.anchor = PrivacyRootV1::new([0xC4; 32]);
        statement.anchor_epoch += 1;
        refresh_statement_digest(&mut stale_anchor);
        assert!(matches!(
            verify_privacy_envelope_v1(&stale_anchor, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::AnchorNotRetained
        ));
        let mut context = fixture.verification_context();
        context.current_height = 101;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::Expired
        ));
        let mut invalid_commitment = fixture.envelope.clone();
        orchard_statement_mut(&mut invalid_commitment).actions[0].note_commitment = [u8::MAX; 32];
        refresh_statement_digest(&mut invalid_commitment);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &invalid_commitment,
                &fixture.verification_context()
            ),
            Err(PrivacyVerificationErrorV1::OrchardState(detail))
                if detail.code == PrivacyOrchardStateFailureCodeV1::SuccessorDerivation
        ));
        let mut wrong_width = fixture.envelope.clone();
        orchard_statement_mut(&mut wrong_width).actions[0]
            .encrypted_note
            .pop();
        refresh_statement_digest(&mut wrong_width);
        assert!(matches!(
            verify_privacy_envelope_v1(&wrong_width, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let public_mutations: [fn(&mut OrchardHalo2ActionsStatementV1); 7] = [
            |statement| statement.context.transaction_intent_digest.0[0] ^= 1,
            |statement| statement.actions[0].nullifier[0] ^= 1,
            |statement| statement.actions[0].randomized_key[0] ^= 1,
            |statement| statement.actions[0].ephemeral_key[0] ^= 1,
            |statement| statement.actions[0].encrypted_note[0] ^= 1,
            |statement| statement.actions[0].outgoing_ciphertext[0] ^= 1,
            |statement| statement.actions[0].value_commitment[0] ^= 1,
        ];
        for mutate in public_mutations {
            let mut changed = fixture.envelope.clone();
            mutate(orchard_statement_mut(&mut changed));
            refresh_statement_digest(&mut changed);
            assert!(
                matches!(
                    verify_privacy_envelope_v1(&changed, &fixture.verification_context()),
                    Err(PrivacyVerificationErrorV1::NativeOrchard(_))
                ),
                "every native public field must be proof/signature bound"
            );
        }
        let mut changed_balance = fixture.envelope.clone();
        orchard_statement_mut(&mut changed_balance).value_balance = PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::OutOfPool,
            amount: 1,
        };
        refresh_statement_digest(&mut changed_balance);
        assert!(matches!(
            verify_privacy_envelope_v1(&changed_balance, &fixture.verification_context()),
            Err(PrivacyVerificationErrorV1::NativeOrchard(_))
        ));
        let PrivacyProofV1::OrchardHalo2ActionsV1(valid_proof) = &fixture.envelope.proof else {
            unreachable!("Orchard proof")
        };
        for invalid_bytes in [
            valid_proof.as_bytes()[..valid_proof.as_bytes().len() - 1].to_vec(),
            {
                let mut trailing = valid_proof.as_bytes().to_vec();
                trailing.push(0);
                trailing
            },
            {
                let mut corrupt = valid_proof.as_bytes().to_vec();
                corrupt[0] ^= 1;
                corrupt
            },
            {
                let mut corrupt = valid_proof.as_bytes().to_vec();
                let middle = corrupt.len() / 2;
                corrupt[middle] ^= 1;
                corrupt
            },
            {
                let mut corrupt = valid_proof.as_bytes().to_vec();
                let last = corrupt.len() - 1;
                corrupt[last] ^= 1;
                corrupt
            },
        ] {
            let mut changed = fixture.envelope.clone();
            changed.proof =
                PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(invalid_bytes));
            assert!(matches!(
                verify_privacy_envelope_v1(&changed, &fixture.verification_context()),
                Err(PrivacyVerificationErrorV1::NativeOrchard(_))
            ));
        }
    }
    #[test]
    fn verified_fcmp_effect_uses_retained_anchor_and_current_mutation_head() {
        let fixture = fcmp_fixture();
        let effects = verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(Some(&fixture.snapshot)),
        )
        .expect("valid FCMP++ transaction");
        let statement = match &fixture.envelope.statement {
            PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) => statement,
            _ => unreachable!("FCMP++ fixture"),
        };
        let effect = match effects.ledger() {
            VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(effect) => effect,
            _ => panic!("missing FCMP++ ledger effect"),
        };
        assert_eq!(effect.namespace(), fixture.snapshot.namespace());
        assert_eq!(
            effect.bootstrap_digest(),
            fixture.snapshot.bootstrap_digest()
        );
        assert_eq!(effect.asset_definition_id(), &statement.asset_definition_id);
        assert_eq!(effect.current_root(), fixture.snapshot.current_root());
        assert_eq!(effect.current_epoch(), fixture.snapshot.current_epoch());
        assert_eq!(effect.next_epoch(), fixture.snapshot.current_epoch() + 1);
        assert_eq!(effect.value_balance(), None);
        let expected_successor = fixture
            .snapshot
            .derive_fcmp_successor(&statement.outputs)
            .expect("authoritative FCMP++ successor");
        assert_eq!(
            effect.next_root(),
            expected_successor.root().history_commitment()
        );
        match effect.transition() {
            VerifiedProofManagedPoolTransitionV1::Fcmp {
                key_images,
                outputs,
                successor_state,
            } => {
                assert_eq!(
                    key_images,
                    &statement
                        .inputs
                        .iter()
                        .map(|input| input.key_image)
                        .collect::<Vec<_>>()
                );
                assert_eq!(outputs, &statement.outputs);
                assert_eq!(successor_state, &expected_successor);
            }
            VerifiedProofManagedPoolTransitionV1::IvmPrivateNote { .. }
            | VerifiedProofManagedPoolTransitionV1::PqMasp { .. } => {
                panic!("FCMP++ effect carried a private-note frontier")
            }
        }
        // Membership remains valid under the retained origin root even after
        // an unrelated output advances the authoritative mutation head.
        let (unrelated_native, _, _) = fcmp_test_spendable_output_v1(83, 89, 97, 1, 101);
        let unrelated = model_fcmp_output(unrelated_native);
        let advanced = fixture.snapshot.with_fcmp_successor_for_test(&[unrelated]);
        let historical = verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(Some(&advanced)),
        )
        .expect("retained historical FCMP++ anchor");
        let historical_effect = match historical.ledger() {
            VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(effect) => effect,
            _ => panic!("missing historical-anchor FCMP++ effect"),
        };
        assert_eq!(historical_effect.current_root(), advanced.current_root());
        assert_eq!(historical_effect.current_epoch(), advanced.current_epoch());
        assert_ne!(
            historical_effect.current_root(),
            statement.output_set_root.history_commitment()
        );
        let historical_successor = advanced
            .derive_fcmp_successor(&statement.outputs)
            .expect("current-head FCMP++ successor");
        assert_eq!(
            historical_effect.next_root(),
            historical_successor.root().history_commitment()
        );
    }
    #[test]
    fn private_ivm_preflight_uses_retained_anchor_and_current_mutation_head() {
        let fixture = IvmPrivateNotePreflightFixture::new();
        let prepared = prepare_ivm_private_note_transition_v1(
            &fixture.statement,
            fixture.expected_namespace(),
            Some(&fixture.snapshot),
        )
        .expect("canonical private-IVM preflight");
        let expected = fixture
            .snapshot
            .derive_note_successor(&fixture.statement.output_commitments)
            .expect("origin-head private-IVM successor");
        assert_eq!(prepared.namespace, fixture.snapshot.namespace());
        assert_eq!(
            prepared.bootstrap_digest,
            fixture.snapshot.bootstrap_digest()
        );
        assert_eq!(prepared.current_root, fixture.snapshot.current_root());
        assert_eq!(prepared.current_epoch, fixture.snapshot.current_epoch());
        assert_eq!(prepared.successor_state, expected);
        let unrelated = PrivacyCommitmentV1::new([0xD2; 32]);
        let advanced = fixture
            .snapshot
            .with_private_note_successor_for_test(&[unrelated]);
        let historical = prepare_ivm_private_note_transition_v1(
            &fixture.statement,
            fixture.expected_namespace(),
            Some(&advanced),
        )
        .expect("retained historical private-IVM anchor");
        assert_eq!(historical.current_root, advanced.current_root());
        assert_eq!(historical.current_epoch, advanced.current_epoch());
        assert_ne!(historical.current_root, fixture.statement.state_root);
        assert_ne!(historical.current_epoch, fixture.statement.root_epoch);
        let expected_from_current = advanced
            .derive_note_successor(&fixture.statement.output_commitments)
            .expect("current-head private-IVM successor");
        assert_eq!(historical.successor_state, expected_from_current);
        assert_eq!(
            historical.successor_state.epoch(),
            advanced.current_epoch() + 1
        );
    }
    #[test]
    fn private_ivm_preflight_rejects_state_namespace_anchor_and_ciphertext_adversaries() {
        let fixture = IvmPrivateNotePreflightFixture::new();
        let pristine = fixture.snapshot.clone();
        let namespace = fixture.expected_namespace();
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(&fixture.statement, namespace, None),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code
                    == PrivacyIvmPrivateNoteStateFailureCodeV1::MissingTrustedState
        ));
        let no_current = fixture.snapshot.without_retained_current_root_for_test();
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &fixture.statement,
                namespace,
                Some(&no_current),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code
                    == PrivacyIvmPrivateNoteStateFailureCodeV1::CurrentRootNotRetained
        ));
        let inconsistent = fixture
            .snapshot
            .with_inconsistent_note_output_count_for_test();
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &fixture.statement,
                namespace,
                Some(&inconsistent),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code == PrivacyIvmPrivateNoteStateFailureCodeV1::FrontierMismatch
        ));
        let advanced = fixture
            .snapshot
            .with_private_note_successor_for_test(&[PrivacyCommitmentV1::new([0xD3; 32])]);
        let evicted = advanced.without_retained_root_for_test(
            fixture.statement.root_epoch,
            fixture.statement.state_root,
        );
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &fixture.statement,
                namespace,
                Some(&evicted),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code == PrivacyIvmPrivateNoteStateFailureCodeV1::AnchorNotRetained
        ));
        let mut unknown_anchor = fixture.statement.clone();
        let mut unknown_root = unknown_anchor.state_root.into_bytes();
        unknown_root[0] ^= 1;
        unknown_anchor.state_root = PrivacyRootV1::new(unknown_root);
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &unknown_anchor,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code == PrivacyIvmPrivateNoteStateFailureCodeV1::AnchorNotRetained
        ));
        for (pool_id, program_id) in [
            (
                PrivacyPoolIdV1::new([0xD4; 32]),
                fixture.statement.program_id,
            ),
            (
                fixture.statement.pool_id,
                iroha_data_model::privacy::PrivacyProgramIdV1::new([0xD5; 32]),
            ),
        ] {
            let other =
                PrivacyProofManagedPoolSnapshotV1::canonical_private_note_bootstrap_for_test(
                    PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
                        PrivacyIvmPrivateNotePoolBootstrapV1 {
                            pool_id,
                            asset_definition_id: fixture.statement.asset_definition_id.clone(),
                            public_balance_scope: fixture.statement.public_balance_scope,
                            reserve_account: fixture.reserve_account.clone(),
                            program_id,
                            initial_note_commitments: vec![fixture.input_commitment],
                        },
                    ),
                );
            assert!(matches!(
                prepare_ivm_private_note_transition_v1(
                    &fixture.statement,
                    namespace,
                    Some(&other),
                ),
                Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                    if detail.code == PrivacyIvmPrivateNoteStateFailureCodeV1::NamespaceMismatch
            ));
        }
        let wrong_asset =
            PrivacyProofManagedPoolSnapshotV1::canonical_private_note_bootstrap_for_test(
                PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
                    PrivacyIvmPrivateNotePoolBootstrapV1 {
                        pool_id: fixture.statement.pool_id,
                        asset_definition_id: AssetDefinitionId::derive_from_components(
                            DomainId::try_new("privacy", "universal").expect("domain"),
                            Name::from_str("wrong_private_asset").expect("name"),
                        ),
                        public_balance_scope: fixture.statement.public_balance_scope,
                        reserve_account: fixture.reserve_account.clone(),
                        program_id: fixture.statement.program_id,
                        initial_note_commitments: vec![fixture.input_commitment],
                    },
                ),
            );
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &fixture.statement,
                namespace,
                Some(&wrong_asset),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code == PrivacyIvmPrivateNoteStateFailureCodeV1::AssetMismatch
        ));
        let wrong_scope =
            PrivacyProofManagedPoolSnapshotV1::canonical_private_note_bootstrap_for_test(
                PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
                    PrivacyIvmPrivateNotePoolBootstrapV1 {
                        pool_id: fixture.statement.pool_id,
                        asset_definition_id: fixture.statement.asset_definition_id.clone(),
                        public_balance_scope: AssetBalanceScope::Dataspace(
                            iroha_model_base::topology::DataSpaceId::new(7),
                        ),
                        reserve_account: fixture.reserve_account.clone(),
                        program_id: fixture.statement.program_id,
                        initial_note_commitments: vec![fixture.input_commitment],
                    },
                ),
            );
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &fixture.statement,
                namespace,
                Some(&wrong_scope),
            ),
            Err(PrivacyVerificationErrorV1::IvmPrivateNoteState(detail))
                if detail.code
                    == PrivacyIvmPrivateNoteStateFailureCodeV1::PublicBalanceScopeMismatch
        ));
        let mut invalid_key = fixture.statement.clone();
        invalid_key.encrypted_outputs[0].ephemeral_public_key =
            PrivacyEncryptionKeyV1::new([u8::MAX; 32]);
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &invalid_key,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::NativeIvmPrivateNote(_))
        ));
        let mut mismatched_commitment = fixture.statement.clone();
        mismatched_commitment.output_commitments[0] = PrivacyCommitmentV1::new([0xD6; 32]);
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &mismatched_commitment,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::NativeIvmPrivateNote(_))
        ));
        let mut omitted_ciphertext = fixture.statement.clone();
        omitted_ciphertext.encrypted_outputs.clear();
        assert!(matches!(
            prepare_ivm_private_note_transition_v1(
                &omitted_ciphertext,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::NativeIvmPrivateNote(_))
        ));
        assert_eq!(fixture.snapshot, pristine);
    }
    #[test]
    fn pq_masp_preflight_uses_retained_anchor_and_current_mutation_head() {
        let fixture = PqMaspPreflightFixture::new();
        let prepared = prepare_pq_masp_transition_v1(
            &fixture.statement,
            fixture.expected_namespace(),
            Some(&fixture.snapshot),
        )
        .expect("canonical PQ-MASP preflight");
        let expected = fixture
            .snapshot
            .derive_note_successor(&fixture.statement.output_commitments)
            .expect("origin-head PQ-MASP successor");
        assert_eq!(prepared.namespace, fixture.snapshot.namespace());
        assert_eq!(
            prepared.bootstrap_digest,
            fixture.snapshot.bootstrap_digest()
        );
        assert_eq!(prepared.current_root, fixture.snapshot.current_root());
        assert_eq!(prepared.current_epoch, fixture.snapshot.current_epoch());
        assert_eq!(prepared.successor_state, expected);
        let unrelated = PrivacyCommitmentV1::new([0xE2; 32]);
        let advanced = fixture
            .snapshot
            .with_pq_masp_successor_for_test(&[unrelated]);
        let historical = prepare_pq_masp_transition_v1(
            &fixture.statement,
            fixture.expected_namespace(),
            Some(&advanced),
        )
        .expect("retained historical PQ-MASP anchor");
        assert_eq!(historical.current_root, advanced.current_root());
        assert_eq!(historical.current_epoch, advanced.current_epoch());
        assert_ne!(historical.current_root, fixture.statement.anchor);
        assert_ne!(historical.current_epoch, fixture.statement.anchor_epoch);
        let expected_from_current = advanced
            .derive_note_successor(&fixture.statement.output_commitments)
            .expect("current-head PQ-MASP successor");
        assert_eq!(historical.successor_state, expected_from_current);
        assert_eq!(
            historical.successor_state.epoch(),
            advanced.current_epoch() + 1
        );
    }
    #[test]
    fn pq_masp_preflight_rejects_trusted_state_and_ciphertext_adversaries() {
        let fixture = PqMaspPreflightFixture::new();
        let pristine = fixture.snapshot.clone();
        let namespace = fixture.expected_namespace();
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, None),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::MissingTrustedState
        ));
        let no_current = fixture.snapshot.without_retained_current_root_for_test();
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&no_current)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::CurrentRootNotRetained
        ));
        let inconsistent = fixture
            .snapshot
            .with_inconsistent_note_output_count_for_test();
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&inconsistent)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::FrontierMismatch
        ));
        let advanced = fixture
            .snapshot
            .with_pq_masp_successor_for_test(&[PrivacyCommitmentV1::new([0xE3; 32])]);
        let evicted = advanced.without_retained_root_for_test(
            fixture.statement.anchor_epoch,
            fixture.statement.anchor,
        );
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&evicted)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::AnchorNotRetained
        ));
        let mut unknown_anchor = fixture.statement.clone();
        let mut unknown_root = unknown_anchor.anchor.into_bytes();
        unknown_root[0] ^= 1;
        unknown_anchor.anchor = PrivacyRootV1::new(unknown_root);
        assert!(matches!(
            prepare_pq_masp_transition_v1(
                &unknown_anchor,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::AnchorNotRetained
        ));
        let other_pool = PrivacyProofManagedPoolSnapshotV1::canonical_pq_masp_bootstrap_for_test(
            PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(PrivacyPqMaspPoolBootstrapV1 {
                pool_id: PrivacyPoolIdV1::new([0xE4; 32]),
                asset_definition_id: fixture.statement.asset_definition_id.clone(),
                initial_note_commitments: vec![fixture.input_commitment],
            }),
        );
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&other_pool)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::NamespaceMismatch
        ));
        let ivm = IvmPrivateNotePreflightFixture::new();
        let cross_protocol = ivm.snapshot.with_namespace_for_test(namespace);
        assert!(matches!(
            prepare_pq_masp_transition_v1(
                &fixture.statement,
                namespace,
                Some(&cross_protocol),
            ),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::ProtocolOrRoleMismatch
        ));
        let wrong_role = fixture
            .snapshot
            .with_root_role_for_test(PrivacyRootRoleV1::ProgramState);
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&wrong_role)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::ProtocolOrRoleMismatch
        ));
        let wrong_asset = PrivacyProofManagedPoolSnapshotV1::canonical_pq_masp_bootstrap_for_test(
            PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(PrivacyPqMaspPoolBootstrapV1 {
                pool_id: fixture.statement.pool_id,
                asset_definition_id: AssetDefinitionId::derive_from_components(
                    DomainId::try_new("privacy", "universal").expect("domain"),
                    Name::from_str("wrong_pq_asset").expect("name"),
                ),
                initial_note_commitments: vec![fixture.input_commitment],
            }),
        );
        assert!(matches!(
            prepare_pq_masp_transition_v1(&fixture.statement, namespace, Some(&wrong_asset)),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::AssetMismatch
        ));
        let mut mismatched_commitment = fixture.statement.clone();
        mismatched_commitment.encrypted_outputs[0].commitment =
            PrivacyCommitmentV1::new([0xE5; 32]);
        assert!(matches!(
            prepare_pq_masp_transition_v1(
                &mismatched_commitment,
                namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(_))
        ));
        let mut corrupt_ciphertext = fixture.statement.clone();
        corrupt_ciphertext.encrypted_outputs[0].ciphertext[0] ^= 1;
        assert!(matches!(
            prepare_pq_masp_transition_v1(&corrupt_ciphertext, namespace, Some(&fixture.snapshot),),
            Err(PrivacyVerificationErrorV1::NativePqMasp(_))
        ));
        let mut wrong_key_digest = fixture.statement.clone();
        wrong_key_digest.note_encryption_key_digest =
            PrivacyNoteEncryptionKeyDigestV1::new([0xE6; 32]);
        assert!(matches!(
            prepare_pq_masp_transition_v1(&wrong_key_digest, namespace, Some(&fixture.snapshot),),
            Err(PrivacyVerificationErrorV1::NativePqMasp(_))
        ));
        let mut reordered_keys = fixture.statement.clone();
        let mut second_commitment = reordered_keys.output_commitments[0].into_bytes();
        second_commitment[0] ^= 1;
        let second_commitment = PrivacyCommitmentV1::new(second_commitment);
        let mut second_output = reordered_keys.encrypted_outputs[0].clone();
        second_output.commitment = second_commitment;
        second_output.recipient = PrivacyRecipientIdV1::new([0xE7; 32]);
        reordered_keys.output_commitments.push(second_commitment);
        reordered_keys.encrypted_outputs.push(second_output);
        reordered_keys.note_encryption_key_digest =
            derive_pq_masp_note_encryption_keys_digest_v1(&reordered_keys)
                .expect("canonical ordered two-output encryption digest");
        let [first, second] = reordered_keys.encrypted_outputs.as_mut_slice() else {
            panic!("adversarial statement must have exactly two encrypted outputs");
        };
        core::mem::swap(&mut first.recipient, &mut second.recipient);
        let ordered_namespace = PrivacyNamespaceV1::from_statement(
            &PrivacyStatementV1::PqMaspStarkV1(reordered_keys.clone()),
        );
        assert!(matches!(
            prepare_pq_masp_transition_v1(
                &reordered_keys,
                ordered_namespace,
                Some(&fixture.snapshot),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Ciphertext(
                        PqMaspWireErrorV1::EncryptedOutputBinding
                    )
                )
        ));
        let mut omitted_ciphertext = fixture.statement.clone();
        omitted_ciphertext.encrypted_outputs.clear();
        assert!(matches!(
            prepare_pq_masp_transition_v1(&omitted_ciphertext, namespace, Some(&fixture.snapshot),),
            Err(PrivacyVerificationErrorV1::NativePqMasp(_))
        ));
        assert_eq!(fixture.snapshot, pristine);
    }
    #[test]
    fn pq_masp_outer_authorization_and_inner_stark_are_independently_fail_closed() {
        let fixture = PqMaspPreflightFixture::new();
        let pristine = fixture.snapshot.clone();
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xE7; 32]),
            b"pq-masp-runtime-authorization",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("authorization key digest");
        let mut statement = fixture.statement.clone();
        statement.authorization_key_digest = key_digest;
        let unsigned = PqMaspPreflightFixture::envelope(&statement, Vec::new());
        let invalid_inner = vec![0xA5; 64];
        let genesis_hash = *statement.context.network_id.as_bytes();
        let consensus_binding = PrivacyNativeConsensusBindingV1::new(
            &statement.context,
            genesis_hash,
            &TEST_CONSENSUS_LIMITS,
        )
        .expect("canonical runtime PQ-MASP consensus binding");
        let consensus_binding_digest = consensus_binding
            .digest()
            .expect("canonical runtime PQ-MASP binding digest");
        let outer = authorize_pq_masp_stark_proof_v1(
            unsigned.statement_digest,
            consensus_binding_digest,
            key_digest,
            authorization_keys.secret_key(),
            &invalid_inner,
            HedgedRngSeed::from_entropy([0xE8; 32]),
        )
        .expect("canonical PQA1 wrapper");
        let envelope = PqMaspPreflightFixture::envelope(&statement, outer.clone());
        let (_, activation) = active_profile();
        let network_id = statement.context.network_id;
        let context = || PrivacyVerificationContextV1 {
            activation: &activation,
            consensus_limits: &TEST_CONSENSUS_LIMITS,
            network_id: &network_id,
            genesis_hash,
            current_height: 10,
            expected_action_index: 0,
            block_timestamp_ms: 1_800_000_000_000,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: Some(&fixture.snapshot),
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        };
        // A valid PQA1 wrapper around non-PQS1 bytes reaches and is rejected
        // by the inner native STARK verifier.
        assert!(matches!(
            verify_pq_masp_action_v1(
                &statement,
                envelope.proof.bytes(),
                &envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Proof(_)
                )
        ));
        let mut changed_genesis_context = context();
        let proving_genesis = changed_genesis_context.genesis_hash;
        changed_genesis_context.genesis_hash[0] ^= 1;
        assert_ne!(proving_genesis, [0; 32]);
        assert_ne!(changed_genesis_context.genesis_hash, [0; 32]);
        assert_ne!(changed_genesis_context.genesis_hash, proving_genesis);
        let changed_genesis_error = verify_pq_masp_action_v1(
            &statement,
            envelope.proof.bytes(),
            &envelope,
            &changed_genesis_context,
        )
        .expect_err("the exact PQ-MASP outer authorization must not replay across genesis");
        assert!(
            matches!(
                changed_genesis_error,
                PrivacyVerificationErrorV1::NativePqMasp(ref detail)
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::ConsensusBinding(
                        PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch
                    )
                )
            ),
            "changed genesis must fail the PQ-MASP typed network binding: \
             {changed_genesis_error:?}"
        );
        let mut changed_inner = outer.clone();
        *changed_inner.last_mut().expect("inner proof byte") ^= 1;
        let changed_inner_envelope = PqMaspPreflightFixture::envelope(&statement, changed_inner);
        assert!(matches!(
            verify_pq_masp_action_v1(
                &statement,
                changed_inner_envelope.proof.bytes(),
                &changed_inner_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Authorization(_)
                )
        ));
        let mut changed_signature = outer.clone();
        changed_signature[2_000] ^= 1;
        let changed_signature_envelope =
            PqMaspPreflightFixture::envelope(&statement, changed_signature);
        assert!(matches!(
            verify_pq_masp_action_v1(
                &statement,
                changed_signature_envelope.proof.bytes(),
                &changed_signature_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Authorization(_)
                )
        ));
        let wrong_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xE9; 32]),
            b"pq-masp-runtime-wrong-authorization",
        )
        .expect("wrong ML-DSA authorization key");
        let wrong_key_digest = derive_pq_masp_authorization_key_digest_v1(wrong_keys.public_key())
            .expect("wrong key digest");
        let wrong_key_outer = authorize_pq_masp_stark_proof_v1(
            envelope.statement_digest,
            consensus_binding_digest,
            wrong_key_digest,
            wrong_keys.secret_key(),
            &invalid_inner,
            HedgedRngSeed::from_entropy([0xEA; 32]),
        )
        .expect("wrong-key PQA1 wrapper");
        let wrong_key_envelope = PqMaspPreflightFixture::envelope(&statement, wrong_key_outer);
        assert!(matches!(
            verify_pq_masp_action_v1(
                &statement,
                wrong_key_envelope.proof.bytes(),
                &wrong_key_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Authorization(
                        PqMaspWireErrorV1::AuthorizationKeyMismatch
                    )
                )
        ));
        let mut wrong_authorization_epoch = statement.clone();
        wrong_authorization_epoch.authorization_epoch += 1;
        let wrong_authorization_epoch_envelope =
            PqMaspPreflightFixture::envelope(&wrong_authorization_epoch, outer.clone());
        assert!(matches!(
            verify_pq_masp_action_v1(
                &wrong_authorization_epoch,
                wrong_authorization_epoch_envelope.proof.bytes(),
                &wrong_authorization_epoch_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::NativePqMasp(detail))
                if matches!(
                    detail.source,
                    PrivacyPqMaspNativeFailureSourceV1::Authorization(
                        PqMaspWireErrorV1::AuthorizationFailed
                    )
                )
        ));
        let mut wrong_epoch = statement.clone();
        wrong_epoch.anchor_epoch += 1;
        wrong_epoch.authorization_epoch += 1;
        let wrong_epoch_envelope = PqMaspPreflightFixture::envelope(&wrong_epoch, outer.clone());
        assert!(matches!(
            verify_pq_masp_action_v1(
                &wrong_epoch,
                wrong_epoch_envelope.proof.bytes(),
                &wrong_epoch_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::AnchorNotRetained
        ));
        let mut wrong_anchor = statement.clone();
        let mut root = wrong_anchor.anchor.into_bytes();
        root[0] ^= 1;
        wrong_anchor.anchor = PrivacyRootV1::new(root);
        let wrong_anchor_envelope = PqMaspPreflightFixture::envelope(&wrong_anchor, outer);
        assert!(matches!(
            verify_pq_masp_action_v1(
                &wrong_anchor,
                wrong_anchor_envelope.proof.bytes(),
                &wrong_anchor_envelope,
                &context(),
            ),
            Err(PrivacyVerificationErrorV1::PqMaspState(detail))
                if detail.code == PrivacyPqMaspStateFailureCodeV1::AnchorNotRetained
        ));
        assert_eq!(fixture.snapshot, pristine);
    }
    #[test]
    fn fcmp_trusted_state_and_anchor_fail_closed_without_mutation() {
        let fixture = fcmp_fixture();
        let pristine = fixture.snapshot.clone();
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(None)
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::MissingTrustedState
        ));
        let statement = match &fixture.envelope.statement {
            PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) => statement,
            _ => unreachable!("FCMP++ fixture"),
        };
        let other_namespace = PrivacyProofManagedPoolSnapshotV1::canonical_fcmp_bootstrap_for_test(
            PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
                pool_id: PrivacyPoolIdV1::new([0xC5; 32]),
                asset_definition_id: statement.asset_definition_id.clone(),
                initial_outputs: vec![fixture.initial_output],
            }),
        );
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(Some(&other_namespace))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::NamespaceMismatch
        ));
        let wrong_asset = PrivacyProofManagedPoolSnapshotV1::canonical_fcmp_bootstrap_for_test(
            PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
                pool_id: statement.pool_id,
                asset_definition_id: AssetDefinitionId::derive_from_components(
                    DomainId::try_new("privacy", "universal").expect("domain"),
                    Name::from_str("wrong_fcmp_asset").expect("name"),
                ),
                initial_outputs: vec![fixture.initial_output],
            }),
        );
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(Some(&wrong_asset))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::AssetMismatch
        ));
        let no_current = fixture.snapshot.without_retained_current_root_for_test();
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(Some(&no_current))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::CurrentRootNotRetained
        ));
        let inconsistent = fixture
            .snapshot
            .with_inconsistent_fcmp_output_count_for_test();
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(Some(&inconsistent))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::FrontierMismatch
        ));
        let (unrelated_native, _, _) = fcmp_test_spendable_output_v1(103, 107, 109, 1, 113);
        let advanced = fixture
            .snapshot
            .with_fcmp_successor_for_test(&[model_fcmp_output(unrelated_native)]);
        let evicted = advanced.without_retained_root_for_test(
            statement.root_epoch,
            statement.output_set_root.history_commitment(),
        );
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(Some(&evicted))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::AnchorNotRetained
        ));
        let mut unknown_anchor = fixture.envelope.clone();
        let (other_native, _, _) = fcmp_test_spendable_output_v1(127, 131, 137, 1, 139);
        let other_root = build_fcmp_frontier_v1(&[other_native])
            .expect("other FCMP++ root")
            .root;
        let other_typed_root = PrivacyFcmpTreeRootV1 {
            layers: other_root.layers(),
            point: other_root.point(),
        };
        other_typed_root.validate().expect("typed other root");
        fcmp_statement_mut(&mut unknown_anchor).output_set_root = other_typed_root;
        refresh_statement_digest(&mut unknown_anchor);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &unknown_anchor,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::FcmpState(detail))
                if detail.code == PrivacyFcmpStateFailureCodeV1::AnchorNotRetained
        ));
        assert_eq!(fixture.snapshot, pristine);
    }
    #[test]
    fn fcmp_proof_balance_ciphertext_and_limits_fail_closed() {
        let fixture = fcmp_fixture();
        let pristine = fixture.snapshot.clone();
        let mut corrupt_proof = fixture.envelope.clone();
        let PrivacyProofV1::MoneroFcmpPlusPlusV1(proof) = &mut corrupt_proof.proof else {
            unreachable!("FCMP++ proof")
        };
        let middle = proof.bytes.len() / 2;
        proof.bytes[middle] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &corrupt_proof,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut corrupt_range_proof = fixture.envelope.clone();
        let PrivacyProofV1::MoneroFcmpPlusPlusV1(proof) = &mut corrupt_range_proof.proof else {
            unreachable!("FCMP++ proof")
        };
        let last = proof.bytes.len() - 1;
        proof.bytes[last] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &corrupt_range_proof,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut mismatching_output_count = fixture.envelope.clone();
        let PrivacyProofV1::MoneroFcmpPlusPlusV1(proof) = &mut mismatching_output_count.proof
        else {
            unreachable!("FCMP++ proof")
        };
        proof.bytes[6] = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &mismatching_output_count,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut changed_commitment = fixture.envelope.clone();
        let statement = fcmp_statement_mut(&mut changed_commitment);
        statement.outputs[0].amount_commitment = fixture.initial_output.amount_commitment;
        statement.encrypted_outputs[0].output_id = statement.outputs[0].output_id();
        refresh_statement_digest(&mut changed_commitment);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &changed_commitment,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut omitted_output = fixture.envelope.clone();
        let statement = fcmp_statement_mut(&mut omitted_output);
        statement.outputs.pop();
        statement.encrypted_outputs.pop();
        refresh_statement_digest(&mut omitted_output);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &omitted_output,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut reordered = fixture.envelope.clone();
        let statement = fcmp_statement_mut(&mut reordered);
        statement.outputs.swap(0, 1);
        statement.encrypted_outputs.swap(0, 1);
        refresh_statement_digest(&mut reordered);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &reordered,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut changed_intent = fixture.envelope.clone();
        fcmp_statement_mut(&mut changed_intent)
            .context
            .transaction_intent_digest
            .0[0] ^= 1;
        refresh_statement_digest(&mut changed_intent);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &changed_intent,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut tampered_ciphertext = fixture.envelope.clone();
        fcmp_statement_mut(&mut tampered_ciphertext).encrypted_outputs[0].ciphertext[40] ^= 1;
        refresh_statement_digest(&mut tampered_ciphertext);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &tampered_ciphertext,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut invalid_codec = fixture.envelope.clone();
        fcmp_statement_mut(&mut invalid_codec).encrypted_outputs[0].ciphertext[0] ^= 1;
        refresh_statement_digest(&mut invalid_codec);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &invalid_codec,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut invalid_ephemeral = fixture.envelope.clone();
        fcmp_statement_mut(&mut invalid_ephemeral).encrypted_outputs[0].ephemeral_public_key =
            PrivacyEncryptionKeyV1::new([u8::MAX; 32]);
        refresh_statement_digest(&mut invalid_ephemeral);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &invalid_ephemeral,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut duplicate_output = fixture.envelope.clone();
        let statement = fcmp_statement_mut(&mut duplicate_output);
        statement.outputs[1] = statement.outputs[0];
        statement.encrypted_outputs[1].output_id = statement.outputs[0].output_id();
        refresh_statement_digest(&mut duplicate_output);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &duplicate_output,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut too_many_inputs = fixture.envelope.clone();
        let statement = fcmp_statement_mut(&mut too_many_inputs);
        for multiple in [149_u64, 151] {
            let mut input = statement.inputs[0];
            input.pseudo_out = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
                * curve25519_dalek::scalar::Scalar::from(multiple))
            .compress()
            .to_bytes();
            input.key_image = PrivacyFcmpKeyImageV1::new(
                (curve25519_dalek::constants::ED25519_BASEPOINT_POINT
                    * curve25519_dalek::scalar::Scalar::from(multiple + 1))
                .compress()
                .to_bytes(),
            );
            statement.inputs.push(input);
        }
        refresh_statement_digest(&mut too_many_inputs);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &too_many_inputs,
                &fixture.verification_context(Some(&fixture.snapshot))
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        assert_eq!(fixture.snapshot, pristine);
    }
    #[test]
    fn fcmp_runtime_context_and_every_public_input_component_are_proof_bound() {
        let fixture = fcmp_fixture();
        let input_mutations: [fn(&mut PrivacyFcmpInputPublicV1); 5] = [
            |input| input.output_key_tilde = input.linking_tag_generator_tilde,
            |input| input.linking_tag_generator_tilde = input.rerandomization_commitment,
            |input| input.rerandomization_commitment = input.output_key_tilde,
            |input| input.pseudo_out = input.output_key_tilde,
            |input| input.key_image = PrivacyFcmpKeyImageV1::new(input.output_key_tilde),
        ];
        for mutate in input_mutations {
            let mut changed = fixture.envelope.clone();
            mutate(&mut fcmp_statement_mut(&mut changed).inputs[0]);
            refresh_statement_digest(&mut changed);
            assert!(
                matches!(
                    verify_privacy_envelope_v1(
                        &changed,
                        &fixture.verification_context(Some(&fixture.snapshot))
                    ),
                    Err(PrivacyVerificationErrorV1::NativeFcmp(_))
                ),
                "every authoritative O~/I~/R/C~/L component must be proof bound"
            );
        }
        let statement_mutations: [FcmpStatementMutation; 4] = [
            ("output key", |statement| {
                statement.outputs[0].output_key = statement.outputs[1].output_key;
                statement.encrypted_outputs[0].output_id = statement.outputs[0].output_id();
            }),
            ("linking-tag generator", |statement| {
                statement.outputs[0].linking_tag_generator =
                    statement.outputs[1].linking_tag_generator;
                statement.encrypted_outputs[0].output_id = statement.outputs[0].output_id();
            }),
            ("valid recipient", |statement| {
                statement.encrypted_outputs[0].recipient = statement.encrypted_outputs[1].recipient;
            }),
            ("valid ephemeral key", |statement| {
                statement.encrypted_outputs[0].ephemeral_public_key =
                    statement.encrypted_outputs[1].ephemeral_public_key;
            }),
        ];
        for (label, mutate) in statement_mutations {
            let mut changed = fixture.envelope.clone();
            mutate(fcmp_statement_mut(&mut changed));
            refresh_statement_digest(&mut changed);
            assert!(
                matches!(
                    verify_privacy_envelope_v1(
                        &changed,
                        &fixture.verification_context(Some(&fixture.snapshot))
                    ),
                    Err(PrivacyVerificationErrorV1::NativeFcmp(_))
                ),
                "FCMP++ proof accepted a structurally valid {label} substitution"
            );
        }
        let other_network = network_id(0xA8);
        let mut cross_chain = fixture.envelope.clone();
        fcmp_statement_mut(&mut cross_chain).context.network_id = other_network;
        refresh_statement_digest(&mut cross_chain);
        let mut cross_chain_context = fixture.verification_context(Some(&fixture.snapshot));
        cross_chain_context.network_id = &other_network;
        cross_chain_context.genesis_hash = *other_network.as_bytes();
        assert!(matches!(
            verify_privacy_envelope_v1(&cross_chain, &cross_chain_context),
            Err(PrivacyVerificationErrorV1::NativeFcmp(_))
        ));
        let mut other_action = fixture.envelope.clone();
        fcmp_statement_mut(&mut other_action).context.action_index = 1;
        refresh_statement_digest(&mut other_action);
        let mut other_action_context = fixture.verification_context(Some(&fixture.snapshot));
        other_action_context.expected_action_index = 1;
        let action_error = verify_privacy_envelope_v1(&other_action, &other_action_context)
            .expect_err("the first-release Taira action limit admits only index zero");
        assert!(
            matches!(
                &action_error,
                PrivacyVerificationErrorV1::Envelope(detail)
                    if matches!(
                        detail.source,
                        PrivacyProofEnvelopeValidationError::Statement(
                            PrivacyStatementValidationError::ActionIndexOutOfBounds {
                                index: 1,
                                max_actions: 1,
                            }
                        )
                    )
            ),
            "unexpected canonical action-index rejection: {action_error:?}"
        );
        // The Taira limit makes a second canonical action index impossible,
        // so exercise the lower native binding directly. This distinguishes
        // fail-closed envelope ordering from an accidentally unbound FCMP
        // transcript field.
        let mut replay_context = fixture.verification_context(Some(&fixture.snapshot));
        replay_context.expected_action_index = 1;
        let replay_runtime_context =
            fcmp_runtime_context_hash_v1(&fixture.envelope, &replay_context);
        let PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) = &fixture.envelope.statement
        else {
            unreachable!("FCMP++ fixture")
        };
        let native_root = FcmpTreeRootV1::new(
            statement.output_set_root.layers,
            statement.output_set_root.point,
        )
        .expect("fixture root");
        let native_inputs = statement
            .inputs
            .iter()
            .map(|input| {
                FcmpProofInputPublicV1::new(
                    input.output_key_tilde,
                    input.linking_tag_generator_tilde,
                    input.rerandomization_commitment,
                    input.pseudo_out,
                    input.key_image.into_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture public inputs");
        let native_outputs = statement
            .outputs
            .iter()
            .map(|output| {
                FcmpOutputTupleV1::new(
                    output.output_key,
                    output.linking_tag_generator,
                    output.amount_commitment,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture outputs");
        let PrivacyProofV1::MoneroFcmpPlusPlusV1(proof) = &fixture.envelope.proof else {
            unreachable!("FCMP++ fixture proof")
        };
        let native_error = verify_fcmp_transaction_v1(
            replay_runtime_context,
            proof.as_bytes(),
            &native_inputs,
            &native_outputs,
            native_root,
        )
        .expect_err("native FCMP++ proof must bind the action-index runtime context");
        assert!(
            !matches!(native_error, FcmpNativeErrorV1::ProofHeaderMismatch),
            "action-index replay reached only a structural mismatch instead of a proof equation: \
             {native_error:?}"
        );
        let mut other_genesis_context = fixture.verification_context(Some(&fixture.snapshot));
        other_genesis_context.genesis_hash[0] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &other_genesis_context),
            Err(PrivacyVerificationErrorV1::Context(detail))
                if detail.code == PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch
        ));
    }
    #[test]
    fn same_display_label_cannot_bridge_distinct_network_geneses() {
        let (envelope, activation, network_id) = valid_envelope();
        // A human-readable ChainName may be identical for these deployments;
        // it is deliberately absent from both the statement and verifier
        // context. Only the exact genesis-derived NetworkId participates here.
        let other_network = self::network_id(0xA8);
        let mut other_network_context = verification_context(&activation, &other_network);
        other_network_context.genesis_hash = *other_network.as_bytes();
        let error = verify_privacy_envelope_v1(&envelope, &other_network_context)
            .expect_err("wrong network");
        assert!(matches!(
            error,
            PrivacyVerificationErrorV1::Context(detail)
                if detail.code == PrivacyVerificationContextFailureCodeV1::NetworkIdMismatch
        ));
        let mut context = verification_context(&activation, &network_id);
        context.expected_action_index = 1;
        let error =
            verify_privacy_envelope_v1(&envelope, &context).expect_err("wrong action index");
        assert!(matches!(
            error,
            PrivacyVerificationErrorV1::Context(detail)
                if detail.code == PrivacyVerificationContextFailureCodeV1::ActionIndexMismatch
        ));
        let mut context = verification_context(&activation, &network_id);
        context.genesis_hash = [0; 32];
        let error = verify_privacy_envelope_v1(&envelope, &context).expect_err("zero genesis");
        assert!(matches!(
            error,
            PrivacyVerificationErrorV1::Context(detail)
                if detail.code == PrivacyVerificationContextFailureCodeV1::ZeroGenesisHash
        ));
    }
    #[test]
    fn admission_failure_precedence_is_activation_then_envelope_then_context() {
        let (envelope, activation, _) = valid_envelope();
        let wrong_network = network_id(0xA8);
        let mut malformed_envelope = envelope.clone();
        malformed_envelope.proof =
            PrivacyProofV1::ZkAcePqAuthorizationV1(envelope.proof.bytes().clone());
        let mut altered_activation = activation;
        altered_activation.verifier_digest.0[0] ^= 1;
        let mut all_invalid_context = verification_context(&altered_activation, &wrong_network);
        all_invalid_context.genesis_hash = [0; 32];
        all_invalid_context.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&malformed_envelope, &all_invalid_context),
            Err(PrivacyVerificationErrorV1::CompiledActivation(_))
        ));
        let mut envelope_and_context_invalid = verification_context(&activation, &wrong_network);
        envelope_and_context_invalid.genesis_hash = [0; 32];
        envelope_and_context_invalid.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&malformed_envelope, &envelope_and_context_invalid),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut context_only_invalid = verification_context(&activation, &wrong_network);
        context_only_invalid.genesis_hash = [0; 32];
        context_only_invalid.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&envelope, &context_only_invalid),
            Err(PrivacyVerificationErrorV1::Context(detail))
                if detail.code == PrivacyVerificationContextFailureCodeV1::ZeroGenesisHash
        ));
    }
    #[test]
    fn altered_activation_statement_and_proof_are_rejected() {
        let (envelope, activation, network_id) = valid_envelope();
        let mut altered_activation = activation;
        altered_activation.verifier_digest.0[0] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &envelope,
                &verification_context(&altered_activation, &network_id)
            ),
            Err(PrivacyVerificationErrorV1::CompiledActivation(_))
        ));
        let mut altered_statement = envelope.clone();
        let PrivacyStatementV1::VeRangeTransparentRangeV1(statement) =
            &mut altered_statement.statement
        else {
            unreachable!("fixture")
        };
        statement.value_commitments[0] = PrivacyP256PointV1::new([0xFF; 33]);
        altered_statement.statement_digest = altered_statement
            .statement
            .digest()
            .expect("changed digest");
        assert!(matches!(
            verify_privacy_envelope_v1(
                &altered_statement,
                &verification_context(&activation, &network_id)
            ),
            Err(PrivacyVerificationErrorV1::NativeVeRange(_))
        ));
        let mut altered_proof = envelope.clone();
        let PrivacyProofV1::VeRangeTransparentRangeV1(proof) = &mut altered_proof.proof else {
            unreachable!("fixture")
        };
        let last = proof.bytes.last_mut().expect("proof is non-empty");
        *last ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &altered_proof,
                &verification_context(&activation, &network_id)
            ),
            Err(PrivacyVerificationErrorV1::NativeVeRange(_))
        ));
        let mut context = verification_context(&activation, &network_id);
        context.genesis_hash[0] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&envelope, &context),
            Err(PrivacyVerificationErrorV1::Context(detail))
                if detail.code == PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch
        ));
    }
    #[test]
    fn proof_wire_rejects_truncation_extensions_and_single_byte_malleation() {
        let (envelope, activation, network_id) = valid_envelope();
        let PrivacyProofV1::VeRangeTransparentRangeV1(proof) = &envelope.proof else {
            unreachable!("VeRange fixture")
        };
        let proof_len = proof.bytes.len();
        assert!(proof_len > 8, "fixture must exercise a structured proof");
        for length in [0, 1, proof_len / 3, proof_len / 2, proof_len - 1] {
            let mut candidate = envelope.clone();
            let PrivacyProofV1::VeRangeTransparentRangeV1(bytes) = &mut candidate.proof else {
                unreachable!("VeRange fixture")
            };
            bytes.bytes.truncate(length);
            assert_rejected(
                &candidate,
                &activation,
                &network_id,
                &format!("truncated-{length}"),
            );
        }
        for suffix in [&[0_u8][..], &[0xFF][..], &[0x00, 0xFF][..]] {
            let mut candidate = envelope.clone();
            let PrivacyProofV1::VeRangeTransparentRangeV1(bytes) = &mut candidate.proof else {
                unreachable!("VeRange fixture")
            };
            bytes.bytes.extend_from_slice(suffix);
            assert_rejected(
                &candidate,
                &activation,
                &network_id,
                &format!("trailing-{}", suffix.len()),
            );
        }
        for offset in [0, 1, proof_len / 3, proof_len / 2, proof_len - 1] {
            let mut candidate = envelope.clone();
            let PrivacyProofV1::VeRangeTransparentRangeV1(bytes) = &mut candidate.proof else {
                unreachable!("VeRange fixture")
            };
            bytes.bytes[offset] ^= 0x80;
            assert_rejected(
                &candidate,
                &activation,
                &network_id,
                &format!("bit-flip-{offset}"),
            );
        }
        let mut all_zero = envelope.clone();
        let PrivacyProofV1::VeRangeTransparentRangeV1(bytes) = &mut all_zero.proof else {
            unreachable!("VeRange fixture")
        };
        bytes.bytes.fill(0);
        assert_rejected(&all_zero, &activation, &network_id, "all-zero-proof");
    }
    #[test]
    fn statement_shape_order_and_public_inputs_are_cryptographically_bound() {
        let (envelope, activation, network_id) = valid_envelope();
        let mut empty = envelope.clone();
        let statement = verange_statement_mut(&mut empty);
        statement.value_commitments.clear();
        statement.aggregation_count = 0;
        refresh_statement_digest(&mut empty);
        assert_rejected(&empty, &activation, &network_id, "empty-batch");
        let mut count_mismatch = envelope.clone();
        verange_statement_mut(&mut count_mismatch).aggregation_count = 1;
        refresh_statement_digest(&mut count_mismatch);
        assert_rejected(
            &count_mismatch,
            &activation,
            &network_id,
            "aggregation-count-mismatch",
        );
        let mut duplicate = envelope.clone();
        let statement = verange_statement_mut(&mut duplicate);
        statement.value_commitments[1] = statement.value_commitments[0];
        refresh_statement_digest(&mut duplicate);
        assert_rejected(&duplicate, &activation, &network_id, "duplicate-commitment");
        let mut reordered = envelope.clone();
        verange_statement_mut(&mut reordered)
            .value_commitments
            .swap(0, 1);
        refresh_statement_digest(&mut reordered);
        assert_rejected(
            &reordered,
            &activation,
            &network_id,
            "reordered-commitments",
        );
        let mut changed_policy = envelope.clone();
        verange_statement_mut(&mut changed_policy).policy_id = PrivacyPolicyIdV1::new([0xA3; 32]);
        refresh_statement_digest(&mut changed_policy);
        assert_rejected(&changed_policy, &activation, &network_id, "changed-policy");
        let mut changed_asset = envelope.clone();
        verange_statement_mut(&mut changed_asset).asset_definition_id =
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("other_asset").expect("name"),
            );
        refresh_statement_digest(&mut changed_asset);
        assert_rejected(&changed_asset, &activation, &network_id, "changed-asset");
        let mut changed_profile = envelope.clone();
        verange_statement_mut(&mut changed_profile).bit_length = PrivacyVeRangeBitLengthV1::Bits64;
        refresh_statement_digest(&mut changed_profile);
        assert_rejected(
            &changed_profile,
            &activation,
            &network_id,
            "changed-bit-length",
        );
    }
    #[test]
    fn governance_lifecycle_and_transcript_context_cannot_be_replayed() {
        let (envelope, activation, network_id) = valid_envelope();
        let mut proposed = activation;
        proposed.lifecycle = PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
            proposed_at_height: 1,
        });
        assert!(matches!(
            verify_privacy_envelope_v1(
                &envelope,
                &verification_context(&proposed, &network_id)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(detail))
                if matches!(
                    detail.source,
                    PrivacyProofEnvelopeValidationError::ActivationNotActive
                )
        ));
        let mut future = activation;
        let PrivacyProtocolLifecycleV1::Active(ref mut active) = future.lifecycle else {
            unreachable!("active fixture")
        };
        active.state_since_height = 11;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &envelope,
                &verification_context(&future, &network_id)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(detail))
                if matches!(
                    detail.source,
                    PrivacyProofEnvelopeValidationError::ActivationNotEffective {
                        current_height: 10,
                        effective_height: 11,
                    }
                )
        ));
        let replay_network = self::network_id(0xA8);
        let mut replayed = envelope.clone();
        verange_statement_mut(&mut replayed).context.network_id = replay_network;
        refresh_statement_digest(&mut replayed);
        let mut replay_context = verification_context(&activation, &replay_network);
        replay_context.genesis_hash = *replay_network.as_bytes();
        assert!(matches!(
            verify_privacy_envelope_v1(&replayed, &replay_context),
            Err(PrivacyVerificationErrorV1::NativeVeRange(_))
        ));
        let mut replayed = envelope.clone();
        verange_statement_mut(&mut replayed).context.action_index = 1;
        refresh_statement_digest(&mut replayed);
        let mut context = verification_context(&activation, &network_id);
        context.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&replayed, &context),
            Err(PrivacyVerificationErrorV1::Envelope(_)
                | PrivacyVerificationErrorV1::NativeVeRange(_))
        ));
    }
    #[test]
    fn jindo_runtime_verification_is_non_mutating_and_honors_the_authoritative_proof_cap() {
        let fixture = jindo_fixture();
        let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(proof) = &fixture.envelope.proof
        else {
            unreachable!("Jindo fixture")
        };
        assert_eq!(proof.as_bytes().len(), JINDO_NATIVE_PROOF_BYTES_V1);
        let effects = verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
        )
        .expect("valid native Jindo proof");
        assert_eq!(
            effects.protocol_id(),
            PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
        );
        assert_eq!(
            effects.statement_digest(),
            fixture.envelope.statement_digest
        );
        assert_eq!(effects.action_index(), 0);
        assert_eq!(effects.ledger(), &VerifiedPrivacyLedgerEffectsV1::None);
        let proof_len = u32::try_from(proof.as_bytes().len()).expect("Jindo proof length fits u32");
        let mut exact_limit = TEST_CONSENSUS_LIMITS;
        exact_limit.max_proof_bytes_per_action = proof_len;
        verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(&exact_limit),
        )
        .expect("exact proof-byte boundary is admitted");
        let mut one_byte_below = exact_limit;
        one_byte_below.max_proof_bytes_per_action = proof_len - 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(&one_byte_below)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    #[test]
    fn vega_unavailable_engine_has_no_verifier_bypass() {
        let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
    }
    #[test]
    fn jindo_wire_rejects_truncation_extension_cross_suite_and_relation_malleation() {
        let fixture = jindo_fixture();
        let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(valid_proof) = &fixture.envelope.proof
        else {
            unreachable!("Jindo fixture")
        };
        let proof_len = valid_proof.as_bytes().len();
        for length in [1, proof_len / 2, proof_len - 1] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(bytes) = &mut candidate.proof
            else {
                unreachable!("Jindo fixture")
            };
            bytes.bytes.truncate(length);
            assert_native_jindo_rejected(
                &candidate,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
                &format!("truncated-{length}"),
            );
        }
        for suffix in [&[0_u8][..], &[0xff][..], &[0, 0xff][..]] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(bytes) = &mut candidate.proof
            else {
                unreachable!("Jindo fixture")
            };
            bytes.bytes.extend_from_slice(suffix);
            assert_native_jindo_rejected(
                &candidate,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
                &format!("trailing-{}", suffix.len()),
            );
        }
        for offset in [0, proof_len / 3, proof_len / 2, proof_len - 1] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(bytes) = &mut candidate.proof
            else {
                unreachable!("Jindo fixture")
            };
            bytes.bytes[offset] ^= 0x80;
            assert_native_jindo_rejected(
                &candidate,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
                &format!("bit-flip-{offset}"),
            );
        }
        let mut empty = fixture.envelope.clone();
        empty.proof =
            PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(Vec::new()));
        assert!(matches!(
            verify_privacy_envelope_v1(
                &empty,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut all_zero = fixture.envelope.clone();
        all_zero.proof = PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(
            PrivacyProofBytesV1::new(vec![0; proof_len]),
        );
        assert!(matches!(
            verify_privacy_envelope_v1(
                &all_zero,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut cross_suite = fixture.envelope.clone();
        cross_suite.proof = PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(
            valid_proof.as_bytes().to_vec(),
        ));
        assert!(matches!(
            verify_privacy_envelope_v1(
                &cross_suite,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    #[test]
    fn jindo_transcript_rejects_intent_statement_network_action_and_governance_replay() {
        let fixture = jindo_fixture();
        let mut stale_digest = fixture.envelope.clone();
        jindo_statement_mut(&mut stale_digest).claimed_evaluations[0] = jindo_field(17);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &stale_digest,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut changed_intent = fixture.envelope.clone();
        jindo_statement_mut(&mut changed_intent)
            .context
            .transaction_intent_digest = PrivacyTransactionIntentDigestV1::new([0xd3; 32]);
        refresh_statement_digest(&mut changed_intent);
        assert_native_jindo_rejected(
            &changed_intent,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
            "transaction-intent replay",
        );
        let mut changed_point = fixture.envelope.clone();
        jindo_statement_mut(&mut changed_point).evaluation_point = jindo_field(19);
        refresh_statement_digest(&mut changed_point);
        assert_native_jindo_rejected(
            &changed_point,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
            "evaluation-point mutation",
        );
        let mut changed_claim = fixture.envelope.clone();
        jindo_statement_mut(&mut changed_claim).claimed_evaluations[0] = jindo_field(23);
        refresh_statement_digest(&mut changed_claim);
        assert_native_jindo_rejected(
            &changed_claim,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
            "claimed-evaluation mutation",
        );
        let mut changed_commitment = fixture.envelope.clone();
        let coefficient_bytes = &mut jindo_statement_mut(&mut changed_commitment)
            .polynomial_commitments[0]
            .encoding[..4];
        let coefficient = i32::from_le_bytes(
            coefficient_bytes
                .try_into()
                .expect("fixed coefficient width"),
        );
        let replacement = if coefficient == IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1 {
            coefficient - 1
        } else {
            coefficient + 1
        };
        coefficient_bytes.copy_from_slice(&replacement.to_le_bytes());
        refresh_statement_digest(&mut changed_commitment);
        assert_native_jindo_rejected(
            &changed_commitment,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
            "commitment mutation",
        );
        let replay_network = network_id(0xA8);
        let mut changed_network = fixture.envelope.clone();
        jindo_statement_mut(&mut changed_network).context.network_id = replay_network;
        refresh_statement_digest(&mut changed_network);
        let mut replay_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        replay_context.network_id = &replay_network;
        replay_context.genesis_hash = *replay_network.as_bytes();
        assert_native_jindo_rejected(&changed_network, &replay_context, "cross-network replay");
        let mut changed_genesis_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        changed_genesis_context.genesis_hash[0] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &changed_genesis_context),
            Err(PrivacyVerificationErrorV1::Context(detail))
                if detail.code
                    == PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch
        ));
        let mut changed_action = fixture.envelope.clone();
        jindo_statement_mut(&mut changed_action)
            .context
            .action_index = 1;
        refresh_statement_digest(&mut changed_action);
        let mut action_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        action_context.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&changed_action, &action_context),
            Err(PrivacyVerificationErrorV1::Envelope(_)
                | PrivacyVerificationErrorV1::NativeJindo(_))
        ));
        let governed_mutations: [fn(&mut PrivacyProofEnvelopeV1); 5] = [
            |value| value.parameter_id.0[0] ^= 1,
            |value| value.parameter_digest.0[0] ^= 1,
            |value| value.verifier_digest.0[0] ^= 1,
            |value| value.statement_schema_digest.0[0] ^= 1,
            |value| value.engine_manifest_digest.0[0] ^= 1,
        ];
        for mutate in governed_mutations {
            let mut candidate = fixture.envelope.clone();
            mutate(&mut candidate);
            assert!(matches!(
                verify_privacy_envelope_v1(
                    &candidate,
                    &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
                ),
                Err(PrivacyVerificationErrorV1::Envelope(_))
            ));
        }
        let mut altered_activation = fixture.activation;
        altered_activation.verifier_digest.0[0] ^= 1;
        let mut context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        context.activation = &altered_activation;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &context),
            Err(PrivacyVerificationErrorV1::CompiledActivation(_))
        ));
    }
    #[test]
    fn bootle_lantern_runtime_verifies_without_effects_and_enforces_the_exact_proof_cap() {
        let fixture = bootle_lantern_fixture();
        let PrivacyProofV1::IrohaBootleLanternAnoncredV1(proof) = &fixture.envelope.proof else {
            unreachable!("Bootle/Lantern fixture")
        };
        assert_eq!(proof.as_bytes().len(), BOOTLE_LANTERN_PROOF_BYTES_V1);
        let effects = verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(&TEST_CONSENSUS_LIMITS),
        )
        .expect("valid Bootle/Lantern presentation");
        assert_eq!(
            effects.protocol_id(),
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1
        );
        assert_eq!(
            effects.statement_digest(),
            fixture.envelope.statement_digest
        );
        assert_eq!(effects.action_index(), 0);
        assert_eq!(effects.ledger(), &VerifiedPrivacyLedgerEffectsV1::None);
        let proof_len =
            u32::try_from(proof.as_bytes().len()).expect("Bootle/Lantern proof length fits u32");
        let mut exact_limit = TEST_CONSENSUS_LIMITS;
        exact_limit.max_proof_bytes_per_action = proof_len;
        verify_privacy_envelope_v1(
            &fixture.envelope,
            &fixture.verification_context(&exact_limit),
        )
        .expect("exact proof-byte boundary is admitted");
        let mut one_byte_below = exact_limit;
        one_byte_below.max_proof_bytes_per_action = proof_len - 1;
        assert!(matches!(
            verify_privacy_envelope_v1(
                &fixture.envelope,
                &fixture.verification_context(&one_byte_below)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    include!("privacy_verifier/bootle_lantern_policy_test.rs");
    #[test]
    fn bootle_lantern_wire_rejects_truncation_extension_malleation_and_cross_suite_replay() {
        let fixture = bootle_lantern_fixture();
        let PrivacyProofV1::IrohaBootleLanternAnoncredV1(valid_proof) = &fixture.envelope.proof
        else {
            unreachable!("Bootle/Lantern fixture")
        };
        let proof_len = valid_proof.as_bytes().len();
        for length in [1, proof_len / 3, proof_len / 2, proof_len - 1] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaBootleLanternAnoncredV1(bytes) = &mut candidate.proof else {
                unreachable!("Bootle/Lantern fixture")
            };
            bytes.bytes.truncate(length);
            assert!(
                matches!(
                    verify_privacy_envelope_v1(
                        &candidate,
                        &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
                    ),
                    Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
                ),
                "truncated Bootle/Lantern proof length {length} was not rejected by the native boundary"
            );
        }
        for suffix in [&[0_u8][..], &[0xff][..], &[0, 0xff][..]] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaBootleLanternAnoncredV1(bytes) = &mut candidate.proof else {
                unreachable!("Bootle/Lantern fixture")
            };
            bytes.bytes.extend_from_slice(suffix);
            assert!(matches!(
                verify_privacy_envelope_v1(
                    &candidate,
                    &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
                ),
                Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
            ));
        }
        for offset in [0, 1, proof_len / 3, proof_len / 2, proof_len - 1] {
            let mut candidate = fixture.envelope.clone();
            let PrivacyProofV1::IrohaBootleLanternAnoncredV1(bytes) = &mut candidate.proof else {
                unreachable!("Bootle/Lantern fixture")
            };
            bytes.bytes[offset] ^= 0x80;
            assert!(matches!(
                verify_privacy_envelope_v1(
                    &candidate,
                    &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
                ),
                Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
            ));
        }
        let mut noncanonical_residue = fixture.envelope.clone();
        let PrivacyProofV1::IrohaBootleLanternAnoncredV1(bytes) = &mut noncanonical_residue.proof
        else {
            unreachable!("Bootle/Lantern fixture")
        };
        bytes.bytes[8..16].fill(0xff);
        assert!(matches!(
            verify_privacy_envelope_v1(
                &noncanonical_residue,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
        ));
        let mut cross_suite = fixture.envelope.clone();
        cross_suite.proof = PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(
            PrivacyProofBytesV1::new(valid_proof.as_bytes().to_vec()),
        );
        assert!(matches!(
            verify_privacy_envelope_v1(
                &cross_suite,
                &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
            ),
            Err(PrivacyVerificationErrorV1::Envelope(_))
        ));
    }
    #[test]
    fn bootle_lantern_statement_intent_network_action_and_policy_are_proof_bound() {
        let fixture = bootle_lantern_fixture();
        let statement_mutations: [fn(&mut IrohaBootleLanternAnoncredStatementV1); 8] = [
            |statement| statement.context.transaction_intent_digest.0[0] ^= 1,
            |statement| statement.issuer_id.0[0] ^= 1,
            |statement| statement.policy_id.0[0] ^= 1,
            |statement| statement.issuer_policy_epoch += 1,
            |statement| statement.issuer_policy_record_digest.0[0] ^= 1,
            |statement| statement.issuer_parameter_id.0[0] ^= 1,
            |statement| statement.issuer_parameter_digest.0[0] ^= 1,
            |statement| statement.disclosures[0].value.0[0] ^= 1,
        ];
        for mutate in statement_mutations {
            let mut candidate = fixture.envelope.clone();
            mutate(bootle_lantern_statement_mut(&mut candidate));
            refresh_statement_digest(&mut candidate);
            assert!(matches!(
                verify_privacy_envelope_v1(
                    &candidate,
                    &fixture.verification_context(&TEST_CONSENSUS_LIMITS)
                ),
                Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
            ));
        }
        let replay_network = network_id(0xA8);
        let mut changed_network = fixture.envelope.clone();
        bootle_lantern_statement_mut(&mut changed_network)
            .context
            .network_id = replay_network;
        refresh_statement_digest(&mut changed_network);
        let mut replay_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        replay_context.network_id = &replay_network;
        replay_context.genesis_hash = *replay_network.as_bytes();
        assert!(matches!(
            verify_privacy_envelope_v1(&changed_network, &replay_context),
            Err(PrivacyVerificationErrorV1::NativeBootleLantern(_))
        ));
        let mut changed_genesis = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        changed_genesis.genesis_hash[0] ^= 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &changed_genesis),
            Err(PrivacyVerificationErrorV1::Context(detail))
                if detail.code == PrivacyVerificationContextFailureCodeV1::NetworkGenesisMismatch
        ));
        let mut changed_action = fixture.envelope.clone();
        bootle_lantern_statement_mut(&mut changed_action)
            .context
            .action_index = 1;
        refresh_statement_digest(&mut changed_action);
        let mut action_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        action_context.expected_action_index = 1;
        assert!(matches!(
            verify_privacy_envelope_v1(&changed_action, &action_context),
            Err(PrivacyVerificationErrorV1::NativeBootleLantern(_)
                | PrivacyVerificationErrorV1::Envelope(_))
        ));
        let mut altered_activation = fixture.activation;
        altered_activation.engine_manifest_digest.0[0] ^= 1;
        let mut activation_context = fixture.verification_context(&TEST_CONSENSUS_LIMITS);
        activation_context.activation = &altered_activation;
        assert!(matches!(
            verify_privacy_envelope_v1(&fixture.envelope, &activation_context),
            Err(PrivacyVerificationErrorV1::CompiledActivation(_))
        ));
    }
    include!("privacy_verifier/governed_binding_tests.rs");
    include!("privacy_verifier/role_dispatch_tests.rs");
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_fixtures {
    use super::*;
    use crate::privacy_engines::{
        fcmp_plus_plus::{
            FcmpInputRerandomizationV1, FcmpProverInputV1, FcmpWalletNoteV1,
            build_fcmp_frontier_v1, encrypt_fcmp_wallet_note_v1, fcmp_recipient_public_key_v1,
            fcmp_test_spendable_output_v1, prove_fcmp_plus_plus_v1,
        },
        zk_ams::{
            ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, ZK_AMS_MIN_RING_SIZE_V1,
            ZkAmsBatchCredentialWitnessV1, ZkAmsSeedSecretV1, prove_zk_ams_batch_admission_v1,
            sign_zk_ams_provision_statement_v1, zk_ams_generator_digest_v1, zk_ams_key_image_v1,
            zk_ams_registry_transition_root_v1, zk_ams_seed_public_key_v1,
        },
    };
    use crate::privacy_profiles::compiled_privacy_profile_v1;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{NetworkId, asset::AssetDefinitionId, block::BlockHeader, privacy::*};
    use iroha_model_base::{domain::DomainId, name::Name};
    use iroha_zkp_halo2::vega::ZkAmsMaskedProverConfigV1;
    use p256::ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey,
        signature::hazmat::PrehashSigner as _,
    };
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    use sha2::{Digest, Sha256};
    use std::{str::FromStr as _, sync::OnceLock};
    const TEST_CONSENSUS_LIMITS: PrivacyConsensusLimitsV1 =
        PrivacyConsensusLimitsV1::taira_default();
    pub(super) fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    pub(super) struct KatRng {
        pub(super) seed: [u8; 32],
        pub(super) counter: u64,
    }
    impl KatRng {
        pub(super) fn new(seed: [u8; 32]) -> Self {
            Self { seed, counter: 0 }
        }
    }
    impl RngCore for KatRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(32) {
                let mut hash = Sha256::new();
                hash.update(b"iroha.privacy.verifier.kat-rng.v1");
                hash.update(self.seed);
                hash.update(self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block: [u8; 32] = hash.finalize().into();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for KatRng {}
    pub(super) fn fcmp_scalar(value: u64) -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar[..8].copy_from_slice(&value.to_le_bytes());
        scalar
    }
    pub(super) fn model_fcmp_output(output: FcmpOutputTupleV1) -> PrivacyFcmpOutputTupleV1 {
        let (output_key, linking_tag_generator, amount_commitment) = output.components();
        PrivacyFcmpOutputTupleV1 {
            output_key,
            linking_tag_generator,
            amount_commitment,
        }
    }
    pub(super) struct FcmpFixture {
        pub(super) envelope: PrivacyProofEnvelopeV1,
        pub(super) activation: PrivacyProtocolActivationRecordV1,
        pub(super) network_id: NetworkId,
        pub(super) snapshot: PrivacyProofManagedPoolSnapshotV1,
        pub(super) initial_output: PrivacyFcmpOutputTupleV1,
    }
    impl FcmpFixture {
        pub(super) fn new() -> Self {
            let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)
                .expect("compiled FCMP++");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let pool_id = PrivacyPoolIdV1::new([0xC1; 32]);
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("fcmp_asset").expect("name"),
            );
            let (initial_native, spend_x, output_y) =
                fcmp_test_spendable_output_v1(17, 23, 31, 11, 37);
            let initial_output = model_fcmp_output(initial_native);
            let bootstrap = PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(
                PrivacyFcmpPoolBootstrapV1 {
                    pool_id,
                    asset_definition_id: asset_definition_id.clone(),
                    initial_outputs: vec![initial_output],
                },
            );
            let snapshot =
                PrivacyProofManagedPoolSnapshotV1::canonical_fcmp_bootstrap_for_test(bootstrap);
            let native_root = build_fcmp_frontier_v1(&[initial_native])
                .expect("FCMP++ origin frontier")
                .root;
            assert_eq!(
                snapshot
                    .fcmp_accumulator_state()
                    .expect("FCMP++ frontier")
                    .root()
                    .point,
                native_root.point()
            );
            let (first_native_output, first_spend_x, first_output_y) =
                fcmp_test_spendable_output_v1(43, 47, 53, 4, 29);
            let (second_native_output, second_spend_x, second_output_y) =
                fcmp_test_spendable_output_v1(59, 61, 67, 7, 49);
            let native_outputs = [first_native_output, second_native_output];
            let outputs = native_outputs
                .into_iter()
                .map(model_fcmp_output)
                .collect::<Vec<_>>();
            let output_notes = [
                FcmpWalletNoteV1::new(
                    first_native_output,
                    first_spend_x,
                    first_output_y,
                    4,
                    fcmp_scalar(29),
                )
                .expect("first FCMP++ output note"),
                FcmpWalletNoteV1::new(
                    second_native_output,
                    second_spend_x,
                    second_output_y,
                    7,
                    fcmp_scalar(49),
                )
                .expect("second FCMP++ output note"),
            ];
            let mut encryption_rng = KatRng::new([0xC4; 32]);
            let encrypted_outputs = outputs
                .iter()
                .copied()
                .zip(&output_notes)
                .enumerate()
                .map(|(index, (output, note))| {
                    let recipient_secret = [0xD0 + u8::try_from(index).expect("fixture index"); 32];
                    let recipient_public = fcmp_recipient_public_key_v1(recipient_secret)
                        .expect("FCMP++ recipient public key");
                    encrypt_fcmp_wallet_note_v1(
                        &mut encryption_rng,
                        pool_id,
                        output,
                        note,
                        recipient_public,
                    )
                    .expect("canonical FCMP++ encrypted output")
                })
                .collect();
            let rerandomization = FcmpInputRerandomizationV1::new(
                fcmp_scalar(71),
                fcmp_scalar(73),
                fcmp_scalar(79),
                fcmp_scalar(41),
            )
            .expect("FCMP++ rerandomization");
            let prover_input = FcmpProverInputV1::new(
                initial_native,
                spend_x,
                output_y,
                rerandomization,
                vec![initial_native],
                Vec::new(),
            )
            .expect("FCMP++ prover input");
            let native_public = prover_input.public_input().expect("FCMP++ public input");
            let statement =
                PrivacyStatementV1::MoneroFcmpPlusPlusV1(MoneroFcmpPlusPlusStatementV1 {
                    context: PrivacyStatementContextV1 {
                        network_id,
                        action_index: 0,
                        transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(
                            [0xC2; 32],
                        ),
                        parameter_id: compiled.parameter_id,
                        parameter_digest: compiled.parameter_digest,
                        verifier_digest: compiled.verifier_digest,
                        statement_schema_digest: compiled.statement_schema_digest,
                        engine_manifest_digest: compiled.engine_manifest_digest,
                    },
                    asset_definition_id,
                    pool_id,
                    output_set_root: snapshot
                        .fcmp_accumulator_state()
                        .expect("FCMP++ frontier")
                        .root(),
                    root_epoch: snapshot.current_epoch(),
                    inputs: vec![PrivacyFcmpInputPublicV1 {
                        output_key_tilde: native_public.output_key_tilde,
                        linking_tag_generator_tilde: native_public.linking_tag_generator_tilde,
                        rerandomization_commitment: native_public.rerandomization_commitment,
                        pseudo_out: native_public.pseudo_out,
                        key_image: PrivacyFcmpKeyImageV1::new(native_public.key_image),
                    }],
                    outputs: outputs.clone(),
                    encrypted_outputs,
                });
            let statement_digest = statement.digest().expect("FCMP++ statement digest");
            let mut envelope = PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest,
                statement,
                proof: PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(Vec::new())),
            };
            let verification_context = PrivacyVerificationContextV1 {
                activation: &activation,
                consensus_limits: &TEST_CONSENSUS_LIMITS,
                network_id: &network_id,
                genesis_hash: [0xA7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: None,
                orchard_state: None,
                proof_managed_state: Some(&snapshot),
                zk_x509_state: None,
                bootle_lantern_policy: None,
                vega_issuer_record: None,
            };
            let runtime_context = fcmp_runtime_context_hash_v1(&envelope, &verification_context);
            let output_openings = output_notes
                .iter()
                .map(FcmpWalletNoteV1::commitment_opening)
                .collect::<Result<Vec<_>, _>>()
                .expect("FCMP++ output range openings");
            let proof = prove_fcmp_plus_plus_v1(
                &mut KatRng::new([0xC3; 32]),
                runtime_context,
                &[prover_input],
                &output_openings,
                native_root,
            )
            .expect("FCMP++ proof");
            assert_eq!(proof.public_inputs(), &[native_public]);
            envelope.proof = PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(
                proof.proof_wire().to_vec(),
            ));
            Self {
                envelope,
                activation,
                network_id,
                snapshot,
                initial_output,
            }
        }
        #[cfg(test)]
        pub(super) fn verification_context<'a>(
            &'a self,
            snapshot: Option<&'a PrivacyProofManagedPoolSnapshotV1>,
        ) -> PrivacyVerificationContextV1<'a> {
            PrivacyVerificationContextV1 {
                activation: &self.activation,
                consensus_limits: &TEST_CONSENSUS_LIMITS,
                network_id: &self.network_id,
                genesis_hash: [0xA7; 32],
                current_height: 10,
                expected_action_index: 0,
                block_timestamp_ms: 1_800_000_000_000,
                pgc_state: None,
                orchard_state: None,
                proof_managed_state: snapshot,
                zk_x509_state: None,
                bootle_lantern_policy: None,
                vega_issuer_record: None,
            }
        }
    }
    pub(super) fn fcmp_fixture() -> &'static FcmpFixture {
        static FIXTURE: OnceLock<FcmpFixture> = OnceLock::new();
        FIXTURE.get_or_init(FcmpFixture::new)
    }
    #[doc(hidden)]
    pub struct FcmpRuntimeFixtureForTest {
        pub envelope: PrivacyProofEnvelopeV1,
        pub activation: PrivacyProtocolActivationRecordV1,
        pub network_id: NetworkId,
        pub snapshot: PrivacyProofManagedPoolSnapshotV1,
        pub initial_output: PrivacyFcmpOutputTupleV1,
        pub genesis_hash: [u8; 32],
        pub current_height: u64,
        pub block_timestamp_ms: u64,
    }
    #[doc(hidden)]
    pub fn fcmp_runtime_fixture_for_test() -> FcmpRuntimeFixtureForTest {
        let fixture = fcmp_fixture();
        FcmpRuntimeFixtureForTest {
            envelope: fixture.envelope.clone(),
            activation: fixture.activation,
            network_id: fixture.network_id,
            snapshot: fixture.snapshot.clone(),
            initial_output: fixture.initial_output,
            genesis_hash: [0xA7; 32],
            current_height: 10,
            block_timestamp_ms: 1_800_000_000_000,
        }
    }
    #[doc(hidden)]
    pub struct ZkAmsRuntimeFixtureForTest {
        pub batch_envelope: PrivacyProofEnvelopeV1,
        pub provision_envelope: PrivacyProofEnvelopeV1,
        pub activation: PrivacyProtocolActivationRecordV1,
        pub network_id: NetworkId,
        pub genesis_hash: [u8; 32],
        pub current_height: u64,
        pub block_timestamp_ms: u64,
        pub bootstrap: PrivacyZkAmsRegistryBootstrapV1,
        pub prestate_anchors: Vec<PrivacyZkAmsAdmissionAnchorV1>,
        pub prestate_statement_digest: PrivacyStatementDigestV1,
        pub current_root: PrivacyRootV1,
        pub current_epoch: u64,
    }
    #[doc(hidden)]
    pub fn zk_ams_runtime_fixture_for_test() -> ZkAmsRuntimeFixtureForTest {
        static FIXTURE: OnceLock<ZkAmsRuntimeFixtureForTest> = OnceLock::new();
        let fixture = FIXTURE.get_or_init(|| {
            let compiled = compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
                .expect("compiled ZK-AMS profile");
            let activation = compiled.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 2,
                    state_since_height: 2,
                },
            ));
            let network_id = network_id(0xA7);
            let genesis_hash = [0xA7; 32];
            let issuer_signing_key = P256SigningKey::from_bytes((&[7_u8; 32]).into())
                .expect("ZK-AMS issuer signing key");
            let issuer_public_key = {
                let encoded = issuer_signing_key.verifying_key().to_encoded_point(true);
                PrivacyP256PointV1::new(
                    encoded
                        .as_bytes()
                        .try_into()
                        .expect("compressed P-256 issuer key"),
                )
            };
            let bootstrap = PrivacyZkAmsRegistryBootstrapV1 {
                issuer_id: PrivacyIssuerIdV1::new([0x31; 32]),
                registry_id: PrivacyZkAmsRegistryIdV1::new([0x33; 32]),
                policy_id: PrivacyPolicyIdV1::new([0x35; 32]),
                issuer_public_key,
                policy_digest: PrivacyPolicyDigestV1::new([0x36; 32]),
                initial_registry_root: PrivacyRootV1::new([0x37; 32]),
                initial_registry_epoch: ZK_AMS_REGISTRY_BOOTSTRAP_INITIAL_EPOCH_V1,
            };
            bootstrap.validate().expect("canonical ZK-AMS bootstrap");
            let mut ring = (1..=ZK_AMS_MIN_RING_SIZE_V1)
                .map(|index| {
                    let mut bytes = [0_u8; 32];
                    bytes[0] = u8::try_from(index).expect("bounded ZK-AMS ring index");
                    let secret = ZkAmsSeedSecretV1::from_bytes(bytes).expect("ZK-AMS seed secret");
                    (zk_ams_seed_public_key_v1(&secret), secret)
                })
                .collect::<Vec<_>>();
            ring.sort_by_key(|(public, _)| *public);
            let credentials = ring
                .iter()
                .enumerate()
                .map(|(index, (public, _))| {
                    let index = u8::try_from(index).expect("bounded ZK-AMS credential index");
                    PrivacyZkAmsPersonhoodCredentialV1 {
                        version: ZK_AMS_PHC_VERSION_V1,
                        issuer_id: bootstrap.issuer_id,
                        policy_id: bootstrap.policy_id,
                        subject_commitment: PrivacyZkAmsSubjectCommitmentV1::new(
                            [0x41_u8.checked_add(index).expect("bounded subject byte"); 32],
                        ),
                        seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(*public),
                        credential_nonce: PrivacyZkAmsCredentialNonceV1::new(
                            [0x51_u8.checked_add(index).expect("bounded nonce byte"); 32],
                        ),
                    }
                })
                .collect::<Vec<_>>();
            let anchors = credentials
                .iter()
                .map(|credential| PrivacyZkAmsAdmissionAnchorV1 {
                    phc_hash: credential.digest(),
                    seed_public_key: credential.seed_public_key,
                })
                .collect::<Vec<_>>();
            let batch_start = anchors
                .len()
                .checked_sub(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1)
                .expect("minimum ZK-AMS ring exceeds one admission batch");
            let prestate_anchors = anchors[..batch_start].to_vec();
            let batch_anchors = anchors[batch_start..].to_vec();
            let current_epoch = bootstrap
                .initial_registry_epoch
                .checked_add(1)
                .expect("ZK-AMS prestate epoch");
            let prestate_batch_size =
                u32::try_from(prestate_anchors.len()).expect("prestate batch size");
            let current_root = prestate_anchors.iter().copied().enumerate().fold(
                bootstrap.initial_registry_root,
                |prior_root, (index, anchor)| {
                    zk_ams_registry_transition_root_v1(
                        bootstrap.registry_id,
                        prior_root,
                        bootstrap.initial_registry_epoch,
                        current_epoch,
                        prestate_batch_size,
                        u32::try_from(index).expect("prestate anchor index"),
                        anchor,
                    )
                },
            );
            let prestate_statement_digest = PrivacyStatementDigestV1::new([0xE1; 32]);
            let batch_next_epoch = current_epoch.checked_add(1).expect("batch successor epoch");
            let batch_size = u32::try_from(batch_anchors.len()).expect("batch anchor count");
            let batch_next_root = batch_anchors.iter().copied().enumerate().fold(
                current_root,
                |prior_root, (index, anchor)| {
                    zk_ams_registry_transition_root_v1(
                        bootstrap.registry_id,
                        prior_root,
                        current_epoch,
                        batch_next_epoch,
                        batch_size,
                        u32::try_from(index).expect("batch anchor index"),
                        anchor,
                    )
                },
            );
            let statement_context = |transaction_intent_byte: u8| PrivacyStatementContextV1 {
                network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(
                    [transaction_intent_byte; 32],
                ),
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
            };
            let batch_statement = IrohaZkAmsStatementV1 {
                context: statement_context(0x21),
                issuer_id: bootstrap.issuer_id,
                issuer_public_key: bootstrap.issuer_public_key,
                issuer_policy_record_digest: bootstrap.issuer_policy_record_digest(),
                registry_id: bootstrap.registry_id,
                registry_record_digest: zk_ams_registry_record_digest_v1(
                    bootstrap.issuer_id,
                    bootstrap.registry_id,
                    bootstrap.policy_id,
                    bootstrap.issuer_policy_record_digest(),
                    bootstrap.policy_digest,
                    current_root,
                    current_epoch,
                ),
                policy_id: bootstrap.policy_id,
                policy_digest: bootstrap.policy_digest,
                action: PrivacyZkAmsActionV1::BatchAdmission(PrivacyZkAmsBatchAdmissionV1 {
                    account_registry_root: current_root,
                    account_registry_root_epoch: current_epoch,
                    next_account_registry_root: batch_next_root,
                    next_account_registry_root_epoch: batch_next_epoch,
                    anchors: batch_anchors.clone(),
                }),
            };
            let batch_typed_statement = PrivacyStatementV1::IrohaZkAmsV1(batch_statement.clone());
            let batch_statement_digest = batch_typed_statement
                .digest()
                .expect("ZK-AMS batch statement digest");
            let batch_binding = TranscriptBindingV1 {
                network_id: network_id.as_bytes(),
                genesis_hash,
                action_index: 0,
                statement_digest: *batch_statement_digest.as_bytes(),
                parameter_id: *compiled.parameter_id.as_bytes(),
                parameter_digest: *compiled.parameter_digest.as_bytes(),
                verifier_digest: *compiled.verifier_digest.as_bytes(),
                statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                generator_digest: zk_ams_generator_digest_v1(),
            };
            let signatures = credentials[batch_start..]
                .iter()
                .map(|credential| {
                    let signature: P256Signature = issuer_signing_key
                        .sign_prehash(credential.digest().as_bytes())
                        .expect("ZK-AMS issuer signature");
                    let signature = signature.normalize_s().unwrap_or(signature);
                    <[u8; 64]>::from(signature.to_bytes())
                })
                .collect::<Vec<_>>();
            let batch_witnesses = credentials[batch_start..]
                .iter()
                .zip(&signatures)
                .zip(&ring[batch_start..])
                .map(|((credential, signature), (_, secret))| {
                    ZkAmsBatchCredentialWitnessV1::new(credential, signature, secret)
                })
                .collect::<Vec<_>>();
            let batch_proof = prove_zk_ams_batch_admission_v1(
                &batch_statement,
                &batch_binding,
                &batch_witnesses,
                ZkAmsMaskedProverConfigV1::new(1).expect("ZK-AMS prover config"),
                &mut KatRng::new([0xB6; 32]),
            )
            .expect("native ZK-AMS batch proof");
            let batch_envelope = PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest: batch_statement_digest,
                statement: batch_typed_statement,
                proof: PrivacyProofV1::IrohaZkAmsV1(
                    IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
                        PrivacyProofBytesV1::new(batch_proof),
                    ),
                ),
            };
            let signer_index = 5;
            let signer_secret = &ring[signer_index].1;
            let key_image = zk_ams_key_image_v1(signer_secret).expect("ZK-AMS key image");
            let account_key = KeyPair::try_from_seed(vec![0x40; 32], Algorithm::Ed25519)
                .expect("ZK-AMS provisioned account");
            let provision_statement = IrohaZkAmsStatementV1 {
                context: statement_context(0x22),
                issuer_id: bootstrap.issuer_id,
                issuer_public_key: bootstrap.issuer_public_key,
                issuer_policy_record_digest: bootstrap.issuer_policy_record_digest(),
                registry_id: bootstrap.registry_id,
                registry_record_digest: zk_ams_registry_record_digest_v1(
                    bootstrap.issuer_id,
                    bootstrap.registry_id,
                    bootstrap.policy_id,
                    bootstrap.issuer_policy_record_digest(),
                    bootstrap.policy_digest,
                    batch_next_root,
                    batch_next_epoch,
                ),
                policy_id: bootstrap.policy_id,
                policy_digest: bootstrap.policy_digest,
                action: PrivacyZkAmsActionV1::ProvisionAccount(PrivacyZkAmsProvisionAccountV1 {
                    account_registry_root: batch_next_root,
                    account_registry_root_epoch: batch_next_epoch,
                    admitted_seed_key_ring: ring
                        .iter()
                        .map(|(public, _)| PrivacyZkAmsSeedPublicKeyV1::new(*public))
                        .collect(),
                    account_id: AccountId::new(account_key.public_key().clone()),
                    key_image: PrivacyZkAmsKeyImageV1::new(key_image),
                }),
            };
            let provision_typed_statement =
                PrivacyStatementV1::IrohaZkAmsV1(provision_statement.clone());
            let provision_statement_digest = provision_typed_statement
                .digest()
                .expect("ZK-AMS provision statement digest");
            let provision_binding = TranscriptBindingV1 {
                network_id: network_id.as_bytes(),
                genesis_hash,
                action_index: 0,
                statement_digest: *provision_statement_digest.as_bytes(),
                parameter_id: *compiled.parameter_id.as_bytes(),
                parameter_digest: *compiled.parameter_digest.as_bytes(),
                verifier_digest: *compiled.verifier_digest.as_bytes(),
                statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                generator_digest: zk_ams_generator_digest_v1(),
            };
            let provision_proof = sign_zk_ams_provision_statement_v1(
                &provision_statement,
                &provision_binding,
                signer_index,
                signer_secret,
                &mut KatRng::new([0xC6; 32]),
            )
            .expect("native ZK-AMS provisioning proof");
            let provision_envelope = PrivacyProofEnvelopeV1 {
                wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                catalog_commitment:
                    iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                protocol_id: compiled.protocol_id,
                proof_system_id: compiled.proof_system_id,
                engine_id: compiled.engine_id,
                parameter_id: compiled.parameter_id,
                parameter_digest: compiled.parameter_digest,
                verifier_digest: compiled.verifier_digest,
                statement_schema_digest: compiled.statement_schema_digest,
                engine_manifest_digest: compiled.engine_manifest_digest,
                statement_digest: provision_statement_digest,
                statement: provision_typed_statement,
                proof: PrivacyProofV1::IrohaZkAmsV1(
                    IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(PrivacyProofBytesV1::new(
                        provision_proof,
                    )),
                ),
            };
            ZkAmsRuntimeFixtureForTest {
                batch_envelope,
                provision_envelope,
                activation,
                network_id,
                genesis_hash,
                current_height: 10,
                block_timestamp_ms: 1_800_000_000_000,
                bootstrap,
                prestate_anchors,
                prestate_statement_digest,
                current_root,
                current_epoch,
            }
        });
        ZkAmsRuntimeFixtureForTest {
            batch_envelope: fixture.batch_envelope.clone(),
            provision_envelope: fixture.provision_envelope.clone(),
            activation: fixture.activation,
            network_id: fixture.network_id,
            genesis_hash: fixture.genesis_hash,
            current_height: fixture.current_height,
            block_timestamp_ms: fixture.block_timestamp_ms,
            bootstrap: fixture.bootstrap,
            prestate_anchors: fixture.prestate_anchors.clone(),
            prestate_statement_digest: fixture.prestate_statement_digest,
            current_root: fixture.current_root,
            current_epoch: fixture.current_epoch,
        }
    }
}
