//! Shared fixtures of the wallet Advance provider tests: a payment key, its enrollment
//! marker, a chain of valid G1 recovery capsules and completion records.
//!
//! Capsules and completion records here are structurally valid G1 frames; their receipt
//! signatures are canonical but not bound to a credential, which the persistence layer never
//! needs (receipt verification belongs to the advance and reconcile owners).

use iroha_data_model::kagemusha::{
    KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1, KagemushaWalletCompletionRecordV1,
    KagemushaWalletEffectV1, KagemushaWalletEnrollmentChallengeV1, KagemushaWalletIndexedTreeV1,
    KagemushaWalletLifecycleV1, KagemushaWalletLineagePublicV1, KagemushaWalletLineageSlotV1,
    KagemushaWalletLineageV1, KagemushaWalletMarkerV1, KagemushaWalletOperationKindV1,
    KagemushaWalletOutputDescriptorV1, KagemushaWalletReceiptBodyV1, KagemushaWalletReceiptV1,
    KagemushaWalletRecoveryCapsuleV1, KagemushaWalletRetainedInputRoleV1,
    KagemushaWalletRetainedInputV1, KagemushaWalletStateCommitmentV1, KagemushaWalletStateCoreV1,
    KagemushaWalletStateRestV1, KagemushaWalletStateV1, KagemushaWalletStatementV1,
    KagemushaWalletStepProofV1, kagemusha_wallet_proof_digest_v1,
    kagemusha_wallet_provider_contract_v1,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, PoisonError},
};

use p256::ecdsa::{
    Signature, SigningKey,
    signature::{RandomizedSigner as _, Signer as _},
};

use super::{
    KagemushaWalletAnchorPolicyV1, KagemushaWalletDurableStoreV1, KagemushaWalletFreshGenerationV1,
    KagemushaWalletKeyGenerationPolicyV1, KagemushaWalletKeyGenerationRequestV1,
    KagemushaWalletKeyGenerationV1, KagemushaWalletKeyProfileV1, KagemushaWalletMarkerRecordV1,
    KagemushaWalletNotPublishedV1, KagemushaWalletPlatformSignatureV1, KagemushaWalletPlatformV1,
    KagemushaWalletProbeV1, KagemushaWalletPublishOutcomeV1, KagemushaWalletRemoveOutcomeV1,
    KagemushaWalletSignMessageV1, KagemushaWalletSimFsV1, KagemushaWalletSlotIdV1,
    KagemushaWalletUnavailableV1, kagemusha_wallet_prepare_root_v1,
    kagemusha_wallet_prepare_slot_dirs_v1,
};

/// Hardware key profile used by every simulated enrollment.
pub(super) const PROFILE: KagemushaWalletKeyProfileV1 =
    KagemushaWalletKeyProfileV1::SecureElementOrTee;

/// Simulated store sharing state with the returned simulator handle.
pub(super) type SimStoreV1 = KagemushaWalletDurableStoreV1<KagemushaWalletSimFsV1>;

/// Simulator and a store over it.
pub(super) fn sim_store() -> (KagemushaWalletSimFsV1, SimStoreV1) {
    let fs = KagemushaWalletSimFsV1::new();
    let store = KagemushaWalletDurableStoreV1::new(fs.clone());
    (fs, store)
}

/// Simulator with a prepared root and the durable directories of `f`'s slot.
pub(super) fn prepared_slot(f: &WalletFixtureV1) -> (KagemushaWalletSimFsV1, SimStoreV1) {
    let (fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    kagemusha_wallet_prepare_slot_dirs_v1(&store, &f.slot).expect("slot dirs");
    (fs, store)
}

/// Boot identity used by fixtures for "the current boot".
pub(super) const BOOT_A: [u8; 32] = [0xa1; 32];
/// Boot identity of a later boot.
pub(super) const BOOT_B: [u8; 32] = [0xb2; 32];

/// One enrolled payment key and its enrollment marker.
pub(super) struct WalletFixtureV1 {
    pub(super) signing: SigningKey,
    pub(super) payment_key: KagemushaDevicePublicKeyV1,
    pub(super) enrollment: KagemushaWalletMarkerV1,
    pub(super) slot: KagemushaWalletSlotIdV1,
}

impl WalletFixtureV1 {
    pub(super) fn scheme_id(&self) -> [u8; 32] {
        self.enrollment.scheme_id
    }

    pub(super) fn wallet_id(&self) -> [u8; 32] {
        self.enrollment.wallet_id
    }

    /// Generation-0 marker record of an unanchored (Android) slot stamped with `boot`.
    pub(super) fn enrollment_record(&self, boot: [u8; 32]) -> KagemushaWalletMarkerRecordV1 {
        self.enrollment_record_with(boot, KagemushaWalletAnchorPolicyV1::NotRequired)
    }

    /// Generation-0 marker record of a slot with anchor kind `anchor` stamped with `boot`.
    pub(super) fn enrollment_record_with(
        &self,
        boot: [u8; 32],
        anchor: KagemushaWalletAnchorPolicyV1,
    ) -> KagemushaWalletMarkerRecordV1 {
        KagemushaWalletMarkerRecordV1::new(self.slot, self.enrollment, anchor, None, boot)
            .expect("enrollment record")
    }
}

/// Deterministic P-256 key from `seed`.
pub(super) fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("signing key")
}

/// Canonical public key of `key`.
pub(super) fn public_key(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .expect("public key")
}

/// Low-S canonical signature of `message` by `key`.
pub(super) fn low_s_signature(key: &SigningKey, message: &[u8]) -> KagemushaDeviceSignatureV1 {
    let signature: Signature = key.sign(message);
    let signature = signature.normalize_s().unwrap_or(signature);
    KagemushaDeviceSignatureV1::from_raw_bytes(signature.to_bytes().as_slice()).expect("signature")
}

/// Scheme of every fixture.
pub(super) const SCHEME: [u8; 32] = [0x11; 32];

/// Enrollment challenge derived from `seed`.
pub(super) fn enrollment_challenge(seed: u8) -> KagemushaWalletEnrollmentChallengeV1 {
    KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: SCHEME,
        asset_digest: [0x12; 32],
        account_digest: [0x13; 32],
        app_policy: [0x14; 32],
        enrollment_policy: [0x15; 32],
        issuer_nonce: [seed; 32],
    }
}

/// Fixture enrolled under a challenge derived from `seed`.
pub(super) fn wallet_fixture(seed: u8) -> WalletFixtureV1 {
    let signing = signing_key(seed);
    let payment_key = public_key(&signing);
    let challenge = enrollment_challenge(seed);
    let enrollment =
        KagemushaWalletMarkerV1::enrollment(&challenge, payment_key).expect("enrollment marker");
    WalletFixtureV1 {
        signing,
        payment_key,
        enrollment,
        slot: KagemushaWalletSlotIdV1([seed.wrapping_add(0x40); 32]),
    }
}

/// Canonical, nonzero σ-field stand-in for a nonzero `seed`: every byte `seed` except the most
/// significant, which is `seed & 0x3f` so the value stays below the field modulus.
pub(super) const fn field_value(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[31] = seed & 0x3f;
    value
}

/// Distinct complete state commitment for a nonzero `seed`.
pub(super) const fn commitment(seed: u8) -> KagemushaWalletStateCommitmentV1 {
    KagemushaWalletStateCommitmentV1 {
        value: field_value(seed),
    }
}

/// Successor state of `statement` for `f`'s wallet. The statement's stand-in successor value
/// seeds the state nonce, so distinct stand-ins give distinct computed commitments.
fn state_for(
    f: &WalletFixtureV1,
    statement: &KagemushaWalletStatementV1,
) -> KagemushaWalletStateV1 {
    KagemushaWalletStateV1 {
        version: 1,
        core: KagemushaWalletStateCoreV1 {
            lifecycle: statement.lifecycle,
            scheme_id: f.scheme_id(),
            asset_digest: f.enrollment.asset_digest,
            wallet_id: f.wallet_id(),
            credential_digest: statement.credential_digest,
            balance: 0,
            burned_total: statement.lineage_burned_total,
            sequence: statement.sequence,
            next_send: 0,
            next_load: statement.next_load,
            next_redeem: 0,
            send_chain: [0; 32],
            recv_chain: [0; 32],
            consumed_credit_root: field_value(0x31),
            pending_outgoing_root: field_value(0x32),
            load_redeem_recovery_root: field_value(0x33),
            fee_claim_root: field_value(0x35),
            quota_usage_root: field_value(0x36),
            enabled_controls: 0,
            quota_windows_root: [0; 32],
            quota_share_expires_at_ms: 0,
            blacklist_version: 0,
            blacklist_root: [0; 32],
            blacklist_issued_at_ms: 0,
            blacklist_max_age_ms: 0,
            lease_expires_at_ms: 0,
            policy_epoch: 0,
            accepted_time_floor_ms: 0,
            time_anchor_max_response_ms: 0,
            state_nonce: statement.successor.value,
        },
        rest: KagemushaWalletStateRestV1 {
            permitted_controls: 0,
            scheme_policy: [0; 32],
            fee_schedule: [0; 32],
            blacklist: [0; 32],
            blacklist_history_root: field_value(0x37),
            quota_share: [0; 32],
            quota_share_id: 0,
            time_anchor: [0; 32],
        },
    }
}

/// Stand-in fold witnesses a capsule of `kind` must retain (spec §4.1).
fn retained_for(kind: KagemushaWalletOperationKindV1) -> Vec<KagemushaWalletRetainedInputV1> {
    use KagemushaWalletRetainedInputRoleV1 as R;
    let roles: &[R] = match kind {
        KagemushaWalletOperationKindV1::Receive => {
            &[R::Request, R::Payment, R::CertificateSet, R::Credential]
        }
        KagemushaWalletOperationKindV1::ArchiveSent => &[
            R::Request,
            R::Payment,
            R::Credited,
            R::Credential,
            R::CertificateSet,
        ],
        KagemushaWalletOperationKindV1::Send => &[R::Request],
        KagemushaWalletOperationKindV1::Load => &[R::LoadReceipt, R::LoadFinality],
        KagemushaWalletOperationKindV1::RefreshPolicy => &[R::PolicyUpdate, R::CertificateSet],
        _ => &[],
    };
    roles
        .iter()
        .map(|role| KagemushaWalletRetainedInputV1 {
            role: *role,
            bytes: vec![role.tag(); 8],
        })
        .collect()
}

/// Stand-in Ω(pred) of `statement` (an operation that consumes Ω(pred)) for `f`'s wallet.
pub(super) fn lineage_for(
    f: &WalletFixtureV1,
    statement: &KagemushaWalletStatementV1,
) -> KagemushaWalletLineageV1 {
    let lifecycle = match statement.effect {
        KagemushaWalletEffectV1::Retiring => KagemushaWalletLifecycleV1::Active,
        _ => statement.lifecycle,
    };
    KagemushaWalletLineageV1 {
        public: KagemushaWalletLineagePublicV1 {
            version: 1,
            scheme_id: statement.scheme_id,
            relation_id: statement.relation_id,
            head: statement.predecessor,
            wallet_id: f.wallet_id(),
            credential_digest: statement.credential_digest,
            payment_key: f.payment_key,
            lifecycle,
            policy_epoch: 0,
            enabled_controls: statement.enabled_controls,
            burned_total: statement.lineage_burned_total,
            pending_outgoing_root: statement.lineage_pending_outgoing_root,
            credit_digest_root: field_value(0x38),
        },
        proof: vec![0x5a; 40],
    }
}

/// Valid capsule of `statement` after `predecessor_capsule_digest`, with step-proof bytes
/// `proof_byte`; Send, Unload and Retiring carry the stand-in Ω(pred) of [`lineage_for`].
///
/// The statement's successor is replaced by the computed commitment of its successor state
/// ([`state_for`], seeded by the stand-in successor), which a valid capsule requires.
pub(super) fn capsule_for(
    f: &WalletFixtureV1,
    mut statement: KagemushaWalletStatementV1,
    predecessor_capsule_digest: [u8; 32],
    proof_byte: u8,
) -> KagemushaWalletRecoveryCapsuleV1 {
    let successor_state = state_for(f, &statement);
    statement.successor = successor_state.commitment().expect("successor commitment");
    let kind = statement.effect.kind();
    let step_proof = KagemushaWalletStepProofV1 {
        bytes: vec![proof_byte; 48],
    };
    let payment_digest = if kind == KagemushaWalletOperationKindV1::Receive {
        field_value(0x63)
    } else {
        [0; 32]
    };
    let predecessor_lineage = if kind.consumes_lineage() {
        KagemushaWalletLineageSlotV1::Present {
            lineage: lineage_for(f, &statement),
        }
    } else {
        KagemushaWalletLineageSlotV1::None
    };
    let proof_digest =
        kagemusha_wallet_proof_digest_v1(kind, predecessor_lineage.lineage(), &step_proof)
            .expect("proof digest");
    let output = KagemushaWalletOutputDescriptorV1::for_transition(
        &statement,
        &proof_digest,
        &payment_digest,
    )
    .expect("output");
    let capsule = KagemushaWalletRecoveryCapsuleV1 {
        version: 1,
        scheme_id: f.scheme_id(),
        wallet_id: f.wallet_id(),
        operation_id: statement
            .operation_id(&f.wallet_id())
            .expect("operation id"),
        kind,
        predecessor_capsule_digest,
        successor_state,
        statement,
        predecessor_lineage,
        step_proof,
        payment_digest,
        map_openings: stand_in_map_openings(1),
        retained_inputs: retained_for(kind),
        output,
    };
    capsule.validate().expect("valid capsule");
    capsule
}

/// Stand-in capsule map openings: the insertion witness of key `seed` into an empty indexed
/// tree as G1 §3.2 opening transcripts, the sentinel's leaf opening and the written slot's
/// empty-slot opening, each with exactly 32 siblings (owner answer A2). Distinct seeds give
/// distinct openings.
pub(super) fn stand_in_map_openings(seed: u8) -> Vec<Vec<u8>> {
    let mut key = [seed; 32];
    key[31] = 0;
    let mut value = [seed ^ 0x5a; 32];
    value[31] = 0;
    let insertion = KagemushaWalletIndexedTreeV1::new()
        .insert(key, value)
        .expect("stand-in insertion");
    vec![
        insertion.low_opening.leaf_transcript(&insertion.low),
        insertion.slot_opening.empty_transcript(),
    ]
}

/// Bootstrap capsule bound to the fixture's enrollment marker.
pub(super) fn bootstrap_capsule(f: &WalletFixtureV1) -> KagemushaWalletRecoveryCapsuleV1 {
    bootstrap_capsule_variant(f, 0)
}

/// Bootstrap capsule with successor variant `variant`: every variant has the same operation
/// identity and a different head, so two variants compete for generation 1.
pub(super) fn bootstrap_capsule_variant(
    f: &WalletFixtureV1,
    variant: u8,
) -> KagemushaWalletRecoveryCapsuleV1 {
    let statement = KagemushaWalletStatementV1 {
        version: 1,
        scheme_id: f.scheme_id(),
        relation_id: [0x41; 32],
        credential_digest: field_value(0x42),
        asset_digest: f.enrollment.asset_digest,
        lifecycle: KagemushaWalletLifecycleV1::Active,
        sequence: 0,
        next_load: 0,
        enabled_controls: 0,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: KagemushaWalletStateCommitmentV1::ZERO,
        successor: commitment(0x51 ^ variant.wrapping_mul(0x20)),
        effect: f.enrollment.bootstrap_effect().expect("bootstrap effect"),
    };
    capsule_for(f, statement, [0; 32], 0x61)
}

/// `ArchiveSent` capsule following `previous`.
pub(super) fn next_capsule(
    f: &WalletFixtureV1,
    previous: &KagemushaWalletRecoveryCapsuleV1,
) -> KagemushaWalletRecoveryCapsuleV1 {
    next_capsule_variant(f, previous, 0)
}

/// `ArchiveSent` capsule following `previous`; `variant` changes the archived credit, so two
/// variants are competing successors of one head with different operation identities.
pub(super) fn next_capsule_variant(
    f: &WalletFixtureV1,
    previous: &KagemushaWalletRecoveryCapsuleV1,
    variant: u8,
) -> KagemushaWalletRecoveryCapsuleV1 {
    let sequence = previous.statement.sequence + 1;
    let tag = (u8::try_from(sequence % 100).expect("tag") + 1) ^ variant.wrapping_mul(0x80);
    let statement = KagemushaWalletStatementV1 {
        lifecycle: KagemushaWalletLifecycleV1::Active,
        sequence,
        next_load: previous.statement.next_load,
        predecessor: previous.statement.successor,
        successor: commitment(tag),
        effect: KagemushaWalletEffectV1::ArchiveSent {
            credit_id: field_value(tag),
            credited: field_value(tag.wrapping_add(2).max(1)),
        },
        ..previous.statement
    };
    capsule_for(
        f,
        statement,
        previous.capsule_digest().expect("previous digest"),
        tag,
    )
}

/// Completion record of `capsule` whose output is `output_byte` repeated.
pub(super) fn completion_for(
    f: &WalletFixtureV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
    output_byte: u8,
) -> KagemushaWalletCompletionRecordV1 {
    let capsule_digest = capsule.capsule_digest().expect("capsule digest");
    let record = KagemushaWalletCompletionRecordV1 {
        version: 1,
        wallet_id: f.wallet_id(),
        operation_id: capsule.operation_id,
        capsule_digest,
        receipt: KagemushaWalletReceiptV1 {
            version: 1,
            operation_id: capsule.operation_id,
            capsule_digest,
            payment_digest: capsule.payment_digest,
            signature: low_s_signature(&f.signing, &[output_byte; 8]),
        },
        output: vec![output_byte; 64],
    };
    record.validate().expect("valid completion");
    record
}

// ---------------------------------------------------------------------------------------
// Fake platform and transition owner for provider flows
// ---------------------------------------------------------------------------------------

/// Simulated provider over the simulated filesystem and the fake platform.
pub(super) type SimProviderV1 = super::KagemushaWalletProviderV1<
    KagemushaWalletSimFsV1,
    FakePlatformV1,
    KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletCompletionRecordV1,
>;

/// How the fake keychain answers an anchor write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorWriteV1 {
    /// Applied and reported.
    Normal,
    /// Refused definitively (no device passcode).
    Refused,
    /// Applied, reported as uncertain.
    UncertainApplied,
    /// Not applied, reported as uncertain.
    UncertainLost,
}

/// Mutable state of the fake platform.
#[derive(Debug, Clone)]
pub(super) struct FakeStateV1 {
    /// Payment keys by slot.
    pub(super) keys: BTreeMap<KagemushaWalletSlotIdV1, SigningKey>,
    /// Seed of the next generated key.
    pub(super) next_key_seed: u8,
    /// Keychain anchors by slot.
    pub(super) anchors: BTreeMap<KagemushaWalletSlotIdV1, Vec<u8>>,
    /// Anchor policy.
    pub(super) policy: KagemushaWalletAnchorPolicyV1,
    /// Anchor write behavior.
    pub(super) anchor_write: AnchorWriteV1,
    /// Boot identity.
    pub(super) boot: Result<[u8; 32], KagemushaWalletUnavailableV1>,
    /// Test-controlled sleep-inclusive clock result.
    pub(super) monotonic: Result<u64, KagemushaWalletUnavailableV1>,
    pub(super) monotonic_script:
        std::collections::VecDeque<Result<u64, KagemushaWalletUnavailableV1>>,
    /// Change the boot result during the next clock read to detect mixed observations.
    pub(super) boot_after_monotonic: Option<Result<[u8; 32], KagemushaWalletUnavailableV1>>,
    /// Storage state answer.
    pub(super) storage: Result<(), KagemushaWalletUnavailableV1>,
    /// Lock storage after this many further successful storage-state answers.
    pub(super) storage_lock_after: Option<usize>,
    /// Key probes answer `Unavailable`.
    pub(super) probe_unavailable: bool,
    /// Actual generation policy of the simulated OS.
    pub(super) generation_policy: KagemushaWalletKeyGenerationPolicyV1,
    /// Number of consumed fresh grants.
    pub(super) fresh_generation_calls: usize,
    /// Key generation answers `Unavailable` (the key may still be created).
    pub(super) generate_unavailable: Option<bool>,
    /// Lock protected storage immediately after a successful generation reply (test only).
    pub(super) lock_after_generation: bool,
    /// Simulated readback failure after an actual successful key-generation return.
    pub(super) generation_readback_unavailable: bool,
    /// Actual returned public key and exact request; never populated from a probe.
    pub(super) generation_originals: BTreeMap<
        KagemushaWalletSlotIdV1,
        (
            KagemushaWalletKeyGenerationRequestV1,
            KagemushaDevicePublicKeyV1,
        ),
    >,
    /// Signing answers `Unavailable`.
    pub(super) sign_unavailable: bool,
    /// Anchor reads answer `Unavailable`.
    pub(super) anchor_read_unavailable: bool,
    /// Key deletion answers `NotRemoved`.
    pub(super) delete_refused: bool,
    /// Number of `key_sign` calls.
    pub(super) sign_calls: usize,
    /// Number of `key_generate` calls.
    pub(super) generate_calls: usize,
    /// Number of `key_delete` calls.
    pub(super) delete_calls: usize,
    /// Number of `key_probe` calls.
    pub(super) probe_calls: usize,
    /// Exact test-only enumeration override; errors remain errors.
    pub(super) enumerate_override:
        Option<Result<Vec<KagemushaWalletSlotIdV1>, KagemushaWalletUnavailableV1>>,
    /// Number of `key_enumerate` calls.
    pub(super) enumerate_calls: usize,
    /// Number of `storage_state` calls.
    pub(super) storage_calls: usize,
    /// Number of anchor writes (creations and updates).
    pub(super) anchor_writes: usize,
    /// The `key_sign` call with this index answers `Unavailable` (one-shot platform fault).
    pub(super) sign_fault_at: Option<usize>,
    /// The `key_probe` call with this index answers `Unavailable` (one-shot platform fault).
    pub(super) probe_fault_at: Option<usize>,
    /// The anchor write with this index behaves as given (one-shot platform fault).
    pub(super) anchor_fault_at: Option<(usize, AnchorWriteV1)>,
    /// Anchor value of each slot before its last applied write (keychain power-loss model).
    pub(super) anchor_previous: BTreeMap<KagemushaWalletSlotIdV1, Option<Vec<u8>>>,
    /// Request of the last `key_generate` call.
    pub(super) last_generation: Option<KagemushaWalletKeyGenerationRequestV1>,
    /// Invariant violations observed inside platform calls.
    pub(super) violations: Vec<String>,
    /// Filesystem observed by the signing guard (design I6, I10).
    pub(super) guard: Option<KagemushaWalletSimFsV1>,
}

/// Fake platform: software P-256 keys with randomized signatures, an in-memory keychain and
/// injectable unavailability. Clones share state; [`Self::fork`] copies it.
#[derive(Debug, Clone)]
pub(super) struct FakePlatformV1 {
    state: Arc<Mutex<FakeStateV1>>,
}

impl FakePlatformV1 {
    /// Fake platform with `policy` whose next generated key is `signing_key(next_key_seed)`.
    pub(super) fn new(policy: KagemushaWalletAnchorPolicyV1, next_key_seed: u8) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeStateV1 {
                keys: BTreeMap::new(),
                next_key_seed,
                anchors: BTreeMap::new(),
                policy,
                anchor_write: AnchorWriteV1::Normal,
                boot: Ok(BOOT_A),
                monotonic: Ok(1_000),
                monotonic_script: std::collections::VecDeque::new(),
                boot_after_monotonic: None,
                storage: Ok(()),
                storage_lock_after: None,
                probe_unavailable: false,
                generation_policy: KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
                fresh_generation_calls: 0,
                generate_unavailable: None,
                lock_after_generation: false,
                generation_readback_unavailable: false,
                generation_originals: BTreeMap::new(),
                sign_unavailable: false,
                anchor_read_unavailable: false,
                delete_refused: false,
                sign_calls: 0,
                generate_calls: 0,
                delete_calls: 0,
                probe_calls: 0,
                enumerate_override: None,
                enumerate_calls: 0,
                storage_calls: 0,
                anchor_writes: 0,
                sign_fault_at: None,
                probe_fault_at: None,
                anchor_fault_at: None,
                anchor_previous: BTreeMap::new(),
                last_generation: None,
                violations: Vec::new(),
                guard: None,
            })),
        }
    }

    /// Keychain power-loss model: the last applied anchor write of every slot is lost, as if
    /// the keychain had not made it durable (design risk "iOS residual window").
    pub(super) fn lose_last_anchor_writes(&self) {
        self.with(|state| {
            for (slot, previous) in std::mem::take(&mut state.anchor_previous) {
                match previous {
                    Some(bytes) => {
                        state.anchors.insert(slot, bytes);
                    }
                    None => {
                        state.anchors.remove(&slot);
                    }
                }
            }
        });
    }

    /// Disarm every one-shot platform fault.
    pub(super) fn clear_faults(&self) {
        self.with(|state| {
            state.sign_fault_at = None;
            state.probe_fault_at = None;
            state.anchor_fault_at = None;
            state.storage_lock_after = None;
            state.lock_after_generation = false;
            state.generation_readback_unavailable = false;
            state.storage = Ok(());
        });
    }

    /// Run `f` on the state.
    pub(super) fn with<T>(&self, f: impl FnOnce(&mut FakeStateV1) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Independent copy whose signing guard observes `fs`.
    pub(super) fn fork(&self, fs: Option<&KagemushaWalletSimFsV1>) -> Self {
        let mut state = self.with(|state| state.clone());
        if state.guard.is_some() {
            state.guard = fs.cloned();
        }
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Public key of `slot`, if any.
    pub(super) fn key_of(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Option<KagemushaDevicePublicKeyV1> {
        self.with(|state| state.keys.get(slot).map(public_key))
    }

    fn storage_answer(state: &mut FakeStateV1) -> Result<(), KagemushaWalletUnavailableV1> {
        state.storage_calls += 1;
        if let Some(remaining) = state.storage_lock_after.as_mut() {
            if *remaining == 0 {
                state.storage = Err(KagemushaWalletUnavailableV1::Locked);
                state.storage_lock_after = None;
            } else {
                *remaining -= 1;
            }
        }
        state.storage
    }

    /// Record a violation unless the current visible marker of `slot` is the only one and is
    /// Selected for a receipt body (design I6, I10), or a terminal marker for a ledger control
    /// (design T3: the Abandon control is signed only after its terminal marker is durable).
    fn check_signing(
        state: &mut FakeStateV1,
        slot: &KagemushaWalletSlotIdV1,
        domain: iroha_data_model::kagemusha::KagemushaWalletSigningDomainV1,
    ) {
        let Some(fs) = state.guard.as_ref() else {
            return;
        };
        use iroha_data_model::kagemusha::KagemushaWalletSigningDomainV1 as Domain;
        let expected = match domain {
            Domain::Receipt => super::KagemushaWalletMarkerPhaseV1::Selected,
            Domain::LedgerControl => super::KagemushaWalletMarkerPhaseV1::Terminal,
            _ => return,
        };
        let dir = super::kagemusha_wallet_markers_dir_v1(slot);
        let names: Vec<String> = fs
            .visible_names(&dir)
            .into_iter()
            .filter(|name| super::kagemusha_wallet_parse_marker_name_v1(name).is_some())
            .collect();
        let verdict = match names.as_slice() {
            [only] => fs
                .visible_file(&dir, only)
                .and_then(|bytes| KagemushaWalletMarkerRecordV1::decode(&bytes, slot, &SCHEME).ok())
                .map(|record| record.phase()),
            _ => None,
        };
        if verdict != Some(expected) {
            state
                .violations
                .push(format!("signed under markers {names:?} phase {verdict:?}"));
        }
    }
}

impl KagemushaWalletPlatformV1 for FakePlatformV1 {
    fn key_recover_generation_reply(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        request: &KagemushaWalletKeyGenerationRequestV1,
    ) -> Result<Option<KagemushaDevicePublicKeyV1>, KagemushaWalletUnavailableV1> {
        self.with(|state| {
            let Some((original, key)) = state.generation_originals.get(slot) else {
                return Ok(None);
            };
            if original != request || state.generation_readback_unavailable {
                return Err(KagemushaWalletUnavailableV1::Busy);
            }
            Ok(Some(*key))
        })
    }

    fn key_enumerate(&self) -> Result<Vec<KagemushaWalletSlotIdV1>, KagemushaWalletUnavailableV1> {
        self.with(|state| {
            state.enumerate_calls += 1;
            state
                .enumerate_override
                .clone()
                .unwrap_or_else(|| Ok(state.keys.keys().copied().collect()))
        })
    }

    fn key_probe(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> KagemushaWalletProbeV1<KagemushaDevicePublicKeyV1> {
        self.with(|state| {
            let call = state.probe_calls;
            state.probe_calls += 1;
            if state.probe_unavailable || state.probe_fault_at == Some(call) {
                return KagemushaWalletProbeV1::Unavailable(KagemushaWalletUnavailableV1::Locked);
            }
            state.keys.get(slot).map_or_else(
                || {
                    if state.generation_policy
                        == KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly
                    {
                        KagemushaWalletProbeV1::Unavailable(KagemushaWalletUnavailableV1::Platform(
                            10,
                        ))
                    } else {
                        KagemushaWalletProbeV1::Absent
                    }
                },
                |key| KagemushaWalletProbeV1::Present(public_key(key)),
            )
        })
    }

    fn key_generate(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        request: &KagemushaWalletKeyGenerationRequestV1,
    ) -> KagemushaWalletKeyGenerationV1 {
        if self.with(|state| state.generation_policy)
            == KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly
        {
            return KagemushaWalletKeyGenerationV1::Unavailable(
                KagemushaWalletUnavailableV1::Platform(9),
            );
        }
        self.generate_key(slot, request)
    }

    fn key_generation_policy(
        &self,
    ) -> Result<KagemushaWalletKeyGenerationPolicyV1, KagemushaWalletUnavailableV1> {
        self.with(|state| Ok(state.generation_policy))
    }

    fn key_generate_fresh(
        &self,
        grant: KagemushaWalletFreshGenerationV1<'_>,
    ) -> KagemushaWalletKeyGenerationV1 {
        let (slot, request) = match grant.consume(self) {
            Ok(bound) => bound,
            Err(reason) => return KagemushaWalletKeyGenerationV1::Unavailable(reason),
        };
        self.with(|state| {
            state.fresh_generation_calls += 1;
            if let Some(fs) = state.guard.as_ref() {
                // The records must already survive power loss before the provider is called.
                let durable = fs.fork();
                durable.power_loss(super::KagemushaWalletSimPowerLossV1::DropUnsynced);
                let dir = super::kagemusha_wallet_slot_dir_v1(&slot);
                let intent = durable
                    .visible_file(&dir, super::KAGEMUSHA_WALLET_INTENT_NAME_V1)
                    .and_then(|bytes| {
                        super::decode_envelope_v1::<super::KagemushaWalletIntentV1>(
                            &bytes,
                            super::KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1,
                        )
                        .ok()
                    });
                let bound = intent.is_some_and(|intent| {
                    intent.slot == slot.0
                        && intent.challenge.challenge_digest() == request.challenge_digest
                        && intent.profile == request.profile.tag()
                        && intent.key_generation_policy()
                            == Ok(KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly)
                });
                if !bound
                    || durable
                        .visible_file(&dir, super::KAGEMUSHA_WALLET_KEY_GENERATION_ATTEMPT_NAME_V1)
                        .is_none()
                {
                    state
                        .violations
                        .push("fresh grant reached generation before durable bound records".into());
                }
            }
        });
        self.generate_key(&slot, &request)
    }

    fn key_sign(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        message: KagemushaWalletSignMessageV1<'_>,
    ) -> Result<KagemushaWalletPlatformSignatureV1, KagemushaWalletUnavailableV1> {
        self.with(|state| {
            let call = state.sign_calls;
            state.sign_calls += 1;
            Self::check_signing(state, slot, message.domain());
            if state.sign_unavailable || state.sign_fault_at == Some(call) {
                return Err(KagemushaWalletUnavailableV1::KeyUnusable);
            }
            let key = state
                .keys
                .get(slot)
                .ok_or(KagemushaWalletUnavailableV1::KeyUnusable)?;
            // Randomized: a second signature over the same body differs, so byte-identical
            // retries can only come from retained records.
            let signature: Signature =
                key.sign_with_rng(&mut rand_core_06::OsRng, message.as_bytes());
            Ok(KagemushaWalletPlatformSignatureV1::Der(
                signature.to_der().as_bytes().to_vec(),
            ))
        })
    }

    fn key_delete(&self, slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletRemoveOutcomeV1 {
        self.with(|state| {
            state.delete_calls += 1;
            Self::check_deletion(state, slot);
            if state.delete_refused {
                return KagemushaWalletRemoveOutcomeV1::NotRemoved(
                    KagemushaWalletUnavailableV1::Locked,
                );
            }
            state.keys.remove(slot);
            KagemushaWalletRemoveOutcomeV1::Removed
        })
    }

    fn anchor_policy(&self) -> KagemushaWalletAnchorPolicyV1 {
        self.with(|state| state.policy)
    }

    fn anchor_create(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        value: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        self.with(|state| {
            if state.anchors.contains_key(slot) {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::DestinationExists,
                );
            }
            Self::anchor_write(state, slot, value)
        })
    }

    fn anchor_read(&self, slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletProbeV1<Vec<u8>> {
        self.with(|state| {
            if state.anchor_read_unavailable {
                return KagemushaWalletProbeV1::Unavailable(KagemushaWalletUnavailableV1::Locked);
            }
            state.anchors.get(slot).cloned().map_or(
                KagemushaWalletProbeV1::Absent,
                KagemushaWalletProbeV1::Present,
            )
        })
    }

    fn anchor_update(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        value: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        self.with(|state| {
            if !state.anchors.contains_key(slot) {
                return KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::DestinationAbsent,
                );
            }
            Self::anchor_write(state, slot, value)
        })
    }

    fn storage_state(&self) -> Result<(), KagemushaWalletUnavailableV1> {
        self.with(Self::storage_answer)
    }

    fn boot_id(&self) -> Result<[u8; 32], KagemushaWalletUnavailableV1> {
        self.with(|state| state.boot)
    }

    fn monotonic_ms(&self) -> Result<u64, KagemushaWalletUnavailableV1> {
        self.with(|state| {
            if let Some(boot) = state.boot_after_monotonic.take() {
                state.boot = boot;
            }
            state
                .monotonic_script
                .pop_front()
                .unwrap_or(state.monotonic)
        })
    }
}

impl FakePlatformV1 {
    fn generate_key(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        request: &KagemushaWalletKeyGenerationRequestV1,
    ) -> KagemushaWalletKeyGenerationV1 {
        self.with(|state| {
            state.generate_calls += 1;
            state.last_generation = Some(*request);
            Self::check_generation(state, slot);
            if state.keys.contains_key(slot) {
                return KagemushaWalletKeyGenerationV1::AlreadyPresent;
            }
            let key = signing_key(state.next_key_seed);
            let public = public_key(&key);
            match state.generate_unavailable {
                Some(created) => {
                    if created {
                        state.keys.insert(*slot, key);
                    }
                    KagemushaWalletKeyGenerationV1::Unavailable(KagemushaWalletUnavailableV1::Io(5))
                }
                None => {
                    state.keys.insert(*slot, key);
                    state.generation_originals.insert(*slot, (*request, public));
                    if state.lock_after_generation {
                        state.storage = Err(KagemushaWalletUnavailableV1::Locked);
                    }
                    if state.generation_readback_unavailable {
                        KagemushaWalletKeyGenerationV1::Unavailable(
                            KagemushaWalletUnavailableV1::Busy,
                        )
                    } else {
                        KagemushaWalletKeyGenerationV1::Generated(public)
                    }
                }
            }
        })
    }

    /// Record a violation unless `slot` is in the state "intent, no marker, not abandoned"
    /// with no key (design I12).
    fn check_generation(state: &mut FakeStateV1, slot: &KagemushaWalletSlotIdV1) {
        let Some(fs) = state.guard.as_ref() else {
            return;
        };
        let slot_names = fs.visible_names(&super::kagemusha_wallet_slot_dir_v1(slot));
        let markers = fs
            .visible_names(&super::kagemusha_wallet_markers_dir_v1(slot))
            .into_iter()
            .filter(|name| super::kagemusha_wallet_parse_marker_name_v1(name).is_some())
            .count();
        let intent = slot_names
            .iter()
            .any(|name| name == super::KAGEMUSHA_WALLET_INTENT_NAME_V1);
        let abandoned = slot_names
            .iter()
            .any(|name| name == super::KAGEMUSHA_WALLET_ABANDONED_NAME_V1);
        if !intent || abandoned || markers != 0 || state.keys.contains_key(slot) {
            state.violations.push(format!(
                "key generated with intent {intent} abandoned {abandoned} markers {markers}"
            ));
        }
    }

    /// Record a violation unless the only visible marker of `slot` is a custody-deletion
    /// terminal marker that the anchor (when required) names (design D3, I11).
    fn check_deletion(state: &mut FakeStateV1, slot: &KagemushaWalletSlotIdV1) {
        let Some(fs) = state.guard.as_ref() else {
            return;
        };
        let dir = super::kagemusha_wallet_markers_dir_v1(slot);
        let names: Vec<String> = fs
            .visible_names(&dir)
            .into_iter()
            .filter(|name| super::kagemusha_wallet_parse_marker_name_v1(name).is_some())
            .collect();
        let record = match names.as_slice() {
            [only] => fs.visible_file(&dir, only).and_then(|bytes| {
                KagemushaWalletMarkerRecordV1::decode(&bytes, slot, &SCHEME).ok()
            }),
            _ => None,
        };
        let terminal = record.as_ref().is_some_and(|record| {
            matches!(
                record.marker().state,
                iroha_data_model::kagemusha::KagemushaWalletMarkerStateV1::Terminal {
                    reason: iroha_data_model::kagemusha::KagemushaWalletTerminalReasonV1::CustodyDeleted,
                    ..
                }
            )
        });
        let anchored = state.policy == KagemushaWalletAnchorPolicyV1::NotRequired
            || record.as_ref().is_some_and(|record| {
                state
                    .anchors
                    .get(slot)
                    .and_then(|bytes| super::KagemushaWalletAnchorV1::decode(bytes).ok())
                    == Some(super::KagemushaWalletAnchorV1::naming(record))
            });
        if !terminal || !anchored {
            state.violations.push(format!(
                "key deleted under markers {names:?} anchored {anchored}"
            ));
        }
    }

    fn anchor_write(
        state: &mut FakeStateV1,
        slot: &KagemushaWalletSlotIdV1,
        value: &[u8],
    ) -> KagemushaWalletPublishOutcomeV1 {
        let call = state.anchor_writes;
        state.anchor_writes += 1;
        let mode = match state.anchor_fault_at {
            Some((at, mode)) if at == call => mode,
            _ => state.anchor_write,
        };
        let apply = |state: &mut FakeStateV1| {
            let previous = state.anchors.insert(*slot, value.to_vec());
            state.anchor_previous.insert(*slot, previous);
        };
        match mode {
            AnchorWriteV1::Normal => {
                apply(state);
                KagemushaWalletPublishOutcomeV1::Published
            }
            AnchorWriteV1::Refused => KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::Failed(KagemushaWalletUnavailableV1::Platform(
                    -25_308,
                )),
            ),
            AnchorWriteV1::UncertainApplied => {
                apply(state);
                KagemushaWalletPublishOutcomeV1::Uncertain(KagemushaWalletUnavailableV1::Platform(
                    1,
                ))
            }
            AnchorWriteV1::UncertainLost => KagemushaWalletPublishOutcomeV1::Uncertain(
                KagemushaWalletUnavailableV1::Platform(1),
            ),
        }
    }
}

/// Transition owner of the tests: the canonical receipt body over the capsule's frozen
/// statement, proof and Payment digests, and a completion whose output embeds its signature.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TestOwnerV1;

impl
    super::KagemushaWalletTransitionOwnerV1<
        KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletCompletionRecordV1,
    > for TestOwnerV1
{
    fn receipt_body(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
    ) -> Result<Vec<u8>, super::KagemushaWalletProviderErrorV1> {
        Ok(KagemushaWalletReceiptBodyV1 {
            version: 1,
            scheme_id: capsule.scheme_id,
            wallet_id: capsule.wallet_id,
            provider_contract: kagemusha_wallet_provider_contract_v1(),
            sequence: capsule.statement.sequence,
            operation_id: capsule.operation_id,
            predecessor: capsule.statement.predecessor,
            successor: capsule.statement.successor,
            statement_digest: capsule.statement.statement_digest().map_err(|_| {
                super::KagemushaWalletProviderErrorV1::Invalid {
                    field: "receipt.statement_digest",
                }
            })?,
            proof_digest: capsule.proof_digest().map_err(|_| {
                super::KagemushaWalletProviderErrorV1::Invalid {
                    field: "receipt.proof_digest",
                }
            })?,
            capsule_digest: *capsule_digest,
            payment_digest: capsule.payment_digest,
        }
        .transcript())
    }

    fn assemble(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
        signature: &KagemushaDeviceSignatureV1,
    ) -> Result<KagemushaWalletCompletionRecordV1, super::KagemushaWalletProviderErrorV1> {
        let mut output = capsule_digest.to_vec();
        output.extend_from_slice(signature.as_raw_bytes());
        let record = KagemushaWalletCompletionRecordV1 {
            version: 1,
            wallet_id: capsule.wallet_id,
            operation_id: capsule.operation_id,
            capsule_digest: *capsule_digest,
            receipt: KagemushaWalletReceiptV1 {
                version: 1,
                operation_id: capsule.operation_id,
                capsule_digest: *capsule_digest,
                payment_digest: capsule.payment_digest,
                signature: *signature,
            },
            output,
        };
        record
            .validate()
            .map_err(|_| super::KagemushaWalletProviderErrorV1::Invalid { field: "output" })?;
        Ok(record)
    }
}

/// Small ballast for simulated flows.
pub(super) const TEST_BALLAST_BYTES: u64 = 2_048;

/// Provider options of simulated flows.
pub(super) fn test_options() -> super::KagemushaWalletProviderOptionsV1 {
    super::KagemushaWalletProviderOptionsV1 {
        ballast_bytes: TEST_BALLAST_BYTES,
    }
}

/// Open a simulated provider.
pub(super) fn open_provider(
    fs: &KagemushaWalletSimFsV1,
    platform: &FakePlatformV1,
) -> Result<SimProviderV1, super::KagemushaWalletProviderErrorV1> {
    SimProviderV1::open(fs.clone(), platform.clone(), SCHEME, test_options())
}

/// `Advance` request of `capsule` on the head named by `current`.
pub(super) fn advance_request(
    current: &KagemushaWalletMarkerRecordV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
) -> super::KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1> {
    super::KagemushaWalletAdvanceRequestV1 {
        expected: super::KagemushaWalletExpectedHeadV1::of(current).expect("expected head"),
        operation_id: capsule.operation_id,
        new_head: capsule.statement.successor,
        proof_digest: capsule.proof_digest().expect("proof digest"),
        capsule: capsule.clone(),
        growth_bytes: 0,
    }
}

/// A simulated device: filesystem and platform.
#[derive(Debug, Clone)]
pub(super) struct DeviceV1 {
    pub(super) fs: KagemushaWalletSimFsV1,
    pub(super) platform: FakePlatformV1,
}

impl DeviceV1 {
    /// Empty device with `policy`, whose next key is `signing_key(seed)` and whose signing
    /// guard observes its filesystem.
    pub(super) fn new(policy: KagemushaWalletAnchorPolicyV1, seed: u8) -> Self {
        let fs = KagemushaWalletSimFsV1::new();
        let platform = FakePlatformV1::new(policy, seed);
        platform.with(|state| state.guard = Some(fs.clone()));
        Self { fs, platform }
    }

    /// Independent copy.
    pub(super) fn fork(&self) -> Self {
        let fs = self.fs.fork();
        let platform = self.platform.fork(Some(&fs));
        Self { fs, platform }
    }

    /// Open a provider.
    pub(super) fn open(&self) -> SimProviderV1 {
        open_provider(&self.fs, &self.platform).expect("open")
    }

    /// Lose power and boot again with a new boot identity.
    pub(super) fn power_loss(&self, mode: super::KagemushaWalletSimPowerLossV1, boot: [u8; 32]) {
        self.fs.power_loss(mode);
        self.platform.with(|state| state.boot = Ok(boot));
    }
}

/// An enrolled device of fixture `seed`: the enrollment marker is durable and the request and
/// credential are retained.
pub(super) fn enrolled_device(
    policy: KagemushaWalletAnchorPolicyV1,
    seed: u8,
) -> (DeviceV1, WalletFixtureV1, KagemushaWalletSlotIdV1) {
    let device = DeviceV1::new(policy, seed);
    let f = wallet_fixture(seed);
    let mut provider = device.open();
    let super::KagemushaWalletEnrollmentStepV1::Enrolled { slot, marker } = provider
        .test_begin_enrollment(
            &enrollment_challenge(seed),
            PROFILE,
            crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                issued_at_ms: 1,
                expires_at_ms: 600_001,
            },
        )
        .expect("begin")
    else {
        panic!("not enrolled");
    };
    assert_eq!(marker.marker(), &f.enrollment);
    provider
        .retain_enrollment_request(&slot, b"request")
        .expect("request");
    provider
        .store_credential(&slot, 0, b"credential")
        .expect("credential");
    (device, f, slot)
}

/// Released outcome's retained result.
pub(super) fn released(
    outcome: super::KagemushaWalletAdvanceOutcomeV1<KagemushaWalletCompletionRecordV1>,
) -> super::KagemushaWalletRetainedV1<KagemushaWalletCompletionRecordV1> {
    match outcome {
        super::KagemushaWalletAdvanceOutcomeV1::Released { retained, .. } => *retained,
        other => panic!("not released: {other:?}"),
    }
}

/// A device after Bootstrap: returns the device, fixture, slot and the Bootstrap capsule.
pub(super) fn bootstrapped_device(
    policy: KagemushaWalletAnchorPolicyV1,
    seed: u8,
) -> (
    DeviceV1,
    WalletFixtureV1,
    KagemushaWalletSlotIdV1,
    KagemushaWalletRecoveryCapsuleV1,
) {
    let (device, f, slot) = enrolled_device(policy, seed);
    let mut provider = device.open();
    let current = provider.status(&slot).expect("status");
    let capsule = bootstrap_capsule(&f);
    let request = advance_request(current.marker().expect("marker"), &capsule);
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("bootstrap"),
    );
    (device, f, slot, capsule)
}
