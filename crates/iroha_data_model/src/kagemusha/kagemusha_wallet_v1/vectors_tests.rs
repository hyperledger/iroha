//! Cross-language KAGEMUSHA wallet V1 vectors and consolidated codec checks (design §8, C11).
//!
//! One deterministic fixture world is built from fixed P-256 scalars `[seed; 32]`. Every
//! signature is the RFC 6979 output of a p256 `SigningKey`, frozen to low S through
//! [`kagemusha_wallet_freeze_signature_v1`] by the objects' own constructors. The world feeds
//! `fixtures/kagemusha/wallet_v1_vectors.json`: every current SHA-256 role and distinct
//! Poseidon signed-object domain,
//! signature vectors with their signing domain, transcript and 32-byte Poseidon signing message,
//! their high-S twins and the low-S boundary scalars, one envelope vector per message kind,
//! frame identities of the top-level records, one pinned canonical frame of every framed object
//! type and marker state, the enum tag table, the σ-field element encodings (statement, state
//! core and rest, chain appends, map and credit-digest values) and the Poseidon values computed
//! over them, the `P_bytes` packing rule, `credit_id`, `proof_digest`, the Payment, lineage,
//! credit-opening, credit-status and credited digests, every signing message, the depth-32
//! indexed map tree with insertions, openings and a removal, the fixed 64-slot quota-usage
//! array with depth-6 openings and an authenticated in-place charge, the limb-ordered
//! blacklist and the quota-window trees, and the verifying-key allowlist digest, that the native
//! and in-circuit encoders must share (§3.2). The file is compared byte for byte;
//! `IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS=1` rewrites it (a test-only convenience). Stand-in σ
//! and Ω bytes, relation bindings and verifying keys are labelled: they change when G3 fixes the
//! artifact set. The vectors are self-consistent: the scheme's relation identity and the
//! artifact manifest bind the computed digest of the vectored allowlist, and every stand-in σ
//! and Ω has exactly its allowlisted length (defects d1 and d2).
//!
//! TODO: migrate the Swift, Kotlin and proof vector consumers to these current field-only
//! statements, signed-object digests and fixed-slot quota openings before cross-language
//! qualification; the reference is regenerated only by this owner's test.

use std::{path::PathBuf, sync::OnceLock};

use norito::json::{Map, Number, Value};
use p256::{
    FieldBytes, ProjectivePoint, Scalar, U256,
    ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey, signature::Verifier as _},
    elliptic_curve::{Field as _, PrimeField as _, ops::Reduce, point::AffineCoordinates as _},
};
use sha2::{Digest as _, Sha256};

use super::{
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag, payload_range},
    identity::identity_tests::{
        IdentityFixture, public_key, raw_output, signing_key, test_account, test_certificate,
    },
    messages::messages_tests::{
        ACCEPTED_MS, MessageFixture, OPENING_OTHER_CREDITS, message_fixture, receiver_head_state,
    },
    state::state_tests::{
        CREDIT_DIGEST_ROOT, LINEAGE_PENDING_ROOT, bootstrap_statement, controlled_state,
        field_value, lineage_with_len, signed_package, signed_package_with, stand_in_proof,
        transition_statement,
    },
    verifying_keys::verifying_keys_tests::{
        STAND_IN_LINEAGE_BYTES, STAND_IN_SIGMA_BYTES, scheme_allowlist,
        scheme_verifying_key_set_digest,
    },
    *,
};

use crate::isi::kagemusha_wallet::load_finality::{
    KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1, KagemushaWalletLoadReceiptV1,
};

type Role = KagemushaWalletDigestRoleV1;
type Domain = KagemushaWalletSigningDomainV1;
type ObjectDomain = KagemushaWalletObjectDigestDomainV1;

/// Path of the vectors file relative to this crate.
const VECTORS_PATH: &str = "../../fixtures/kagemusha/wallet_v1_vectors.json";
/// Test-only switch that rewrites the vectors file instead of comparing it.
const UPDATE_VARIABLE: &str = "IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS";
/// Common prefix of every wallet V1 frame name.
const FRAME_NAME_PREFIX: &str = "iroha_data_model::kagemusha::kagemusha_wallet_v1::";

/// Stand-in relation bindings shared with the identity fixture (design C3); the real values
/// come from the G3 artifact set. The verifying-key-set digest is the computed digest of the
/// vectored allowlist ([`scheme_verifying_key_set_digest`], defect d1).
const EQ: [u8; 32] = [0x21; 32];
const EP: [u8; 32] = [0x22; 32];
const NATIVE: [u8; 32] = [0x23; 32];
const INVENTORY: [u8; 32] = [0x25; 32];

/// Fixed scalar seeds `[seed; 32]` of the vector signers.
const ROOT_SEED: u8 = 0x11;
const RECEIVER_ISSUER_SEED: u8 = 0x22;
const PAYER_ISSUER_SEED: u8 = 0x26;
const REGULATOR_SEED: u8 = 0x33;
const TIME_SEED: u8 = 0x35;
const ARTIFACT_SEED: u8 = 0x36;
const RENEWAL_KEY_SEED: u8 = 0x37;
const PAYER_SEED: u8 = 0x51;
const RECEIVER_SEED: u8 = 0x52;
/// Ed25519 seed of the fee and charge beneficiary account.
const BENEFICIARY_SEED: u8 = 0x5b;

/// Stand-in σ length of the vectored packages: the allowlisted length of every empty-mask
/// selector.
const VECTOR_PROOF_LEN: usize = STAND_IN_SIGMA_BYTES;
/// Stand-in Ω(h) transport proof length of the vectored `CreditStatus`: the allowlist's exact Ω
/// length, like every other vectored Ω (defect d2).
const STATUS_LINEAGE_LEN: usize = STAND_IN_LINEAGE_BYTES;
/// Session nonce of the vectored Offer and session controls.
const SESSION_NONCE: [u8; 32] = [0x5e; 32];
/// Renewal challenge of the vectored renewal request.
const RENEWAL_CHALLENGE: [u8; 32] = [0x7c; 32];
/// Start of the vectored quota windows.
const QUOTA_START_MS: u64 = 1_789_948_800_000;
const DAY_MS: u64 = 86_400_000;

/// P-256 group order `n`.
const ORDER_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// `floor(n / 2)`, the largest accepted `s`.
const HALF_ORDER_HEX: &str = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";
/// Fixed nonce `k` of the boundary signature (design C11).
const BOUNDARY_NONCE: [u8; 32] = [0x5a; 32];
/// Signing domain of the boundary signature, and the start of its zero-padded transcript.
const BOUNDARY_DOMAIN: Domain = Domain::Receipt;
const BOUNDARY_BODY: &[u8] = b"kagemusha wallet v1 low-S boundary";

// ---------------------------------------------------------------------------------------
// Fixture world
// ---------------------------------------------------------------------------------------

/// One fully valid object of every vectored kind, built from fixed P-256 scalars.
pub(super) struct VectorWorld {
    /// Payer, receiver and regulator of one scheme.
    pub(super) f: MessageFixture,
    /// `TimeAnchor`-role signer.
    time_signer: SigningKey,
    /// `TimeAnchor`-role certificate.
    time_certificate: KagemushaWalletSignerCertificateV1,
    /// `Artifact`-role signer.
    artifact_signer: SigningKey,
    /// `Artifact`-role certificate.
    artifact_certificate: KagemushaWalletSignerCertificateV1,
    /// Epoch-1 scheme policy naming the fee schedule.
    scheme_policy: KagemushaWalletSchemePolicyV1,
    /// Fee schedule of the Request.
    fee_schedule: KagemushaWalletFeeScheduleV1,
    /// Three-entry blacklist.
    blacklist: KagemushaWalletBlacklistV1,
    /// Two-window quota share of the payer.
    quota_share: KagemushaWalletQuotaShareV1,
    /// Time anchor of the payer.
    time_anchor: KagemushaWalletTimeAnchorV1,
    /// Load charge quote of the payer.
    charge_quote: KagemushaWalletChargeQuoteV1,
    /// Ordinary quoted Load receipt of the payer.
    load_receipt: KagemushaWalletLoadReceiptV1,
    /// Artifact manifest of the scheme.
    manifest: KagemushaWalletArtifactManifestV1,
    /// Android renewal request of the payer.
    renewal: KagemushaWalletRenewalRequestV1,
    /// Payer Offer.
    offer: KagemushaWalletOfferV1,
    /// Signed `Close` control of the payer.
    close: KagemushaWalletSessionControlV1,
    /// Unsigned `UnsupportedScheme` control.
    unsupported: KagemushaWalletSessionControlV1,
    /// Receiver-signed Request with the fee schedule; the Payment carries its signed body.
    request: KagemushaWalletRequestV1,
    /// Fee-bearing compact Payment carrying Ω(pred).
    payment: KagemushaWalletPaymentV1,
    /// Lineage message carrying the Payment's exact Ω(pred) bytes.
    lineage: KagemushaWalletLineageMessageV1,
    /// Receiver's Receive package of the Payment, receipted over `capsule`.
    receive: KagemushaWalletPackageV1,
    /// Recovery capsule of the Receive.
    capsule: KagemushaWalletRecoveryCapsuleV1,
    /// Completion record of the Receive.
    completion: KagemushaWalletCompletionRecordV1,
    /// Credited evidence from the Receive package.
    credited_receive: KagemushaWalletCreditedV1,
    /// Credited evidence from a `CreditStatus` of a folded receiver head.
    credited_status: KagemushaWalletCreditedV1,
    /// Fold record of the payer head that the Payment's Ω(pred) covers.
    fold: KagemushaWalletFoldRecordV1,
    /// Generation-0 enrollment marker of the payer.
    marker: KagemushaWalletMarkerV1,
    /// Bootstrap package of the payer, bound to `marker`.
    bootstrap: KagemushaWalletPackageV1,
    /// Activate ledger control of the payer.
    control: KagemushaWalletLedgerControlV1,
    /// Stand-in verifying-key allowlist matching the vectored proof lengths.
    allowlist: KagemushaWalletVerifyingKeyAllowlistV1,
}

/// The fixture world, built once per test binary.
pub(super) fn vector_world() -> &'static VectorWorld {
    static WORLD: OnceLock<VectorWorld> = OnceLock::new();
    WORLD.get_or_init(build_world)
}

/// Payer Offer of 1,000 units at send ordinal 4.
pub(super) fn vector_offer(f: &MessageFixture) -> KagemushaWalletOfferV1 {
    let body = KagemushaWalletOfferBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.scheme_id(),
        asset_digest: f.asset_digest(),
        payer_wallet_id: f.payer.credential.body.wallet_id,
        payer_credential_digest: f.payer.credential.credential_digest(),
        next_send: 4,
        amount: 1_000,
        session_nonce: SESSION_NONCE,
    };
    KagemushaWalletOfferV1::sign(
        body,
        f.payer.credential,
        &f.payer.enrollment_certificate,
        raw_output(&f.payer.payment, &body.signing_message()),
    )
    .expect("offer")
}

/// Payer session control of `kind`; signed except `UnsupportedScheme`.
pub(super) fn vector_control(
    f: &MessageFixture,
    kind: KagemushaWalletSessionControlKindV1,
) -> KagemushaWalletSessionControlV1 {
    use KagemushaWalletSessionControlKindV1 as Kind;
    let control = KagemushaWalletSessionControlV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.scheme_id(),
        asset_digest: f.asset_digest(),
        sender_wallet_id: if kind == Kind::UnsupportedScheme {
            [0; 32]
        } else {
            f.payer.credential.body.wallet_id
        },
        peer_wallet_id: f.receiver.credential.body.wallet_id,
        session_nonce: SESSION_NONCE,
        kind,
        reason: match kind {
            Kind::SetupDeclined | Kind::ReceiveDeferred => 7,
            Kind::UnsupportedScheme | Kind::Close => 0,
        },
        credit_id: if kind == Kind::ReceiveDeferred {
            field_value(0x71)
        } else {
            [0; 32]
        },
        auth: KagemushaWalletSessionAuthV1::Unsigned,
    };
    if kind == Kind::UnsupportedScheme {
        control.validate().expect("unsigned control");
        return control;
    }
    control
        .sign(
            &f.payer.credential,
            raw_output(&f.payer.payment, &control.signing_message()),
        )
        .expect("signed control")
}

/// Signed blacklist of `count` distinct stand-in account digests in limb order (owner answer
/// A4); their unsigned byte order differs.
fn vector_blacklist(f: &MessageFixture, count: u32) -> KagemushaWalletBlacklistV1 {
    let mut entries: Vec<KagemushaWalletBlacklistEntryV1> = (0..count)
        .map(|index| KagemushaWalletBlacklistEntryV1 {
            account_digest: kagemusha_wallet_digest_v1(Role::Account, &index.to_le_bytes()),
        })
        .collect();
    let mut byte_ordered = entries.clone();
    byte_ordered.sort_by_key(|entry| entry.account_digest);
    entries.sort_by(|left, right| {
        kagemusha_wallet_integer_cmp_v1(&left.account_digest, &right.account_digest)
    });
    assert_ne!(entries, byte_ordered, "byte order and limb order differ");
    let body = KagemushaWalletBlacklistBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.scheme_id(),
        list_version: 3,
        issued_at_ms: ACCEPTED_MS - 10_000,
        entry_count: count,
        entries_root: kagemusha_wallet_blacklist_root_v1(&entries).expect("root"),
        signer_certificate: f.regulator_certificate.certificate_digest(),
    };
    KagemushaWalletBlacklistV1::sign(
        body,
        entries,
        &f.regulator_certificate,
        raw_output(&f.regulator, &body.signing_message()),
    )
    .expect("blacklist")
}

/// Stand-in verifying-key allowlist: the one the test scheme's relation identity binds
/// ([`scheme_allowlist`]): every operation with the vectored σ length, Send also with every
/// control enabled, Receive also with the blacklist bit, and the vectored Ω transport length;
/// the verifying-key digests are labelled stand-ins.
fn vector_allowlist() -> KagemushaWalletVerifyingKeyAllowlistV1 {
    let allowlist = scheme_allowlist();
    assert_eq!(
        u32::try_from(super::messages::messages_tests::PAYMENT_LINEAGE_LEN).ok(),
        Some(allowlist.lineage_proof_bytes)
    );
    allowlist
}

/// Build every vectored object and check that each one validates.
fn build_world() -> VectorWorld {
    let f = message_fixture();
    let scheme = f.payer.scheme;
    let scheme_id = scheme.scheme_id();
    let asset_digest = f.asset_digest();
    let payer = f.payer.credential;
    let receiver = f.receiver.credential;
    for (seed, key) in [
        (ROOT_SEED, scheme.scheme_root_key),
        (
            RECEIVER_ISSUER_SEED,
            f.receiver.enrollment_certificate.body.key,
        ),
        (PAYER_ISSUER_SEED, f.payer.enrollment_certificate.body.key),
        (REGULATOR_SEED, f.regulator_certificate.body.key),
        (PAYER_SEED, payer.body.payment_key),
        (RECEIVER_SEED, receiver.body.payment_key),
    ] {
        assert_eq!(public_key(&signing_key(seed)), key, "seed {seed:#04x}");
    }
    assert_eq!(
        kagemusha_wallet_relation_id_v1(
            &EQ,
            &EP,
            &NATIVE,
            &scheme_verifying_key_set_digest(),
            &INVENTORY
        ),
        scheme.relation_id
    );

    let root = &f.payer.root;
    let time_signer = signing_key(TIME_SEED);
    let time_certificate = test_certificate(
        &scheme,
        root,
        KagemushaWalletSignerRoleV1::TimeAnchor,
        &time_signer,
        4,
    );
    let artifact_signer = signing_key(ARTIFACT_SEED);
    let artifact_certificate = test_certificate(
        &scheme,
        root,
        KagemushaWalletSignerRoleV1::Artifact,
        &artifact_signer,
        5,
    );
    let regulator_certificate = f.regulator_certificate.certificate_digest();
    let beneficiary =
        kagemusha_wallet_account_digest_v1(&test_account(BENEFICIARY_SEED)).expect("beneficiary");

    let fee_schedule = f.fee_schedule();
    let policy_body = KagemushaWalletSchemePolicyBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        policy_epoch: 1,
        enabled_controls: 0,
        fee_schedule: fee_schedule.fee_schedule_digest(),
        signer_certificate: regulator_certificate,
    };
    let scheme_policy = KagemushaWalletSchemePolicyV1::sign(
        policy_body,
        &f.regulator_certificate,
        raw_output(&f.regulator, &policy_body.signing_message()),
    )
    .expect("scheme policy");
    let blacklist = vector_blacklist(&f, 3);

    let windows = vec![
        KagemushaWalletQuotaWindowV1 {
            kind: KagemushaWalletQuotaWindowKindV1::Daily,
            start_ms: QUOTA_START_MS,
            end_ms: QUOTA_START_MS + DAY_MS,
            limit: 50_000,
        },
        KagemushaWalletQuotaWindowV1 {
            kind: KagemushaWalletQuotaWindowKindV1::Monthly,
            start_ms: QUOTA_START_MS,
            end_ms: QUOTA_START_MS + 30 * DAY_MS,
            limit: 500_000,
        },
    ];
    let share_body = KagemushaWalletQuotaShareBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        wallet_id: payer.body.wallet_id,
        share_id: 1,
        issued_at_ms: QUOTA_START_MS,
        expires_at_ms: QUOTA_START_MS + 31 * DAY_MS,
        windows_root: kagemusha_wallet_quota_windows_root_v1(&windows).expect("windows root"),
        window_count: 2,
        signer_certificate: regulator_certificate,
    };
    let quota_share = KagemushaWalletQuotaShareV1::sign(
        share_body,
        windows,
        &f.regulator_certificate,
        raw_output(&f.regulator, &share_body.signing_message()),
    )
    .expect("quota share");

    let anchor_body = KagemushaWalletTimeAnchorBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        wallet_id: payer.body.wallet_id,
        nonce: [0x7e; 32],
        issuer_time_ms: ACCEPTED_MS + 1_000,
        signer_certificate: time_certificate.certificate_digest(),
    };
    let time_anchor = KagemushaWalletTimeAnchorV1::sign(
        anchor_body,
        &time_certificate,
        raw_output(&time_signer, &anchor_body.signing_message()),
    )
    .expect("time anchor");

    let quote_body = KagemushaWalletChargeQuoteBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        wallet_id: payer.body.wallet_id,
        kind: KagemushaWalletChargeKindV1::Load,
        ordinal: 0,
        net_amount: 5_000,
        online_charge: 25,
        beneficiary_account_digest: beneficiary,
        issued_at_ms: ACCEPTED_MS - 60_000,
        signer_certificate: regulator_certificate,
    };
    let charge_quote = KagemushaWalletChargeQuoteV1::sign(
        quote_body,
        &f.regulator_certificate,
        raw_output(&f.regulator, &quote_body.signing_message()),
    )
    .expect("charge quote");
    let load_receipt = KagemushaWalletLoadReceiptV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        wallet_id: payer.body.wallet_id,
        request_id: [0x9b; 32],
        ordinal: 0,
        amount: 5_000,
        online_charge: 25,
        charge_quote: charge_quote.charge_quote_digest(),
        transaction_hash: [0x9a; 32],
        block_height: 42,
        payer_account_digest: kagemusha_wallet_account_digest_v1(&test_account(BENEFICIARY_SEED))
            .unwrap(),
    };
    load_receipt
        .require_charge_quote(Some(&charge_quote))
        .expect("quoted ordinary receipt");

    let manifest_body = KagemushaWalletArtifactManifestBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: scheme.network_id,
        relation_id: scheme.relation_id,
        eq_protocol_digest: EQ,
        ep_protocol_digest: EP,
        native_profile_digest: NATIVE,
        verifying_key_set_digest: scheme_verifying_key_set_digest(),
        artifact_inventory_digest: INVENTORY,
        provider_contract: scheme.provider_contract,
        signer_certificate: artifact_certificate.certificate_digest(),
    };
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        manifest_body,
        &artifact_certificate,
        raw_output(&artifact_signer, &manifest_body.signing_message()),
    )
    .expect("manifest");
    manifest
        .verify(&scheme, &artifact_certificate)
        .expect("manifest verifies");

    let renewal_key = public_key(&signing_key(RENEWAL_KEY_SEED));
    let binding = kagemusha_wallet_renewal_key_binding_message_v1(
        &scheme_id,
        &payer.body.wallet_id,
        &RENEWAL_CHALLENGE,
        &renewal_key,
    );
    let evidence = KagemushaWalletRenewalEvidenceV1::android_signed(
        &payer,
        &RENEWAL_CHALLENGE,
        renewal_key,
        raw_output(&f.payer.payment, &binding),
        vec![
            KagemushaWalletDerCertificateV1 {
                der: b"renewal-leaf-der".to_vec(),
            },
            KagemushaWalletDerCertificateV1 {
                der: b"renewal-intermediate-der".to_vec(),
            },
        ],
    )
    .expect("renewal evidence");
    let possession = kagemusha_wallet_renewal_challenge_message_v1(
        &scheme_id,
        &payer.body.wallet_id,
        &payer.credential_digest(),
        &RENEWAL_CHALLENGE,
    );
    let renewal = KagemushaWalletRenewalRequestV1::sign(
        &payer,
        RENEWAL_CHALLENGE,
        raw_output(&f.payer.payment, &possession),
        evidence,
    )
    .expect("renewal request");

    let offer = vector_offer(&f);
    let close = vector_control(&f, KagemushaWalletSessionControlKindV1::Close);
    let unsupported = vector_control(&f, KagemushaWalletSessionControlKindV1::UnsupportedScheme);

    let request = f.request(true);
    let payment = f.payment(true, VECTOR_PROOF_LEN);
    assert_eq!(payment.request, request.signed());
    assert_eq!(
        payment.request.body.scheme_policy,
        scheme_policy.scheme_policy_digest()
    );
    assert_eq!(
        payment.request.body.fee_schedule,
        fee_schedule.fee_schedule_digest()
    );
    let payer_issuer = KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate])
        .expect("payer issuer set");
    let payment_digest = payment
        .verify(&scheme, &payer, &payer_issuer, &request)
        .expect("payment verifies")
        .payment;
    let lineage = f.lineage_message(&payment);
    lineage
        .verify_for_offer(&offer)
        .expect("lineage matches the offer");

    // The Receive package is receipted over its real capsule, so the completion record verifies.
    // Its successor is the computed commitment of the capsule's successor state.
    let mut state = KagemushaWalletStateV1::bootstrap(&receiver, field_value(0x5c)).expect("state");
    state.core.sequence = 5;
    state.core.balance = 1_000;
    state.core.next_send = 1;
    state.core.recv_chain = field_value(0x2d);
    // The capsule retains this Receive's consumed-credit insertion witness as §3.2 opening
    // transcripts (owner answer A2): the low leaf's opening against the predecessor's empty map
    // and the written slot's empty-slot opening; the successor holds the inserted root.
    let consumed = payment.consumed_credit_leaf(5).expect("consumed credit");
    let mut consumed_credits = KagemushaWalletIndexedTreeV1::new();
    let consumed_value = consumed.leaf_value().expect("consumed value");
    let insertion = consumed_credits
        .insert(consumed.key(), consumed_value)
        .expect("consumed-credit insertion");
    assert_eq!(
        insertion
            .verify(
                &kagemusha_wallet_empty_map_root_v1(),
                &consumed.key(),
                &consumed_value
            )
            .ok(),
        Some(consumed_credits.root())
    );
    state.core.consumed_credit_root = consumed_credits.root();
    let map_openings = vec![
        insertion.low_opening.leaf_transcript(&insertion.low),
        insertion.slot_opening.empty_transcript(),
    ];
    let statement = KagemushaWalletStatementV1 {
        successor: state.commitment().expect("successor commitment"),
        ..transition_statement(
            &f.receiver,
            5,
            0,
            KagemushaWalletLifecycleV1::Active,
            payment
                .receive_effect(&request, &receiver, &receiver_head_state(&receiver), None)
                .expect("receive effect"),
        )
    };
    let proof = stand_in_proof(VECTOR_PROOF_LEN);
    let proof_digest =
        kagemusha_wallet_proof_digest_v1(KagemushaWalletOperationKindV1::Receive, None, &proof)
            .expect("σ-only proof digest");
    let retained = |role, bytes| KagemushaWalletRetainedInputV1 { role, bytes };
    let capsule = KagemushaWalletRecoveryCapsuleV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        wallet_id: receiver.body.wallet_id,
        operation_id: statement
            .operation_id(&receiver.body.wallet_id)
            .expect("Receive operation identity"),
        kind: KagemushaWalletOperationKindV1::Receive,
        predecessor_capsule_digest: [0x5b; 32],
        successor_state: state,
        statement,
        predecessor_lineage: KagemushaWalletLineageSlotV1::None,
        step_proof: proof.clone(),
        payment_digest,
        map_openings,
        retained_inputs: vec![
            retained(
                KagemushaWalletRetainedInputRoleV1::Request,
                encode_frame_v1(&request, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
                    .expect("request frame"),
            ),
            retained(
                KagemushaWalletRetainedInputRoleV1::Payment,
                payment.to_canonical_bytes().expect("payment frame"),
            ),
            retained(
                KagemushaWalletRetainedInputRoleV1::CertificateSet,
                encode_frame_v1(&payer_issuer, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
                    .expect("certificate set frame"),
            ),
            retained(
                KagemushaWalletRetainedInputRoleV1::Credential,
                payer.to_canonical_bytes().expect("payer credential frame"),
            ),
        ],
        output: KagemushaWalletOutputDescriptorV1::for_transition(
            &statement,
            &proof_digest,
            &payment_digest,
        )
        .expect("output"),
    };
    let capsule_digest = capsule.capsule_digest().expect("capsule digest");
    let receiver_signer =
        KagemushaWalletReceiptSignerV1::from_credential(&receiver).expect("receiver signer");
    let receipt_body = KagemushaWalletReceiptBodyV1::derive(
        &receiver_signer,
        &statement,
        &proof_digest,
        capsule_digest,
        payment_digest,
    )
    .expect("receipt body");
    let receipt = KagemushaWalletReceiptV1::sign(
        &receiver,
        &statement,
        &proof_digest,
        capsule_digest,
        payment_digest,
        raw_output(&f.receiver.payment, &receipt_body.signing_message()),
    )
    .expect("receipt");
    let receive = KagemushaWalletPackageV1::new(
        statement,
        KagemushaWalletLineageSlotV1::None,
        proof,
        receipt,
    );
    let completion = KagemushaWalletCompletionRecordV1::new(
        &capsule,
        receipt,
        encode_frame_v1(&receive, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).expect("package frame"),
    )
    .expect("completion");
    completion
        .verify(&receiver, &capsule)
        .expect("completion verifies");
    let credited_receive =
        KagemushaWalletCreditedV1::from_receive(receive.clone()).expect("credited receive");
    credited_receive
        .verify_for(&scheme, &request, &payment)
        .expect("credited receive verifies");
    let mut status = f.credit_status(&payment, STATUS_LINEAGE_LEN, OPENING_OTHER_CREDITS, false);
    // The general message fixture uses a different stand-in σ length. Bind the vectored
    // status and its receipt to the same allowlisted Receive proof as the package.
    status.proof_digest = proof_digest;
    let status_signer = KagemushaWalletReceiptSignerV1::from_lineage(&status.lineage.public)
        .expect("status signer");
    let status_receipt_body = KagemushaWalletReceiptBodyV1::derive(
        &status_signer,
        &status.statement,
        &status.proof_digest,
        status.receipt.capsule_digest,
        status.receipt.payment_digest,
    )
    .expect("status receipt body");
    status.receipt = KagemushaWalletReceiptV1::sign(
        &receiver,
        &status.statement,
        &status.proof_digest,
        status.receipt.capsule_digest,
        status.receipt.payment_digest,
        raw_output(&f.receiver.payment, &status_receipt_body.signing_message()),
    )
    .expect("status receipt");
    let credited_status = KagemushaWalletCreditedV1::from_status(status).expect("credited status");
    credited_status
        .verify_for(&scheme, &request, &payment)
        .expect("credited status verifies");

    // The payer recorded Ω for its head at sequence 2 after one Λ run over steps 1 and 2.
    let omega = payment.send.lineage.lineage().expect("Ω(pred)").clone();
    let fold = KagemushaWalletFoldRecordV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        wallet_id: payer.body.wallet_id,
        first_sequence: 1,
        sequence: 2,
        head: omega.public.head,
        capsule_digest: [0x6a; 32],
        lineage: omega,
    };
    fold.validate().expect("fold record");

    let marker = KagemushaWalletMarkerV1::enrollment(&f.payer.challenge, payer.body.payment_key)
        .expect("enrollment marker");
    let bootstrap_body = KagemushaWalletStatementV1 {
        effect: marker.bootstrap_effect().expect("bootstrap effect"),
        ..bootstrap_statement(&f.payer)
    };
    let bootstrap = signed_package(
        &f.payer,
        &payer,
        &bootstrap_body,
        stand_in_proof(VECTOR_PROOF_LEN),
    );
    let control_body = KagemushaWalletLedgerControlBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        wallet_id: payer.body.wallet_id,
        action: KagemushaWalletLedgerControlActionV1::Activate {
            package_digest: bootstrap.package_digest(&payer).expect("bootstrap digest"),
        },
        nonce: [0x6c; 32],
    };
    let control = KagemushaWalletLedgerControlV1::sign(
        control_body,
        &payer.body.payment_key,
        raw_output(&f.payer.payment, &control_body.signing_message()),
    )
    .expect("ledger control");
    // The vectors are self-consistent (defects d1 and d2): the allowlist decodes against the
    // manifest, which binds its computed digest, and every σ and Ω has its allowlisted length.
    let allowlist = vector_allowlist();
    assert_eq!(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
            &allowlist.to_canonical_bytes().expect("allowlist frame"),
            &manifest.body,
        )
        .expect("the allowlist decodes against the vectored manifest"),
        allowlist
    );
    allowlist
        .check_package(&payment.send, None)
        .expect("the Payment's proofs have the allowlisted lengths");
    allowlist
        .check_package(&receive, Some(&request.body))
        .expect("the Receive package has the allowlisted σ length");
    allowlist
        .check_lineage(&lineage.lineage)
        .expect("the Lineage message's Ω has the allowlisted length");
    allowlist
        .check_lineage(&fold.lineage)
        .expect("the fold record's Ω has the allowlisted length");
    let KagemushaWalletCreditedEvidenceV1::Status { status } = &credited_status.evidence else {
        panic!("status evidence");
    };
    allowlist
        .check_lineage(&status.lineage)
        .expect("the CreditStatus Ω(h) has the allowlisted length");

    VectorWorld {
        f,
        time_signer,
        time_certificate,
        artifact_signer,
        artifact_certificate,
        scheme_policy,
        fee_schedule,
        blacklist,
        quota_share,
        time_anchor,
        charge_quote,
        load_receipt,
        manifest,
        renewal,
        offer,
        close,
        unsupported,
        request,
        payment,
        lineage,
        receive,
        capsule,
        completion,
        credited_receive,
        credited_status,
        fold,
        marker,
        bootstrap,
        control,
        allowlist,
    }
}

impl VectorWorld {
    fn scheme(&self) -> KagemushaWalletSchemeV1 {
        self.f.payer.scheme
    }

    fn scheme_id(&self) -> [u8; 32] {
        self.f.scheme_id()
    }

    fn payer(&self) -> &KagemushaWalletCredentialV1 {
        &self.f.payer.credential
    }

    fn receiver(&self) -> &KagemushaWalletCredentialV1 {
        &self.f.receiver.credential
    }

    fn status(&self) -> &KagemushaWalletCreditStatusV1 {
        match &self.credited_status.evidence {
            KagemushaWalletCreditedEvidenceV1::Status { status } => status,
            KagemushaWalletCreditedEvidenceV1::Receive { .. } => panic!("status evidence"),
        }
    }

    fn payer_issuer_set(&self) -> KagemushaWalletCertificateSetV1 {
        KagemushaWalletCertificateSetV1::new(vec![self.f.payer.enrollment_certificate])
            .expect("payer issuer set")
    }

    fn close_signature(&self) -> KagemushaDeviceSignatureV1 {
        match self.close.auth {
            KagemushaWalletSessionAuthV1::Signed { signature } => signature,
            KagemushaWalletSessionAuthV1::Unsigned => panic!("signed control"),
        }
    }

    fn policy_data(&self, item: KagemushaWalletPolicyDataItemV1) -> KagemushaWalletPolicyDataV1 {
        let data = KagemushaWalletPolicyDataV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.f.asset_digest(),
            item,
        };
        data.validate().expect("policy data");
        data
    }
}

// ---------------------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------------------

fn json_object(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate key {key}"
        );
    }
    Value::Object(map)
}

fn json_hex(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn json_text(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn json_number(value: usize) -> Value {
    Value::Number(Number::U64(u64::try_from(value).expect("fits u64")))
}

fn bytes32(hex_text: &str) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&hex::decode(hex_text).expect("hex"));
    out
}

fn signed_object_body(message: &[u8; 32], signature: &KagemushaDeviceSignatureV1) -> Vec<u8> {
    let mut body = message.to_vec();
    body.extend_from_slice(signature.as_raw_bytes());
    body
}

/// Exact SHA-256 preimage of `H(role, body)`: `prefix || role || 0x00 || LE64 len || body`.
fn digest_preimage(role: Role, body: &[u8]) -> Vec<u8> {
    let mut preimage = KAGEMUSHA_WALLET_DIGEST_PREFIX_V1.to_vec();
    preimage.extend_from_slice(role.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&u64::try_from(body.len()).expect("length").to_le_bytes());
    preimage.extend_from_slice(body);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&preimage)),
        kagemusha_wallet_digest_v1(role, body)
    );
    preimage
}

// ---------------------------------------------------------------------------------------
// Digest vectors (one per SHA-256 role)
// ---------------------------------------------------------------------------------------

/// One `H(role, body)` vector.
struct DigestVector {
    role: Role,
    object: &'static str,
    body: Vec<u8>,
    stand_in_proof: bool,
}

/// Build one digest vector and check it against the digest its owner computes.
fn digest_vector(
    role: Role,
    object: &'static str,
    body: Vec<u8>,
    stand_in_proof: bool,
    expected: Option<[u8; 32]>,
) -> DigestVector {
    if let Some(expected) = expected {
        assert_eq!(
            kagemusha_wallet_digest_v1(role, &body),
            expected,
            "{}",
            role.as_str()
        );
    }
    DigestVector {
        role,
        object,
        body,
        stand_in_proof,
    }
}

/// One digest vector per current SHA-256 role, in the owner's declaration order.
fn digest_vectors(w: &VectorWorld) -> Vec<DigestVector> {
    let f = &w.f;
    let scheme = w.scheme();
    let scheme_id = w.scheme_id();
    let payer = w.payer();
    let receiver = w.receiver();
    let payment = &w.payment;
    let digests = payment.digests().expect("payment digests");
    let receiver_challenge = f.receiver.challenge.challenge_digest();
    let payer_challenge = f.payer.challenge.challenge_digest();
    let receive_digests = w.receive.verify(receiver).expect("receive package");
    let (new_app, new_enrollment) =
        enrollment_policy::enrollment_policy_tests::policy_fixture(false);

    vec![
        digest_vector(
            Role::Scheme,
            "scheme",
            scheme.transcript(),
            false,
            Some(scheme_id),
        ),
        digest_vector(
            Role::Relation,
            "relation bindings of the scheme (stand-ins and the computed allowlist digest)",
            kagemusha_wallet_relation_transcript_v1(
                &EQ,
                &EP,
                &NATIVE,
                &scheme_verifying_key_set_digest(),
                &INVENTORY,
            ),
            false,
            Some(scheme.relation_id),
        ),
        digest_vector(
            Role::ProviderContract,
            "single V1 provider contract",
            kagemusha_wallet_provider_contract_transcript_v1(),
            false,
            Some(kagemusha_wallet_provider_contract_v1()),
        ),
        digest_vector(
            Role::AssetScope,
            "asset scope",
            f.payer.asset.transcript(),
            false,
            Some(payer.body.asset_digest),
        ),
        digest_vector(
            Role::Account,
            "payer AccountId frame",
            norito::encode_canonical(&test_account(PAYER_SEED)).expect("account frame"),
            false,
            Some(payer.body.account_digest),
        ),
        digest_vector(
            Role::EnrollmentChallenge,
            "payer enrollment challenge",
            f.payer.challenge.transcript(),
            false,
            Some(payer_challenge),
        ),
        digest_vector(
            Role::AppPolicy,
            "NEW unadmitted DATA app policy; public pins are placeholders, no approval",
            new_app.transcript().expect("policy transcript"),
            false,
            Some(new_app.policy_digest().expect("policy digest")),
        ),
        digest_vector(
            Role::EnrollmentPolicy,
            "NEW unadmitted DATA enrollment policy; public pins are placeholders, no approval",
            new_enrollment.transcript().expect("policy transcript"),
            false,
            Some(new_enrollment.policy_digest().expect("policy digest")),
        ),
        digest_vector(
            Role::EnrollmentId,
            "payer enrollment identity",
            kagemusha_wallet_enrollment_key_transcript_v1(
                &payer_challenge,
                &payer.body.payment_key,
            ),
            false,
            Some(payer.body.enrollment_id),
        ),
        digest_vector(
            Role::EnrollmentKeyBinding,
            "receiver App Attest enrollment assertion client data",
            kagemusha_wallet_enrollment_key_transcript_v1(
                &receiver_challenge,
                &receiver.body.payment_key,
            ),
            false,
            Some(kagemusha_wallet_enrollment_key_binding_v1(
                &receiver_challenge,
                &receiver.body.payment_key,
            )),
        ),
        digest_vector(
            Role::WalletId,
            "payer wallet identity",
            kagemusha_wallet_id_transcript_v1(
                &scheme_id,
                &payer.body.asset_digest,
                &payer.body.payment_key,
                &payer.body.enrollment_id,
            ),
            false,
            Some(payer.body.wallet_id),
        ),
        digest_vector(
            Role::ArtifactManifest,
            "artifact manifest",
            signed_object_body(&w.manifest.body.signing_message(), &w.manifest.signature),
            false,
            Some(w.manifest.manifest_digest()),
        ),
        digest_vector(
            Role::Evidence,
            "payer enrollment evidence items",
            kagemusha_wallet_evidence_transcript_v1(
                KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
                &[&b"tee-leaf-der"[..], &b"tee-intermediate-der"[..]],
            )
            .expect("evidence transcript"),
            false,
            Some(payer.body.enrollment_evidence.digest),
        ),
        digest_vector(
            Role::RenewalAssertion,
            "App Attest renewal assertion client data",
            w.renewal.possession_transcript(),
            false,
            Some(w.renewal.assertion_client_data_hash()),
        ),
        digest_vector(
            Role::VerifyingKeySet,
            "stand-in verifying-key allowlist",
            w.allowlist.transcript().expect("allowlist transcript"),
            true,
            Some(
                w.allowlist
                    .verifying_key_set_digest()
                    .expect("verifying-key-set digest"),
            ),
        ),
        digest_vector(
            Role::Output,
            "Receive output descriptor",
            kagemusha_wallet_output_transcript_v1(
                KagemushaWalletOperationKindV1::Receive,
                &receive_digests.statement,
                &receive_digests.proof,
                &digests.payment,
            ),
            false,
            Some(w.capsule.output.digest),
        ),
        digest_vector(
            Role::Marker,
            "payer enrollment marker frame",
            w.marker.to_canonical_bytes().expect("marker frame"),
            false,
            Some(w.marker.marker_digest().expect("marker digest")),
        ),
        digest_vector(
            Role::Capsule,
            "Receive recovery capsule frame",
            w.capsule.to_canonical_bytes().expect("capsule frame"),
            true,
            Some(w.capsule.capsule_digest().expect("capsule digest")),
        ),
        digest_vector(
            Role::Completion,
            "Receive completion record frame",
            w.completion.to_canonical_bytes().expect("completion frame"),
            true,
            Some(w.completion.completion_digest().expect("completion digest")),
        ),
        digest_vector(
            Role::Fold,
            "payer fold record frame",
            w.fold.to_canonical_bytes().expect("fold frame"),
            true,
            Some(w.fold.fold_digest().expect("fold digest")),
        ),
    ]
}

fn digest_vectors_json(vectors: &[DigestVector]) -> Value {
    Value::Array(
        vectors
            .iter()
            .map(|vector| {
                let preimage = digest_preimage(vector.role, &vector.body);
                json_object(vec![
                    ("role", json_text(vector.role.as_str())),
                    ("object", json_text(vector.object)),
                    ("body_hex", json_hex(&vector.body)),
                    ("preimage_hex", json_hex(&preimage)),
                    (
                        "digest_hex",
                        json_hex(&kagemusha_wallet_digest_v1(vector.role, &vector.body)),
                    ),
                    ("stand_in_proof", Value::Bool(vector.stand_in_proof)),
                ])
            })
            .collect(),
    )
}

/// One signed-object digest with its exact canonical field input.
struct ObjectDigestVector {
    domain: ObjectDomain,
    object: &'static str,
    message: [u8; 32],
    signature: KagemushaDeviceSignatureV1,
    digest: [u8; 32],
}

/// Check a current object digest against its signed object's own owner.
fn object_digest_vector(
    domain: ObjectDomain,
    object: &'static str,
    message: [u8; 32],
    signature: KagemushaDeviceSignatureV1,
    digest: [u8; 32],
) -> ObjectDigestVector {
    assert_eq!(
        kagemusha_wallet_signed_object_digest_v1(domain, &message, &signature),
        digest,
        "{object}"
    );
    ObjectDigestVector {
        domain,
        object,
        message,
        signature,
        digest,
    }
}

/// Every current signed-object domain in the authoritative declaration order.
fn object_digest_vectors(w: &VectorWorld) -> Vec<ObjectDigestVector> {
    let certificate = &w.f.payer.enrollment_certificate;
    let payer = w.payer();
    let send = &w.payment.send;
    let digests = w.payment.digests().expect("payment digests");
    let receipt_body = send
        .receipt
        .body(
            &KagemushaWalletReceiptSignerV1::from_lineage(
                &send.lineage.lineage().expect("Ω(pred)").public,
            )
            .expect("Ω signer"),
            &send.statement,
            &digests.package.proof,
        )
        .expect("Send receipt body");
    vec![
        object_digest_vector(
            ObjectDomain::Certificate,
            "payer issuer certificate",
            certificate.body.signing_message(),
            certificate.signature,
            certificate.certificate_digest(),
        ),
        object_digest_vector(
            ObjectDomain::Credential,
            "payer credential",
            payer.body.signing_message(),
            payer.signature,
            payer.credential_digest(),
        ),
        object_digest_vector(
            ObjectDomain::Receipt,
            "Send receipt",
            receipt_body.signing_message(),
            send.receipt.signature,
            digests.package.receipt,
        ),
        object_digest_vector(
            ObjectDomain::SchemePolicy,
            "scheme policy",
            w.scheme_policy.body.signing_message(),
            w.scheme_policy.signature,
            w.scheme_policy.scheme_policy_digest(),
        ),
        object_digest_vector(
            ObjectDomain::FeeSchedule,
            "fee schedule",
            w.fee_schedule.body.signing_message(),
            w.fee_schedule.signature,
            w.fee_schedule.fee_schedule_digest(),
        ),
        object_digest_vector(
            ObjectDomain::Blacklist,
            "blacklist",
            w.blacklist.body.signing_message(),
            w.blacklist.signature,
            w.blacklist.blacklist_digest(),
        ),
        object_digest_vector(
            ObjectDomain::QuotaShare,
            "quota share",
            w.quota_share.body.signing_message(),
            w.quota_share.signature,
            w.quota_share.quota_share_digest(),
        ),
        object_digest_vector(
            ObjectDomain::TimeAnchor,
            "time anchor",
            w.time_anchor.body.signing_message(),
            w.time_anchor.signature,
            w.time_anchor.time_anchor_digest(),
        ),
        object_digest_vector(
            ObjectDomain::ChargeQuote,
            "load charge quote",
            w.charge_quote.body.signing_message(),
            w.charge_quote.signature,
            w.charge_quote.charge_quote_digest(),
        ),
        object_digest_vector(
            ObjectDomain::Request,
            "Request",
            w.request.body.signing_message(),
            w.request.signature,
            digests.request,
        ),
    ]
}

/// Reference fields of the exact five-element signed-object digest preimage.
fn object_digest_vectors_json(w: &VectorWorld) -> Value {
    Value::Array(
        object_digest_vectors(w)
            .iter()
            .map(|vector| {
                let items =
                    kagemusha_wallet_signed_object_items_v1(&vector.message, &vector.signature);
                let Value::Object(mut row) =
                    json_poseidon(vector.domain.domain(), &items, &vector.digest)
                else {
                    unreachable!("object")
                };
                row.insert("object".to_owned(), json_text(vector.object));
                row.insert(
                    "signing_domain".to_owned(),
                    json_text(vector.domain.signing_domain().as_str()),
                );
                row.insert("message_hex".to_owned(), json_hex(&vector.message));
                row.insert(
                    "signature_hex".to_owned(),
                    json_hex(vector.signature.as_raw_bytes()),
                );
                Value::Object(row)
            })
            .collect(),
    )
}

/// Use labels of the current signed-object domains, distinct from signing messages.
fn object_domain_use(domain: ObjectDomain) -> &'static str {
    match domain {
        ObjectDomain::Certificate => "object_certificate",
        ObjectDomain::Credential => "object_credential",
        ObjectDomain::Receipt => "object_receipt",
        ObjectDomain::SchemePolicy => "object_scheme_policy",
        ObjectDomain::FeeSchedule => "object_fee_schedule",
        ObjectDomain::Blacklist => "object_blacklist",
        ObjectDomain::QuotaShare => "object_quota_share",
        ObjectDomain::TimeAnchor => "object_time_anchor",
        ObjectDomain::ChargeQuote => "object_charge_quote",
        ObjectDomain::Request => "object_request",
    }
}

// ---------------------------------------------------------------------------------------
// Signature vectors and the low-S boundary (design C11)
// ---------------------------------------------------------------------------------------

/// One frozen signature of a vectored object: its signing domain, transcript and key.
struct SignatureVector {
    object: &'static str,
    domain: Domain,
    key: KagemushaDevicePublicKeyV1,
    transcript: Vec<u8>,
    signature: KagemushaDeviceSignatureV1,
}

impl SignatureVector {
    /// The 32-byte signing message `P_bytes(domain, transcript)`.
    fn message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(self.domain, &self.transcript)
    }
}

/// Every signed body of the world with its signer key and frozen signature.
fn signature_vectors(w: &VectorWorld) -> Vec<SignatureVector> {
    let f = &w.f;
    let payer = w.payer();
    let payer_key = payer.body.payment_key;
    let regulator_key = f.regulator_certificate.body.key;
    let certificate = &f.payer.enrollment_certificate;
    let request = &w.request;
    let send = &w.payment.send;
    let receipt_body = send
        .receipt
        .body(
            &KagemushaWalletReceiptSignerV1::from_credential(payer).expect("payer signer"),
            &send.statement,
            &send.proof_digest().expect("send proof digest"),
        )
        .expect("receipt body");
    let receive_body = w
        .receive
        .receipt
        .body(
            &KagemushaWalletReceiptSignerV1::from_credential(w.receiver()).expect("signer"),
            &w.receive.statement,
            &w.receive.proof_digest().expect("receive proof digest"),
        )
        .expect("receive receipt body");
    let KagemushaWalletRenewalEvidenceV1::Android {
        new_attested_key,
        key_binding_signature,
        ..
    } = w.renewal.evidence
    else {
        panic!("android renewal");
    };
    vec![
        SignatureVector {
            object: "payer issuer certificate",
            domain: Domain::Certificate,
            key: w.scheme().scheme_root_key,
            transcript: certificate.body.transcript(),
            signature: certificate.signature,
        },
        SignatureVector {
            object: "payer credential",
            domain: Domain::Credential,
            key: certificate.body.key,
            transcript: payer.body.transcript(),
            signature: payer.signature,
        },
        SignatureVector {
            object: "Offer",
            domain: Domain::Offer,
            key: payer_key,
            transcript: w.offer.body.transcript(),
            signature: w.offer.signature,
        },
        SignatureVector {
            object: "Request",
            domain: Domain::Request,
            key: request.receiver_credential.body.payment_key,
            transcript: request.body.transcript(),
            signature: request.signature,
        },
        SignatureVector {
            object: "Send receipt",
            domain: Domain::Receipt,
            key: payer_key,
            transcript: receipt_body.transcript(),
            signature: send.receipt.signature,
        },
        SignatureVector {
            object: "Receive receipt binding the Payment digest",
            domain: Domain::Receipt,
            key: w.receiver().body.payment_key,
            transcript: receive_body.transcript(),
            signature: w.receive.receipt.signature,
        },
        SignatureVector {
            object: "Close session control",
            domain: Domain::SessionControl,
            key: payer_key,
            transcript: w.close.transcript(),
            signature: w.close_signature(),
        },
        SignatureVector {
            object: "scheme policy",
            domain: Domain::SchemePolicy,
            key: regulator_key,
            transcript: w.scheme_policy.body.transcript(),
            signature: w.scheme_policy.signature,
        },
        SignatureVector {
            object: "fee schedule",
            domain: Domain::FeeSchedule,
            key: regulator_key,
            transcript: w.fee_schedule.body.transcript(),
            signature: w.fee_schedule.signature,
        },
        SignatureVector {
            object: "blacklist",
            domain: Domain::Blacklist,
            key: regulator_key,
            transcript: w.blacklist.body.transcript(),
            signature: w.blacklist.signature,
        },
        SignatureVector {
            object: "quota share",
            domain: Domain::QuotaShare,
            key: regulator_key,
            transcript: w.quota_share.body.transcript(),
            signature: w.quota_share.signature,
        },
        SignatureVector {
            object: "time anchor",
            domain: Domain::TimeAnchor,
            key: w.time_certificate.body.key,
            transcript: w.time_anchor.body.transcript(),
            signature: w.time_anchor.signature,
        },
        SignatureVector {
            object: "Activate ledger control",
            domain: Domain::LedgerControl,
            key: payer_key,
            transcript: w.control.body.transcript(),
            signature: w.control.signature,
        },
        SignatureVector {
            object: "renewal possession",
            domain: Domain::RenewalChallenge,
            key: payer_key,
            transcript: w.renewal.possession_transcript(),
            signature: w.renewal.possession_signature,
        },
        SignatureVector {
            object: "Android renewal key binding",
            domain: Domain::RenewalKeyBinding,
            key: payer_key,
            transcript: kagemusha_wallet_renewal_key_binding_transcript_v1(
                &w.renewal.scheme_id,
                &w.renewal.wallet_id,
                &w.renewal.challenge,
                &new_attested_key,
            ),
            signature: key_binding_signature,
        },
        SignatureVector {
            object: "artifact manifest",
            domain: Domain::ArtifactManifest,
            key: w.artifact_certificate.body.key,
            transcript: w.manifest.body.transcript(),
            signature: w.manifest.signature,
        },
        SignatureVector {
            object: "load charge quote",
            domain: Domain::ChargeQuote,
            key: regulator_key,
            transcript: w.charge_quote.body.transcript(),
            signature: w.charge_quote.signature,
        },
    ]
}

/// Verdicts of 64 raw bytes over the 32-byte signing message `message` under `key`.
///
/// `codec_ok`: the canonical fixed-width low-S codec accepts the bytes (`1 <= r < n`,
/// `1 <= s <= floor(n/2)`). `verify_ok`: the ECDSA-P256-SHA256 equation over `message` holds
/// with the scalars taken as they are, as a generic verifier (JCA, `CryptoKit`) would check it;
/// a high-S twin satisfies it. A consumer accepts exactly when both hold.
fn signature_verdicts(
    key: &KagemushaDevicePublicKeyV1,
    message: &[u8; 32],
    raw: &[u8; 64],
) -> (bool, bool) {
    let codec = KagemushaDeviceSignatureV1::from_raw_bytes(raw);
    let equation = P256Signature::from_slice(raw).is_ok_and(|signature| {
        VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())
            .expect("canonical key")
            .verify(message, &signature)
            .is_ok()
    });
    if let Ok(signature) = codec {
        assert_eq!(
            signature.verify(key, message).is_ok(),
            equation,
            "canonical verifier"
        );
    }
    (codec.is_ok(), equation)
}

/// `n - s` of a low-S signature: its high-S twin.
fn high_s_twin(signature: &KagemushaDeviceSignatureV1) -> [u8; 64] {
    let raw = signature.as_raw_bytes();
    let s = Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(&raw[32..])))
        .expect("s scalar");
    let mut twin = *raw;
    twin[32..].copy_from_slice(&(-s).to_repr());
    twin
}

fn signature_vectors_json(vectors: &[SignatureVector]) -> Value {
    Value::Array(
        vectors
            .iter()
            .map(|vector| {
                assert_eq!(
                    vector.transcript.len(),
                    vector.domain.transcript_bytes(),
                    "{}",
                    vector.object
                );
                let message = vector.message();
                let raw = vector.signature.as_raw_bytes();
                assert_eq!(
                    signature_verdicts(&vector.key, &message, raw),
                    (true, true),
                    "{}",
                    vector.object
                );
                kagemusha_wallet_verify_signature_v1(
                    &vector.key,
                    vector.domain,
                    &message,
                    &vector.signature,
                )
                .expect("signature over the signing message");
                let twin = high_s_twin(&vector.signature);
                assert_eq!(
                    signature_verdicts(&vector.key, &message, &twin),
                    (false, true),
                    "{} twin",
                    vector.object
                );
                let twin_der = P256Signature::from_slice(&twin).expect("twin").to_der();
                for output in [
                    KagemushaWalletSignerOutputV1::Raw(twin),
                    KagemushaWalletSignerOutputV1::Der(twin_der.as_bytes()),
                ] {
                    assert_eq!(
                        kagemusha_wallet_freeze_signature_v1(
                            &vector.key,
                            vector.domain,
                            &message,
                            output
                        )
                        .expect("freeze twin"),
                        vector.signature
                    );
                }
                json_object(vec![
                    ("object", json_text(vector.object)),
                    ("domain", json_text(vector.domain.as_str())),
                    ("public_key_hex", json_hex(vector.key.as_sec1_bytes())),
                    ("transcript_hex", json_hex(&vector.transcript)),
                    (
                        "elements",
                        json_number(kagemusha_wallet_packed_bytes_v1(&vector.transcript).len()),
                    ),
                    ("message_hex", json_hex(&message)),
                    ("signature_hex", json_hex(raw)),
                    ("codec_ok", Value::Bool(true)),
                    ("verify_ok", Value::Bool(true)),
                    (
                        "high_s_twin",
                        json_object(vec![
                            ("signature_hex", json_hex(&twin)),
                            ("der_hex", json_hex(twin_der.as_bytes())),
                            ("codec_ok", Value::Bool(false)),
                            ("verify_ok", Value::Bool(true)),
                            ("frozen_signature_hex", json_hex(raw)),
                        ]),
                    ),
                ])
            })
            .collect(),
    )
}

/// Signature with `s = floor(n/2)` that verifies, derived per design C11.
///
/// Choose the nonce `k` and `s = floor(n/2)`; with `r = x(kG) mod n` and
/// `e = SHA-256(m) mod n` for the signing message `m`, the key `d = (s*k - e) * r^-1 mod n`
/// makes `(r, s)` a valid signature: `u1*G + u2*Q = (e + r*d)/s * G = k*G`.
struct BoundaryVector {
    k: Scalar,
    r: Scalar,
    e: Scalar,
    d: Scalar,
    key: KagemushaDevicePublicKeyV1,
    transcript: Vec<u8>,
    message: [u8; 32],
}

/// Transcript of the boundary signature: [`BOUNDARY_BODY`] zero-filled to the length of
/// [`BOUNDARY_DOMAIN`].
fn boundary_transcript() -> Vec<u8> {
    let mut transcript = BOUNDARY_BODY.to_vec();
    transcript.resize(BOUNDARY_DOMAIN.transcript_bytes(), 0);
    transcript
}

#[allow(
    clippy::many_single_char_names,
    reason = "the ECDSA scalars k, r, e, s and d keep their standard names"
)]
fn boundary_vector() -> BoundaryVector {
    let transcript = boundary_transcript();
    let message = kagemusha_wallet_signing_message_v1(BOUNDARY_DOMAIN, &transcript);
    let k = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&BOUNDARY_NONCE));
    let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&r_point.x());
    let e = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(
        Sha256::digest(message).as_slice(),
    ));
    let s = Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(&bytes32(
        HALF_ORDER_HEX,
    ))))
    .expect("half order is a scalar");
    let r_inverse = Option::<Scalar>::from(r.invert()).expect("r is nonzero");
    let d = (s * k - e) * r_inverse;
    assert!(!bool::from(d.is_zero()), "derived key is nonzero");
    let signing = SigningKey::from_bytes(&d.to_repr()).expect("derived key");
    BoundaryVector {
        k,
        r,
        e,
        d,
        key: public_key(&signing),
        transcript,
        message,
    }
}

fn raw_pair(r: &[u8], s: &[u8]) -> [u8; 64] {
    let mut raw = [0; 64];
    raw[..32].copy_from_slice(r);
    raw[32..].copy_from_slice(s);
    raw
}

/// Boundary cases with their expected verdicts `(codec_ok, verify_ok)`.
fn boundary_cases(boundary: &BoundaryVector) -> Vec<(&'static str, [u8; 64], bool, bool)> {
    let order = bytes32(ORDER_HEX);
    let half = bytes32(HALF_ORDER_HEX);
    let r = boundary.r.to_repr();
    let half_scalar =
        Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(&half))).expect("half");
    let half_plus_one = (-half_scalar).to_repr();
    vec![
        ("s_half_order", raw_pair(&r, &half), true, true),
        (
            "s_half_order_plus_one_high_s_twin",
            raw_pair(&r, &half_plus_one),
            false,
            true,
        ),
        ("r_zero", raw_pair(&[0; 32], &half), false, false),
        ("s_zero", raw_pair(&r, &[0; 32]), false, false),
        ("r_order", raw_pair(&order, &half), false, false),
        ("s_order", raw_pair(&r, &order), false, false),
    ]
}

fn boundary_json() -> Value {
    let boundary = boundary_vector();
    let cases = boundary_cases(&boundary);
    let mut rows = Vec::new();
    for (name, raw, codec_ok, verify_ok) in &cases {
        assert_eq!(
            signature_verdicts(&boundary.key, &boundary.message, raw),
            (*codec_ok, *verify_ok),
            "{name}"
        );
        rows.push(json_object(vec![
            ("name", json_text(name)),
            ("signature_hex", json_hex(raw)),
            ("codec_ok", Value::Bool(*codec_ok)),
            ("verify_ok", Value::Bool(*verify_ok)),
        ]));
    }
    // The high twin freezes to the boundary signature itself.
    let frozen = kagemusha_wallet_freeze_signature_v1(
        &boundary.key,
        BOUNDARY_DOMAIN,
        &boundary.message,
        KagemushaWalletSignerOutputV1::Raw(cases[1].1),
    )
    .expect("freeze the high twin");
    assert_eq!(frozen.as_raw_bytes(), &cases[0].1);
    let order = bytes32(ORDER_HEX);
    let half = bytes32(HALF_ORDER_HEX);
    json_object(vec![
        ("order_hex", json_hex(&order)),
        ("half_order_hex", json_hex(&half)),
        ("half_order_plus_one_hex", json_hex(&cases[1].1[32..])),
        (
            "derivation",
            json_text(
                "m = P_bytes(domain, transcript); r = x(k*G) mod n; s = floor(n/2); \
                 e = SHA-256(m) mod n; d = (s*k - e) * r^-1 mod n; public key Q = d*G",
            ),
        ),
        ("domain", json_text(BOUNDARY_DOMAIN.as_str())),
        ("transcript_hex", json_hex(&boundary.transcript)),
        ("message_hex", json_hex(&boundary.message)),
        ("k_hex", json_hex(&boundary.k.to_repr())),
        ("r_hex", json_hex(&boundary.r.to_repr())),
        ("e_hex", json_hex(&boundary.e.to_repr())),
        ("d_hex", json_hex(&boundary.d.to_repr())),
        ("public_key_hex", json_hex(boundary.key.as_sec1_bytes())),
        ("cases", Value::Array(rows)),
    ])
}

// ---------------------------------------------------------------------------------------
// Envelope vectors and frame identities
// ---------------------------------------------------------------------------------------

/// One message of every kind and variant, in tag order.
fn envelope_messages(w: &VectorWorld) -> Vec<(&'static str, KagemushaWalletMessageV1, bool)> {
    vec![
        (
            "Offer",
            KagemushaWalletMessageV1::Offer {
                offer: w.offer.clone(),
            },
            false,
        ),
        (
            "Request",
            KagemushaWalletMessageV1::Request {
                request: w.request.clone(),
            },
            false,
        ),
        (
            "Payment",
            KagemushaWalletMessageV1::Payment {
                payment: w.payment.clone(),
            },
            true,
        ),
        (
            "Credited::Receive",
            KagemushaWalletMessageV1::Credited {
                credited: w.credited_receive.clone(),
            },
            true,
        ),
        (
            "Credited::Status",
            KagemushaWalletMessageV1::Credited {
                credited: w.credited_status.clone(),
            },
            true,
        ),
        (
            "SessionControl::Close",
            KagemushaWalletMessageV1::SessionControl { control: w.close },
            false,
        ),
        (
            "SessionControl::UnsupportedScheme",
            KagemushaWalletMessageV1::SessionControl {
                control: w.unsupported,
            },
            false,
        ),
        (
            "PolicyData::SchemePolicy",
            KagemushaWalletMessageV1::PolicyData {
                data: w.policy_data(KagemushaWalletPolicyDataItemV1::SchemePolicy {
                    policy: w.scheme_policy,
                }),
            },
            false,
        ),
        (
            "Lineage",
            KagemushaWalletMessageV1::Lineage {
                lineage: w.lineage.clone(),
            },
            true,
        ),
    ]
}

fn message_kind_name(message: &KagemushaWalletMessageV1) -> &'static str {
    match message {
        KagemushaWalletMessageV1::Offer { .. } => "Offer",
        KagemushaWalletMessageV1::Request { .. } => "Request",
        KagemushaWalletMessageV1::Payment { .. } => "Payment",
        KagemushaWalletMessageV1::Credited { .. } => "Credited",
        KagemushaWalletMessageV1::SessionControl { .. } => "SessionControl",
        KagemushaWalletMessageV1::PolicyData { .. } => "PolicyData",
        KagemushaWalletMessageV1::Lineage { .. } => "Lineage",
    }
}

fn envelope_vectors_json(w: &VectorWorld) -> Value {
    let scheme_id = w.scheme_id();
    let mut rows = Vec::new();
    for (variant, message, stand_in_proof) in envelope_messages(w) {
        let envelope = KagemushaWalletEnvelopeV1::new(message);
        let frame = envelope.to_canonical_bytes().expect("envelope frame");
        assert_eq!(
            KagemushaWalletEnvelopeV1::decode_canonical(&frame, &scheme_id).expect("decode"),
            envelope,
            "{variant}"
        );
        let header = norito::core::Header::read(frame.as_slice()).expect("header");
        let payload = payload_range(&frame);
        assert_eq!(
            header.schema,
            norito::schema::identity::frame_hash::<KagemushaWalletEnvelopeV1>()
        );
        assert_eq!(header.flags, norito::core::header_flags::COMPACT_LEN);
        assert_eq!(
            usize::try_from(header.length).expect("length"),
            payload.len()
        );
        assert_eq!(
            header.checksum,
            norito::crc64_fallback(&frame[payload.clone()])
        );
        let text = envelope.to_text().expect("text");
        assert_eq!(
            KagemushaWalletEnvelopeV1::from_text(&text, &scheme_id).expect("from text"),
            envelope
        );
        let bound = envelope.message.max_bytes();
        let text_bound = if bound == KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1 {
            KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1
        } else {
            KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1
        };
        assert!(frame.len() <= bound && text.len() <= text_bound);
        rows.push(json_object(vec![
            ("kind", json_text(message_kind_name(&envelope.message))),
            ("variant", json_text(variant)),
            ("tag", json_number(usize::from(envelope.message.tag()))),
            (
                "frame_name",
                json_text(&<KagemushaWalletEnvelopeV1 as norito::NoritoSchema>::frame_name()),
            ),
            ("schema_hash_hex", json_hex(&header.schema)),
            ("flags", json_number(usize::from(header.flags))),
            (
                "padding_len",
                json_number(payload.start - norito::core::Header::SIZE),
            ),
            ("payload_len", json_number(payload.len())),
            ("frame_len", json_number(frame.len())),
            ("crc64_hex", json_text(&format!("{:016x}", header.checksum))),
            ("canonical_hex", json_hex(&frame)),
            ("text", json_text(&text)),
            ("bound", json_number(bound)),
            ("text_bound", json_number(text_bound)),
            ("scheme_id_hex", json_hex(&scheme_id)),
            ("stand_in_proof", Value::Bool(stand_in_proof)),
        ]));
    }
    Value::Array(rows)
}

/// Frame identity of one top-level record.
struct FramePin {
    short_name: &'static str,
    frame_name: String,
    frame_hash: [u8; 16],
    max_bytes: usize,
}

fn frame_pin<T: norito::NoritoSchema>(short_name: &'static str, max_bytes: usize) -> FramePin {
    let frame_name = <T as norito::NoritoSchema>::frame_name();
    let expected = if short_name == "KagemushaWalletLoadReceiptV1" {
        format!("iroha_data_model::isi::kagemusha_wallet::{short_name}")
    } else {
        format!("{FRAME_NAME_PREFIX}{short_name}")
    };
    assert_eq!(frame_name, expected);
    let frame_hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(frame_hash, norito::core::schema_hash_for_name(&frame_name));
    FramePin {
        short_name,
        frame_name,
        frame_hash,
        max_bytes,
    }
}

/// Frame identities and caps of the envelope and every top-level record.
fn frame_pins() -> Vec<FramePin> {
    vec![
        frame_pin::<KagemushaWalletEnvelopeV1>(
            "KagemushaWalletEnvelopeV1",
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletSchemeV1>(
            "KagemushaWalletSchemeV1",
            KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletSignerCertificateV1>(
            "KagemushaWalletSignerCertificateV1",
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletCredentialV1>(
            "KagemushaWalletCredentialV1",
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletRenewalRequestV1>(
            "KagemushaWalletRenewalRequestV1",
            KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletArtifactManifestV1>(
            "KagemushaWalletArtifactManifestV1",
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletVerifyingKeyAllowlistV1>(
            "KagemushaWalletVerifyingKeyAllowlistV1",
            KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletSchemePolicyV1>(
            "KagemushaWalletSchemePolicyV1",
            KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletFeeScheduleV1>(
            "KagemushaWalletFeeScheduleV1",
            KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletBlacklistV1>(
            "KagemushaWalletBlacklistV1",
            KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletQuotaShareV1>(
            "KagemushaWalletQuotaShareV1",
            KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletQuotaRefreshWitnessV1>(
            "KagemushaWalletQuotaRefreshWitnessV1",
            KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletTimeAnchorV1>(
            "KagemushaWalletTimeAnchorV1",
            KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletChargeQuoteV1>(
            "KagemushaWalletChargeQuoteV1",
            KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletPaymentV1>(
            "KagemushaWalletPaymentV1",
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletPackageV1>(
            "KagemushaWalletPackageV1",
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletMarkerV1>(
            "KagemushaWalletMarkerV1",
            KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletRecoveryCapsuleV1>(
            "KagemushaWalletRecoveryCapsuleV1",
            KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletCompletionRecordV1>(
            "KagemushaWalletCompletionRecordV1",
            KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletFoldRecordV1>(
            "KagemushaWalletFoldRecordV1",
            KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletLoadReceiptV1>(
            "KagemushaWalletLoadReceiptV1",
            KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletLoadFinalityV1>(
            "KagemushaWalletLoadFinalityV1",
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletUnloadClaimV1>(
            "KagemushaWalletUnloadClaimV1",
            KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletFeeClaimV1>(
            "KagemushaWalletFeeClaimV1",
            KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletLedgerControlV1>(
            "KagemushaWalletLedgerControlV1",
            KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletActivationV1>(
            "KagemushaWalletActivationV1",
            KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletCloseLoadsV1>(
            "KagemushaWalletCloseLoadsV1",
            KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1,
        ),
        frame_pin::<KagemushaWalletAbandonmentV1>(
            "KagemushaWalletAbandonmentV1",
            KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1,
        ),
    ]
}

fn frame_pins_json() -> Value {
    Value::Array(
        frame_pins()
            .iter()
            .map(|pin| {
                json_object(vec![
                    ("type", json_text(pin.short_name)),
                    ("frame_name", json_text(&pin.frame_name)),
                    ("frame_hash_hex", json_hex(&pin.frame_hash)),
                    ("max_bytes", json_number(pin.max_bytes)),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------------------
// Canonical object pins (design §8: a canonical-bytes pin for every object)
// ---------------------------------------------------------------------------------------

/// Unload charge of the vectored unload claim.
const UNLOAD_AMOUNT: u128 = 700;
const UNLOAD_CHARGE: u128 = 7;
/// Stand-in capsule digest of the vectored Bootstrap head marker (the payer's capsule is not
/// vectored).
const HEAD_CAPSULE: [u8; 32] = [0x6b; 32];

/// Complete canonical frame of one vectored object.
struct ObjectPin {
    short_name: &'static str,
    variant: &'static str,
    frame_name: String,
    frame: Vec<u8>,
    stand_in_proof: bool,
}

/// Pin `frame`, the canonical frame of `value`, after checking that `decoded` (its bounded
/// decode) round-trips and that it is exactly `norito::encode_canonical(value)`.
fn object_pin<T>(
    short_name: &'static str,
    variant: &'static str,
    value: &T,
    frame: Vec<u8>,
    decoded: &T,
    stand_in_proof: bool,
) -> ObjectPin
where
    T: norito::NoritoSchema + norito::NoritoSerialize + PartialEq + core::fmt::Debug,
{
    assert_eq!(decoded, value, "{short_name} {variant} round trip");
    assert_eq!(
        norito::encode_canonical(value).expect("encode"),
        frame,
        "{short_name} {variant} canonical frame"
    );
    let frame_name = <T as norito::NoritoSchema>::frame_name();
    let expected = if short_name == "KagemushaWalletLoadReceiptV1" {
        format!("iroha_data_model::isi::kagemusha_wallet::{short_name}")
    } else {
        format!("{FRAME_NAME_PREFIX}{short_name}")
    };
    assert_eq!(frame_name, expected);
    let header = norito::core::Header::read(frame.as_slice()).expect("header");
    assert_eq!(
        header.schema,
        norito::core::schema_hash_for_name(&frame_name)
    );
    ObjectPin {
        short_name,
        variant,
        frame_name,
        frame,
        stand_in_proof,
    }
}

/// Pin a value without a standalone frame bound (`norito::encode_canonical` only).
fn unbounded_pin<T>(short_name: &'static str, variant: &'static str, value: &T) -> ObjectPin
where
    T: norito::NoritoSchema
        + norito::NoritoSerialize
        + for<'de> norito::NoritoDeserialize<'de>
        + PartialEq
        + core::fmt::Debug,
{
    let frame = norito::encode_canonical(value).expect("encode");
    let decoded: T =
        norito::decode_canonical_with_limits(&frame, norito::canonical_decode_limits(frame.len()))
            .expect("decode");
    object_pin(short_name, variant, value, frame, &decoded, false)
}

/// Ledger boundary objects of the payer built on the vector world.
struct LedgerObjects {
    unload_claim: KagemushaWalletUnloadClaimV1,
    fee_claim: KagemushaWalletFeeClaimV1,
    activation: KagemushaWalletActivationV1,
    close_loads: KagemushaWalletCloseLoadsV1,
    abandonment: KagemushaWalletAbandonmentV1,
    head_marker: KagemushaWalletMarkerV1,
    deleted_marker: KagemushaWalletMarkerV1,
    abandoned_marker: KagemushaWalletMarkerV1,
    anchored_time: KagemushaWalletAnchoredTimeV1,
}

/// Signed package of `statement`, an operation that consumes Ω(pred), whose stand-in Ω(pred)
/// and σ have exactly the vectored allowlist's lengths (defect d2).
fn allowlisted_lineage_package(
    f: &IdentityFixture,
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
) -> KagemushaWalletPackageV1 {
    assert!(statement.effect.kind().consumes_lineage());
    signed_package_with(
        f,
        credential,
        statement,
        KagemushaWalletLineageSlotV1::Present {
            lineage: lineage_with_len(credential, statement, STAND_IN_LINEAGE_BYTES),
        },
        stand_in_proof(VECTOR_PROOF_LEN),
        [0; 32],
    )
}

/// Payer ledger control signed by its payment key.
fn payer_control(
    w: &VectorWorld,
    action: KagemushaWalletLedgerControlActionV1,
    nonce: [u8; 32],
) -> KagemushaWalletLedgerControlV1 {
    let payer = w.payer();
    let body = KagemushaWalletLedgerControlBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: payer.body.scheme_id,
        asset_digest: payer.body.asset_digest,
        wallet_id: payer.body.wallet_id,
        action,
        nonce,
    };
    KagemushaWalletLedgerControlV1::sign(
        body,
        &payer.body.payment_key,
        raw_output(&w.f.payer.payment, &body.signing_message()),
    )
    .expect("payer control")
}

fn ledger_objects(w: &VectorWorld) -> LedgerObjects {
    let f = &w.f;
    let payer = w.payer();
    let scheme_id = w.scheme_id();
    let issuer_set = KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate])
        .expect("issuer set");

    // A charged Unload of the payer and its self-contained claim (design C7).
    let beneficiary = test_account(BENEFICIARY_SEED);
    let quote_body = KagemushaWalletChargeQuoteBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest: payer.body.asset_digest,
        wallet_id: payer.body.wallet_id,
        kind: KagemushaWalletChargeKindV1::Unload,
        ordinal: 0,
        net_amount: UNLOAD_AMOUNT,
        online_charge: UNLOAD_CHARGE,
        beneficiary_account_digest: kagemusha_wallet_account_digest_v1(&beneficiary)
            .expect("beneficiary"),
        issued_at_ms: ACCEPTED_MS - 60_000,
        signer_certificate: f.regulator_certificate.certificate_digest(),
    };
    let quote = KagemushaWalletChargeQuoteV1::sign(
        quote_body,
        &f.regulator_certificate,
        raw_output(&f.regulator, &quote_body.signing_message()),
    )
    .expect("unload quote");
    let unload = transition_statement(
        &f.payer,
        6,
        1,
        KagemushaWalletLifecycleV1::Active,
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&scheme_id, &payer.body.wallet_id, 0),
            redeem_ordinal: 0,
            amount: UNLOAD_AMOUNT,
            online_charge: UNLOAD_CHARGE,
            charge_quote: quote.charge_quote_digest(),
        },
    );
    let unload_claim = KagemushaWalletUnloadClaimV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        credential: *payer,
        package: allowlisted_lineage_package(&f.payer, payer, &unload),
        account: test_account(PAYER_SEED),
        charge: KagemushaWalletUnloadChargeV1::Quoted { quote, beneficiary },
        certificates: KagemushaWalletCertificateSetV1::new(vec![
            f.payer.enrollment_certificate,
            f.regulator_certificate,
        ])
        .expect("claim certificates"),
    };
    unload_claim
        .verify(&w.scheme())
        .expect("unload claim verifies");
    w.allowlist
        .check_package(&unload_claim.package, None)
        .expect("the unload claim's proofs have the allowlisted lengths");

    let fee_claim = KagemushaWalletFeeClaimV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        payment: w.payment.clone(),
        beneficiary: test_account(BENEFICIARY_SEED),
    };
    fee_claim
        .verify(&w.scheme(), &w.request, payer, &w.payer_issuer_set())
        .expect("fee claim verifies");

    let activation = KagemushaWalletActivationV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        control: w.control,
        credential: *payer,
        bootstrap: w.bootstrap.clone(),
        asset: f.payer.asset.clone(),
        certificates: issuer_set.clone(),
    };
    activation.verify(&w.scheme()).expect("activation verifies");

    let retiring = allowlisted_lineage_package(
        &f.payer,
        payer,
        &transition_statement(
            &f.payer,
            7,
            1,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Retiring,
        ),
    );
    let close_loads = KagemushaWalletCloseLoadsV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        control: payer_control(
            w,
            KagemushaWalletLedgerControlActionV1::CloseLoads {
                package_digest: retiring.package_digest(payer).expect("retiring digest"),
                next_load: 1,
            },
            [0x6d; 32],
        ),
        credential: *payer,
        package: retiring,
        certificates: issuer_set,
    };
    close_loads
        .verify(&w.scheme())
        .expect("close loads verifies");
    w.allowlist
        .check_package(&close_loads.package, None)
        .expect("the close-loads package's proofs have the allowlisted lengths");

    let head_marker = w
        .marker
        .successor(KagemushaWalletMarkerStateV1::Head {
            sequence: 0,
            operation_id: w
                .bootstrap
                .statement
                .operation_id(&payer.body.wallet_id)
                .expect("Bootstrap operation identity"),
            head: w.bootstrap.statement.successor,
            capsule_digest: HEAD_CAPSULE,
            predecessor_capsule_digest: [0; 32],
        })
        .expect("head marker");
    let deleted_marker = head_marker
        .successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
            last_capsule_digest: HEAD_CAPSULE,
        })
        .expect("custody-deleted marker");
    let abandoned_marker = w
        .marker
        .successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::Abandoned,
            last_capsule_digest: [0; 32],
        })
        .expect("abandoned marker");
    let challenge_digest = f.payer.challenge.challenge_digest();
    let abandon_body = KagemushaWalletAbandonmentV1::control_body(
        &abandoned_marker,
        &challenge_digest,
        [0x6e; 32],
    )
    .expect("abandon body");
    let abandonment = KagemushaWalletAbandonmentV1::sign(
        &abandoned_marker,
        challenge_digest,
        [0x6e; 32],
        raw_output(&f.payer.payment, &abandon_body.signing_message()),
    )
    .expect("abandonment");

    let anchored_time =
        KagemushaWalletAnchoredTimeV1::new(w.time_anchor, [0xb0; 32], 1_000, 1_250, 5_000)
            .expect("anchored time");

    LedgerObjects {
        unload_claim,
        fee_claim,
        activation,
        close_loads,
        abandonment,
        head_marker,
        deleted_marker,
        abandoned_marker,
        anchored_time,
    }
}

/// Encode `$value` with its own bounded encoder, decode it with its own bounded decoder under
/// `$expected`, and pin the frame.
macro_rules! framed_pin {
    ($ty:ident, $variant:literal, $value:expr, $expected:expr, $stand_in:expr) => {{
        let value = &$value;
        let frame = value.to_canonical_bytes().expect(stringify!($ty));
        let decoded = $ty::decode_canonical(&frame, $expected).expect(stringify!($ty));
        object_pin(stringify!($ty), $variant, value, frame, &decoded, $stand_in)
    }};
}

/// Full 64-slot typed custody sample and a structurally valid quota-refresh capsule.
/// The predecessor and sigma remain declared stand-ins, never proof acceptance.
fn quota_custody_objects(
    w: &VectorWorld,
) -> (
    KagemushaWalletQuotaRefreshWitnessV1,
    KagemushaWalletRecoveryCapsuleV1,
) {
    let mut before = KagemushaWalletStateV1::bootstrap(w.payer(), field_value(0xc1)).unwrap();
    let start = before.core.accepted_time_floor_ms.max(QUOTA_START_MS);
    let span = before.core.time_anchor_max_response_ms.max(DAY_MS) + 1;
    let windows: Vec<_> = (0..64)
        .map(|i| {
            let start = start + u64::try_from(i).unwrap() * span;
            KagemushaWalletQuotaWindowV1 {
                kind: KagemushaWalletQuotaWindowKindV1::Daily,
                start_ms: start,
                end_ms: start + span,
                limit: 50_000,
            }
        })
        .collect();
    let usage = KagemushaWalletQuotaUsageArrayV1::from_slots(core::array::from_fn(|i| {
        Some(KagemushaWalletQuotaUsageLeafV1::for_window(
            &windows[i],
            100 + u128::try_from(i).unwrap(),
        ))
    }))
    .unwrap();
    let witness = KagemushaWalletQuotaRefreshWitnessV1::from_usage(&usage).unwrap();
    before.core.quota_usage_root = usage.root();
    before.core.quota_windows_root = kagemusha_wallet_quota_windows_root_v1(&windows).unwrap();
    before.core.quota_share_expires_at_ms = windows.last().unwrap().end_ms;
    before.rest.quota_share_id = 1;
    before.rest.quota_share = field_value(0xc2);
    let body = KagemushaWalletQuotaShareBodyV1 {
        version: 1,
        scheme_id: w.scheme_id(),
        asset_digest: w.payer().body.asset_digest,
        wallet_id: w.payer().body.wallet_id,
        share_id: 2,
        issued_at_ms: start,
        expires_at_ms: windows.last().unwrap().end_ms,
        windows_root: before.core.quota_windows_root,
        window_count: 64,
        signer_certificate: w.f.regulator_certificate.certificate_digest(),
    };
    let share = KagemushaWalletQuotaShareV1::sign(
        body,
        windows,
        &w.f.regulator_certificate,
        raw_output(&w.f.regulator, &body.signing_message()),
    )
    .unwrap();
    let changed = before
        .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &share,
            usage: &usage,
        })
        .unwrap();
    let mut successor = KagemushaWalletStateV1 {
        version: 1,
        core: changed.core,
        rest: changed.rest,
    };
    successor.core.sequence += 1;
    successor.core.state_nonce = field_value(0xc3);
    let statement = KagemushaWalletStatementV1 {
        version: 1,
        scheme_id: w.scheme_id(),
        relation_id: w.scheme().relation_id,
        credential_digest: w.payer().credential_digest(),
        asset_digest: before.core.asset_digest,
        lifecycle: successor.core.lifecycle,
        sequence: successor.core.sequence,
        next_load: successor.core.next_load,
        enabled_controls: before.core.enabled_controls,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: before.commitment().unwrap(),
        successor: successor.commitment().unwrap(),
        effect: changed.effect,
    };
    let proof = stand_in_proof(VECTOR_PROOF_LEN);
    let proof_digest = kagemusha_wallet_proof_digest_v1(
        KagemushaWalletOperationKindV1::RefreshPolicy,
        None,
        &proof,
    )
    .unwrap();
    let set = KagemushaWalletCertificateSetV1::new(vec![w.f.regulator_certificate]).unwrap();
    let capsule = KagemushaWalletRecoveryCapsuleV1 {
        version: 1,
        scheme_id: w.scheme_id(),
        wallet_id: w.payer().body.wallet_id,
        operation_id: statement.operation_id(&w.payer().body.wallet_id).unwrap(),
        kind: KagemushaWalletOperationKindV1::RefreshPolicy,
        predecessor_capsule_digest: [0xc4; 32],
        successor_state: successor,
        statement,
        predecessor_lineage: KagemushaWalletLineageSlotV1::None,
        step_proof: proof,
        payment_digest: [0; 32],
        map_openings: vec![],
        retained_inputs: vec![
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
                bytes: share.to_canonical_bytes().unwrap(),
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::CertificateSet,
                bytes: norito::encode_canonical(&set).unwrap(),
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness,
                bytes: witness.to_canonical_bytes().unwrap(),
            },
        ],
        output: KagemushaWalletOutputDescriptorV1::for_transition(
            &statement,
            &proof_digest,
            &[0; 32],
        )
        .unwrap(),
    };
    capsule.validate().unwrap();
    (witness, capsule)
}

/// One canonical frame of every framed object type other than the envelope (pinned by the
/// envelope vectors), every marker state, and the unframed asset scope and anchored time.
fn object_pins(w: &VectorWorld) -> Vec<ObjectPin> {
    let scheme = w.scheme();
    let scheme_id = w.scheme_id();
    let receiver_wallet = w.receiver().body.wallet_id;
    let l = ledger_objects(w);
    let (quota_witness, quota_capsule) = quota_custody_objects(w);
    let package_frame =
        encode_frame_v1(&w.receive, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).expect("package frame");
    let decoded_package: KagemushaWalletPackageV1 =
        decode_frame_v1(&package_frame, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
            .expect("package decode");
    decoded_package
        .verify(w.receiver())
        .expect("package verifies");
    let allowlist_frame = w.allowlist.to_canonical_bytes().expect("allowlist frame");
    let decoded_allowlist = KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
        &allowlist_frame,
        &w.manifest.body,
    )
    .expect("allowlist decode");
    vec![
        framed_pin!(KagemushaWalletSchemeV1, "", scheme, &scheme_id, false),
        framed_pin!(
            KagemushaWalletSignerCertificateV1,
            "RegulatoryPolicy",
            w.f.regulator_certificate,
            &scheme,
            false
        ),
        framed_pin!(
            KagemushaWalletCredentialV1,
            "AndroidKeyMintTee",
            *w.payer(),
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletRenewalRequestV1,
            "Android",
            w.renewal,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletArtifactManifestV1,
            "",
            w.manifest,
            &scheme,
            false
        ),
        object_pin(
            "KagemushaWalletVerifyingKeyAllowlistV1",
            "stand-in keys",
            &w.allowlist,
            allowlist_frame,
            &decoded_allowlist,
            true,
        ),
        framed_pin!(
            KagemushaWalletSchemePolicyV1,
            "",
            w.scheme_policy,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletFeeScheduleV1,
            "",
            w.fee_schedule,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletBlacklistV1,
            "3 entries",
            w.blacklist,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletQuotaShareV1,
            "2 windows",
            w.quota_share,
            &scheme_id,
            false
        ),
        {
            let frame = quota_witness.to_canonical_bytes().unwrap();
            let decoded = KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&frame).unwrap();
            object_pin(
                "KagemushaWalletQuotaRefreshWitnessV1",
                "64 occupied predecessor slots",
                &quota_witness,
                frame,
                &decoded,
                false,
            )
        },
        framed_pin!(
            KagemushaWalletTimeAnchorV1,
            "",
            w.time_anchor,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletChargeQuoteV1,
            "Load",
            w.charge_quote,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletPaymentV1,
            "fee, Ω(pred)",
            w.payment,
            &scheme_id,
            true
        ),
        object_pin(
            "KagemushaWalletPackageV1",
            "Receive",
            &w.receive,
            package_frame,
            &decoded_package,
            true,
        ),
        framed_pin!(
            KagemushaWalletMarkerV1,
            "Enrollment",
            w.marker,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletMarkerV1,
            "Head",
            l.head_marker,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletMarkerV1,
            "Terminal::CustodyDeleted",
            l.deleted_marker,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletMarkerV1,
            "Terminal::Abandoned",
            l.abandoned_marker,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletRecoveryCapsuleV1,
            "Receive",
            w.capsule,
            &scheme_id,
            true
        ),
        framed_pin!(
            KagemushaWalletRecoveryCapsuleV1,
            "QuotaShare, 64 retained predecessor slots",
            quota_capsule,
            &scheme_id,
            true
        ),
        framed_pin!(
            KagemushaWalletCompletionRecordV1,
            "Receive",
            w.completion,
            &receiver_wallet,
            true
        ),
        framed_pin!(
            KagemushaWalletFoldRecordV1,
            "payer head 2",
            w.fold,
            &scheme_id,
            true
        ),
        {
            let frame = w.load_receipt.to_canonical_bytes().unwrap();
            let decoded = KagemushaWalletLoadReceiptV1::decode_canonical(&frame).unwrap();
            object_pin(
                "KagemushaWalletLoadReceiptV1",
                "quoted ordinary transaction",
                &w.load_receipt,
                frame,
                &decoded,
                false,
            )
        },
        {
            let evidence = KagemushaWalletLoadFinalityV1 {
                version: 1,
                receipt_digest: w.load_receipt.receipt_digest().unwrap(),
                certificate: crate::sumeragi_finality::SumeragiCommitCertificateV1 {
                    consensus_header: vec![0x5a; 32],
                    commit_qc: vec![0x5b; 32],
                    result_preimage: vec![0x5c; 32],
                },
                event_proof: {
                    let event = crate::events::EventBox::Data(
                        crate::events::data::DataEvent::KagemushaLoadCommitted(
                            crate::events::data::kagemusha::KagemushaLoadCommittedV1::from_receipt(
                                &w.load_receipt,
                            )
                            .unwrap(),
                        )
                        .into(),
                    );
                    let tree: iroha_crypto::MerkleTree<crate::events::EventBox> =
                        [iroha_crypto::HashOf::new(&event)].into_iter().collect();
                    tree.get_proof(0).unwrap()
                },
            };
            let frame = evidence.to_canonical_bytes().unwrap();
            let decoded = KagemushaWalletLoadFinalityV1::decode_canonical(&frame).unwrap();
            object_pin(
                "KagemushaWalletLoadFinalityV1",
                "shape-only native certificate",
                &evidence,
                frame,
                &decoded,
                true,
            )
        },
        framed_pin!(
            KagemushaWalletUnloadClaimV1,
            "quoted",
            l.unload_claim,
            &scheme_id,
            true
        ),
        framed_pin!(KagemushaWalletFeeClaimV1, "", l.fee_claim, &scheme_id, true),
        framed_pin!(
            KagemushaWalletLedgerControlV1,
            "Activate",
            w.control,
            &scheme_id,
            false
        ),
        framed_pin!(
            KagemushaWalletActivationV1,
            "",
            l.activation,
            &scheme_id,
            true
        ),
        framed_pin!(
            KagemushaWalletCloseLoadsV1,
            "",
            l.close_loads,
            &scheme_id,
            true
        ),
        framed_pin!(
            KagemushaWalletAbandonmentV1,
            "",
            l.abandonment,
            &scheme_id,
            false
        ),
        unbounded_pin("KagemushaWalletAssetScopeV1", "", &w.f.payer.asset),
        unbounded_pin("KagemushaWalletAnchoredTimeV1", "", &l.anchored_time),
    ]
}

fn object_pins_json(w: &VectorWorld) -> Value {
    Value::Array(
        object_pins(w)
            .iter()
            .map(|pin| {
                json_object(vec![
                    ("type", json_text(pin.short_name)),
                    ("variant", json_text(pin.variant)),
                    ("frame_name", json_text(&pin.frame_name)),
                    ("frame_len", json_number(pin.frame.len())),
                    ("canonical_hex", json_hex(&pin.frame)),
                    ("stand_in_proof", Value::Bool(pin.stand_in_proof)),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------------------
// Enum tags
// ---------------------------------------------------------------------------------------

/// Variants of one wire enum: name, transcript tag and Norito wire tag.
struct EnumTags {
    name: &'static str,
    variants: Vec<(&'static str, u8, u32)>,
}

fn tag_row<T: norito::NoritoSerialize>(
    variant: &'static str,
    value: &T,
    tag: u8,
) -> (&'static str, u8, u32) {
    (variant, tag, norito_tag(value))
}

fn unit_tags<T: Copy + norito::NoritoSerialize>(
    name: &'static str,
    values: &[T],
    names: &[&'static str],
    tag: impl Fn(T) -> u8,
) -> EnumTags {
    assert_eq!(values.len(), names.len(), "{name}");
    EnumTags {
        name,
        variants: values
            .iter()
            .zip(names)
            .map(|(value, &variant)| tag_row(variant, value, tag(*value)))
            .collect(),
    }
}

/// Every Norito wire enum of the module with one sample of every variant.
fn enum_tag_table(w: &VectorWorld) -> Vec<EnumTags> {
    use KagemushaWalletEffectV1 as Effect;
    use KagemushaWalletLedgerControlActionV1 as Action;
    use KagemushaWalletMarkerStateV1 as MarkerState;
    use KagemushaWalletMessageV1 as Message;
    use KagemushaWalletPolicyDataItemV1 as Item;

    let payment = &w.payment;
    let evidence_android = w.renewal.evidence.clone();
    let evidence_apple = KagemushaWalletRenewalEvidenceV1::Apple {
        assertion: b"app-attest-assertion".to_vec(),
    };
    let effects = [
        ("Bootstrap", w.bootstrap.statement.effect),
        ("Load", w.load_receipt.load_effect().expect("load effect")),
        ("Send", payment.send.statement.effect),
        ("Receive", w.receive.statement.effect),
        (
            "ArchiveSent",
            w.credited_receive
                .archive_sent_effect(
                    &w.scheme(),
                    &w.request,
                    payment,
                    &payment.pending_outgoing_leaf().expect("pending leaf"),
                )
                .expect("archive effect"),
        ),
        (
            "Unload",
            Effect::Unload {
                nullifier: kagemusha_wallet_unload_nullifier_v1(
                    &w.scheme_id(),
                    &w.payer().body.wallet_id,
                    2,
                ),
                redeem_ordinal: 2,
                amount: 700,
                online_charge: 0,
                charge_quote: [0; 32],
            },
        ),
        (
            "RefreshPolicy",
            Effect::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
                update: w.scheme_policy.scheme_policy_digest(),
                accepted_time_floor_ms: 0,
            },
        ),
        ("Retiring", Effect::Retiring),
    ];
    let markers = [
        ("Enrollment", w.marker.state),
        (
            "Head",
            w.capsule.head_marker_state().expect("head marker state"),
        ),
        (
            "Terminal",
            MarkerState::Terminal {
                reason: KagemushaWalletTerminalReasonV1::Abandoned,
                last_capsule_digest: [0; 32],
            },
        ),
    ];
    let actions = [
        ("Activate", w.control.body.action),
        (
            "CloseLoads",
            Action::CloseLoads {
                package_digest: [0x4c; 32],
                next_load: 1,
            },
        ),
        (
            "Abandon",
            Action::Abandon {
                enrollment_id: w.payer().body.enrollment_id,
                marker_generation: 1,
                terminal_marker_digest: [0x4d; 32],
            },
        ),
    ];
    let items = [
        (
            "SchemePolicy",
            Item::SchemePolicy {
                policy: w.scheme_policy,
            },
        ),
        (
            "FeeSchedule",
            Item::FeeSchedule {
                schedule: w.fee_schedule,
            },
        ),
        (
            "Certificates",
            Item::Certificates {
                certificates: KagemushaWalletCertificateSetV1::new(vec![w.f.regulator_certificate])
                    .expect("set"),
            },
        ),
    ];
    let messages: Vec<(&'static str, Message)> = envelope_messages(w)
        .into_iter()
        .filter(|(variant, _, _)| {
            !matches!(
                *variant,
                "Credited::Status" | "SessionControl::UnsupportedScheme"
            )
        })
        .map(|(_, message, _)| (message_kind_name(&message), message))
        .collect();

    vec![
        unit_tags(
            "KagemushaWalletSignerRoleV1",
            &KagemushaWalletSignerRoleV1::ALL,
            &["Enrollment", "RegulatoryPolicy", "TimeAnchor", "Artifact"],
            KagemushaWalletSignerRoleV1::tag,
        ),
        unit_tags(
            "KagemushaWalletEvidenceKindV1",
            &KagemushaWalletEvidenceKindV1::ALL,
            &[
                "AndroidKeyMintTee",
                "AndroidKeyMintStrongBox",
                "AppleAppAttest",
            ],
            KagemushaWalletEvidenceKindV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletRenewalEvidenceV1",
            variants: vec![
                tag_row("Android", &evidence_android, evidence_android.tag()),
                tag_row("Apple", &evidence_apple, evidence_apple.tag()),
            ],
        },
        unit_tags(
            "KagemushaWalletLifecycleV1",
            &KagemushaWalletLifecycleV1::ALL,
            &["Active", "Retiring"],
            KagemushaWalletLifecycleV1::tag,
        ),
        unit_tags(
            "KagemushaWalletOperationKindV1",
            &KagemushaWalletOperationKindV1::ALL,
            &[
                "Bootstrap",
                "Load",
                "Send",
                "Receive",
                "ArchiveSent",
                "Unload",
                "RefreshPolicy",
                "Retiring",
            ],
            KagemushaWalletOperationKindV1::tag,
        ),
        unit_tags(
            "KagemushaWalletPolicyUpdateKindV1",
            &KagemushaWalletPolicyUpdateKindV1::ALL,
            &[
                "Credential",
                "SchemePolicy",
                "Blacklist",
                "QuotaShare",
                "TimeAnchor",
            ],
            KagemushaWalletPolicyUpdateKindV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletEffectV1",
            variants: effects
                .iter()
                .map(|&(variant, ref effect)| tag_row(variant, effect, effect.tag()))
                .collect(),
        },
        unit_tags(
            "KagemushaWalletFeeRoundingV1",
            &KagemushaWalletFeeRoundingV1::ALL,
            &["Down", "Up"],
            KagemushaWalletFeeRoundingV1::tag,
        ),
        unit_tags(
            "KagemushaWalletQuotaWindowKindV1",
            &KagemushaWalletQuotaWindowKindV1::ALL,
            &["Daily", "Monthly"],
            KagemushaWalletQuotaWindowKindV1::tag,
        ),
        unit_tags(
            "KagemushaWalletChargeKindV1",
            &KagemushaWalletChargeKindV1::ALL,
            &["Load", "Unload"],
            KagemushaWalletChargeKindV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletFeeScheduleSlotV1",
            variants: [
                ("None", KagemushaWalletFeeScheduleSlotV1::None),
                (
                    "Present",
                    KagemushaWalletFeeScheduleSlotV1::Present {
                        schedule: w.fee_schedule,
                    },
                ),
            ]
            .iter()
            .map(|&(variant, ref slot)| tag_row(variant, slot, slot.tag()))
            .collect(),
        },
        EnumTags {
            name: "KagemushaWalletLineageSlotV1",
            variants: [
                ("None", &w.receive.lineage),
                ("Present", &payment.send.lineage),
            ]
            .iter()
            .map(|&(variant, slot)| tag_row(variant, slot, slot.tag()))
            .collect(),
        },
        EnumTags {
            name: "KagemushaWalletCreditedEvidenceV1",
            variants: [
                ("Receive", &w.credited_receive.evidence),
                ("Status", &w.credited_status.evidence),
            ]
            .iter()
            .map(|&(variant, evidence)| tag_row(variant, evidence, evidence.tag()))
            .collect(),
        },
        unit_tags(
            "KagemushaWalletSessionControlKindV1",
            &KagemushaWalletSessionControlKindV1::ALL,
            &[
                "SetupDeclined",
                "UnsupportedScheme",
                "ReceiveDeferred",
                "Close",
            ],
            KagemushaWalletSessionControlKindV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletSessionAuthV1",
            variants: [("Unsigned", w.unsupported.auth), ("Signed", w.close.auth)]
                .iter()
                .map(|&(variant, ref auth)| tag_row(variant, auth, auth.tag()))
                .collect(),
        },
        EnumTags {
            name: "KagemushaWalletPolicyDataItemV1",
            variants: items
                .iter()
                .map(|&(variant, ref item)| tag_row(variant, item, item.tag()))
                .collect(),
        },
        EnumTags {
            name: "KagemushaWalletMessageV1",
            variants: messages
                .iter()
                .map(|&(variant, ref message)| tag_row(variant, message, message.tag()))
                .collect(),
        },
        unit_tags(
            "KagemushaWalletTerminalReasonV1",
            &KagemushaWalletTerminalReasonV1::ALL,
            &["Abandoned", "CustodyDeleted"],
            KagemushaWalletTerminalReasonV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletMarkerStateV1",
            variants: markers
                .iter()
                .map(|&(variant, ref state)| tag_row(variant, state, state.tag()))
                .collect(),
        },
        unit_tags(
            "KagemushaWalletRetainedInputRoleV1",
            &KagemushaWalletRetainedInputRoleV1::ALL,
            &[
                "Request",
                "Payment",
                "Credited",
                "LoadReceipt",
                "ChargeQuote",
                "PolicyUpdate",
                "CertificateSet",
                "Credential",
                "LoadFinality",
                "QuotaRefreshWitness",
            ],
            KagemushaWalletRetainedInputRoleV1::tag,
        ),
        EnumTags {
            name: "KagemushaWalletLedgerControlActionV1",
            variants: actions
                .iter()
                .map(|&(variant, ref action)| tag_row(variant, action, action.tag()))
                .collect(),
        },
        EnumTags {
            name: "KagemushaWalletUnloadChargeV1",
            variants: [
                ("None", KagemushaWalletUnloadChargeV1::None),
                ("Quoted", ledger_objects(w).unload_claim.charge),
            ]
            .iter()
            .map(|&(variant, ref charge)| tag_row(variant, charge, charge.tag()))
            .collect(),
        },
    ]
}

fn enum_tags_json(table: &[EnumTags]) -> Value {
    let mut map = Map::new();
    for entry in table {
        let rows = entry
            .variants
            .iter()
            .map(|(variant, tag, _)| {
                json_object(vec![
                    ("variant", json_text(variant)),
                    ("tag", json_number(usize::from(*tag))),
                ])
            })
            .collect();
        assert!(
            map.insert(entry.name.to_owned(), Value::Array(rows))
                .is_none()
        );
    }
    Value::Object(map)
}

// ---------------------------------------------------------------------------------------
// Vectors file
// ---------------------------------------------------------------------------------------

fn keys_json(w: &VectorWorld) -> Value {
    let keys = [
        ("scheme_root", ROOT_SEED),
        ("receiver_issuer", RECEIVER_ISSUER_SEED),
        ("payer_issuer", PAYER_ISSUER_SEED),
        ("regulator", REGULATOR_SEED),
        ("time_anchor", TIME_SEED),
        ("artifact", ARTIFACT_SEED),
        ("renewal_attested_key", RENEWAL_KEY_SEED),
        ("payer_payment", PAYER_SEED),
        ("receiver_payment", RECEIVER_SEED),
    ];
    for (signer, certificate) in [
        (&w.time_signer, &w.time_certificate),
        (&w.artifact_signer, &w.artifact_certificate),
    ] {
        assert_eq!(public_key(signer), certificate.body.key);
    }
    Value::Array(
        keys.iter()
            .map(|(name, seed)| {
                json_object(vec![
                    ("name", json_text(name)),
                    ("scalar_hex", json_hex(&[*seed; 32])),
                    (
                        "public_key_hex",
                        json_hex(public_key(&signing_key(*seed)).as_sec1_bytes()),
                    ),
                ])
            })
            .collect(),
    )
}

fn stand_ins_json() -> Value {
    json_object(vec![
        (
            "note",
            json_text(
                "labelled stand-in values: proof bytes, relation bindings, verifying keys and the \
                 lineage roots of the Payment's Ω(pred) are fixed by the G3 artifact set and \
                 lineage relation; vectors that depend on them change then. Map roots, \
                 credit-digest roots and openings are computed. The relation identity and the \
                 artifact manifest bind the computed digest of the vectored allowlist, and every \
                 stand-in σ and Ω has exactly its allowlisted length",
            ),
        ),
        ("eq_protocol_digest_hex", json_hex(&EQ)),
        ("ep_protocol_digest_hex", json_hex(&EP)),
        ("native_profile_digest_hex", json_hex(&NATIVE)),
        ("artifact_inventory_digest_hex", json_hex(&INVENTORY)),
        (
            "lineage_pending_outgoing_root_hex",
            json_hex(&LINEAGE_PENDING_ROOT),
        ),
        ("credit_digest_root_hex", json_hex(&CREDIT_DIGEST_ROOT)),
        (
            "field_value_rule",
            json_text("seed s: 31 bytes s followed by s & 0x3f (little-endian, canonical)"),
        ),
        ("proof_byte_rule", json_text("σ byte i = i mod 251")),
        (
            "lineage_proof_byte_rule",
            json_text(
                "Ω transport proof byte i = (i + 7) mod 251; CreditStatus Ω(h): (i + 11) mod 251; \
                 every Ω has the allowlist's lineage_proof_bytes",
            ),
        ),
        (
            "verifying_key_rule",
            json_text(
                "σ verifying-key digest: 32 bytes 0x80 | tag << 3 | mask; Ω transport key: 32 \
                 bytes 0xc4; σ length: 48 at the empty mask, 49 at the other mask of Send and \
                 Receive",
            ),
        ),
    ])
}

fn header_json(w: &VectorWorld) -> Value {
    let frame = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer {
        offer: w.offer.clone(),
    })
    .to_canonical_bytes()
    .expect("frame");
    let header = norito::core::Header::read(frame.as_slice()).expect("header");
    json_object(vec![
        ("magic_hex", json_hex(&header.magic)),
        ("major", json_number(usize::from(header.major))),
        ("minor", json_number(usize::from(header.minor))),
        ("compression", json_number(0)),
        ("header_bytes", json_number(norito::core::Header::SIZE)),
        (
            "schema_hash_rule",
            json_text("first 16 bytes of SHA-256(\"norito:v1:type-name\" || 0x00 || frame_name)"),
        ),
        (
            "crc64_rule",
            json_text("CRC-64/XZ of the payload, stored little-endian; crc64_hex is big-endian"),
        ),
    ])
}

fn bounds_json() -> Value {
    json_object(vec![
        (
            "version",
            json_number(usize::from(KAGEMUSHA_WALLET_VERSION_V1)),
        ),
        ("text_prefix", json_text(KAGEMUSHA_WALLET_TEXT_PREFIX_V1)),
        (
            "session_max_bytes",
            json_number(KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1),
        ),
        (
            "message_max_bytes",
            json_number(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
        ),
        (
            "session_text_max_bytes",
            json_number(KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1),
        ),
        (
            "message_text_max_bytes",
            json_number(KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1),
        ),
        (
            "lineage_max_bytes",
            json_number(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
        ),
        (
            "fold_record_max_bytes",
            json_number(KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1),
        ),
        (
            "credential_max_bytes",
            json_number(KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1),
        ),
        (
            "payment_fixed_bytes",
            json_number(KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1),
        ),
        (
            "payment_proof_budget_bytes",
            json_number(KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1),
        ),
        (
            "credited_receive_fixed_bytes",
            json_number(KAGEMUSHA_WALLET_CREDITED_RECEIVE_FIXED_BYTES_V1),
        ),
        (
            "credited_receive_proof_budget_bytes",
            json_number(KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1),
        ),
        (
            "credited_status_fixed_bytes",
            json_number(KAGEMUSHA_WALLET_CREDITED_STATUS_FIXED_BYTES_V1),
        ),
        (
            "lineage_proof_cap_bytes",
            json_number(KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1),
        ),
        (
            "proof_caps",
            json_text(
                "the exact σ and Ω transport lengths of the frozen verifying-key allowlist, with \
                 Ω + the largest σ_send <= payment_proof_budget_bytes, σ_recv <= \
                 credited_receive_proof_budget_bytes and Ω <= lineage_proof_cap_bytes; until \
                 the artifacts freeze only the carrying frames bound them",
            ),
        ),
        (
            "verifying_key_allowlist_max_bytes",
            json_number(KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1),
        ),
        (
            "verifying_key_entries_max",
            json_number(KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1),
        ),
        (
            "indexed_tree_depth",
            json_number(KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1),
        ),
        (
            "quota_usage_slots",
            json_number(KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1),
        ),
        (
            "quota_tree_depth",
            json_number(KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1),
        ),
        (
            "credit_opening_bytes",
            json_number(KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1),
        ),
        (
            "certificate_set_max",
            json_number(KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1),
        ),
    ])
}

/// One σ-field element list as hex strings of canonical little-endian encodings.
fn json_items(items: &[[u8; 32]]) -> Value {
    Value::Array(items.iter().map(|item| json_hex(item)).collect())
}

/// One Poseidon value: its element list and digest under `domain`.
fn json_poseidon(domain: u64, items: &[[u8; 32]], digest: &[u8; 32]) -> Value {
    assert_eq!(
        kagemusha_wallet_poseidon_v1(domain, items).expect("canonical items"),
        *digest
    );
    json_object(vec![
        (
            "domain",
            json_text(core::str::from_utf8(&domain.to_le_bytes()).expect("ascii")),
        ),
        ("items", json_items(items)),
        ("digest_hex", json_hex(digest)),
    ])
}

/// One map leaf: its key, element list and leaf value.
fn json_leaf(domain: u64, key: &[u8; 32], items: &[[u8; 32]], value: &[u8; 32]) -> Value {
    let Value::Object(mut map) = json_poseidon(domain, items, value) else {
        unreachable!("object");
    };
    map.insert("key_hex".to_owned(), json_hex(key));
    Value::Object(map)
}

/// One indexed-tree leaf `(key, value, next_key)` and its hash.
fn json_indexed_leaf(leaf: &KagemushaWalletIndexedLeafV1) -> Value {
    json_object(vec![
        ("key_hex", json_hex(&leaf.key)),
        ("value_hex", json_hex(&leaf.value)),
        ("next_key_hex", json_hex(&leaf.next_key)),
        ("leaf_hex", json_hex(&leaf.hash().expect("leaf hash"))),
    ])
}

/// One indexed-tree opening: its slot and exactly 32 siblings, height 0 first.
fn json_indexed_opening(opening: &KagemushaWalletIndexedOpeningV1) -> Value {
    json_object(vec![
        (
            "slot",
            json_number(usize::try_from(opening.slot).expect("slot")),
        ),
        ("siblings", json_items(&opening.siblings)),
    ])
}

/// One leaf opening under `root`, with its 1,124-byte transcript.
fn json_leaf_opening(
    leaf: &KagemushaWalletIndexedLeafV1,
    opening: &KagemushaWalletIndexedOpeningV1,
    root: &[u8; 32],
) -> Value {
    assert_eq!(opening.leaf_root(leaf).expect("opening root"), *root);
    json_object(vec![
        ("leaf", json_indexed_leaf(leaf)),
        ("opening", json_indexed_opening(opening)),
        ("transcript_hex", json_hex(&opening.leaf_transcript(leaf))),
        ("root_hex", json_hex(root)),
    ])
}

/// Every current Poseidon domain: ordinary uses, signing domains, then object domains.
fn all_domains() -> Vec<(&'static str, u64)> {
    let mut domains = KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1.to_vec();
    for domain in Domain::ALL {
        domains.push((signing_domain_use(domain), domain.domain()));
    }
    for domain in ObjectDomain::ALL {
        domains.push((object_domain_use(domain), domain.domain()));
    }
    domains
}

/// Use label of a signing domain in the domain table.
fn signing_domain_use(domain: Domain) -> &'static str {
    match domain {
        Domain::Certificate => "signing_certificate",
        Domain::Credential => "signing_credential",
        Domain::RenewalChallenge => "signing_renewal_challenge",
        Domain::RenewalKeyBinding => "signing_renewal_key_binding",
        Domain::ArtifactManifest => "signing_artifact_manifest",
        Domain::Receipt => "signing_receipt",
        Domain::SchemePolicy => "signing_scheme_policy",
        Domain::FeeSchedule => "signing_fee_schedule",
        Domain::Blacklist => "signing_blacklist",
        Domain::QuotaShare => "signing_quota_share",
        Domain::TimeAnchor => "signing_time_anchor",
        Domain::ChargeQuote => "signing_charge_quote",
        Domain::Offer => "signing_offer",
        Domain::SessionControl => "signing_session_control",
        Domain::Request => "signing_request",
        Domain::LedgerControl => "signing_ledger_control",
    }
}

/// The canonical frame, core and rest element lists, rest digest and commitment of `state`.
fn json_state(state: &KagemushaWalletStateV1) -> Vec<(&'static str, Value)> {
    vec![
        (
            "state_hex",
            json_hex(&norito::encode_canonical(state).expect("state frame")),
        ),
        (
            "core_items",
            json_items(&state.core_field_items().expect("core items")),
        ),
        (
            "rest_items",
            json_items(&state.rest_field_items().expect("rest items")),
        ),
        (
            "rest_digest_hex",
            json_hex(&state.rest_digest().expect("rest digest")),
        ),
        (
            "commitment_hex",
            json_hex(&state.commitment().expect("commitment").value),
        ),
    ]
}

/// The controlled state over the identities of `base` ([`controlled_state`]): every core and
/// rest element distinct, with each field's value by name (integers in decimal, 32-byte values
/// in hex), so a consumer binds every element position to its field (owner answers Q3, Q4, Q5
/// and Q10).
fn json_controlled_state(base: &KagemushaWalletStateV1) -> Value {
    let state = controlled_state(base);
    let core = &state.core;
    let rest = &state.rest;
    let number = |value: u128| json_text(&value.to_string());
    let mut entries = json_state(&state);
    entries.push((
        "core_fields",
        json_object(vec![
            ("lifecycle", number(u128::from(core.lifecycle.tag()))),
            ("scheme_id", json_hex(&core.scheme_id)),
            ("asset_digest", json_hex(&core.asset_digest)),
            ("wallet_id", json_hex(&core.wallet_id)),
            ("credential_digest", json_hex(&core.credential_digest)),
            ("balance", number(core.balance)),
            ("burned_total", number(core.burned_total)),
            ("sequence", number(core.sequence)),
            ("next_send", number(core.next_send)),
            ("next_load", number(core.next_load)),
            ("next_redeem", number(core.next_redeem)),
            ("send_chain", json_hex(&core.send_chain)),
            ("recv_chain", json_hex(&core.recv_chain)),
            ("consumed_credit_root", json_hex(&core.consumed_credit_root)),
            (
                "pending_outgoing_root",
                json_hex(&core.pending_outgoing_root),
            ),
            (
                "load_redeem_recovery_root",
                json_hex(&core.load_redeem_recovery_root),
            ),
            ("fee_claim_root", json_hex(&core.fee_claim_root)),
            ("quota_usage_root", json_hex(&core.quota_usage_root)),
            (
                "enabled_controls",
                number(u128::from(core.enabled_controls)),
            ),
            ("quota_windows_root", json_hex(&core.quota_windows_root)),
            (
                "quota_share_expires_at_ms",
                number(u128::from(core.quota_share_expires_at_ms)),
            ),
            (
                "time_anchor_max_response_ms",
                number(u128::from(core.time_anchor_max_response_ms)),
            ),
            (
                "blacklist_version",
                number(u128::from(core.blacklist_version)),
            ),
            ("blacklist_root", json_hex(&core.blacklist_root)),
            (
                "blacklist_issued_at_ms",
                number(u128::from(core.blacklist_issued_at_ms)),
            ),
            (
                "blacklist_max_age_ms",
                number(u128::from(core.blacklist_max_age_ms)),
            ),
            (
                "lease_expires_at_ms",
                number(u128::from(core.lease_expires_at_ms)),
            ),
            ("policy_epoch", number(u128::from(core.policy_epoch))),
            (
                "accepted_time_floor_ms",
                number(u128::from(core.accepted_time_floor_ms)),
            ),
            ("state_nonce", json_hex(&core.state_nonce)),
        ]),
    ));
    entries.push((
        "rest_fields",
        json_object(vec![
            (
                "permitted_controls",
                number(u128::from(rest.permitted_controls)),
            ),
            ("scheme_policy", json_hex(&rest.scheme_policy)),
            ("fee_schedule", json_hex(&rest.fee_schedule)),
            ("blacklist", json_hex(&rest.blacklist)),
            (
                "blacklist_history_root",
                json_hex(&rest.blacklist_history_root),
            ),
            ("quota_share", json_hex(&rest.quota_share)),
            ("quota_share_id", number(u128::from(rest.quota_share_id))),
            ("time_anchor", json_hex(&rest.time_anchor)),
        ]),
    ));
    json_object(entries)
}

/// The σ-field encodings shared by native and in-circuit encoders (§3.2): the element lists of
/// the statement, state core and rest, chain appends and map values, with the Poseidon values
/// the data model computes over them and every current ordinary, signing and object domain.
fn field_encodings_json(w: &VectorWorld) -> Value {
    let payment = &w.payment;
    let send = &payment.send.statement;
    let receive = &w.receive.statement;
    let state = &w.capsule.successor_state;
    let digests = payment.digests().expect("payment digests");
    let send_entry = payment.send_chain_entry().expect("send chain entry");
    let recv_entry = payment.recv_chain_entry().expect("recv chain entry");
    let consumed = payment
        .consumed_credit_leaf(receive.sequence)
        .expect("consumed-credit leaf");
    let pending = payment.pending_outgoing_leaf().expect("pending leaf");
    let fee = payment
        .fee_claim_leaf()
        .expect("fee leaf")
        .expect("nonzero fee");
    let credit_digest = w.status().opening.leaf();
    assert_eq!(credit_digest.payment_digest, digests.payment);
    let domain_rows = all_domains()
        .iter()
        .map(|(name, domain)| {
            json_object(vec![
                ("use", json_text(name)),
                (
                    "ascii",
                    json_text(core::str::from_utf8(&domain.to_le_bytes()).expect("ascii")),
                ),
                ("u64_le_hex", json_hex(&domain.to_le_bytes())),
            ])
        })
        .collect();
    let send_items = send.field_items().expect("send statement items");
    let receive_items = receive.field_items().expect("receive statement items");
    let send_append = send_entry.append_preimage(&[0; 32]).expect("send append");
    let recv_append = recv_entry
        .append_preimage(&field_value(0x2c))
        .expect("recv append");
    json_object(vec![
        (
            "field",
            json_text(
                "Pasta Fp (Vesta scalar field), p = \
                 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
            ),
        ),
        (
            "modulus_le_hex",
            json_hex(&KAGEMUSHA_WALLET_FIELD_MODULUS_V1),
        ),
        (
            "element_rule",
            json_text(
                "32-byte little-endian canonical encoding (< p); an integer, tag or mask is one \
                 element; a 32-byte SHA-256 digest or identifier is two u128 limbs, low half \
                 first; a Poseidon value (commitment, chain, root, nonce, credit_id, \
                 proof_digest, statement, object, certificate-set, package, operation, nullifier, \
                 Payment, lineage, credit-opening, credit-status or credited digest, \
                 signing message) is one element",
            ),
        ),
        (
            "poseidon_rule",
            json_text(
                "P(domain, items) = iroha_pasta::poseidon::hash_with_domain::<Fp>(domain, items) \
                 (RP57): a fresh sponge absorbs [domain, len(items), items...]; domain is the u64 \
                 of the 8 little-endian ASCII bytes",
            ),
        ),
        (
            "packing_rule",
            json_text(
                "P_bytes(domain, b) = P(domain, [len(b)] || c_0 || ... || c_(m-1)), m = \
                 ceil(len(b) / 31), c_i = bytes 31i..31i+30 of b as a little-endian integer, \
                 the last chunk zero-filled",
            ),
        ),
        ("domains", Value::Array(domain_rows)),
        (
            "send_statement",
            json_poseidon(
                KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
                &send_items,
                &send.statement_digest().expect("send statement digest"),
            ),
        ),
        (
            "receive_statement",
            json_poseidon(
                KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
                &receive_items,
                &receive
                    .statement_digest()
                    .expect("receive statement digest"),
            ),
        ),
        ("receive_successor_state", json_object(json_state(state))),
        ("controlled_state", json_controlled_state(state)),
        ("send_chain_append_from_empty", json_items(&send_append)),
        (
            "send_chain_append_from_empty_hex",
            json_hex(&send_entry.append(&[0; 32]).expect("send chain")),
        ),
        ("recv_chain_append", json_items(&recv_append)),
        (
            "recv_chain_append_hex",
            json_hex(&recv_entry.append(&field_value(0x2c)).expect("recv chain")),
        ),
        (
            "consumed_credit_value",
            json_items(&consumed.field_items().expect("consumed items")),
        ),
        (
            "pending_outgoing_value",
            json_items(&pending.field_items().expect("pending items")),
        ),
        (
            "fee_claim_value",
            json_items(&fee.field_items().expect("fee items")),
        ),
        (
            "credit_digest_value",
            json_items(&credit_digest.field_items().expect("credit-digest items")),
        ),
        (
            "indexed_leaf_rule",
            json_text(
                "leaf = P(kgwimlf1, [key, value, next_key]) with value = P(value domain, \
                 elements); node = P(kgwimnd1, [left, right]); an empty slot is 0; depth 32, \
                 slot bit h selects the child at height h; the empty tree is the sentinel \
                 (0, 0, 0) in slot 0",
            ),
        ),
    ])
}

/// Poseidon vectors (owner answers Q1, Q2, Q9, Q10 and Q11, and A1 to A4): one KAT per domain,
/// the packing rule, `credit_id`, both `proof_digest` domains, the Payment, lineage,
/// credit-opening, credit-status and credited digests, every signing message, every map value
/// and its key, the depth-32 indexed tree (empty tree, insertions, openings and a removal),
/// the fixed-slot quota array, the credit-digest opening of the vectored `CreditStatus`,
/// the limb-ordered
/// blacklist and the quota-window trees, and the verifying-key allowlist.
fn poseidon_json(w: &VectorWorld) -> Value {
    let int = kagemusha_wallet_field_from_u128_v1;
    let payment = &w.payment;
    let request = &w.request;
    let digests = payment.digests().expect("payment digests");
    let receive_digests = w.receive.verify(w.receiver()).expect("receive package");

    // One KAT per domain over the elements [1, 2, 3], the signing domains included.
    let kat_items = [int(1), int(2), int(3)];
    let kats = all_domains()
        .iter()
        .map(|(_, domain)| {
            json_poseidon(
                *domain,
                &kat_items,
                &kagemusha_wallet_poseidon_v1(*domain, &kat_items).expect("kat"),
            )
        })
        .collect();

    // The packing rule at the empty input and the 31-byte chunk boundaries.
    let packed_bytes: Vec<u8> = (1..=63_u8).collect();
    let packing = [0_usize, 1, 30, 31, 32, 62, 63]
        .iter()
        .map(|len| {
            let bytes = &packed_bytes[..*len];
            let items = kagemusha_wallet_packed_bytes_v1(bytes);
            json_object(vec![
                ("len", json_number(*len)),
                ("bytes_hex", json_hex(bytes)),
                (
                    "poseidon",
                    json_poseidon(
                        KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
                        &items,
                        &kagemusha_wallet_poseidon_bytes_v1(
                            KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
                            bytes,
                        ),
                    ),
                ),
            ])
        })
        .collect();

    // The large-input digests (`P_bytes`).
    let length_prefixed = |parts: &[&[u8]]| {
        let mut body = Vec::new();
        for part in parts {
            body.extend_from_slice(&u32::try_from(part.len()).expect("len").to_le_bytes());
            body.extend_from_slice(part);
        }
        body
    };
    let omega = payment.send.lineage.lineage().expect("Ω(pred)");
    let send_proof_body = length_prefixed(&[&omega.bytes(), &payment.send.step_proof.bytes]);
    let receive_proof_body = length_prefixed(&[&w.receive.step_proof.bytes]);
    let payment_transcript = kagemusha_wallet_payment_transcript_v1(
        &digests.request,
        &payment.payer_payment_key,
        &digests.payer_credential,
        &digests.package.package,
    );
    let status = w.status();
    let status_receipt = status
        .receipt
        .verify(
            &KagemushaWalletReceiptSignerV1::from_lineage(&status.lineage.public)
                .expect("Ω(h) signer"),
            &status.statement,
            &status.proof_digest,
        )
        .expect("status receipt");
    let opening_transcript = status.opening.transcript().expect("opening transcript");
    let opening_digest = status.opening.opening_digest().expect("opening digest");
    let status_transcript = [
        &1_u16.to_le_bytes()[..],
        &status
            .statement
            .statement_digest()
            .expect("status statement digest")[..],
        &status.proof_digest[..],
        &status_receipt[..],
        &status.lineage.lineage_digest()[..],
        &opening_digest[..],
    ]
    .concat();
    let status_digest = status.credit_status_digest().expect("credit status");
    let credited_transcript = |tag: u8, evidence: &[u8; 32]| {
        [
            &1_u16.to_le_bytes()[..],
            &[tag][..],
            &digests.credit_id[..],
            &digests.payment[..],
            &evidence[..],
        ]
        .concat()
    };
    let (credited_receive, _) = w
        .credited_receive
        .verify_for(&w.scheme(), request, payment)
        .expect("credited receive");
    let (credited_status, _) = w
        .credited_status
        .verify_for(&w.scheme(), request, payment)
        .expect("credited status");
    let large_inputs = vec![
        packed_digest(
            "proof_digest of the Send: stand-in Ω(pred) and σ_send",
            KAGEMUSHA_WALLET_PROOF_DOMAIN_V1,
            &send_proof_body,
            &digests.package.proof,
        ),
        packed_digest(
            "proof_digest of the Receive: stand-in σ_recv",
            KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
            &receive_proof_body,
            &receive_digests.proof,
        ),
        packed_digest(
            "Payment digest over the payment transcript",
            KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
            &payment_transcript,
            &digests.payment,
        ),
        packed_digest(
            "lineage digest over the stand-in Ω(pred) bytes of the Payment",
            KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1,
            &omega.bytes(),
            &w.lineage.lineage_digest(),
        ),
        packed_digest(
            "credit-opening digest of the CreditStatus opening",
            KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
            &opening_transcript,
            &opening_digest,
        ),
        packed_digest(
            "credit-status digest of the folded crediting head",
            KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1,
            &status_transcript,
            &status_digest,
        ),
        packed_digest(
            "Credited digest of the Receive form",
            KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
            &credited_transcript(1, &receive_digests.package),
            &credited_receive,
        ),
        packed_digest(
            "Credited digest of the Status form",
            KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
            &credited_transcript(2, &status_digest),
            &credited_status,
        ),
    ];
    let signing_messages = signature_vectors(w)
        .iter()
        .map(|vector| {
            packed_digest(
                vector.object,
                vector.domain.domain(),
                &vector.transcript,
                &vector.message(),
            )
        })
        .collect();

    // Every map value and its key.
    let consumed = payment
        .consumed_credit_leaf(w.receive.statement.sequence)
        .expect("consumed leaf");
    let pending = payment.pending_outgoing_leaf().expect("pending leaf");
    let fee = payment
        .fee_claim_leaf()
        .expect("fee leaf")
        .expect("nonzero fee");
    let load = KagemushaWalletLoadLeafV1 {
        ordinal: 0,
        receipt_digest: w.load_receipt.receipt_digest().expect("receipt digest"),
        amount: w.load_receipt.amount,
    };
    let redeem = KagemushaWalletRedeemLeafV1 {
        ordinal: 0,
        nullifier: kagemusha_wallet_unload_nullifier_v1(
            &w.scheme_id(),
            &w.payer().body.wallet_id,
            0,
        ),
        amount: 700,
        online_charge: 7,
    };
    let usage = KagemushaWalletQuotaUsageLeafV1 {
        window_kind: KagemushaWalletQuotaWindowKindV1::Daily,
        window_start_ms: QUOTA_START_MS,
        window_end_ms: QUOTA_START_MS + DAY_MS,
        used: payment.request.body.amount + payment.request.body.fee,
    };
    let map_values = json_object(vec![
        (
            "consumed_credit",
            json_leaf(
                KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1,
                &consumed.key(),
                &consumed.field_items().expect("items"),
                &consumed.leaf_value().expect("value"),
            ),
        ),
        (
            "pending_outgoing",
            json_leaf(
                KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
                &pending.key(),
                &pending.field_items().expect("items"),
                &pending.leaf_value().expect("value"),
            ),
        ),
        (
            "load",
            json_leaf(
                KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
                &load.key(),
                &load.field_items().expect("load items"),
                &load.leaf_value().expect("load value"),
            ),
        ),
        (
            "redeem",
            json_leaf(
                KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1,
                &redeem.key(),
                &redeem.field_items().expect("redeem items"),
                &redeem.leaf_value().expect("redeem value"),
            ),
        ),
        (
            "fee_claim",
            json_leaf(
                KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
                &fee.key(),
                &fee.field_items().expect("items"),
                &fee.leaf_value().expect("value"),
            ),
        ),
    ]);

    let credit_leaf = status.opening.leaf();
    let credit_indexed = credit_leaf
        .indexed_leaf(status.opening.next_key)
        .expect("credit leaf");
    let credit_opening = status.opening.indexed_opening().expect("credit opening");
    let credit_digest_opening = json_object(vec![
        (
            "value",
            json_leaf(
                KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
                &credit_leaf.key(),
                &credit_leaf.field_items().expect("items"),
                &credit_leaf.leaf_value().expect("value"),
            ),
        ),
        (
            "membership",
            json_leaf_opening(
                &credit_indexed,
                &credit_opening,
                &status.lineage.public.credit_digest_root,
            ),
        ),
        ("credit_opening_hex", json_hex(&opening_transcript)),
    ]);

    json_object(vec![
        ("kats", Value::Array(kats)),
        ("packing", Value::Array(packing)),
        (
            "credit_id",
            json_object(vec![
                ("request_body_hex", json_hex(&request.body.transcript())),
                (
                    "poseidon",
                    json_poseidon(
                        KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1,
                        &request.body.field_items(),
                        &digests.credit_id,
                    ),
                ),
            ]),
        ),
        (
            "certificate_set",
            json_poseidon(
                KAGEMUSHA_WALLET_CERTIFICATE_SET_DOMAIN_V1,
                &request.certificates.field_items(),
                &request.body.certificates,
            ),
        ),
        (
            "package",
            json_poseidon(
                KAGEMUSHA_WALLET_PACKAGE_DOMAIN_V1,
                &[
                    digests.package.statement,
                    digests.package.proof,
                    digests.package.receipt,
                ],
                &digests.package.package,
            ),
        ),
        (
            "operation_id",
            json_poseidon(
                KAGEMUSHA_WALLET_OPERATION_ID_DOMAIN_V1,
                &kagemusha_wallet_operation_id_items_v1(
                    &w.receiver().body.wallet_id,
                    KagemushaWalletOperationKindV1::Receive,
                    &digests.credit_id,
                )
                .expect("Receive operation items"),
                &w.capsule.operation_id,
            ),
        ),
        (
            "unload_nullifier",
            json_poseidon(
                KAGEMUSHA_WALLET_NULLIFIER_DOMAIN_V1,
                &kagemusha_wallet_unload_nullifier_items_v1(
                    &w.scheme_id(),
                    &w.payer().body.wallet_id,
                    2,
                ),
                &kagemusha_wallet_unload_nullifier_v1(&w.scheme_id(), &w.payer().body.wallet_id, 2),
            ),
        ),
        ("large_input_digests", Value::Array(large_inputs)),
        ("signing_messages", Value::Array(signing_messages)),
        ("map_values", map_values),
        ("indexed_tree", indexed_tree_json(&load, &redeem, &pending)),
        ("credit_digest_opening", credit_digest_opening),
        ("blacklist", blacklist_json(w)),
        ("quota_windows", quota_windows_json(w)),
        ("quota_usage_array", quota_usage_array_json(w, &usage)),
        (
            "verifying_key_set",
            json_object(vec![
                (
                    "transcript_hex",
                    json_hex(&w.allowlist.transcript().expect("allowlist transcript")),
                ),
                (
                    "digest_hex",
                    json_hex(
                        &w.allowlist
                            .verifying_key_set_digest()
                            .expect("allowlist digest"),
                    ),
                ),
                (
                    "manifest_verifying_key_set_digest_hex",
                    json_hex(&w.manifest.body.verifying_key_set_digest),
                ),
            ]),
        ),
    ])
}

/// One `P_bytes` digest: its domain, byte body, packed element count and value.
fn packed_digest(name: &str, domain: u64, body: &[u8], digest: &[u8; 32]) -> Value {
    assert_eq!(
        kagemusha_wallet_poseidon_bytes_v1(domain, body),
        *digest,
        "{name}"
    );
    json_object(vec![
        ("object", json_text(name)),
        (
            "domain",
            json_text(core::str::from_utf8(&domain.to_le_bytes()).expect("ascii")),
        ),
        ("body_hex", json_hex(body)),
        (
            "elements",
            json_number(kagemusha_wallet_packed_bytes_v1(body).len()),
        ),
        ("digest_hex", json_hex(digest)),
    ])
}

/// One step of an insertion: the key and value, the witness and every root.
fn json_insertion(
    tree: &mut KagemushaWalletIndexedTreeV1,
    key: [u8; 32],
    value: [u8; 32],
) -> Value {
    let before = tree.root();
    let slot = tree.next_free_slot();
    let witness = tree.insert(key, value).expect("insert");
    let root = tree.root();
    assert_eq!(witness.verify(&before, &key, &value).ok(), Some(root));
    assert_eq!(u64::from(witness.slot_opening.slot), slot);
    let linked = KagemushaWalletIndexedLeafV1 {
        next_key: key,
        ..witness.low
    };
    let intermediate = witness
        .low_opening
        .leaf_root(&linked)
        .expect("intermediate root");
    assert_eq!(witness.slot_opening.empty_root().ok(), Some(intermediate));
    json_object(vec![
        ("key_hex", json_hex(&key)),
        ("value_hex", json_hex(&value)),
        ("slot", json_number(usize::try_from(slot).expect("slot"))),
        ("old_root_hex", json_hex(&before)),
        (
            "low",
            json_leaf_opening(&witness.low, &witness.low_opening, &before),
        ),
        ("linked_low", json_indexed_leaf(&linked)),
        ("intermediate_root_hex", json_hex(&intermediate)),
        (
            "empty_slot_opening",
            json_object(vec![
                ("opening", json_indexed_opening(&witness.slot_opening)),
                (
                    "transcript_hex",
                    json_hex(&witness.slot_opening.empty_transcript()),
                ),
            ]),
        ),
        (
            "leaf",
            json_indexed_leaf(&tree.leaf_at(witness.slot_opening.slot).expect("leaf")),
        ),
        ("root_hex", json_hex(&root)),
    ])
}

/// The depth-32 indexed map tree (owner answer A2): the empty tree, successive insertions into
/// the load/redeem recovery map with every intermediate root, membership and non-membership
/// openings (through the sentinel, an interior low leaf and the largest key) and a
/// pending-outgoing removal. Quota usage is the separate fixed-slot tree.
fn indexed_tree_json(
    load: &KagemushaWalletLoadLeafV1,
    redeem: &KagemushaWalletRedeemLeafV1,
    pending: &KagemushaWalletPendingOutgoingLeafV1,
) -> Value {
    let int = kagemusha_wallet_field_from_u128_v1;
    let sentinel = KagemushaWalletIndexedLeafV1::SENTINEL;
    let empty_root = kagemusha_wallet_empty_map_root_v1();
    // This unsigned map KAT uses a canonical component stand-in, not a finalized receipt.
    let next_load = KagemushaWalletLoadLeafV1 {
        ordinal: 1,
        receipt_digest: field_value(0x9c),
        amount: 2_500,
    };
    let mut recovery = KagemushaWalletIndexedTreeV1::new();
    assert_eq!(recovery.root(), empty_root);
    let insertions = vec![
        json_insertion(
            &mut recovery,
            redeem.key(),
            redeem.leaf_value().expect("redeem value"),
        ),
        json_insertion(
            &mut recovery,
            load.key(),
            load.leaf_value().expect("load value"),
        ),
        json_insertion(
            &mut recovery,
            next_load.key(),
            next_load.leaf_value().expect("next_load value"),
        ),
    ];
    let root = recovery.root();
    let (member, member_opening) = recovery.membership(&load.key()).expect("membership");
    let absent_low = int(5);
    let absent_interior = kagemusha_wallet_pair_key_v1(1, 7);
    let absent_high = kagemusha_wallet_pair_key_v1(3, 0);
    let non_membership = |absent: &[u8; 32], low_key: &[u8; 32]| {
        let (low, opening) = recovery.non_membership(absent).expect("absent");
        assert_eq!(low.key, *low_key);
        kagemusha_wallet_indexed_verify_non_membership_v1(&root, absent, &low, &opening)
            .expect("non-membership");
        json_object(vec![
            ("absent_key_hex", json_hex(absent)),
            ("low", json_leaf_opening(&low, &opening, &root)),
        ])
    };

    // Pending outgoing: a stand-in credit and the Payment's, then ArchiveSent's removal.
    // The other unsigned map entry uses a canonical component Request-digest stand-in.
    let other_pending = KagemushaWalletPendingOutgoingLeafV1 {
        credit_id: field_value(0x05),
        receiver_wallet_id: [0x5d; 32],
        send_ordinal: 3,
        amount: 250,
        fee: 0,
        request_digest: field_value(0x5f),
    };
    let mut outgoing = KagemushaWalletIndexedTreeV1::new();
    json_insertion(
        &mut outgoing,
        other_pending.key(),
        other_pending.leaf_value().expect("value"),
    );
    json_insertion(
        &mut outgoing,
        pending.key(),
        pending.leaf_value().expect("value"),
    );
    let before_remove = outgoing.root();
    let removal = outgoing.remove(&pending.key()).expect("remove");
    let relinked = KagemushaWalletIndexedLeafV1 {
        next_key: removal.leaf.next_key,
        ..removal.predecessor
    };
    let intermediate = removal
        .predecessor_opening
        .leaf_root(&relinked)
        .expect("intermediate root");
    assert_eq!(
        removal.verify(&before_remove, &pending.key()).ok(),
        Some(outgoing.root())
    );

    json_object(vec![
        ("empty_slot_hex", json_hex(&[0; 32])),
        (
            "sentinel_leaf",
            json_poseidon(
                KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1,
                &[sentinel.key, sentinel.value, sentinel.next_key],
                &sentinel.hash().expect("sentinel"),
            ),
        ),
        (
            "empty_subtree_height_1",
            json_poseidon(
                KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1,
                &[[0; 32], [0; 32]],
                &kagemusha_wallet_indexed_empty_subtree_v1(1).expect("height 1"),
            ),
        ),
        ("empty_root_hex", json_hex(&empty_root)),
        ("load_redeem_insertions", Value::Array(insertions)),
        (
            "membership",
            json_leaf_opening(&member, &member_opening, &root),
        ),
        (
            "non_membership_through_sentinel",
            non_membership(&absent_low, &[0; 32]),
        ),
        (
            "non_membership_through_interior_low_leaf",
            non_membership(&absent_interior, &next_load.key()),
        ),
        (
            "non_membership_above_the_largest_key",
            non_membership(&absent_high, &redeem.key()),
        ),
        (
            "pending_outgoing_removal",
            json_object(vec![
                ("removed_key_hex", json_hex(&pending.key())),
                ("old_root_hex", json_hex(&before_remove)),
                (
                    "predecessor",
                    json_leaf_opening(
                        &removal.predecessor,
                        &removal.predecessor_opening,
                        &before_remove,
                    ),
                ),
                ("relinked_predecessor", json_indexed_leaf(&relinked)),
                ("intermediate_root_hex", json_hex(&intermediate)),
                (
                    "removed",
                    json_leaf_opening(&removal.leaf, &removal.leaf_opening, &intermediate),
                ),
                ("root_hex", json_hex(&outgoing.root())),
                (
                    "next_free_slot",
                    json_number(usize::try_from(outgoing.next_free_slot()).expect("slot")),
                ),
            ]),
        ),
    ])
}

/// The limb-ordered blacklist tree (§7, owner answer A4): entries whose unsigned byte order
/// differs from their limb order, the first gap leaf, a node, the root and a gap opening.
fn blacklist_json(w: &VectorWorld) -> Value {
    let entries = &w.blacklist.entries;
    let blacklist_leaf_items = |lower: &[u8; 32], upper: &[u8; 32]| {
        let limbs = |value: &[u8; 32]| {
            let mut low = [0_u8; 32];
            let mut high = [0_u8; 32];
            low[..16].copy_from_slice(&value[..16]);
            high[..16].copy_from_slice(&value[16..]);
            [low, high]
        };
        [limbs(lower), limbs(upper)].concat()
    };
    let leaf_0 = kagemusha_wallet_blacklist_leaf_v1(
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1,
        &entries[0].account_digest,
    );
    let leaf_1 =
        kagemusha_wallet_blacklist_leaf_v1(&entries[0].account_digest, &entries[1].account_digest);
    let outsider = kagemusha_wallet_digest_v1(Role::Account, b"unlisted");
    let gap = w.blacklist.gap_opening(&outsider).expect("gap opening");
    gap.verify(&w.blacklist.body.entries_root, &outsider)
        .expect("gap opening verifies");
    let mut byte_ordered: Vec<[u8; 32]> =
        entries.iter().map(|entry| entry.account_digest).collect();
    byte_ordered.sort_unstable();
    json_object(vec![
        (
            "order",
            json_text(
                "limb order: int(a) = hi * 2^128 + lo, the 32 bytes read as one little-endian \
                 integer",
            ),
        ),
        (
            "entries",
            json_items(
                &entries
                    .iter()
                    .map(|entry| entry.account_digest)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("entries_in_unsigned_byte_order", json_items(&byte_ordered)),
        (
            "leaf_0",
            json_poseidon(
                KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1,
                &blacklist_leaf_items(
                    &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1,
                    &entries[0].account_digest,
                ),
                &leaf_0,
            ),
        ),
        (
            "node_0_1",
            json_poseidon(
                KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1,
                &[leaf_0, leaf_1],
                &kagemusha_wallet_blacklist_node_v1(&leaf_0, &leaf_1).expect("node"),
            ),
        ),
        ("entries_root_hex", json_hex(&w.blacklist.body.entries_root)),
        (
            "gap_opening",
            json_object(vec![
                ("account_digest_hex", json_hex(&outsider)),
                (
                    "leaf_index",
                    json_number(usize::try_from(gap.leaf_index).expect("index")),
                ),
                ("lower_hex", json_hex(&gap.lower)),
                ("upper_hex", json_hex(&gap.upper)),
                ("siblings", json_items(&gap.siblings)),
                ("root_hex", json_hex(&gap.root().expect("gap root"))),
            ]),
        ),
    ])
}

/// The quota-window tree (§7).
fn quota_windows_json(w: &VectorWorld) -> Value {
    let windows = &w.quota_share.windows;
    json_object(vec![
        (
            "window_0",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1,
                &windows[0].field_items(),
                &windows[0].leaf_value(),
            ),
        ),
        (
            "empty_window_hex",
            json_hex(&kagemusha_wallet_quota_empty_window_leaf_v1()),
        ),
        (
            "node_0_1",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1,
                &[windows[0].leaf_value(), windows[1].leaf_value()],
                &kagemusha_wallet_quota_node_v1(&windows[0].leaf_value(), &windows[1].leaf_value())
                    .expect("node"),
            ),
        ),
        (
            "windows_root_hex",
            json_hex(&w.quota_share.body.windows_root),
        ),
    ])
}

/// Component quota-array input aligned to the original signed two-window share.
///
/// The Daily slot carries the vectored gross usage; the Monthly slot is uncharged. This is
/// a slot-update KAT, not a complete Send or a recursive monetary proof.
fn quota_usage_charge_vector(
    w: &VectorWorld,
    usage: &KagemushaWalletQuotaUsageLeafV1,
) -> (
    KagemushaWalletQuotaUsageArrayV1,
    KagemushaWalletQuotaChargeV1,
) {
    let window = w.quota_share.windows[0];
    assert!(usage.matches_window(&window));
    let mut array =
        KagemushaWalletQuotaUsageArrayV1::zero_for(&w.quota_share.windows).expect("aligned array");
    array
        .charge(0, usage.used, window.limit)
        .expect("initial Daily usage");
    array
        .validate_aligned(&w.quota_share.windows)
        .expect("alignment");
    let charge = KagemushaWalletQuotaChargeV1 {
        window,
        window_opening: kagemusha_wallet_quota_window_opening_v1(&w.quota_share.windows, 0)
            .expect("window opening"),
        usage: array.leaf(0).expect("Daily usage"),
        usage_opening: array.opening(0).expect("usage opening"),
    };
    (array, charge)
}

/// Exact slot and six siblings of a current quota opening.
fn json_quota_opening(opening: &KagemushaWalletQuotaOpeningV1) -> Value {
    json_object(vec![
        ("slot", json_number(usize::from(opening.slot))),
        ("siblings", json_items(&opening.siblings)),
    ])
}

/// The fixed64/depth6 quota array and an authenticated in-place Daily charge.
fn quota_usage_array_json(w: &VectorWorld, usage: &KagemushaWalletQuotaUsageLeafV1) -> Value {
    let (array, charge) = quota_usage_charge_vector(w, usage);
    let before = array.root();
    let gross = 500;
    let mut charged = array;
    charged
        .charge(0, gross, charge.window.limit)
        .expect("charge");
    let new_leaf = charged.leaf(0).expect("charged Daily usage");
    let after = charged.root();
    assert_eq!(
        charge
            .verify(&w.quota_share.body.windows_root, &before, gross)
            .ok(),
        Some(after)
    );
    assert_eq!(charged.leaf(1), array.leaf(1));
    let padding = kagemusha_wallet_quota_usage_padding_leaf_v1();
    let last = u8::try_from(KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1 - 1).expect("last slot");
    let padding_opening = array.opening(last).expect("padding opening");
    assert_eq!(padding_opening.usage_root(&padding).ok(), Some(before));
    let empty = KagemushaWalletQuotaUsageArrayV1::empty();
    assert_eq!(empty.root(), kagemusha_wallet_quota_usage_empty_root_v1());
    let leaf_values = array
        .slots()
        .iter()
        .map(|leaf| {
            json_hex(
                &leaf
                    .as_ref()
                    .map_or(padding, KagemushaWalletQuotaUsageLeafV1::leaf_value),
            )
        })
        .collect();
    json_object(vec![
        ("slots", json_number(KAGEMUSHA_WALLET_QUOTA_USAGE_SLOTS_V1)),
        ("depth", json_number(KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1)),
        ("leaf_values", Value::Array(leaf_values)),
        (
            "padding_leaf",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1,
                &[[0; 32]; 4],
                &padding,
            ),
        ),
        (
            "padding_node_height_1",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1,
                &[padding, padding],
                &kagemusha_wallet_quota_usage_node_v1(&padding, &padding).expect("padding node"),
            ),
        ),
        ("empty_root_hex", json_hex(&empty.root())),
        ("old_root_hex", json_hex(&before)),
        ("padding_opening", json_quota_opening(&padding_opening)),
        (
            "windows_root_hex",
            json_hex(&w.quota_share.body.windows_root),
        ),
        (
            "window",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1,
                &charge.window.field_items(),
                &charge.window.leaf_value(),
            ),
        ),
        ("window_opening", json_quota_opening(&charge.window_opening)),
        (
            "usage",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1,
                &charge.usage.field_items(),
                &charge.usage.leaf_value(),
            ),
        ),
        ("usage_opening", json_quota_opening(&charge.usage_opening)),
        ("gross", json_text(&gross.to_string())),
        (
            "charged_usage",
            json_poseidon(
                KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1,
                &new_leaf.field_items(),
                &new_leaf.leaf_value(),
            ),
        ),
        ("root_hex", json_hex(&after)),
    ])
}

/// Complete text of the vectors file.
fn vectors_file_text(w: &VectorWorld) -> String {
    let digests = digest_vectors(w);
    let document = json_object(vec![
        ("fixture_version", json_number(1)),
        (
            "domain_prefix",
            json_text(
                core::str::from_utf8(KAGEMUSHA_WALLET_DIGEST_PREFIX_V1).expect("ascii prefix"),
            ),
        ),
        (
            "domain_prefix_hex",
            json_hex(KAGEMUSHA_WALLET_DIGEST_PREFIX_V1),
        ),
        (
            "digest_rule",
            json_text("H(role, body) = SHA-256(prefix || role || 0x00 || LE64(len(body)) || body)"),
        ),
        (
            "signature_rule",
            json_text(
                "ECDSA-P256-SHA256 over the 32-byte message_hex = P_bytes(domain, \
                 transcript_hex); RFC 6979 from the fixed scalars, frozen to low S; a consumer \
                 accepts iff codec_ok and verify_ok",
            ),
        ),
        ("stand_ins", stand_ins_json()),
        ("bounds", bounds_json()),
        ("norito_header", header_json(w)),
        ("keys", keys_json(w)),
        ("digests", digest_vectors_json(&digests)),
        ("object_digests", object_digest_vectors_json(w)),
        (
            "ordinary_load_receipt",
            json_object(vec![
                (
                    "transcript_hex",
                    json_hex(&w.load_receipt.transcript().unwrap()),
                ),
                ("domain_ascii", json_text("kgwolod1")),
                (
                    "digest_hex",
                    json_hex(&w.load_receipt.receipt_digest().unwrap()),
                ),
                (
                    "packed_items",
                    json_items(&kagemusha_wallet_packed_bytes_v1(
                        &w.load_receipt.transcript().unwrap(),
                    )),
                ),
            ]),
        ),
        ("signatures", signature_vectors_json(&signature_vectors(w))),
        ("signature_boundaries", boundary_json()),
        ("envelopes", envelope_vectors_json(w)),
        ("frames", frame_pins_json()),
        ("objects", object_pins_json(w)),
        ("enum_tags", enum_tags_json(&enum_tag_table(w))),
        ("field_encodings", field_encodings_json(w)),
        ("poseidon", poseidon_json(w)),
    ]);
    let mut text = norito::json::to_string_pretty(&document).expect("vectors json");
    text.push('\n');
    text
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_PATH)
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[test]
fn kagemusha_wallet_v1_vectors_file_matches_the_generated_vectors() {
    let text = vectors_file_text(vector_world());
    let path = vectors_path();
    if std::env::var_os(UPDATE_VARIABLE).is_some_and(|value| value == "1") {
        std::fs::create_dir_all(path.parent().expect("fixture directory"))
            .expect("create fixture directory");
        std::fs::write(&path, &text).expect("write vectors");
        return;
    }
    let Ok(existing) = std::fs::read_to_string(&path) else {
        panic!(
            "missing {}; regenerate it with `{UPDATE_VARIABLE}=1 cargo test -p iroha_data_model \
             --lib kagemusha_wallet_v1_vectors`",
            path.display()
        );
    };
    if existing != text {
        let line = existing
            .lines()
            .zip(text.lines())
            .position(|(old, new)| old != new)
            .unwrap_or_else(|| existing.lines().count().min(text.lines().count()));
        panic!(
            "{} differs from the generated vectors at line {}; regenerate it with \
             `{UPDATE_VARIABLE}=1 cargo test -p iroha_data_model \
             --lib kagemusha_wallet_v1_vectors`",
            path.display(),
            line + 1
        );
    }
}

#[test]
fn kagemusha_wallet_v1_vectors_are_deterministic_and_parse() {
    let world = vector_world();
    let text = vectors_file_text(world);
    assert_eq!(text, vectors_file_text(world));
    let parsed = norito::json::parse_value(&text).expect("valid json");
    let Value::Object(document) = parsed else {
        panic!("object");
    };
    for key in [
        "digests",
        "object_digests",
        "signatures",
        "signature_boundaries",
        "envelopes",
        "frames",
        "objects",
        "enum_tags",
        "keys",
        "field_encodings",
        "poseidon",
    ] {
        assert!(document.contains_key(key), "{key}");
    }
    let Some(Value::Array(envelopes)) = document.get("envelopes") else {
        panic!("envelopes");
    };
    assert_eq!(envelopes.len(), envelope_messages(world).len());
}

#[test]
fn kagemusha_wallet_v1_vectors_cover_every_role_once_in_order() {
    let vectors = digest_vectors(vector_world());
    let roles: Vec<Role> = vectors.iter().map(|vector| vector.role).collect();
    assert_eq!(roles, Role::ALL.to_vec());
    let json = digest_vectors_json(&vectors);
    let Value::Array(rows) = json else {
        panic!("array");
    };
    assert_eq!(rows.len(), Role::ALL.len());
    // Only the vectors whose bytes carry stand-in proof bytes are labelled.
    let labelled: Vec<&str> = vectors
        .iter()
        .filter(|vector| vector.stand_in_proof)
        .map(|vector| vector.role.as_str())
        .collect();
    assert_eq!(
        labelled,
        ["verifying-key-set", "capsule", "completion", "fold"]
    );
}

#[test]
fn kagemusha_wallet_v1_vectors_bind_every_object_digest_domain_and_limb() {
    let w = vector_world();
    let vectors = object_digest_vectors(w);
    assert_eq!(
        vectors
            .iter()
            .map(|vector| vector.domain)
            .collect::<Vec<_>>(),
        ObjectDomain::ALL.to_vec()
    );
    let Value::Array(rows) = object_digest_vectors_json(w) else {
        panic!("object digests");
    };
    assert_eq!(rows.len(), ObjectDomain::ALL.len());
    for vector in &vectors {
        let items = kagemusha_wallet_signed_object_items_v1(&vector.message, &vector.signature);
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], vector.message);
        let raw = vector.signature.as_raw_bytes();
        // The transport's big-endian scalar halves become numeric low,high field limbs.
        for (item, offset) in items[1..].iter().zip([16, 0, 48, 32]) {
            let half =
                u128::from_be_bytes(raw[offset..offset + 16].try_into().expect("scalar half"));
            assert_eq!(*item, kagemusha_wallet_field_from_u128_v1(half));
        }
        assert!(items.iter().all(kagemusha_wallet_is_canonical_field_v1));
        assert_eq!(
            kagemusha_wallet_poseidon_v1(vector.domain.domain(), &items).ok(),
            Some(vector.digest)
        );
        for position in 0..items.len() {
            let mut changed = items.clone();
            changed[position][0] ^= 1;
            assert_ne!(
                kagemusha_wallet_poseidon_v1(vector.domain.domain(), &changed).unwrap(),
                vector.digest
            );
        }
        let domains = ObjectDomain::ALL.map(|domain| {
            kagemusha_wallet_poseidon_v1(domain.domain(), &items).expect("object domain")
        });
        assert_eq!(
            domains
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            ObjectDomain::ALL.len()
        );
    }
    let domains = all_domains();
    assert_eq!(
        domains.len(),
        KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1.len() + Domain::ALL.len() + ObjectDomain::ALL.len()
    );
    assert_eq!(
        domains
            .iter()
            .map(|(_, domain)| domain)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        domains.len()
    );
    assert!(matches!(poseidon_json(w), Value::Object(_)));
}

#[test]
fn kagemusha_wallet_v1_quota_usage_vectors_open_and_charge_fixed_slots() {
    let w = vector_world();
    let leaf = KagemushaWalletQuotaUsageLeafV1::for_window(
        &w.quota_share.windows[0],
        w.request.body.amount + w.request.body.fee,
    );
    let (array, charge) = quota_usage_charge_vector(w, &leaf);
    let before = array.root();
    let windows = w.quota_share.body.windows_root;
    assert_eq!(array.slots().len(), 64);
    assert_eq!(charge.usage_opening.siblings.len(), 6);
    assert_eq!(charge.window_opening.siblings.len(), 6);
    assert_eq!(
        charge.usage_opening.usage_root(&leaf.leaf_value()).ok(),
        Some(before)
    );
    let mut successor = array;
    successor
        .charge(0, 500, charge.window.limit)
        .expect("charge");
    assert_eq!(
        charge.verify(&windows, &before, 500).ok(),
        Some(successor.root())
    );
    assert_eq!(successor.leaf(0).unwrap().used, leaf.used + 500);
    assert_eq!(successor.slots()[1..], array.slots()[1..]);
    assert_ne!(successor.root(), before);
    let mut changed = charge;
    changed.usage_opening.slot = 1;
    assert!(matches!(
        changed.verify(&windows, &before, 500),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_charge.slot"
        })
    ));
    let mut changed = charge;
    changed.window_opening.siblings[0][0] ^= 1;
    assert!(matches!(
        changed.verify(&windows, &before, 500),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_charge.window"
        })
    ));
    let mut changed = charge;
    changed.usage.window_end_ms += 1;
    assert!(matches!(
        changed.verify(&windows, &before, 500),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_charge.usage"
        })
    ));
    let mut changed = charge;
    changed.usage.used += 1;
    assert!(matches!(
        changed.verify(&windows, &before, 500),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_charge.usage_root"
        })
    ));
    let mut changed = charge;
    changed.usage_opening.siblings[0][0] ^= 1;
    assert!(matches!(
        changed.verify(&windows, &before, 500),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_charge.usage_root"
        })
    ));
    assert!(matches!(
        charge.verify(&windows, &before, charge.window.limit - leaf.used + 1),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "quota_window.limit"
        })
    ));
    assert_eq!(array.root(), before);
    assert_eq!(array.leaf(0), Some(leaf));
    assert!(matches!(quota_usage_array_json(w, &leaf), Value::Object(_)));
}

#[test]
fn kagemusha_wallet_v1_signature_vectors_and_boundaries() {
    let world = vector_world();
    let vectors = signature_vectors(world);
    assert_eq!(vectors.len(), 17);
    let Value::Array(rows) = signature_vectors_json(&vectors) else {
        panic!("array");
    };
    assert_eq!(rows.len(), vectors.len());

    let boundary = boundary_vector();
    let cases = boundary_cases(&boundary);
    let verdicts: Vec<(&str, bool, bool)> = cases
        .iter()
        .map(|(name, raw, _, _)| {
            let (codec_ok, verify_ok) = signature_verdicts(&boundary.key, &boundary.message, raw);
            (*name, codec_ok, verify_ok)
        })
        .collect();
    assert_eq!(
        verdicts,
        [
            ("s_half_order", true, true),
            ("s_half_order_plus_one_high_s_twin", false, true),
            ("r_zero", false, false),
            ("s_zero", false, false),
            ("r_order", false, false),
            ("s_order", false, false),
        ]
    );
    assert_eq!(
        hex::encode(&cases[1].1[32..]),
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"
    );
    let signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&cases[0].1).expect("s = floor(n/2)");
    kagemusha_wallet_verify_signature_v1(
        &boundary.key,
        BOUNDARY_DOMAIN,
        &boundary.message,
        &signature,
    )
    .expect("boundary signature verifies");
    assert_eq!(boundary.transcript.len(), 338);
    assert_eq!(&boundary.transcript[..BOUNDARY_BODY.len()], BOUNDARY_BODY);
    assert!(matches!(boundary_json(), Value::Object(_)));
    assert_eq!(
        high_s_twin(&signature).as_slice(),
        cases[1].1.as_slice(),
        "the twin of floor(n/2) is floor(n/2) + 1"
    );
    assert_eq!(&raw_pair(&[1; 32], &[2; 32])[31..33], &[1, 2]);
}

#[test]
fn kagemusha_wallet_v1_envelope_vectors_and_frame_pins() {
    let world = vector_world();
    let Value::Array(rows) = envelope_vectors_json(world) else {
        panic!("array");
    };
    let kinds: Vec<&str> = envelope_messages(world)
        .iter()
        .map(|(_, message, _)| message_kind_name(message))
        .collect();
    for kind in [
        "Offer",
        "Request",
        "Payment",
        "Credited",
        "SessionControl",
        "PolicyData",
        "Lineage",
    ] {
        assert!(kinds.contains(&kind), "{kind}");
    }
    assert_eq!(rows.len(), kinds.len());
    let pins = frame_pins();
    let mut names: Vec<&str> = pins.iter().map(|pin| pin.short_name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), pins.len());
    assert!(matches!(frame_pins_json(), Value::Array(rows) if rows.len() == pins.len()));
    assert_eq!(
        hex::encode(norito::core::schema_hash_for_name(&format!(
            "{FRAME_NAME_PREFIX}KagemushaWalletEnvelopeV1"
        ))),
        hex::encode(norito::schema::identity::frame_hash::<
            KagemushaWalletEnvelopeV1,
        >())
    );
}

#[test]
fn kagemusha_wallet_v1_object_pins_cover_every_frame_type() {
    let world = vector_world();
    let pins = object_pins(world);
    for frame in frame_pins() {
        if frame.short_name == "KagemushaWalletEnvelopeV1" {
            // Pinned by the envelope vectors, one per message kind and variant.
            continue;
        }
        assert!(
            pins.iter().any(|pin| pin.short_name == frame.short_name),
            "{} has no canonical pin",
            frame.short_name
        );
        for pin in pins.iter().filter(|pin| pin.short_name == frame.short_name) {
            assert_eq!(pin.frame_name, frame.frame_name);
            assert!(pin.frame.len() <= frame.max_bytes, "{}", pin.short_name);
        }
    }
    let markers: Vec<&str> = pins
        .iter()
        .filter(|pin| pin.short_name == "KagemushaWalletMarkerV1")
        .map(|pin| pin.variant)
        .collect();
    assert_eq!(
        markers,
        [
            "Enrollment",
            "Head",
            "Terminal::CustodyDeleted",
            "Terminal::Abandoned"
        ]
    );
    let mut keys: Vec<(&str, &str)> = pins
        .iter()
        .map(|pin| (pin.short_name, pin.variant))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), pins.len());
    assert!(matches!(object_pins_json(world), Value::Array(rows) if rows.len() == pins.len()));
    // Every pinned frame declares compact lengths and carries its payload checksum.
    for pin in &pins {
        let header = norito::core::Header::read(pin.frame.as_slice()).expect("header");
        assert_eq!(header.flags, norito::core::header_flags::COMPACT_LEN);
        let payload = payload_range(&pin.frame);
        assert_eq!(header.checksum, norito::crc64_fallback(&pin.frame[payload]));
    }
}

#[track_caller]
fn assert_version_error<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { field, version: 2 })
            if field == expected => {}
        other => panic!("expected unsupported `{expected}` version 2, got {other:?}"),
    }
}

#[test]
fn kagemusha_wallet_v1_every_version_field_precedes_the_scheme() {
    let w = vector_world();
    let l = ledger_objects(w);
    let foreign = [0x78; 32];

    let mut unload = l.unload_claim.clone();
    unload.package.statement.version = 2;
    unload.credential.body.scheme_id = foreign;
    assert_version_error(unload.require_versions(), "statement.version");
    assert_version_error(
        KagemushaWalletUnloadClaimV1::decode_canonical(
            &norito::encode_canonical(&unload).expect("encode"),
            &w.scheme_id(),
        ),
        "statement.version",
    );
    let mut fee = l.fee_claim.clone();
    fee.payment.send.statement.version = 2;
    fee.payment.request.body.scheme_id = foreign;
    assert_version_error(
        KagemushaWalletFeeClaimV1::decode_canonical(
            &norito::encode_canonical(&fee).expect("encode"),
            &w.scheme_id(),
        ),
        "statement.version",
    );
    let mut fold = w.fold.clone();
    fold.lineage.public.version = 2;
    fold.scheme_id = foreign;
    assert_version_error(
        KagemushaWalletFoldRecordV1::decode_canonical(
            &norito::encode_canonical(&fold).expect("encode"),
            &w.scheme_id(),
        ),
        "lineage.version",
    );
    let mut activation = l.activation.clone();
    activation.asset.version = 2;
    assert_version_error(
        KagemushaWalletActivationV1::decode_canonical(
            &norito::encode_canonical(&activation).expect("encode"),
            &foreign,
        ),
        "asset_scope.version",
    );
    let mut close = l.close_loads.clone();
    close.control.body.version = 2;
    assert_version_error(
        KagemushaWalletCloseLoadsV1::decode_canonical(
            &norito::encode_canonical(&close).expect("encode"),
            &foreign,
        ),
        "ledger_control.version",
    );
    let mut abandonment = l.abandonment;
    abandonment.control.body.version = 2;
    assert_version_error(abandonment.require_versions(), "ledger_control.version");
    let mut capsule = w.capsule.clone();
    capsule.successor_state.version = 2;
    assert_version_error(
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(
            &norito::encode_canonical(&capsule).expect("encode"),
            &foreign,
        ),
        "state.version",
    );
    let mut completion = w.completion.clone();
    completion.receipt.version = 2;
    assert_version_error(completion.require_versions(), "receipt.version");
    let mut status = w.credited_status.clone();
    if let KagemushaWalletCreditedEvidenceV1::Status { status } = &mut status.evidence {
        status.statement.version = 2;
    }
    assert_version_error(status.require_versions(), "statement.version");
    let mut request = w.request.clone();
    if let KagemushaWalletFeeScheduleSlotV1::Present { schedule } = &mut request.fee_schedule {
        schedule.body.version = 2;
    }
    request.body.scheme_id = foreign;
    assert_version_error(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&KagemushaWalletEnvelopeV1::new(
                KagemushaWalletMessageV1::Request { request },
            ))
            .expect("encode"),
            &w.scheme_id(),
        ),
        "fee_schedule.version",
    );
    let mut offer = w.offer.clone();
    offer.certificates.certificates[0].body.version = 2;
    assert_version_error(offer.require_versions(), "certificate.version");
    let mut list = w.blacklist.clone();
    list.body.version = 2;
    assert_version_error(list.require_versions(), "blacklist.version");
    let mut policy = w.policy_data(KagemushaWalletPolicyDataItemV1::SchemePolicy {
        policy: w.scheme_policy,
    });
    if let KagemushaWalletPolicyDataItemV1::SchemePolicy { policy } = &mut policy.item {
        policy.body.version = 2;
    }
    assert_version_error(policy.require_versions(), "scheme_policy.version");
    let mut quote = l.unload_claim.charge.clone();
    if let KagemushaWalletUnloadChargeV1::Quoted { quote, .. } = &mut quote {
        quote.body.version = 2;
    }
    assert_version_error(quote.require_versions(), "charge_quote.version");
    assert!(
        KagemushaWalletUnloadChargeV1::None
            .require_versions()
            .is_ok()
    );
    assert!(
        KagemushaWalletFeeScheduleSlotV1::None
            .require_versions()
            .is_ok()
    );
    // Every vectored object passes.
    for envelope in envelope_messages(w) {
        KagemushaWalletEnvelopeV1::new(envelope.1)
            .require_versions()
            .expect("envelope versions");
    }
    l.unload_claim.require_versions().expect("unload claim");
    l.fee_claim.require_versions().expect("fee claim");
    l.activation.require_versions().expect("activation");
    l.close_loads.require_versions().expect("close loads");
    l.abandonment.require_versions().expect("abandonment");
}

#[test]
fn kagemusha_wallet_v1_every_enum_norito_tag_equals_its_transcript_tag() {
    let table = enum_tag_table(vector_world());
    assert_eq!(table.len(), 22);
    for entry in &table {
        let mut previous = None;
        for (variant, tag, wire) in &entry.variants {
            assert_eq!(u32::from(*tag), *wire, "{}::{variant}", entry.name);
            assert!(
                previous.is_none_or(|previous| previous < *tag),
                "{}::{variant} out of order",
                entry.name
            );
            previous = Some(*tag);
        }
    }
    let Value::Object(map) = enum_tags_json(&table) else {
        panic!("object");
    };
    assert_eq!(map.len(), table.len());
}

#[test]
fn kagemusha_wallet_v1_vector_world_objects_validate() {
    let w = vector_world();
    let scheme = w.scheme();
    w.payment
        .verify(&scheme, w.payer(), &w.payer_issuer_set(), &w.request)
        .expect("payment");
    w.credited_receive
        .verify_for(&w.scheme(), &w.request, &w.payment)
        .expect("credited receive");
    w.credited_status
        .verify_for(&w.scheme(), &w.request, &w.payment)
        .expect("credited status");
    w.lineage.verify_for_offer(&w.offer).expect("lineage");
    w.fold.validate().expect("fold record");
    w.offer.verify(&scheme).expect("offer");
    w.close.verify(Some(w.payer())).expect("close");
    w.unsupported.verify(None).expect("unsupported");
    w.scheme_policy
        .verify(&scheme, &w.f.regulator_certificate)
        .expect("scheme policy");
    w.blacklist
        .verify(&scheme, &w.f.regulator_certificate)
        .expect("blacklist");
    w.quota_share
        .verify(&scheme, &w.f.regulator_certificate)
        .expect("quota share");
    w.time_anchor
        .verify(&scheme, &w.time_certificate)
        .expect("time anchor");
    w.charge_quote
        .verify(&scheme, &w.f.regulator_certificate)
        .expect("charge quote");
    w.load_receipt.validate().expect("receipt shape");
    w.renewal.verify(w.payer()).expect("renewal");
    w.control
        .verify(&w.payer().body.payment_key)
        .expect("ledger control");
    w.bootstrap.verify(w.payer()).expect("bootstrap");
    w.marker
        .bootstrap_effect()
        .expect("marker binds the bootstrap");
    assert_eq!(
        w.bootstrap.statement.effect,
        w.marker.bootstrap_effect().expect("effect")
    );
    w.completion
        .verify(w.receiver(), &w.capsule)
        .expect("completion");
    let pool = std::ptr::from_ref(vector_world());
    assert_eq!(pool, std::ptr::from_ref(w), "built once");
}

#[test]
fn kagemusha_wallet_v1_vector_artifacts_bind_manifest_and_exact_proof_lengths() {
    let w = vector_world();
    let key_set = w
        .allowlist
        .verifying_key_set_digest()
        .expect("key-set digest");
    assert_eq!(w.manifest.body.verifying_key_set_digest, key_set);
    let relation = kagemusha_wallet_relation_id_v1(&EQ, &EP, &NATIVE, &key_set, &INVENTORY);
    assert_eq!(w.scheme().relation_id, relation);
    assert_eq!(w.f.receiver.scheme.relation_id, relation);
    assert_eq!(w.manifest.body.relation_id, relation);
    let allowlist_frame = w.allowlist.to_canonical_bytes().expect("allowlist frame");
    assert_eq!(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
            &allowlist_frame,
            &w.manifest.body
        )
        .expect("vectored manifest binds the allowlist"),
        w.allowlist
    );
    let mut substituted = w.allowlist.clone();
    substituted.lineage_verifying_key_digest[0] ^= 1;
    assert!(matches!(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
            &substituted
                .to_canonical_bytes()
                .expect("substituted allowlist frame"),
            &w.manifest.body,
        ),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "artifact_manifest.verifying_key_set_digest"
        })
    ));

    let ledger = ledger_objects(w);
    let KagemushaWalletCreditedEvidenceV1::Receive {
        package: credited_receive,
    } = &w.credited_receive.evidence
    else {
        panic!("Receive evidence");
    };
    for (name, package) in [
        ("Payment", &w.payment.send),
        ("Receive", &w.receive),
        ("Credited::Receive", credited_receive),
        ("Bootstrap", &w.bootstrap),
        ("Unload", &ledger.unload_claim.package),
        ("Activate", &ledger.activation.bootstrap),
        ("CloseLoads", &ledger.close_loads.package),
        ("FeeClaim Payment", &ledger.fee_claim.payment.send),
    ] {
        w.allowlist
            .check_package(package, Some(&w.request.body))
            .unwrap_or_else(|error| {
                panic!("{name} proofs differ from the vectored allowlist: {error:?}");
            });
    }
    w.allowlist
        .check_lineage(&w.lineage.lineage)
        .expect("Lineage Ω length");
    w.allowlist
        .check_lineage(&w.fold.lineage)
        .expect("fold Ω length");
    let status = w.status();
    w.allowlist
        .check_lineage(&status.lineage)
        .expect("status Ω length");
    assert_ne!(
        w.lineage.lineage.proof, status.lineage.proof,
        "distinct Ω proof bodies"
    );
    let status_entry = w
        .allowlist
        .entry(
            KagemushaWalletOperationKindV1::Receive,
            if w.request.body.receiver_blacklist_version == 0 {
                0
            } else {
                KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1
            },
        )
        .expect("status Receive selector");
    let status_sigma = stand_in_proof(usize::try_from(status_entry.proof_bytes).expect("σ length"));
    assert_eq!(
        status.proof_digest,
        kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Receive,
            None,
            &status_sigma
        )
        .expect("status σ digest")
    );
    let (kind, mask) = w
        .receive
        .verifying_key_selector(Some(&w.request.body))
        .expect("Receive selector");
    assert_eq!(w.capsule.kind, kind);
    w.allowlist
        .check_step_proof(kind, mask, &w.capsule.step_proof)
        .expect("capsule σ length");
    if let Some(lineage) = w.capsule.predecessor_lineage.lineage() {
        w.allowlist
            .check_lineage(lineage)
            .expect("capsule Ω length");
    }
    let mut longer_step = w.receive.clone();
    longer_step.step_proof.bytes.push(0);
    assert!(matches!(
        w.allowlist
            .check_package(&longer_step, Some(&w.request.body)),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "step_proof.length"
        })
    ));
    let mut longer_lineage = status.lineage.clone();
    longer_lineage.proof.push(0);
    assert!(matches!(
        w.allowlist.check_lineage(&longer_lineage),
        Err(KagemushaWalletValidationErrorV1::InvalidField {
            field: "lineage.proof_length"
        })
    ));
}

// ---------------------------------------------------------------------------------------
// Every-byte flips (design C11)
// ---------------------------------------------------------------------------------------

/// Flip every byte of `value`'s canonical frame: each flip must be rejected by `accept` or
/// change the digest it returns.
fn assert_flips<T: norito::NoritoSerialize>(
    value: &T,
    digest: [u8; 32],
    accept: impl Fn(&[u8]) -> Option<[u8; 32]>,
) {
    let frame = norito::encode_canonical(value).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, digest, accept);
}

#[test]
fn kagemusha_wallet_v1_flips_credential() {
    let w = vector_world();
    let (scheme, payer) = (w.scheme(), w.payer());
    assert_flips(payer, payer.credential_digest(), |bytes| {
        let credential =
            KagemushaWalletCredentialV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        credential
            .verify(&scheme, &w.f.payer.enrollment_certificate)
            .ok()?;
        Some(credential.credential_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_certificate() {
    let w = vector_world();
    let scheme = w.scheme();
    let certificate = &w.f.payer.enrollment_certificate;
    assert_flips(certificate, certificate.certificate_digest(), |bytes| {
        KagemushaWalletSignerCertificateV1::decode_canonical(bytes, &scheme)
            .ok()
            .map(|certificate| certificate.certificate_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_offer() {
    let w = vector_world();
    let scheme = w.scheme();
    assert_flips(&w.offer, w.offer.body.signing_message(), |bytes| {
        let offer: KagemushaWalletOfferV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1).ok()?;
        offer.verify(&scheme).ok()?;
        Some(offer.body.signing_message())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_request() {
    let w = vector_world();
    let scheme = w.scheme();
    let request = &w.request;
    assert_flips(request, request.request_digest(), |bytes| {
        let request: KagemushaWalletRequestV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        request.verify(&scheme).ok()?;
        Some(request.request_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_payment() {
    let w = vector_world();
    let scheme_id = w.scheme_id();
    let digest = w.payment.payment_digest().expect("payment digest");
    assert_flips(&w.payment, digest, |bytes| {
        KagemushaWalletPaymentV1::decode_canonical(bytes, &scheme_id)
            .ok()?
            .payment_digest()
            .ok()
    });
}

#[test]
fn kagemusha_wallet_v1_flips_credited_receive() {
    let w = vector_world();
    let (digest, _) = w
        .credited_receive
        .verify_for(&w.scheme(), &w.request, &w.payment)
        .expect("credited");
    assert_flips(&w.credited_receive, digest, |bytes| {
        let credited: KagemushaWalletCreditedV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        credited
            .verify_for(&w.scheme(), &w.request, &w.payment)
            .ok()
            .map(|(digest, _)| digest)
    });
}

#[test]
fn kagemusha_wallet_v1_flips_credited_status() {
    let w = vector_world();
    let (digest, _) = w
        .credited_status
        .verify_for(&w.scheme(), &w.request, &w.payment)
        .expect("credited");
    assert_flips(&w.credited_status, digest, |bytes| {
        let credited: KagemushaWalletCreditedV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        credited
            .verify_for(&w.scheme(), &w.request, &w.payment)
            .ok()
            .map(|(digest, _)| digest)
    });
}

#[test]
fn kagemusha_wallet_v1_flips_lineage_message() {
    let w = vector_world();
    assert_flips(&w.lineage, w.lineage.lineage_digest(), |bytes| {
        let lineage: KagemushaWalletLineageMessageV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        lineage.verify_for_offer(&w.offer).ok()?;
        Some(lineage.lineage_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_fold_record() {
    let w = vector_world();
    let digest = w.fold.fold_digest().expect("fold digest");
    assert_flips(&w.fold, digest, |bytes| {
        KagemushaWalletFoldRecordV1::decode_canonical(bytes, &w.scheme_id())
            .ok()?
            .fold_digest()
            .ok()
    });
}

#[test]
fn kagemusha_wallet_v1_flips_package() {
    let w = vector_world();
    let receiver = w.receiver();
    let digest = w.receive.package_digest(receiver).expect("package");
    assert_flips(&w.receive, digest, |bytes| {
        let package: KagemushaWalletPackageV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        package.package_digest(receiver).ok()
    });
}

#[test]
fn kagemusha_wallet_v1_flips_ordinary_load_receipt() {
    let w = vector_world();
    assert_flips(
        &w.load_receipt,
        w.load_receipt.receipt_digest().unwrap(),
        |bytes| {
            KagemushaWalletLoadReceiptV1::decode_canonical(bytes)
                .ok()?
                .receipt_digest()
                .ok()
        },
    );
}

#[test]
fn kagemusha_wallet_v1_flips_scheme_policy() {
    let w = vector_world();
    let scheme = w.scheme();
    let policy = &w.scheme_policy;
    assert_flips(policy, policy.scheme_policy_digest(), |bytes| {
        let policy =
            KagemushaWalletSchemePolicyV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        policy.verify(&scheme, &w.f.regulator_certificate).ok()?;
        Some(policy.scheme_policy_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_fee_schedule() {
    let w = vector_world();
    let scheme = w.scheme();
    let schedule = &w.fee_schedule;
    assert_flips(schedule, schedule.fee_schedule_digest(), |bytes| {
        let schedule =
            KagemushaWalletFeeScheduleV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        schedule.verify(&scheme, &w.f.regulator_certificate).ok()?;
        Some(schedule.fee_schedule_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_blacklist_body_and_list() {
    let w = vector_world();
    let scheme = w.scheme();
    let list = &w.blacklist;
    assert_flips(&list.body, list.body.signing_message(), |bytes| {
        let body: KagemushaWalletBlacklistBodyV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1).ok()?;
        body.validate().ok()?;
        Some(body.signing_message())
    });
    assert_flips(list, list.blacklist_digest(), |bytes| {
        let list = KagemushaWalletBlacklistV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        list.verify(&scheme, &w.f.regulator_certificate).ok()?;
        Some(list.blacklist_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_quota_share() {
    let w = vector_world();
    let scheme = w.scheme();
    let share = &w.quota_share;
    assert_flips(share, share.quota_share_digest(), |bytes| {
        let share =
            KagemushaWalletQuotaShareV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        share.verify(&scheme, &w.f.regulator_certificate).ok()?;
        Some(share.quota_share_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_time_anchor() {
    let w = vector_world();
    let scheme = w.scheme();
    let anchor = &w.time_anchor;
    assert_flips(anchor, anchor.time_anchor_digest(), |bytes| {
        let anchor =
            KagemushaWalletTimeAnchorV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        anchor.verify(&scheme, &w.time_certificate).ok()?;
        Some(anchor.time_anchor_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_charge_quote() {
    let w = vector_world();
    let scheme = w.scheme();
    let quote = &w.charge_quote;
    assert_flips(quote, quote.charge_quote_digest(), |bytes| {
        let quote =
            KagemushaWalletChargeQuoteV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        quote.verify(&scheme, &w.f.regulator_certificate).ok()?;
        Some(quote.charge_quote_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_ledger_control() {
    let w = vector_world();
    let scheme_id = w.scheme_id();
    let key = w.payer().body.payment_key;
    assert_flips(&w.control, w.control.body.signing_message(), |bytes| {
        let control = KagemushaWalletLedgerControlV1::decode_canonical(bytes, &scheme_id).ok()?;
        control.verify(&key).ok()?;
        Some(control.body.signing_message())
    });
}

#[test]
fn kagemusha_wallet_v1_flips_artifact_manifest() {
    let w = vector_world();
    let scheme = w.scheme();
    let manifest = &w.manifest;
    assert_flips(manifest, manifest.manifest_digest(), |bytes| {
        let manifest = KagemushaWalletArtifactManifestV1::decode_canonical(bytes, &scheme).ok()?;
        manifest.verify(&scheme, &w.artifact_certificate).ok()?;
        Some(manifest.manifest_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_vector_json_helpers() {
    assert_eq!(json_hex(&[0xab, 0x01]), Value::String("ab01".to_owned()));
    assert_eq!(json_text("x"), Value::String("x".to_owned()));
    assert_eq!(json_number(7), Value::Number(Number::U64(7)));
    let Value::Object(map) = json_object(vec![("b", json_number(1)), ("a", json_number(2))]) else {
        panic!("object");
    };
    assert_eq!(map.keys().collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(bytes32(&"01".repeat(32)), [1; 32]);
    let signature = vector_world().offer.signature;
    let body = signed_object_body(&[9; 32], &signature);
    assert_eq!(&body[..32], &[9; 32]);
    assert_eq!(&body[32..], signature.as_raw_bytes());
    assert!(vectors_path().ends_with("fixtures/kagemusha/wallet_v1_vectors.json"));
}
