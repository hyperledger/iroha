//! Cross-language KAGEMUSHA wallet V1 vectors and consolidated codec checks (design §8, C11).
//!
//! One deterministic fixture world is built from fixed P-256 scalars `[seed; 32]`. Every
//! signature is the RFC 6979 output of a p256 `SigningKey`, frozen to low S through
//! [`kagemusha_wallet_freeze_signature_v1`] by the objects' own constructors. The world feeds
//! `fixtures/kagemusha/wallet_v1_vectors.json`: digest vectors for every role, signature
//! vectors with their high-S twins and the low-S boundary scalars, one envelope vector per
//! message kind, frame identities of the top-level records, one pinned canonical frame of every
//! framed object type and marker state, the enum tag table, the σ-field element encodings
//! (statement, state core and rest, chain appends, map and credit-digest leaves) and the
//! Poseidon values computed over them, the `P_bytes` packing rule, `credit_id`, `proof_digest`
//! and the Payment digest, the indexed, blacklist and quota-window trees with openings, and the
//! verifying-key allowlist digest, that the native and in-circuit encoders must share (§3.2).
//! The file is compared byte for byte; `IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS=1` rewrites it (a
//! test-only convenience). Stand-in σ and Ω bytes, relation bindings and verifying keys are
//! labelled: they change when G3 fixes the artifact set.

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
        public_key, raw_output, signing_key, test_account, test_certificate,
    },
    messages::messages_tests::{ACCEPTED_MS, MessageFixture, OPENING_SIBLINGS, message_fixture},
    state::state_tests::{
        CREDIT_DIGEST_ROOT, LINEAGE_PENDING_ROOT, bootstrap_statement, controlled_state,
        field_value, signed_package, stand_in_proof, transition_statement,
    },
    *,
};

type Role = KagemushaWalletDigestRoleV1;
type Domain = KagemushaWalletSigningDomainV1;

/// Path of the vectors file relative to this crate.
const VECTORS_PATH: &str = "../../fixtures/kagemusha/wallet_v1_vectors.json";
/// Test-only switch that rewrites the vectors file instead of comparing it.
const UPDATE_VARIABLE: &str = "IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS";
/// Common prefix of every wallet V1 frame name.
const FRAME_NAME_PREFIX: &str = "iroha_data_model::kagemusha::kagemusha_wallet_v1::";

/// Stand-in relation bindings shared with the identity fixture (design C3); the real values
/// come from the G3 artifact set.
const EQ: [u8; 32] = [0x21; 32];
const EP: [u8; 32] = [0x22; 32];
const NATIVE: [u8; 32] = [0x23; 32];
const VK_SET: [u8; 32] = [0x24; 32];
const INVENTORY: [u8; 32] = [0x25; 32];

/// Fixed scalar seeds `[seed; 32]` of the vector signers.
const ROOT_SEED: u8 = 0x11;
const RECEIVER_ISSUER_SEED: u8 = 0x22;
const PAYER_ISSUER_SEED: u8 = 0x26;
const REGULATOR_SEED: u8 = 0x33;
const LOAD_SEED: u8 = 0x34;
const TIME_SEED: u8 = 0x35;
const ARTIFACT_SEED: u8 = 0x36;
const RENEWAL_KEY_SEED: u8 = 0x37;
const PAYER_SEED: u8 = 0x51;
const RECEIVER_SEED: u8 = 0x52;
/// Ed25519 seed of the fee and charge beneficiary account.
const BENEFICIARY_SEED: u8 = 0x5b;

/// Stand-in σ length of the vectored packages.
const VECTOR_PROOF_LEN: usize = 48;
/// Stand-in Ω(h) transport proof length of the vectored `CreditStatus`.
const STATUS_LINEAGE_LEN: usize = 24;
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
/// Signed role and body of the boundary signature.
const BOUNDARY_DOMAIN: Domain = Domain::Receipt;
const BOUNDARY_BODY: &[u8] = &[0x5c; Domain::Receipt.transcript_bytes()];

// ---------------------------------------------------------------------------------------
// Fixture world
// ---------------------------------------------------------------------------------------

/// One fully valid object of every vectored kind, built from fixed P-256 scalars.
pub(super) struct VectorWorld {
    /// Payer, receiver and regulator of one scheme.
    pub(super) f: MessageFixture,
    /// `LoadAuthorization`-role signer.
    load_signer: SigningKey,
    /// `LoadAuthorization`-role certificate.
    load_certificate: KagemushaWalletSignerCertificateV1,
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
    /// Quoted load voucher of the payer.
    voucher: KagemushaWalletLoadVoucherV1,
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

/// Signed blacklist of `count` distinct stand-in account digests.
fn vector_blacklist(f: &MessageFixture, count: u32) -> KagemushaWalletBlacklistV1 {
    let mut entries: Vec<KagemushaWalletBlacklistEntryV1> = (0..count)
        .map(|index| KagemushaWalletBlacklistEntryV1 {
            account_digest: kagemusha_wallet_digest_v1(Role::Account, &index.to_le_bytes()),
        })
        .collect();
    entries.sort();
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

/// Stand-in verifying-key allowlist: every operation with the vectored σ length, Send also with
/// every control enabled, and the vectored Ω transport length; the verifying-key digests are
/// labelled stand-ins.
fn vector_allowlist() -> KagemushaWalletVerifyingKeyAllowlistV1 {
    let sigma = u32::try_from(VECTOR_PROOF_LEN).expect("σ length");
    let mut steps = Vec::new();
    for kind in KagemushaWalletOperationKindV1::ALL {
        let masks: &[u32] = if kind == KagemushaWalletOperationKindV1::Send {
            &[0, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1]
        } else {
            &[0]
        };
        for (index, mask) in masks.iter().enumerate() {
            steps.push(KagemushaWalletVerifyingKeyEntryV1 {
                kind,
                enabled_controls: *mask,
                verifying_key_digest: [0x80
                    | (kind.tag() << 3)
                    | u8::try_from(*mask).expect("mask"); 32],
                proof_bytes: sigma + u32::try_from(index).expect("index"),
            });
        }
    }
    let allowlist = KagemushaWalletVerifyingKeyAllowlistV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        steps,
        lineage_verifying_key_digest: [0xc4; 32],
        lineage_proof_bytes: u32::try_from(super::messages::messages_tests::PAYMENT_LINEAGE_LEN)
            .expect("Ω length"),
    };
    allowlist.validate().expect("vector allowlist");
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
        kagemusha_wallet_relation_id_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY),
        scheme.relation_id
    );

    let root = &f.payer.root;
    let load_signer = signing_key(LOAD_SEED);
    let load_certificate = test_certificate(
        &scheme,
        root,
        KagemushaWalletSignerRoleV1::LoadAuthorization,
        &load_signer,
        3,
    );
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
    let voucher_body = KagemushaWalletLoadVoucherBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id,
        asset_digest,
        wallet_id: payer.body.wallet_id,
        ordinal: 0,
        amount: 5_000,
        online_charge: 25,
        charge_quote: charge_quote.charge_quote_digest(),
        transaction_hash: [0x9a; 32],
        block_height: 42,
        authorizer_certificate: load_certificate.certificate_digest(),
    };
    let voucher = KagemushaWalletLoadVoucherV1::sign(
        voucher_body,
        &load_certificate,
        raw_output(&load_signer, &voucher_body.signing_message()),
    )
    .expect("voucher");
    voucher
        .require_charge_quote(Some(&charge_quote))
        .expect("quoted voucher");

    let manifest_body = KagemushaWalletArtifactManifestBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: scheme.network_id,
        relation_id: scheme.relation_id,
        eq_protocol_digest: EQ,
        ep_protocol_digest: EP,
        native_profile_digest: NATIVE,
        verifying_key_set_digest: VK_SET,
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
    let binding = kagemusha_wallet_renewal_key_binding_transcript_v1(
        &scheme_id,
        &payer.body.wallet_id,
        &RENEWAL_CHALLENGE,
        &renewal_key,
    );
    let evidence = KagemushaWalletRenewalEvidenceV1::android_signed(
        &payer,
        &RENEWAL_CHALLENGE,
        renewal_key,
        raw_output(
            &f.payer.payment,
            &kagemusha_wallet_signing_message_v1(Domain::RenewalKeyBinding, &binding),
        ),
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
    let possession = kagemusha_wallet_renewal_challenge_transcript_v1(
        &scheme_id,
        &payer.body.wallet_id,
        &payer.credential_digest(),
        &RENEWAL_CHALLENGE,
    );
    let renewal = KagemushaWalletRenewalRequestV1::sign(
        &payer,
        RENEWAL_CHALLENGE,
        raw_output(
            &f.payer.payment,
            &kagemusha_wallet_signing_message_v1(Domain::RenewalChallenge, &possession),
        ),
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
    let statement = KagemushaWalletStatementV1 {
        successor: state.commitment().expect("successor commitment"),
        ..transition_statement(
            &f.receiver,
            5,
            0,
            KagemushaWalletLifecycleV1::Active,
            payment
                .receive_effect(&request, &receiver)
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
        operation_id: statement.operation_id(&receiver.body.wallet_id),
        kind: KagemushaWalletOperationKindV1::Receive,
        predecessor_capsule_digest: [0x5b; 32],
        successor_state: state,
        statement,
        predecessor_lineage: KagemushaWalletLineageSlotV1::None,
        step_proof: proof.clone(),
        payment_digest,
        map_openings: vec![vec![0x6d; 32]],
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
    let credited_status = f.credited_status(&payment, STATUS_LINEAGE_LEN, OPENING_SIBLINGS);
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
    let allowlist = vector_allowlist();
    allowlist
        .check_package(&payment.send)
        .expect("the Payment's proofs have the allowlisted lengths");
    allowlist
        .check_package(&receive)
        .expect("the Receive package has the allowlisted σ length");

    VectorWorld {
        f,
        load_signer,
        load_certificate,
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
        voucher,
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

// ---------------------------------------------------------------------------------------
// Digest vectors (one per role)
// ---------------------------------------------------------------------------------------

/// The four protocol delivery digests computed with `P_bytes`.
#[derive(Clone, Copy)]
enum PackedDomain {
    Lineage,
    CreditOpening,
    CreditStatus,
    Credited,
}

impl PackedDomain {
    fn label(self) -> &'static str {
        match self {
            Self::Lineage => "kgwlin_1",
            Self::CreditOpening => "kgwcopn1",
            Self::CreditStatus => "kgwcsts1",
            Self::Credited => "kgwcrdd1",
        }
    }

    fn domain(self) -> u64 {
        match self {
            Self::Lineage => KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1,
            Self::CreditOpening => KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
            Self::CreditStatus => KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1,
            Self::Credited => KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
        }
    }
}

/// Native digest operation of one vector, with no retired SHA body-role namespace.
#[derive(Clone, Copy)]
enum DigestKind {
    Hash(Role),
    Signing(Domain),
    Packed(PackedDomain),
}

impl From<Role> for DigestKind {
    fn from(role: Role) -> Self {
        Self::Hash(role)
    }
}

impl From<Domain> for DigestKind {
    fn from(domain: Domain) -> Self {
        Self::Signing(domain)
    }
}

impl DigestKind {
    fn label(self) -> &'static str {
        match self {
            Self::Hash(role) => role.as_str(),
            Self::Signing(domain) => domain.as_str(),
            Self::Packed(domain) => domain.label(),
        }
    }

    fn algorithm(self) -> &'static str {
        match self {
            Self::Hash(_) => "H",
            Self::Signing(_) | Self::Packed(_) => "P_bytes",
        }
    }

    fn digest(self, body: &[u8]) -> [u8; 32] {
        match self {
            Self::Hash(role) => kagemusha_wallet_digest_v1(role, body),
            Self::Signing(domain) => kagemusha_wallet_signing_message_v1(domain, body),
            Self::Packed(domain) => kagemusha_wallet_poseidon_bytes_v1(domain.domain(), body),
        }
    }

    /// Exact input to the native hash. P_bytes carries its domain separately and packs body.
    fn preimage(self, body: &[u8]) -> Vec<u8> {
        match self {
            Self::Hash(role) => {
                let mut bytes = KAGEMUSHA_WALLET_DIGEST_PREFIX_V1.to_vec();
                bytes.extend_from_slice(role.as_str().as_bytes());
                bytes.push(0);
                bytes.extend_from_slice(
                    &u64::try_from(body.len())
                        .expect("body length")
                        .to_le_bytes(),
                );
                bytes.extend_from_slice(body);
                bytes
            }
            Self::Signing(_) | Self::Packed(_) => body.to_vec(),
        }
    }
}

/// One canonical native H or P_bytes vector.
struct DigestVector {
    kind: DigestKind,
    object: &'static str,
    body: Vec<u8>,
    stand_in_proof: bool,
}

/// Check the independent transcript vector against the actual owner-computed value.
fn digest_vector(
    kind: impl Into<DigestKind>,
    object: &'static str,
    body: Vec<u8>,
    stand_in_proof: bool,
    expected: Option<[u8; 32]>,
) -> DigestVector {
    let kind = kind.into();
    if let Some(expected) = expected {
        assert_eq!(kind.digest(&body), expected, "{}", kind.label());
    }
    DigestVector {
        kind,
        object,
        body,
        stand_in_proof,
    }
}

/// One vector per native H role, signing domain and transported P_bytes digest.
fn digest_vectors(w: &VectorWorld) -> Vec<DigestVector> {
    let f = &w.f;
    let scheme = w.scheme();
    let scheme_id = w.scheme_id();
    let payer = w.payer();
    let receiver = w.receiver();
    let certificate = &f.payer.enrollment_certificate;
    let payment = &w.payment;
    let request = &w.request;
    let digests = payment.digests().expect("payment digests");
    let send = &payment.send;
    let omega = send.lineage.lineage().expect("Ω(pred)");
    let omega_bytes = omega.bytes();
    let payer_signer =
        KagemushaWalletReceiptSignerV1::from_lineage(&omega.public).expect("Ω signer");
    let receipt_body = send
        .receipt
        .body(&payer_signer, &send.statement, &digests.package.proof)
        .expect("receipt body");
    let status = w.status();
    let receiver_challenge = f.receiver.challenge.challenge_digest();
    let payer_challenge = f.payer.challenge.challenge_digest();
    let receive_digests = w.receive.verify(receiver).expect("receive package");
    let (credited_digest, _) = w
        .credited_receive
        .verify_for(&scheme, request, payment)
        .expect("credited receive");
    let status_receipt = status
        .receipt
        .verify(
            &KagemushaWalletReceiptSignerV1::from_lineage(&status.lineage.public)
                .expect("Ω(h) signer"),
            &status.statement,
            &status.proof_digest,
        )
        .expect("status receipt");
    let KagemushaWalletRenewalEvidenceV1::Android {
        new_attested_key, ..
    } = w.renewal.evidence
    else {
        panic!("android renewal");
    };
    let nullifier = kagemusha_wallet_unload_nullifier_v1(&scheme_id, &payer.body.wallet_id, 2);

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
            "stand-in relation bindings of the scheme",
            kagemusha_wallet_relation_transcript_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY),
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
            Domain::Certificate,
            "payer issuer certificate body",
            certificate.body.transcript(),
            false,
            Some(certificate.body.signing_message()),
        ),
        digest_vector(
            Role::Certificate,
            "payer issuer certificate",
            signed_object_body(&certificate.body.signing_message(), &certificate.signature),
            false,
            Some(certificate.certificate_digest()),
        ),
        digest_vector(
            Role::CertificateSet,
            "Request certificate set",
            request.certificates.transcript().expect("set transcript"),
            false,
            Some(request.body.certificates),
        ),
        digest_vector(
            Domain::Credential,
            "payer credential body",
            payer.body.transcript(),
            false,
            Some(payer.body.signing_message()),
        ),
        digest_vector(
            Role::Credential,
            "payer credential",
            signed_object_body(&payer.body.signing_message(), &payer.signature),
            false,
            Some(payer.credential_digest()),
        ),
        digest_vector(
            Domain::SchemePolicy,
            "scheme policy body",
            w.scheme_policy.body.transcript(),
            false,
            Some(w.scheme_policy.body.signing_message()),
        ),
        digest_vector(
            Role::SchemePolicy,
            "scheme policy",
            signed_object_body(
                &w.scheme_policy.body.signing_message(),
                &w.scheme_policy.signature,
            ),
            false,
            Some(w.scheme_policy.scheme_policy_digest()),
        ),
        digest_vector(
            Domain::FeeSchedule,
            "fee schedule body",
            w.fee_schedule.body.transcript(),
            false,
            Some(w.fee_schedule.body.signing_message()),
        ),
        digest_vector(
            Role::FeeSchedule,
            "fee schedule",
            signed_object_body(
                &w.fee_schedule.body.signing_message(),
                &w.fee_schedule.signature,
            ),
            false,
            Some(w.fee_schedule.fee_schedule_digest()),
        ),
        digest_vector(
            Domain::Blacklist,
            "blacklist body",
            w.blacklist.body.transcript(),
            false,
            Some(w.blacklist.body.signing_message()),
        ),
        digest_vector(
            Role::Blacklist,
            "blacklist",
            signed_object_body(&w.blacklist.body.signing_message(), &w.blacklist.signature),
            false,
            Some(w.blacklist.blacklist_digest()),
        ),
        digest_vector(
            Domain::QuotaShare,
            "quota share body",
            w.quota_share.body.transcript(),
            false,
            Some(w.quota_share.body.signing_message()),
        ),
        digest_vector(
            Role::QuotaShare,
            "quota share",
            signed_object_body(
                &w.quota_share.body.signing_message(),
                &w.quota_share.signature,
            ),
            false,
            Some(w.quota_share.quota_share_digest()),
        ),
        digest_vector(
            Domain::TimeAnchor,
            "time anchor body",
            w.time_anchor.body.transcript(),
            false,
            Some(w.time_anchor.body.signing_message()),
        ),
        digest_vector(
            Role::TimeAnchor,
            "time anchor",
            signed_object_body(
                &w.time_anchor.body.signing_message(),
                &w.time_anchor.signature,
            ),
            false,
            Some(w.time_anchor.time_anchor_digest()),
        ),
        digest_vector(
            Domain::Offer,
            "Offer body",
            w.offer.body.transcript(),
            false,
            Some(w.offer.body.signing_message()),
        ),
        digest_vector(
            Domain::SessionControl,
            "Close session control",
            w.close.transcript(),
            false,
            Some(w.close.signing_message()),
        ),
        digest_vector(
            Domain::Request,
            "Request body",
            request.body.transcript(),
            false,
            Some(request.body.signing_message()),
        ),
        digest_vector(
            Role::Request,
            "Request",
            signed_object_body(&request.body.signing_message(), &request.signature),
            false,
            Some(digests.request),
        ),
        digest_vector(
            Role::Statement,
            "Send statement",
            send.statement.transcript(),
            false,
            Some(digests.package.statement),
        ),
        digest_vector(
            DigestKind::Packed(PackedDomain::Lineage),
            "stand-in Ω(pred) bytes of the Payment",
            omega_bytes.clone(),
            true,
            Some(w.lineage.lineage_digest()),
        ),
        digest_vector(
            Domain::Receipt,
            "Send receipt body",
            receipt_body.transcript(),
            false,
            Some(receipt_body.signing_message()),
        ),
        digest_vector(
            Role::Receipt,
            "Send receipt",
            signed_object_body(&receipt_body.signing_message(), &send.receipt.signature),
            false,
            Some(digests.package.receipt),
        ),
        digest_vector(
            Role::Package,
            "Send package",
            [
                &digests.package.statement[..],
                &digests.package.proof[..],
                &digests.package.receipt[..],
            ]
            .concat(),
            false,
            Some(digests.package.package),
        ),
        digest_vector(
            DigestKind::Packed(PackedDomain::CreditOpening),
            "CreditStatus credit-digest opening",
            status.opening.transcript().expect("opening transcript"),
            false,
            Some(status.opening.opening_digest().expect("opening digest")),
        ),
        digest_vector(
            DigestKind::Packed(PackedDomain::CreditStatus),
            "CreditStatus of the folded crediting head",
            [
                &1_u16.to_le_bytes()[..],
                &status.statement.statement_digest()[..],
                &status.proof_digest[..],
                &status_receipt[..],
                &status.lineage.lineage_digest()[..],
                &status.opening.opening_digest().expect("opening")[..],
            ]
            .concat(),
            false,
            Some(status.credit_status_digest().expect("credit status")),
        ),
        digest_vector(
            DigestKind::Packed(PackedDomain::Credited),
            "Credited from the Receive package",
            [
                &1_u16.to_le_bytes()[..],
                &[1][..],
                &digests.credit_id[..],
                &digests.payment[..],
                &receive_digests.package[..],
            ]
            .concat(),
            false,
            Some(credited_digest),
        ),
        digest_vector(
            Role::OperationId,
            "Receive operation identity",
            kagemusha_wallet_operation_id_transcript_v1(
                &receiver.body.wallet_id,
                KagemushaWalletOperationKindV1::Receive,
                &digests.credit_id,
            ),
            false,
            Some(w.capsule.operation_id),
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
            Role::Capsule,
            "Receive recovery capsule frame",
            w.capsule.to_canonical_bytes().expect("capsule frame"),
            true,
            Some(w.capsule.capsule_digest().expect("capsule digest")),
        ),
        digest_vector(
            Role::Marker,
            "payer enrollment marker frame",
            w.marker.to_canonical_bytes().expect("marker frame"),
            false,
            Some(w.marker.marker_digest().expect("marker digest")),
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
        digest_vector(
            Domain::Voucher,
            "load voucher body",
            w.voucher.body.transcript(),
            false,
            Some(w.voucher.body.signing_message()),
        ),
        digest_vector(
            Role::Voucher,
            "load voucher",
            signed_object_body(&w.voucher.body.signing_message(), &w.voucher.signature),
            false,
            Some(w.voucher.voucher_digest()),
        ),
        digest_vector(
            Role::UnloadNullifier,
            "payer unload nullifier at redeem ordinal 2",
            kagemusha_wallet_unload_nullifier_transcript_v1(&scheme_id, &payer.body.wallet_id, 2),
            false,
            Some(nullifier),
        ),
        digest_vector(
            Domain::LedgerControl,
            "Activate ledger control body",
            w.control.body.transcript(),
            false,
            Some(w.control.body.signing_message()),
        ),
        digest_vector(
            Domain::RenewalChallenge,
            "renewal possession transcript",
            w.renewal.possession_transcript(),
            false,
            None,
        ),
        digest_vector(
            Domain::RenewalKeyBinding,
            "Android renewal key binding",
            kagemusha_wallet_renewal_key_binding_transcript_v1(
                &scheme_id,
                &payer.body.wallet_id,
                &RENEWAL_CHALLENGE,
                &new_attested_key,
            ),
            false,
            None,
        ),
        digest_vector(
            Role::RenewalAssertion,
            "App Attest renewal assertion client data",
            w.renewal.possession_transcript(),
            false,
            Some(w.renewal.assertion_client_data_hash()),
        ),
        digest_vector(
            Domain::ArtifactManifest,
            "artifact manifest body",
            w.manifest.body.transcript(),
            false,
            Some(w.manifest.body.signing_message()),
        ),
        digest_vector(
            Role::ArtifactManifest,
            "artifact manifest",
            signed_object_body(&w.manifest.body.signing_message(), &w.manifest.signature),
            false,
            Some(w.manifest.manifest_digest()),
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
            Domain::ChargeQuote,
            "load charge quote body",
            w.charge_quote.body.transcript(),
            false,
            Some(w.charge_quote.body.signing_message()),
        ),
        digest_vector(
            Role::ChargeQuote,
            "load charge quote",
            signed_object_body(
                &w.charge_quote.body.signing_message(),
                &w.charge_quote.signature,
            ),
            false,
            Some(w.charge_quote.charge_quote_digest()),
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
    ]
}

fn digest_vectors_json(vectors: &[DigestVector]) -> Value {
    Value::Array(
        vectors
            .iter()
            .map(|vector| {
                let preimage = vector.kind.preimage(&vector.body);
                json_object(vec![
                    ("role", json_text(vector.kind.label())),
                    ("algorithm", json_text(vector.kind.algorithm())),
                    ("object", json_text(vector.object)),
                    ("body_hex", json_hex(&vector.body)),
                    ("preimage_hex", json_hex(&preimage)),
                    ("digest_hex", json_hex(&vector.kind.digest(&vector.body))),
                    ("stand_in_proof", Value::Bool(vector.stand_in_proof)),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------------------
// Signature vectors and the low-S boundary (design C11)
// ---------------------------------------------------------------------------------------

/// One frozen signature of a vectored object.
struct SignatureVector {
    object: &'static str,
    domain: Domain,
    key: KagemushaDevicePublicKeyV1,
    body: Vec<u8>,
    signature: KagemushaDeviceSignatureV1,
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
            body: certificate.body.transcript(),
            signature: certificate.signature,
        },
        SignatureVector {
            object: "payer credential",
            domain: Domain::Credential,
            key: certificate.body.key,
            body: payer.body.transcript(),
            signature: payer.signature,
        },
        SignatureVector {
            object: "Offer",
            domain: Domain::Offer,
            key: payer_key,
            body: w.offer.body.transcript(),
            signature: w.offer.signature,
        },
        SignatureVector {
            object: "Request",
            domain: Domain::Request,
            key: request.receiver_credential.body.payment_key,
            body: request.body.transcript(),
            signature: request.signature,
        },
        SignatureVector {
            object: "Send receipt",
            domain: Domain::Receipt,
            key: payer_key,
            body: receipt_body.transcript(),
            signature: send.receipt.signature,
        },
        SignatureVector {
            object: "Receive receipt binding the Payment digest",
            domain: Domain::Receipt,
            key: w.receiver().body.payment_key,
            body: receive_body.transcript(),
            signature: w.receive.receipt.signature,
        },
        SignatureVector {
            object: "Close session control",
            domain: Domain::SessionControl,
            key: payer_key,
            body: w.close.transcript(),
            signature: w.close_signature(),
        },
        SignatureVector {
            object: "scheme policy",
            domain: Domain::SchemePolicy,
            key: regulator_key,
            body: w.scheme_policy.body.transcript(),
            signature: w.scheme_policy.signature,
        },
        SignatureVector {
            object: "fee schedule",
            domain: Domain::FeeSchedule,
            key: regulator_key,
            body: w.fee_schedule.body.transcript(),
            signature: w.fee_schedule.signature,
        },
        SignatureVector {
            object: "blacklist",
            domain: Domain::Blacklist,
            key: regulator_key,
            body: w.blacklist.body.transcript(),
            signature: w.blacklist.signature,
        },
        SignatureVector {
            object: "quota share",
            domain: Domain::QuotaShare,
            key: regulator_key,
            body: w.quota_share.body.transcript(),
            signature: w.quota_share.signature,
        },
        SignatureVector {
            object: "time anchor",
            domain: Domain::TimeAnchor,
            key: w.time_certificate.body.key,
            body: w.time_anchor.body.transcript(),
            signature: w.time_anchor.signature,
        },
        SignatureVector {
            object: "load voucher",
            domain: Domain::Voucher,
            key: w.load_certificate.body.key,
            body: w.voucher.body.transcript(),
            signature: w.voucher.signature,
        },
        SignatureVector {
            object: "Activate ledger control",
            domain: Domain::LedgerControl,
            key: payer_key,
            body: w.control.body.transcript(),
            signature: w.control.signature,
        },
        SignatureVector {
            object: "renewal possession",
            domain: Domain::RenewalChallenge,
            key: payer_key,
            body: w.renewal.possession_transcript(),
            signature: w.renewal.possession_signature,
        },
        SignatureVector {
            object: "Android renewal key binding",
            domain: Domain::RenewalKeyBinding,
            key: payer_key,
            body: kagemusha_wallet_renewal_key_binding_transcript_v1(
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
            body: w.manifest.body.transcript(),
            signature: w.manifest.signature,
        },
        SignatureVector {
            object: "load charge quote",
            domain: Domain::ChargeQuote,
            key: regulator_key,
            body: w.charge_quote.body.transcript(),
            signature: w.charge_quote.signature,
        },
    ]
}

/// Verdicts of 64 raw bytes over `preimage` under `key`.
///
/// `codec_ok`: the canonical fixed-width low-S codec accepts the bytes (`1 <= r < n`,
/// `1 <= s <= floor(n/2)`). `verify_ok`: the ECDSA-P256-SHA256 equation holds with the scalars
/// taken as they are, as a generic verifier (JCA, `CryptoKit`) would check it; a high-S twin
/// satisfies it. A consumer accepts exactly when both hold.
fn signature_verdicts(
    key: &KagemushaDevicePublicKeyV1,
    preimage: &[u8],
    raw: &[u8; 64],
) -> (bool, bool) {
    let codec = KagemushaDeviceSignatureV1::from_raw_bytes(raw);
    let equation = P256Signature::from_slice(raw).is_ok_and(|signature| {
        VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())
            .expect("canonical key")
            .verify(preimage, &signature)
            .is_ok()
    });
    if let Ok(signature) = codec {
        assert_eq!(
            signature.verify(key, preimage).is_ok(),
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
                let message = kagemusha_wallet_signing_message_v1(vector.domain, &vector.body);
                let raw = vector.signature.as_raw_bytes();
                assert_eq!(
                    signature_verdicts(&vector.key, &message, raw),
                    (true, true),
                    "{}",
                    vector.object
                );
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
                    ("body_hex", json_hex(&vector.body)),
                    ("public_key_hex", json_hex(vector.key.as_sec1_bytes())),
                    ("signing_message_hex", json_hex(&message)),
                    ("e_hex", json_hex(&Sha256::digest(message))),
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
/// `e = SHA-256(signing_message) mod n`, the key `d = (s*k - e) * r^-1 mod n` makes `(r, s)` a valid
/// signature: `u1*G + u2*Q = (e + r*d)/s * G = k*G`.
struct BoundaryVector {
    k: Scalar,
    r: Scalar,
    e: Scalar,
    d: Scalar,
    key: KagemushaDevicePublicKeyV1,
    preimage: [u8; 32],
}

#[allow(
    clippy::many_single_char_names,
    reason = "the ECDSA scalars k, r, e, s and d keep their standard names"
)]
fn boundary_vector() -> BoundaryVector {
    let preimage = kagemusha_wallet_signing_message_v1(BOUNDARY_DOMAIN, BOUNDARY_BODY);
    let k = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&BOUNDARY_NONCE));
    let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&r_point.x());
    let e = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(
        Sha256::digest(&preimage).as_slice(),
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
        preimage,
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
            signature_verdicts(&boundary.key, &boundary.preimage, raw),
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
        &boundary.preimage,
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
                "r = x(k*G) mod n; s = floor(n/2); e = SHA-256(signing_message) mod n; \
                 d = (s*k - e) * r^-1 mod n; public key Q = d*G",
            ),
        ),
        ("domain", json_text(BOUNDARY_DOMAIN.as_str())),
        ("body_hex", json_hex(BOUNDARY_BODY)),
        ("signing_message_hex", json_hex(&boundary.preimage)),
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
    assert_eq!(frame_name, format!("{FRAME_NAME_PREFIX}{short_name}"));
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
        frame_pin::<KagemushaWalletLoadVoucherV1>(
            "KagemushaWalletLoadVoucherV1",
            KAGEMUSHA_WALLET_LOAD_VOUCHER_MAX_BYTES_V1,
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
    assert_eq!(frame_name, format!("{FRAME_NAME_PREFIX}{short_name}"));
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
        package: signed_package(&f.payer, payer, &unload, stand_in_proof(VECTOR_PROOF_LEN)),
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

    let retiring = signed_package(
        &f.payer,
        payer,
        &transition_statement(
            &f.payer,
            7,
            1,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Retiring,
        ),
        stand_in_proof(VECTOR_PROOF_LEN),
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

    let head_marker = w
        .marker
        .successor(KagemushaWalletMarkerStateV1::Head {
            sequence: 0,
            operation_id: w.bootstrap.statement.operation_id(&payer.body.wallet_id),
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

/// One canonical frame of every framed object type other than the envelope (pinned by the
/// envelope vectors), every marker state, and the unframed asset scope and anchored time.
fn object_pins(w: &VectorWorld) -> Vec<ObjectPin> {
    let scheme = w.scheme();
    let scheme_id = w.scheme_id();
    let receiver_wallet = w.receiver().body.wallet_id;
    let l = ledger_objects(w);
    let package_frame =
        encode_frame_v1(&w.receive, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).expect("package frame");
    let decoded_package: KagemushaWalletPackageV1 =
        decode_frame_v1(&package_frame, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
            .expect("package decode");
    decoded_package
        .verify(w.receiver())
        .expect("package verifies");
    let allowlist_frame = w.allowlist.to_canonical_bytes().expect("allowlist frame");
    let decoded_allowlist: KagemushaWalletVerifyingKeyAllowlistV1 = decode_frame_v1(
        &allowlist_frame,
        KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
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
        framed_pin!(
            KagemushaWalletLoadVoucherV1,
            "quoted",
            w.voucher,
            &scheme_id,
            false
        ),
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
        ("Load", w.voucher.load_effect().expect("load effect")),
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
            &[
                "Enrollment",
                "LoadAuthorization",
                "RegulatoryPolicy",
                "TimeAnchor",
                "Artifact",
            ],
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
                "LoadVoucher",
                "ChargeQuote",
                "PolicyUpdate",
                "CertificateSet",
                "Credential",
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
        ("load_authorizer", LOAD_SEED),
        ("time_anchor", TIME_SEED),
        ("artifact", ARTIFACT_SEED),
        ("renewal_attested_key", RENEWAL_KEY_SEED),
        ("payer_payment", PAYER_SEED),
        ("receiver_payment", RECEIVER_SEED),
    ];
    for (signer, certificate) in [
        (&w.load_signer, &w.load_certificate),
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
                 credit-digest roots and openings are computed",
            ),
        ),
        ("eq_protocol_digest_hex", json_hex(&EQ)),
        ("ep_protocol_digest_hex", json_hex(&EP)),
        ("native_profile_digest_hex", json_hex(&NATIVE)),
        ("verifying_key_set_digest_hex", json_hex(&VK_SET)),
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
                "Ω transport proof byte i = (i + 7) mod 251; CreditStatus Ω(h): (i + 11) mod 251",
            ),
        ),
        (
            "verifying_key_rule",
            json_text(
                "σ verifying-key digest: 32 bytes 0x80 | tag << 3 | mask; Ω transport key: 32 \
                 bytes 0xc4",
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
            "proof_caps",
            json_text(
                "the exact σ and Ω transport lengths of the frozen verifying-key allowlist, with \
                 Ω + the largest σ_send <= payment_proof_budget_bytes; until the artifacts freeze \
                 only the carrying frames bound them",
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
            "credit_opening_siblings_max",
            json_number(KAGEMUSHA_WALLET_CREDIT_OPENING_DEPTH_V1),
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

/// One exact indexed opening: key, linked leaf, allocated slot and 32 siblings.
fn json_opening(
    key: &[u8; 32],
    leaf: &KagemushaWalletIndexedLeafV1,
    opening: &KagemushaWalletIndexedOpeningV1,
    root: &[u8; 32],
    membership: bool,
) -> Value {
    if membership {
        assert_eq!(leaf.key, *key, "membership key");
        kagemusha_wallet_indexed_verify_membership_v1(root, leaf, opening).expect("membership");
    } else {
        kagemusha_wallet_indexed_verify_non_membership_v1(root, key, leaf, opening)
            .expect("ordered absence");
    }
    assert_eq!(opening.leaf_root(leaf).expect("opening root"), *root);
    json_object(vec![
        ("key_hex", json_hex(key)),
        ("low_or_member_key_hex", json_hex(&leaf.key)),
        ("value_hex", json_hex(&leaf.value)),
        ("next_key_hex", json_hex(&leaf.next_key)),
        ("leaf_hex", json_hex(&leaf.hash().expect("leaf"))),
        (
            "slot",
            json_number(usize::try_from(opening.slot).expect("slot")),
        ),
        ("siblings", json_items(&opening.siblings)),
        (
            "opening_transcript_hex",
            json_hex(&opening.leaf_transcript(leaf)),
        ),
        ("membership", Value::Bool(membership)),
        ("root_hex", json_hex(root)),
    ])
}

fn json_membership(tree: &KagemushaWalletIndexedTreeV1, key: &[u8; 32]) -> Value {
    let (leaf, opening) = tree.membership(key).expect("membership");
    json_opening(key, &leaf, &opening, &tree.root(), true)
}

fn json_non_membership(tree: &KagemushaWalletIndexedTreeV1, key: &[u8; 32]) -> Value {
    let (low, opening) = tree.non_membership(key).expect("absence");
    json_opening(key, &low, &opening, &tree.root(), false)
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
            (
                "time_anchor_max_response_ms",
                number(u128::from(rest.time_anchor_max_response_ms)),
            ),
            ("scheme_policy", json_hex(&rest.scheme_policy)),
            ("fee_schedule", json_hex(&rest.fee_schedule)),
            ("blacklist", json_hex(&rest.blacklist)),
            ("quota_share", json_hex(&rest.quota_share)),
            ("quota_share_id", number(u128::from(rest.quota_share_id))),
            ("time_anchor", json_hex(&rest.time_anchor)),
        ]),
    ));
    json_object(entries)
}

/// The σ-field encodings shared by native and in-circuit encoders (§3.2): the element lists of
/// the statement, state core and rest, chain appends and map leaves, with the Poseidon values
/// the data model computes over them.
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
    let domain_rows = KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1
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
                 proof_digest, Payment digest) is one element",
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
            json_object(vec![
                ("statement_hex", json_hex(&send.transcript())),
                ("items", json_items(&send_items)),
                (
                    "digest_hex",
                    json_hex(&send.field_digest().expect("send statement digest")),
                ),
            ]),
        ),
        (
            "receive_statement",
            json_object(vec![
                ("statement_hex", json_hex(&receive.transcript())),
                ("items", json_items(&receive_items)),
                (
                    "digest_hex",
                    json_hex(&receive.field_digest().expect("receive statement digest")),
                ),
            ]),
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
            "consumed_credit_leaf",
            json_items(&consumed.field_items().expect("consumed items")),
        ),
        (
            "pending_outgoing_leaf",
            json_items(&pending.field_items().expect("pending items")),
        ),
        (
            "fee_claim_leaf",
            json_items(&fee.field_items().expect("fee items")),
        ),
        (
            "credit_digest_leaf",
            json_items(&credit_digest.field_items().expect("credit-digest items")),
        ),
    ])
}

/// Poseidon vectors (owner answers Q1, Q2, Q7, Q9, Q10 and Q11): one KAT per domain, the
/// packing rule, `credit_id`, both `proof_digest` domains, the Payment digest, every map leaf
/// and its key, the indexed tree with membership and low-leaf absence openings, the credit-digest opening
/// of the vectored `CreditStatus`, the blacklist and quota-window trees, and the verifying-key
/// allowlist.
fn poseidon_json(w: &VectorWorld) -> Value {
    let int = kagemusha_wallet_field_from_u128_v1;
    let payment = &w.payment;
    let request = &w.request;
    let digests = payment.digests().expect("payment digests");
    let receive_digests = w.receive.verify(w.receiver()).expect("receive package");

    // One KAT per domain over the elements [1, 2, 3].
    let kat_items = [int(1), int(2), int(3)];
    let kats = KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1
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

    // proof_digest in both domains and the Payment digest.
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
    let packed_digest = |name: &str, domain: u64, body: &[u8], digest: &[u8; 32]| {
        assert_eq!(kagemusha_wallet_poseidon_bytes_v1(domain, body), *digest);
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
    };

    // Every map leaf and its key; the consumed-credit map of the Receive with membership and
    // absence openings.
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
        voucher_digest: w.voucher.voucher_digest(),
        amount: w.voucher.body.amount,
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
    let leaves = json_object(vec![
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
            "load_recovery",
            json_leaf(
                KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
                &load.key(),
                &load.field_items(),
                &load.leaf_value(),
            ),
        ),
        (
            "redeem_recovery",
            json_leaf(
                KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1,
                &redeem.key(),
                &redeem.field_items(),
                &redeem.leaf_value(),
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
        (
            "quota_usage",
            json_leaf(
                KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1,
                &usage.key(),
                &usage.field_items(),
                &usage.leaf_value(),
            ),
        ),
    ]);
    let mut recovery = KagemushaWalletIndexedTreeV1::new();
    recovery
        .insert(load.key(), load.leaf_value())
        .expect("load leaf");
    recovery
        .insert(redeem.key(), redeem.leaf_value())
        .expect("redeem leaf");
    let mut consumed_map = KagemushaWalletIndexedTreeV1::new();
    consumed_map
        .insert(consumed.key(), consumed.leaf_value().expect("value"))
        .expect("consumed leaf");
    let absent = super::messages::messages_tests::flip_bit(&consumed.key(), 0);
    let indexed = json_object(vec![
        ("empty_leaf_hex", json_hex(&[0; 32])),
        (
            "sentinel_leaf_hex",
            json_hex(
                &KagemushaWalletIndexedLeafV1::SENTINEL
                    .hash()
                    .expect("sentinel"),
            ),
        ),
        (
            "default_height_1_hex",
            json_hex(&kagemusha_wallet_indexed_empty_subtree_v1(1).expect("height 1")),
        ),
        (
            "empty_root_hex",
            json_hex(&kagemusha_wallet_empty_map_root_v1()),
        ),
        ("depth", json_number(KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1)),
        ("load_redeem_recovery_root_hex", json_hex(&recovery.root())),
        ("load_membership", json_membership(&recovery, &load.key())),
        (
            "consumed_credit_membership",
            json_membership(&consumed_map, &consumed.key()),
        ),
        (
            "consumed_credit_absence",
            json_non_membership(&consumed_map, &absent),
        ),
    ]);

    // The credit-digest opening of the vectored CreditStatus.
    let status = w.status();
    let leaf = status.opening.leaf();
    let credit_opening = json_object(vec![
        (
            "leaf",
            json_leaf(
                KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
                &leaf.key(),
                &leaf.field_items().expect("items"),
                &leaf.leaf_value().expect("value"),
            ),
        ),
        (
            "opening",
            json_opening(
                &leaf.key(),
                &leaf
                    .indexed_leaf(status.opening.next_key)
                    .expect("indexed credit leaf"),
                &KagemushaWalletIndexedOpeningV1::from_sibling_bytes(
                    status.opening.slot,
                    &status.opening.siblings,
                )
                .expect("indexed opening"),
                &status.lineage.public.credit_digest_root,
                true,
            ),
        ),
    ]);

    // Blacklist and quota-window trees (§7).
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
    let blacklist = json_object(vec![
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
    ]);
    let windows = &w.quota_share.windows;
    let quota = json_object(vec![
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
            "proof_digests",
            Value::Array(vec![
                packed_digest(
                    "Send: stand-in Ω(pred) and σ_send",
                    KAGEMUSHA_WALLET_PROOF_DOMAIN_V1,
                    &send_proof_body,
                    &digests.package.proof,
                ),
                packed_digest(
                    "Receive: stand-in σ_recv",
                    KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1,
                    &receive_proof_body,
                    &receive_digests.proof,
                ),
            ]),
        ),
        (
            "payment_digest",
            packed_digest(
                "compact Payment",
                KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
                &payment_transcript,
                &digests.payment,
            ),
        ),
        ("leaves", leaves),
        ("indexed_tree", indexed),
        ("credit_digest_opening", credit_opening),
        ("blacklist", blacklist),
        ("quota_windows", quota),
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
            ]),
        ),
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
                "ECDSA-P256-SHA256 over the 32-byte signing_message_hex; RFC 6979 from the fixed scalars, \
                 frozen to low S; a consumer accepts iff codec_ok and verify_ok",
            ),
        ),
        ("stand_ins", stand_ins_json()),
        ("bounds", bounds_json()),
        ("norito_header", header_json(w)),
        ("keys", keys_json(w)),
        ("digests", digest_vectors_json(&digests)),
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
    let roles: Vec<Role> = vectors
        .iter()
        .filter_map(|vector| match vector.kind {
            DigestKind::Hash(role) => Some(role),
            _ => None,
        })
        .collect();
    assert_eq!(roles, Role::ALL.to_vec());
    let mut domains: Vec<Domain> = vectors
        .iter()
        .filter_map(|vector| match vector.kind {
            DigestKind::Signing(domain) => Some(domain),
            _ => None,
        })
        .collect();
    domains.sort();
    assert_eq!(domains, Domain::ALL.to_vec());
    let json = digest_vectors_json(&vectors);
    let Value::Array(rows) = json else {
        panic!("array");
    };
    assert_eq!(rows.len(), Role::ALL.len() + Domain::ALL.len() + 4);
    // Only the vectors whose bytes carry stand-in proof bytes are labelled.
    let labelled: Vec<&str> = vectors
        .iter()
        .filter(|vector| vector.stand_in_proof)
        .map(|vector| vector.kind.label())
        .collect();
    assert_eq!(
        labelled,
        [
            "kgwlin_1",
            "capsule",
            "completion",
            "fold",
            "verifying-key-set"
        ]
    );
}

#[test]
fn kagemusha_wallet_v1_signature_vectors_and_boundaries() {
    let world = vector_world();
    let vectors = signature_vectors(world);
    assert_eq!(vectors.len(), 18);
    let Value::Array(rows) = signature_vectors_json(&vectors) else {
        panic!("array");
    };
    assert_eq!(rows.len(), vectors.len());

    let boundary = boundary_vector();
    let cases = boundary_cases(&boundary);
    let verdicts: Vec<(&str, bool, bool)> = cases
        .iter()
        .map(|(name, raw, _, _)| {
            let (codec_ok, verify_ok) = signature_verdicts(&boundary.key, &boundary.preimage, raw);
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
        &boundary.preimage,
        &signature,
    )
    .expect("boundary signature verifies");
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
    w.voucher
        .verify(&scheme, &w.load_certificate)
        .expect("voucher");
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
fn kagemusha_wallet_v1_flips_load_voucher() {
    let w = vector_world();
    let scheme = w.scheme();
    assert_flips(&w.voucher, w.voucher.voucher_digest(), |bytes| {
        let voucher =
            KagemushaWalletLoadVoucherV1::decode_canonical(bytes, &scheme.scheme_id()).ok()?;
        voucher.verify(&scheme, &w.load_certificate).ok()?;
        Some(voucher.voucher_digest())
    });
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
