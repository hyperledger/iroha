//! Private state, statement, step and lineage proof, receipt and package tests.
//!
//! The fixtures are visible to the other wallet test modules so later areas build packages
//! from the same statements.

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    KagemushaWalletValidationErrorV1,
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag},
    decode_frame_v1,
    digest::{
        KAGEMUSHA_WALLET_FIELD_MODULUS_V1, kagemusha_wallet_field_from_u128_v1,
        kagemusha_wallet_is_canonical_field_v1,
    },
    identity::{
        KagemushaWalletEvidenceKindV1,
        identity_tests::{IdentityFixture, identity_fixture, raw_output, signing_key},
    },
    poseidon::{
        KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1, KagemushaWalletIndexedTreeV1,
        kagemusha_wallet_packed_bytes_v1, kagemusha_wallet_poseidon_v1,
    },
};

/// A canonical, nonzero σ-field stand-in value for a nonzero `seed`: every byte `seed`
/// except the most significant, which is `seed & 0x3f` so the value stays below `p`.
pub(in crate::kagemusha::kagemusha_wallet_v1) const fn field_value(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[31] = seed & 0x3f;
    value
}

/// Stand-in recovery capsule digest.
pub(in crate::kagemusha::kagemusha_wallet_v1) const CAPSULE: [u8; 32] = [0xca; 32];
/// Stand-in Ω(pred) pending-outgoing root of statements that consume Ω(pred).
pub(in crate::kagemusha::kagemusha_wallet_v1) const LINEAGE_PENDING_ROOT: [u8; 32] =
    field_value(0xd2);
/// Stand-in Ω credit-digest root.
pub(in crate::kagemusha::kagemusha_wallet_v1) const CREDIT_DIGEST_ROOT: [u8; 32] =
    field_value(0xd3);
/// Stand-in Payment digest (a σ-field value) bound by Receive receipts of the generic fixtures.
pub(in crate::kagemusha::kagemusha_wallet_v1) const RECEIVE_PAYMENT: [u8; 32] = field_value(0x7f);
/// Stand-in Ω transport proof length.
pub(in crate::kagemusha::kagemusha_wallet_v1) const LINEAGE_PROOF_LEN: usize = 40;
const MARKER: [u8; 32] = [0x61; 32];

/// Distinct complete commitment for a nonzero seed.
pub(in crate::kagemusha::kagemusha_wallet_v1) const fn commitment(
    seed: u8,
) -> KagemushaWalletStateCommitmentV1 {
    KagemushaWalletStateCommitmentV1 {
        value: field_value(seed),
    }
}

/// Valid Bootstrap statement of `f`'s credential.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn bootstrap_statement(
    f: &IdentityFixture,
) -> KagemushaWalletStatementV1 {
    KagemushaWalletStatementV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.credential.body.scheme_id,
        relation_id: f.scheme.relation_id,
        credential_digest: f.credential.credential_digest(),
        asset_digest: f.credential.body.asset_digest,
        lifecycle: KagemushaWalletLifecycleV1::Active,
        sequence: 0,
        next_load: 0,
        enabled_controls: 0,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: KagemushaWalletStateCommitmentV1::ZERO,
        successor: commitment(1),
        effect: KagemushaWalletEffectV1::Bootstrap {
            enrollment_id: f.credential.body.enrollment_id,
            enrollment_marker: MARKER,
        },
    }
}

/// Valid non-Bootstrap statement at `sequence` (1 to 100) with `effect`; an operation that
/// consumes Ω(pred) takes [`LINEAGE_PENDING_ROOT`] and a zero `burned_total` from it.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn transition_statement(
    f: &IdentityFixture,
    sequence: u8,
    next_load: u128,
    lifecycle: KagemushaWalletLifecycleV1,
    effect: KagemushaWalletEffectV1,
) -> KagemushaWalletStatementV1 {
    let consumes = effect.kind().consumes_lineage();
    KagemushaWalletStatementV1 {
        sequence: u128::from(sequence),
        next_load,
        lifecycle,
        lineage_pending_outgoing_root: if consumes {
            LINEAGE_PENDING_ROOT
        } else {
            [0; 32]
        },
        predecessor: commitment(sequence),
        successor: commitment(sequence + 1),
        effect,
        ..bootstrap_statement(f)
    }
}

/// Valid Send effect to a foreign receiver.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn send_effect() -> KagemushaWalletEffectV1 {
    KagemushaWalletEffectV1::Send {
        credit_id: field_value(0x71),
        receiver_wallet_id: [0x72; 32],
        send_ordinal: 4,
        amount: 1_000,
        fee: 10,
        request: [0x73; 32],
        accepted_lower_ms: 5,
        accepted_upper_ms: 9,
    }
}

/// One valid effect of every kind for `f`'s credential, in tag order.
fn sample_effects(f: &IdentityFixture) -> [KagemushaWalletEffectV1; 8] {
    let body = &f.credential.body;
    [
        KagemushaWalletEffectV1::Bootstrap {
            enrollment_id: body.enrollment_id,
            enrollment_marker: MARKER,
        },
        KagemushaWalletEffectV1::Load {
            voucher: [0x62; 32],
            load_ordinal: 0,
            amount: 5_000,
            online_charge: 25,
        },
        send_effect(),
        KagemushaWalletEffectV1::Receive {
            credit_id: field_value(0x75),
            payer_wallet_id: [0x76; 32],
            amount: 300,
        },
        KagemushaWalletEffectV1::ArchiveSent {
            credit_id: field_value(0x71),
            credited: field_value(0x78),
        },
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&body.scheme_id, &body.wallet_id, 2),
            redeem_ordinal: 2,
            amount: 700,
            online_charge: 7,
            charge_quote: [0x79; 32],
        },
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: [0x7a; 32],
            accepted_time_floor_ms: 12,
        },
        KagemushaWalletEffectV1::Retiring,
    ]
}

/// Valid statement carrying `effect` of `f`'s credential.
fn statement_for(
    f: &IdentityFixture,
    effect: KagemushaWalletEffectV1,
) -> KagemushaWalletStatementV1 {
    match effect {
        KagemushaWalletEffectV1::Bootstrap { .. } => bootstrap_statement(f),
        KagemushaWalletEffectV1::Load { load_ordinal, .. } => transition_statement(
            f,
            3,
            load_ordinal + 1,
            KagemushaWalletLifecycleV1::Active,
            effect,
        ),
        KagemushaWalletEffectV1::Retiring => {
            transition_statement(f, 3, 0, KagemushaWalletLifecycleV1::Retiring, effect)
        }
        _ => transition_statement(f, 3, 0, KagemushaWalletLifecycleV1::Active, effect),
    }
}

/// Stand-in step proof σ of `len` bytes.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn stand_in_proof(
    len: usize,
) -> KagemushaWalletStepProofV1 {
    KagemushaWalletStepProofV1 {
        bytes: stand_in_bytes(len, 0),
    }
}

/// Deterministic stand-in proof bytes of `len` bytes starting at `offset`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn stand_in_bytes(
    len: usize,
    offset: usize,
) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index + offset) % 251).expect("byte"))
        .collect()
}

/// Stand-in Ω(pred) of `statement` (which consumes Ω(pred)) for the wallet of `credential`,
/// with a transport proof of `proof_len` bytes.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn lineage_with_len(
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
    proof_len: usize,
) -> KagemushaWalletLineageV1 {
    let lifecycle = match statement.effect {
        KagemushaWalletEffectV1::Retiring => KagemushaWalletLifecycleV1::Active,
        _ => statement.lifecycle,
    };
    KagemushaWalletLineageV1 {
        public: KagemushaWalletLineagePublicV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: statement.scheme_id,
            relation_id: statement.relation_id,
            head: statement.predecessor,
            wallet_id: credential.body.wallet_id,
            credential_digest: statement.credential_digest,
            payment_key: credential.body.payment_key,
            lifecycle,
            policy_epoch: 0,
            enabled_controls: statement.enabled_controls,
            burned_total: statement.lineage_burned_total,
            pending_outgoing_root: statement.lineage_pending_outgoing_root,
            credit_digest_root: CREDIT_DIGEST_ROOT,
        },
        proof: stand_in_bytes(proof_len, 7),
    }
}

/// Stand-in Ω(pred) of `statement` with [`LINEAGE_PROOF_LEN`] proof bytes.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn lineage_for(
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
) -> KagemushaWalletLineageV1 {
    lineage_with_len(credential, statement, LINEAGE_PROOF_LEN)
}

/// Package of `statement`, `lineage`, `proof` and `payment_digest` with a receipt signed by
/// `f`'s payment key under `credential`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn signed_package_with(
    f: &IdentityFixture,
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
    lineage: KagemushaWalletLineageSlotV1,
    proof: KagemushaWalletStepProofV1,
    payment_digest: [u8; 32],
) -> KagemushaWalletPackageV1 {
    let proof_digest =
        kagemusha_wallet_proof_digest_v1(statement.effect.kind(), lineage.lineage(), &proof)
            .expect("proof digest");
    let signer = KagemushaWalletReceiptSignerV1::from_credential(credential).expect("signer");
    let body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        statement,
        &proof_digest,
        CAPSULE,
        payment_digest,
    )
    .expect("receipt body");
    let receipt = KagemushaWalletReceiptV1::sign(
        credential,
        statement,
        &proof_digest,
        CAPSULE,
        payment_digest,
        raw_output(&f.payment, &body.signing_message()),
    )
    .expect("receipt");
    KagemushaWalletPackageV1::new(*statement, lineage, proof, receipt)
}

/// Package of `statement` and `proof`: Ω(pred) is [`lineage_for`] exactly when the operation
/// consumes it, and a Receive binds [`RECEIVE_PAYMENT`].
pub(in crate::kagemusha::kagemusha_wallet_v1) fn signed_package(
    f: &IdentityFixture,
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
    proof: KagemushaWalletStepProofV1,
) -> KagemushaWalletPackageV1 {
    let kind = statement.effect.kind();
    let lineage = if kind.consumes_lineage() {
        KagemushaWalletLineageSlotV1::Present {
            lineage: lineage_for(credential, statement),
        }
    } else {
        KagemushaWalletLineageSlotV1::None
    };
    let payment = if kind == KagemushaWalletOperationKindV1::Receive {
        RECEIVE_PAYMENT
    } else {
        [0; 32]
    };
    signed_package_with(f, credential, statement, lineage, proof, payment)
}

fn android() -> IdentityFixture {
    identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x47)
}

fn is_invalid<T>(result: WalletResult<T>, expected: &str) -> bool {
    matches!(
        result.err(),
        Some(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected
    )
}

fn effect_fields_len(effect: &KagemushaWalletEffectV1) -> usize {
    effect
        .write_fields(WalletTranscriptV1::with_capacity(0))
        .finish()
        .len()
}

fn int(value: u128) -> [u8; 32] {
    kagemusha_wallet_field_from_u128_v1(value)
}

/// The two 128-bit limbs of a 32-byte digest as σ-field elements, low half first.
fn limb_items(value: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut low = [0_u8; 32];
    let mut high = [0_u8; 32];
    low[..16].copy_from_slice(&value[..16]);
    high[..16].copy_from_slice(&value[16..]);
    [low, high]
}

/// Bootstrap state of `f`'s credential with nonce seed `seed`.
fn bootstrap_state(f: &IdentityFixture, seed: u8) -> KagemushaWalletStateV1 {
    KagemushaWalletStateV1::bootstrap(&f.credential, field_value(seed)).expect("bootstrap state")
}

#[test]
fn kagemusha_wallet_v1_state_transcript_lengths_are_pinned() {
    let f = android();
    for (constant, expected) in [
        (KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1, 32),
        (KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1, 160),
        (KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1, 161),
        (KAGEMUSHA_WALLET_STATEMENT_TRANSCRIPT_BYTES_V1, 440),
        (KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1, 338),
        (KAGEMUSHA_WALLET_OPERATION_ID_TRANSCRIPT_BYTES_V1, 65),
        (KAGEMUSHA_WALLET_PACKAGE_TRANSCRIPT_BYTES_V1, 96),
        (KAGEMUSHA_WALLET_UNLOAD_NULLIFIER_TRANSCRIPT_BYTES_V1, 80),
        (KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1, 320),
        (KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1, 32),
        (KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1, 13),
        (KAGEMUSHA_WALLET_EFFECT_FIELD_ITEMS_V1, 10),
        (KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1, 28),
    ] {
        assert_eq!(constant, expected);
    }
    assert_eq!(max_width_v1(&[]), 0);
    assert_eq!(max_width_v1(&[3, 9, 4]), 9);
    assert_eq!(
        KAGEMUSHA_WALLET_EFFECT_UNION_BYTES_V1,
        *EFFECT_FIELDS_BYTES.iter().max().expect("variants")
    );
    let effects = sample_effects(&f);
    for ((effect, width), items) in effects
        .iter()
        .zip(EFFECT_FIELDS_BYTES)
        .zip(EFFECT_FIELD_ITEMS)
    {
        assert_eq!(effect_fields_len(effect), width, "{effect:?}");
        assert_eq!(effect.fields_bytes(), width);
        assert_eq!(effect.field_items_len(), items);
        assert_eq!(
            effect
                .write_field_items(WalletFieldItemsV1::with_capacity(0))
                .len(),
            items
        );
        assert_eq!(
            effect.transcript().len(),
            KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1
        );
        let statement = statement_for(&f, *effect);
        assert_eq!(
            statement.transcript().len(),
            KAGEMUSHA_WALLET_STATEMENT_TRANSCRIPT_BYTES_V1
        );
        assert_eq!(
            statement.field_items().expect("items").len(),
            KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1
        );
    }
    assert_eq!(
        commitment(3).transcript().len(),
        KAGEMUSHA_WALLET_COMMITMENT_TRANSCRIPT_BYTES_V1
    );
    let statement = bootstrap_statement(&f);
    let signer = KagemushaWalletReceiptSignerV1::from_credential(&f.credential).expect("signer");
    let body =
        KagemushaWalletReceiptBodyV1::derive(&signer, &statement, &[1; 32], CAPSULE, [0; 32])
            .expect("receipt body");
    assert_eq!(
        body.transcript().len(),
        KAGEMUSHA_WALLET_RECEIPT_BODY_TRANSCRIPT_BYTES_V1
    );
    let send = statement_for(&f, send_effect());
    assert_eq!(
        lineage_for(&f.credential, &send).public.transcript().len(),
        KAGEMUSHA_WALLET_LINEAGE_PUBLIC_TRANSCRIPT_BYTES_V1
    );
}

#[test]
fn kagemusha_wallet_v1_field_encoding_is_canonical() {
    // p in little-endian bytes, and its neighbours.
    let modulus = KAGEMUSHA_WALLET_FIELD_MODULUS_V1;
    assert_eq!(modulus[0], 0x01);
    assert_eq!(modulus[31], 0x40);
    assert_eq!(
        modulus,
        [
            0x992d_30ed_0000_0001_u64.to_le_bytes(),
            0x2246_98fc_094c_f91b_u64.to_le_bytes(),
            0_u64.to_le_bytes(),
            0x4000_0000_0000_0000_u64.to_le_bytes(),
        ]
        .concat()[..]
    );
    assert!(!kagemusha_wallet_is_canonical_field_v1(&modulus));
    let mut below = modulus;
    below[0] = 0;
    assert!(kagemusha_wallet_is_canonical_field_v1(&below));
    let mut above = modulus;
    above[0] = 2;
    assert!(!kagemusha_wallet_is_canonical_field_v1(&above));
    // 2^254 < p, but 2^254 + 2^128 > p.
    let mut high = [0_u8; 32];
    high[31] = 0x40;
    assert!(kagemusha_wallet_is_canonical_field_v1(&high));
    high[16] = 0x01;
    assert!(!kagemusha_wallet_is_canonical_field_v1(&high));
    high[31] = 0x3f;
    high[0] = 0xff;
    assert!(kagemusha_wallet_is_canonical_field_v1(&high));
    assert!(kagemusha_wallet_is_canonical_field_v1(&[0; 32]));
    assert!(!kagemusha_wallet_is_canonical_field_v1(&[0xff; 32]));
    assert!(kagemusha_wallet_is_canonical_field_v1(&int(u128::MAX)));
    let mut expected = [0_u8; 32];
    expected[..16].copy_from_slice(&0x0102_u128.to_le_bytes());
    assert_eq!(int(0x0102), expected);
    for seed in [1_u8, 0x40, 0x80, 0xc1, 0xff] {
        assert!(kagemusha_wallet_is_canonical_field_v1(&field_value(seed)));
        assert!(commitment(seed).is_complete());
    }
    let items = WalletFieldItemsV1::with_capacity(4)
        .integer(7)
        .digest(&[0x11; 32])
        .field(&field_value(0x22))
        .zeros(1);
    assert_eq!(items.len(), 5);
    let [low, high] = limb_items(&[0x11; 32]);
    assert_eq!(
        items.finish(),
        vec![int(7), low, high, field_value(0x22), [0; 32]]
    );
}

#[test]
fn kagemusha_wallet_v1_state_enum_tags_equal_norito_tags() {
    let f = android();
    for lifecycle in KagemushaWalletLifecycleV1::ALL {
        assert_eq!(norito_tag(&lifecycle), u32::from(lifecycle.tag()));
    }
    for (index, kind) in KagemushaWalletOperationKindV1::ALL.into_iter().enumerate() {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
        assert_eq!(usize::from(kind.tag()), index + 1);
    }
    for kind in KagemushaWalletPolicyUpdateKindV1::ALL {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
    }
    for (effect, kind) in sample_effects(&f)
        .iter()
        .zip(KagemushaWalletOperationKindV1::ALL)
    {
        assert_eq!(effect.kind(), kind);
        assert_eq!(effect.tag(), kind.tag());
        assert_eq!(norito_tag(effect), u32::from(effect.tag()));
    }
    assert_eq!(norito_tag(&KagemushaWalletLineageSlotV1::None), 0);
    let send = statement_for(&f, send_effect());
    let present = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage_for(&f.credential, &send),
    };
    assert_eq!(norito_tag(&present), u32::from(present.tag()));
    assert_eq!(present.tag(), 1);
}

#[test]
fn kagemusha_wallet_v1_operations_that_consume_lineage() {
    use KagemushaWalletOperationKindV1 as Kind;
    let consuming: Vec<Kind> = Kind::ALL
        .into_iter()
        .filter(|kind| kind.consumes_lineage())
        .collect();
    assert_eq!(consuming, [Kind::Send, Kind::Unload, Kind::Retiring]);
}

#[test]
fn kagemusha_wallet_v1_effect_transcripts_are_zero_filled_unions() {
    let f = android();
    for effect in sample_effects(&f) {
        let transcript = effect.transcript();
        assert_eq!(transcript[0], effect.tag());
        let fields = effect_fields_len(&effect);
        assert!(transcript[1 + fields..].iter().all(|byte| *byte == 0));
    }
    assert_eq!(
        KagemushaWalletEffectV1::Retiring.transcript(),
        [&[8_u8][..], &[0; 160][..]].concat()
    );
    let mut expected = vec![3_u8];
    expected.extend_from_slice(&field_value(0x71));
    expected.extend_from_slice(&[0x72; 32]);
    expected.extend_from_slice(&4_u128.to_le_bytes());
    expected.extend_from_slice(&1_000_u128.to_le_bytes());
    expected.extend_from_slice(&10_u128.to_le_bytes());
    expected.extend_from_slice(&[0x73; 32]);
    expected.extend_from_slice(&5_u64.to_le_bytes());
    expected.extend_from_slice(&9_u64.to_le_bytes());
    assert_eq!(send_effect().transcript(), expected);

    // The Receive effect binds no Payment digest (§3).
    let receive = KagemushaWalletEffectV1::Receive {
        credit_id: field_value(0x75),
        payer_wallet_id: [0x76; 32],
        amount: 300,
    };
    let mut expected = vec![4_u8];
    expected.extend_from_slice(&field_value(0x75));
    expected.extend_from_slice(&[0x76; 32]);
    expected.extend_from_slice(&300_u128.to_le_bytes());
    expected.resize(KAGEMUSHA_WALLET_EFFECT_TRANSCRIPT_BYTES_V1, 0);
    assert_eq!(receive.transcript(), expected);

    let refresh = KagemushaWalletEffectV1::RefreshPolicy {
        update_kind: KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
        update: [0x7b; 32],
        accepted_time_floor_ms: 0x0102,
    };
    let transcript = refresh.transcript();
    assert_eq!(&transcript[..2], &[7, 5]);
    assert_eq!(&transcript[2..34], &[0x7b; 32]);
    assert_eq!(&transcript[34..42], &0x0102_u64.to_le_bytes());
    assert!(transcript[42..].iter().all(|byte| *byte == 0));
}

#[test]
fn kagemusha_wallet_v1_effect_validation_rules() {
    let f = android();
    for effect in sample_effects(&f) {
        effect.validate().expect("sample effect");
    }
    let KagemushaWalletEffectV1::Send {
        credit_id,
        receiver_wallet_id,
        send_ordinal,
        request,
        ..
    } = send_effect()
    else {
        unreachable!("send effect");
    };
    let send = |amount, fee, lower, upper| KagemushaWalletEffectV1::Send {
        credit_id,
        receiver_wallet_id,
        send_ordinal,
        amount,
        fee,
        request,
        accepted_lower_ms: lower,
        accepted_upper_ms: upper,
    };
    assert!(is_invalid(send(0, 0, 1, 1).validate(), "effect.amount"));
    assert!(matches!(
        send(u128::MAX, 1, 1, 1).validate(),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow {
            field: "effect.gross"
        })
    ));
    send(u128::MAX, 0, 1, 1).validate().expect("maximal gross");
    assert!(is_invalid(
        send(1, 0, 2, 1).validate(),
        "effect.accepted_time"
    ));
    let mut zero_request = send(1, 0, 1, 1);
    if let KagemushaWalletEffectV1::Send { request, .. } = &mut zero_request {
        *request = [0; 32];
    }
    assert!(is_invalid(zero_request.validate(), "effect.request"));
    let mut wide_credit = send(1, 0, 1, 1);
    if let KagemushaWalletEffectV1::Send { credit_id, .. } = &mut wide_credit {
        *credit_id = [0x71; 32];
    }
    assert!(is_invalid(wide_credit.validate(), "effect.credit_id"));

    let unload = |amount, online_charge, charge_quote| KagemushaWalletEffectV1::Unload {
        nullifier: [0x01; 32],
        redeem_ordinal: 0,
        amount,
        online_charge,
        charge_quote,
    };
    unload(10, 0, [0; 32]).validate().expect("no charge");
    unload(10, 10, [1; 32]).validate().expect("full charge");
    assert!(is_invalid(
        unload(0, 0, [0; 32]).validate(),
        "effect.amount"
    ));
    assert!(is_invalid(
        unload(10, 11, [1; 32]).validate(),
        "effect.online_charge"
    ));
    assert!(is_invalid(
        unload(10, 1, [0; 32]).validate(),
        "effect.charge_quote"
    ));
    assert!(is_invalid(
        unload(10, 0, [1; 32]).validate(),
        "effect.charge_quote"
    ));

    for (effect, field) in [
        (
            KagemushaWalletEffectV1::Bootstrap {
                enrollment_id: [0; 32],
                enrollment_marker: MARKER,
            },
            "effect.enrollment_id",
        ),
        (
            KagemushaWalletEffectV1::Bootstrap {
                enrollment_id: [1; 32],
                enrollment_marker: [0; 32],
            },
            "effect.enrollment_marker",
        ),
        (
            KagemushaWalletEffectV1::Load {
                voucher: [0; 32],
                load_ordinal: 0,
                amount: 1,
                online_charge: 0,
            },
            "effect.voucher",
        ),
        (
            KagemushaWalletEffectV1::Receive {
                credit_id: [1; 32],
                payer_wallet_id: [1; 32],
                amount: 0,
            },
            "effect.amount",
        ),
        (
            KagemushaWalletEffectV1::Receive {
                credit_id: [0; 32],
                payer_wallet_id: [1; 32],
                amount: 1,
            },
            "effect.credit_id",
        ),
        (
            KagemushaWalletEffectV1::Receive {
                credit_id: [1; 32],
                payer_wallet_id: [0; 32],
                amount: 1,
            },
            "effect.payer_wallet_id",
        ),
        (
            KagemushaWalletEffectV1::ArchiveSent {
                credit_id: [1; 32],
                credited: [0; 32],
            },
            "effect.credited",
        ),
        // `credit_id` is a canonical σ-field value (§5.1, owner answer Q1).
        (
            KagemushaWalletEffectV1::ArchiveSent {
                credit_id: [0xff; 32],
                credited: [1; 32],
            },
            "effect.credit_id",
        ),
        (
            KagemushaWalletEffectV1::Receive {
                credit_id: KAGEMUSHA_WALLET_FIELD_MODULUS_V1,
                payer_wallet_id: [1; 32],
                amount: 1,
            },
            "effect.credit_id",
        ),
        (
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Blacklist,
                update: [0; 32],
                accepted_time_floor_ms: 0,
            },
            "effect.update",
        ),
    ] {
        assert!(is_invalid(effect.validate(), field), "{field}");
    }
}

#[test]
fn kagemusha_wallet_v1_operation_id_derivation() {
    let f = android();
    let wallet_id = f.credential.body.wallet_id;
    let inputs = [
        f.credential.body.enrollment_id,
        [0x62; 32],
        field_value(0x71),
        field_value(0x75),
        // ArchiveSent binds its Credited digest, so a re-archive after a no-op branch is a new
        // operation (§§3.2, 4.1).
        [0x78; 32],
        sample_effects(&f)[5].operation_input(),
        [0x7a; 32],
        [0; 32],
    ];
    let mut seen = std::collections::BTreeSet::new();
    for ((effect, kind), input) in sample_effects(&f)
        .iter()
        .zip(KagemushaWalletOperationKindV1::ALL)
        .zip(inputs)
    {
        assert_eq!(effect.operation_input(), input);
        let mut transcript = wallet_id.to_vec();
        transcript.push(kind.tag());
        transcript.extend_from_slice(&input);
        assert_eq!(
            kagemusha_wallet_operation_id_transcript_v1(&wallet_id, kind, &input),
            transcript
        );
        let operation_id = kagemusha_wallet_operation_id_v1(&wallet_id, kind, &input);
        assert_eq!(
            operation_id,
            kagemusha_wallet_digest_v1(Role::OperationId, &transcript)
        );
        assert_eq!(
            statement_for(&f, *effect).operation_id(&wallet_id),
            operation_id
        );
        assert!(seen.insert(operation_id), "{kind:?}");
    }
    let archive = |credited| KagemushaWalletEffectV1::ArchiveSent {
        credit_id: field_value(0x71),
        credited,
    };
    assert_ne!(
        archive([1; 32]).operation_input(),
        archive([2; 32]).operation_input()
    );
    assert_ne!(
        kagemusha_wallet_operation_id_v1(
            &wallet_id,
            KagemushaWalletOperationKindV1::Send,
            &[1; 32]
        ),
        kagemusha_wallet_operation_id_v1(
            &wallet_id,
            KagemushaWalletOperationKindV1::ArchiveSent,
            &[1; 32]
        )
    );
}

#[test]
fn kagemusha_wallet_v1_unload_nullifier_layout() {
    let scheme = [0x01; 32];
    let wallet = [0x02; 32];
    let transcript = kagemusha_wallet_unload_nullifier_transcript_v1(&scheme, &wallet, 0x0304);
    let mut expected = scheme.to_vec();
    expected.extend_from_slice(&wallet);
    expected.extend_from_slice(&0x0304_u128.to_le_bytes());
    assert_eq!(transcript, expected);
    assert_eq!(
        kagemusha_wallet_unload_nullifier_v1(&scheme, &wallet, 0x0304),
        kagemusha_wallet_digest_v1(Role::UnloadNullifier, &expected)
    );
    assert_ne!(
        kagemusha_wallet_unload_nullifier_v1(&scheme, &wallet, 0),
        kagemusha_wallet_unload_nullifier_v1(&scheme, &wallet, 1)
    );
}

#[test]
fn kagemusha_wallet_v1_statement_layout_and_validation() {
    let f = android();
    let statement = bootstrap_statement(&f);
    statement.validate().expect("bootstrap");
    let mut expected = 1_u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&statement.scheme_id);
    expected.extend_from_slice(&statement.relation_id);
    expected.extend_from_slice(&statement.credential_digest);
    expected.extend_from_slice(&statement.asset_digest);
    expected.push(1);
    expected.extend_from_slice(&0_u128.to_le_bytes());
    expected.extend_from_slice(&0_u128.to_le_bytes());
    expected.extend_from_slice(&0_u32.to_le_bytes());
    expected.extend_from_slice(&0_u128.to_le_bytes());
    expected.extend_from_slice(&[0; 32]);
    expected.extend_from_slice(&[0; 32]);
    expected.extend_from_slice(&commitment(1).transcript());
    expected.extend_from_slice(&statement.effect.transcript());
    assert_eq!(statement.transcript(), expected);
    assert_eq!(
        statement.statement_digest(),
        kagemusha_wallet_digest_v1(Role::Statement, &expected)
    );

    // A consuming statement carries Ω(pred)'s burned_total and pending-outgoing root.
    let mut send = statement_for(&f, send_effect());
    send.lineage_burned_total = 0x0506;
    send.enabled_controls = 1;
    let transcript = send.transcript();
    let lineage_offset = 2 + 4 * 32 + 1 + 32;
    assert_eq!(
        &transcript[lineage_offset..lineage_offset + 4],
        &1_u32.to_le_bytes()
    );
    assert_eq!(
        &transcript[lineage_offset + 4..lineage_offset + 20],
        &0x0506_u128.to_le_bytes()
    );
    assert_eq!(
        &transcript[lineage_offset + 20..lineage_offset + 52],
        &LINEAGE_PENDING_ROOT
    );

    for effect in sample_effects(&f) {
        statement_for(&f, effect)
            .validate()
            .expect("sample statement");
    }

    let reject = |mutate: &dyn Fn(&mut KagemushaWalletStatementV1), field: &str| {
        let mut statement = bootstrap_statement(&f);
        mutate(&mut statement);
        assert!(is_invalid(statement.validate(), field), "{field}");
    };
    reject(&|s| s.sequence = 1, "statement.bootstrap");
    reject(&|s| s.predecessor = commitment(2), "statement.bootstrap");
    reject(
        &|s| s.lifecycle = KagemushaWalletLifecycleV1::Retiring,
        "statement.bootstrap",
    );
    reject(&|s| s.next_load = 1, "statement.bootstrap");
    reject(&|s| s.enabled_controls = 1, "statement.bootstrap");
    reject(
        &|s| s.successor = KagemushaWalletStateCommitmentV1::ZERO,
        "statement.successor",
    );
    reject(
        &|s| s.successor.value = KAGEMUSHA_WALLET_FIELD_MODULUS_V1,
        "statement.successor",
    );
    reject(
        &|s| s.predecessor.value = [0xff; 32],
        "statement.predecessor",
    );
    reject(&|s| s.relation_id = [0; 32], "statement.relation_id");
    reject(&|s| s.enabled_controls = 0x80, "statement.enabled_controls");
    // Operations that do not consume Ω(pred) carry the core values forward.
    reject(&|s| s.lineage_burned_total = 1, "statement.lineage");
    reject(
        &|s| s.lineage_pending_outgoing_root = LINEAGE_PENDING_ROOT,
        "statement.lineage",
    );
    reject(
        &|s| s.lineage_pending_outgoing_root = [0xff; 32],
        "statement.lineage_pending_outgoing_root",
    );
    let mut version = bootstrap_statement(&f);
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    let send = |sequence, predecessor| KagemushaWalletStatementV1 {
        sequence,
        predecessor,
        ..transition_statement(&f, 3, 0, KagemushaWalletLifecycleV1::Active, send_effect())
    };
    assert!(is_invalid(
        send(0, commitment(3)).validate(),
        "statement.sequence"
    ));
    assert!(is_invalid(
        send(3, KagemushaWalletStateCommitmentV1::ZERO).validate(),
        "statement.predecessor"
    ));
    let mut no_root = send(3, commitment(3));
    no_root.lineage_pending_outgoing_root = [0; 32];
    assert!(is_invalid(
        no_root.validate(),
        "statement.lineage_pending_outgoing_root"
    ));
    let retiring = transition_statement(
        &f,
        3,
        0,
        KagemushaWalletLifecycleV1::Active,
        KagemushaWalletEffectV1::Retiring,
    );
    assert!(is_invalid(retiring.validate(), "statement.lifecycle"));
    let load = |next_load, load_ordinal| {
        transition_statement(
            &f,
            3,
            next_load,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Load {
                voucher: [1; 32],
                load_ordinal,
                amount: 1,
                online_charge: 0,
            },
        )
    };
    load(3, 2).validate().expect("retiring load");
    assert!(is_invalid(load(2, 2).validate(), "statement.next_load"));
    assert!(matches!(
        load(0, u128::MAX).validate(),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
    let replacement = |update| {
        transition_statement(
            &f,
            3,
            0,
            KagemushaWalletLifecycleV1::Active,
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                update,
                accepted_time_floor_ms: 0,
            },
        )
    };
    replacement(f.credential.credential_digest())
        .validate()
        .expect("replacement statement names its credential");
    assert!(is_invalid(replacement([9; 32]).validate(), "effect.update"));
}

#[test]
fn kagemusha_wallet_v1_statement_field_items_layout() {
    let f = android();
    let mut statement = statement_for(&f, send_effect());
    statement.enabled_controls = 1;
    statement.lineage_burned_total = 77;
    let items = statement.field_items().expect("items");
    let mut expected = vec![int(1)];
    expected.extend(limb_items(&statement.relation_id));
    expected.extend(limb_items(&statement.scheme_id));
    expected.extend(limb_items(&statement.asset_digest));
    expected.extend(limb_items(&statement.credential_digest));
    expected.extend([int(1), int(3), int(0), int(1), int(77)]);
    expected.extend([
        LINEAGE_PENDING_ROOT,
        commitment(3).value,
        commitment(4).value,
    ]);
    expected.push(int(3));
    // `credit_id` is one σ-field element; every other digest two limbs (§3).
    expected.push(field_value(0x71));
    expected.extend(limb_items(&[0x72; 32]));
    expected.extend([int(4), int(1_000), int(10)]);
    expected.extend(limb_items(&[0x73; 32]));
    expected.extend([int(5), int(9)]);
    assert_eq!(items, expected);
    assert_eq!(items.len(), KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1);
    assert_eq!(
        statement.field_digest().ok(),
        Some(poseidon_items_v1(
            KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
            &expected
        ))
    );
    let mut other = statement;
    other.lineage_burned_total = 78;
    assert_ne!(other.field_digest().ok(), statement.field_digest().ok());

    // Every effect is zero-filled to the 10-element union after its tag at element 17.
    for effect in sample_effects(&f) {
        let items = statement_for(&f, effect).field_items().expect("items");
        assert_eq!(items[17], int(u128::from(effect.tag())));
        assert!(
            items[18 + effect.field_items_len()..]
                .iter()
                .all(|item| *item == [0; 32])
        );
    }
    let retiring = statement_for(&f, KagemushaWalletEffectV1::Retiring);
    let items = retiring.field_items().expect("items");
    assert_eq!(items[9], int(2));
    assert_eq!(items[14], LINEAGE_PENDING_ROOT);
    let mut invalid = bootstrap_statement(&f);
    invalid.successor = KagemushaWalletStateCommitmentV1::ZERO;
    assert!(is_invalid(invalid.field_items(), "statement.successor"));
    assert!(is_invalid(invalid.field_digest(), "statement.successor"));
    assert_eq!(
        KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1.to_le_bytes(),
        *b"kgwstmt1"
    );
}

#[test]
fn kagemusha_wallet_v1_statement_scheme_and_credential_bindings() {
    let f = android();
    let statement = bootstrap_statement(&f);
    statement.validate_for_scheme(&f.scheme).expect("scheme");
    statement
        .validate_for_credential(&f.credential)
        .expect("credential");
    let mut other_relation = statement;
    other_relation.relation_id = [0x99; 32];
    assert!(matches!(
        other_relation.validate_for_scheme(&f.scheme),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "statement.relation_id"
        })
    ));
    let mut other_scheme = statement;
    other_scheme.scheme_id = [0x98; 32];
    assert!(matches!(
        other_scheme.validate_for_scheme(&f.scheme),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert!(matches!(
        other_scheme.validate_for_credential(&f.credential),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));

    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x48);
    assert!(is_invalid(
        statement.validate_for_credential(&other.credential),
        "statement.credential_digest"
    ));
    let mut other_asset = statement;
    other_asset.asset_digest = [0x97; 32];
    assert!(is_invalid(
        other_asset.validate_for_credential(&f.credential),
        "statement.asset_digest"
    ));
    let mut other_enrollment = statement;
    other_enrollment.effect = KagemushaWalletEffectV1::Bootstrap {
        enrollment_id: [0x96; 32],
        enrollment_marker: MARKER,
    };
    assert!(is_invalid(
        other_enrollment.validate_for_credential(&f.credential),
        "effect.enrollment_id"
    ));

    let wallet_id = f.credential.body.wallet_id;
    let mut to_self = send_effect();
    if let KagemushaWalletEffectV1::Send {
        receiver_wallet_id, ..
    } = &mut to_self
    {
        *receiver_wallet_id = wallet_id;
    }
    assert!(is_invalid(
        statement_for(&f, to_self).validate_for_credential(&f.credential),
        "effect.receiver_wallet_id"
    ));
    let from_self = KagemushaWalletEffectV1::Receive {
        credit_id: [1; 32],
        payer_wallet_id: wallet_id,
        amount: 1,
    };
    assert!(is_invalid(
        statement_for(&f, from_self).validate_for_credential(&f.credential),
        "effect.payer_wallet_id"
    ));
    let wrong_nullifier = KagemushaWalletEffectV1::Unload {
        nullifier: kagemusha_wallet_unload_nullifier_v1(
            &f.credential.body.scheme_id,
            &wallet_id,
            3,
        ),
        redeem_ordinal: 2,
        amount: 1,
        online_charge: 0,
        charge_quote: [0; 32],
    };
    assert!(is_invalid(
        statement_for(&f, wrong_nullifier).validate_for_credential(&f.credential),
        "effect.nullifier"
    ));
    for effect in sample_effects(&f) {
        statement_for(&f, effect)
            .validate_for_credential(&f.credential)
            .expect("sample statement binds the credential");
    }
}

#[test]
fn kagemusha_wallet_v1_statement_successor_rules() {
    let f = android();
    let bootstrap = bootstrap_statement(&f);
    let load = |ordinal: u128, lifecycle| KagemushaWalletStatementV1 {
        predecessor: commitment(1),
        ..transition_statement(
            &f,
            1,
            ordinal + 1,
            lifecycle,
            KagemushaWalletEffectV1::Load {
                voucher: [0x62; 32],
                load_ordinal: ordinal,
                amount: 1,
                online_charge: 0,
            },
        )
    };
    let first = load(0, KagemushaWalletLifecycleV1::Active);
    first.validate_successor_of(&bootstrap).expect("first load");
    assert!(is_invalid(
        load(1, KagemushaWalletLifecycleV1::Active).validate_successor_of(&bootstrap),
        "statement.next_load"
    ));
    assert!(is_invalid(
        load(0, KagemushaWalletLifecycleV1::Retiring).validate_successor_of(&bootstrap),
        "statement.lifecycle"
    ));
    let mut unchained = first;
    unchained.predecessor = commitment(9);
    assert!(is_invalid(
        unchained.validate_successor_of(&bootstrap),
        "statement.predecessor"
    ));
    let mut skipped = first;
    skipped.sequence = 2;
    assert!(is_invalid(
        skipped.validate_successor_of(&bootstrap),
        "statement.sequence"
    ));
    let mut other_relation = first;
    other_relation.relation_id = [0x55; 32];
    assert!(matches!(
        other_relation.validate_successor_of(&bootstrap),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "statement.relation_id"
        })
    ));

    let retiring = KagemushaWalletStatementV1 {
        predecessor: commitment(2),
        ..transition_statement(
            &f,
            2,
            1,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Retiring,
        )
    };
    retiring.validate_successor_of(&first).expect("retire");
    let retiring_again = KagemushaWalletStatementV1 {
        predecessor: commitment(3),
        ..transition_statement(
            &f,
            3,
            1,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Retiring,
        )
    };
    assert!(is_invalid(
        retiring_again.validate_successor_of(&retiring),
        "statement.lifecycle"
    ));
    let reverted = KagemushaWalletStatementV1 {
        predecessor: commitment(3),
        ..transition_statement(&f, 3, 1, KagemushaWalletLifecycleV1::Active, send_effect())
    };
    assert!(is_invalid(
        reverted.validate_successor_of(&retiring),
        "statement.lifecycle"
    ));
    // A Retiring wallet keeps sending, receiving, loading issued vouchers, archiving,
    // unloading and refreshing policy (§6.3).
    let body = &f.credential.body;
    for effect in [
        send_effect(),
        KagemushaWalletEffectV1::Receive {
            credit_id: field_value(0x75),
            payer_wallet_id: [0x76; 32],
            amount: 3,
        },
        KagemushaWalletEffectV1::ArchiveSent {
            credit_id: field_value(0x71),
            credited: field_value(0x78),
        },
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&body.scheme_id, &body.wallet_id, 0),
            redeem_ordinal: 0,
            amount: 1,
            online_charge: 0,
            charge_quote: [0; 32],
        },
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: [0x7a; 32],
            accepted_time_floor_ms: 0,
        },
    ] {
        let late = KagemushaWalletStatementV1 {
            predecessor: commitment(3),
            ..transition_statement(&f, 3, 1, KagemushaWalletLifecycleV1::Retiring, effect)
        };
        late.validate_successor_of(&retiring)
            .expect("a retiring wallet keeps operating");
    }
    let late_load = KagemushaWalletStatementV1 {
        predecessor: commitment(3),
        ..transition_statement(
            &f,
            3,
            2,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Load {
                voucher: [0x63; 32],
                load_ordinal: 1,
                amount: 1,
                online_charge: 0,
            },
        )
    };
    late_load
        .validate_successor_of(&retiring)
        .expect("a retiring wallet loads issued vouchers");
    let mut late_send = reverted;
    late_send.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    let mut stale_load = late_send;
    stale_load.next_load = 0;
    assert!(is_invalid(
        stale_load.validate_successor_of(&retiring),
        "statement.next_load"
    ));

    let mut other_credential = late_send;
    other_credential.credential_digest = [0x44; 32];
    assert!(is_invalid(
        other_credential.validate_successor_of(&retiring),
        "statement.credential_digest"
    ));
    let replacement = KagemushaWalletStatementV1 {
        credential_digest: [0x44; 32],
        predecessor: commitment(3),
        ..transition_statement(
            &f,
            3,
            1,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                update: [0x44; 32],
                accepted_time_floor_ms: 0,
            },
        )
    };
    replacement
        .validate_successor_of(&retiring)
        .expect("replacement credential changes the statement credential");
}

#[test]
fn kagemusha_wallet_v1_statement_consumer_checks_against_lineage() {
    let f = android();
    let statement = statement_for(&f, send_effect());
    let omega = lineage_for(&f.credential, &statement).public;
    statement
        .validate_against_lineage(&omega)
        .expect("consumer checks");
    let retiring = statement_for(&f, KagemushaWalletEffectV1::Retiring);
    let retiring_omega = lineage_for(&f.credential, &retiring).public;
    assert_eq!(retiring_omega.lifecycle, KagemushaWalletLifecycleV1::Active);
    retiring
        .validate_against_lineage(&retiring_omega)
        .expect("retiring consumes an Active head");

    let reject = |mutate: &dyn Fn(&mut KagemushaWalletLineagePublicV1), field: &str| {
        let mut omega = omega;
        mutate(&mut omega);
        assert!(
            is_invalid(statement.validate_against_lineage(&omega), field),
            "{field}"
        );
    };
    reject(&|o| o.head = commitment(9), "lineage.head");
    reject(
        &|o| o.credential_digest = [0x41; 32],
        "lineage.credential_digest",
    );
    reject(&|o| o.burned_total = 1, "lineage.burned_total");
    reject(
        &|o| o.pending_outgoing_root = field_value(0x42),
        "lineage.pending_outgoing_root",
    );
    reject(&|o| o.enabled_controls = 1, "lineage.enabled_controls");
    reject(
        &|o| o.lifecycle = KagemushaWalletLifecycleV1::Retiring,
        "lineage.lifecycle",
    );
    reject(&|o| o.wallet_id = [0x72; 32], "effect.receiver_wallet_id");
    let mut other_relation = omega;
    other_relation.relation_id = [0x43; 32];
    assert!(matches!(
        statement.validate_against_lineage(&other_relation),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "lineage.relation_id"
        })
    ));
    // A σ_send fed the stale core burned_total instead of Ω(pred)'s is rejected (§11).
    let mut stale = statement;
    stale.lineage_burned_total = 5;
    assert!(is_invalid(
        stale.validate_against_lineage(&omega),
        "lineage.burned_total"
    ));
    let load = statement_for(
        &f,
        KagemushaWalletEffectV1::Load {
            voucher: [1; 32],
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    assert!(is_invalid(
        load.validate_against_lineage(&omega),
        "statement.lineage"
    ));
}

#[test]
fn kagemusha_wallet_v1_step_and_lineage_proofs() {
    let f = android();
    stand_in_proof(1).validate().expect("one byte");
    assert!(is_invalid(stand_in_proof(0).validate(), "step_proof.bytes"));

    let statement = statement_for(&f, send_effect());
    let lineage = lineage_for(&f.credential, &statement);
    lineage.validate().expect("lineage");
    let public = lineage.public;
    let mut expected = 1_u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&public.scheme_id);
    expected.extend_from_slice(&public.relation_id);
    expected.extend_from_slice(&public.head.value);
    expected.extend_from_slice(&public.wallet_id);
    expected.extend_from_slice(&public.credential_digest);
    expected.extend_from_slice(public.payment_key.as_sec1_bytes());
    expected.push(1);
    expected.extend_from_slice(&0_u64.to_le_bytes());
    expected.extend_from_slice(&0_u32.to_le_bytes());
    expected.extend_from_slice(&0_u128.to_le_bytes());
    expected.extend_from_slice(&LINEAGE_PENDING_ROOT);
    expected.extend_from_slice(&CREDIT_DIGEST_ROOT);
    assert_eq!(public.transcript(), expected);
    let mut bytes = expected.clone();
    bytes.extend_from_slice(&lineage.proof);
    assert_eq!(lineage.bytes(), bytes);
    assert_eq!(
        lineage.lineage_digest(),
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, &bytes)
    );

    let reject = |mutate: &dyn Fn(&mut KagemushaWalletLineageV1), field: &str| {
        let mut lineage = lineage.clone();
        mutate(&mut lineage);
        assert!(is_invalid(lineage.validate(), field), "{field}");
    };
    reject(&|l| l.proof.clear(), "lineage.proof");
    reject(&|l| l.public.wallet_id = [0; 32], "lineage.wallet_id");
    reject(
        &|l| l.public.head = KagemushaWalletStateCommitmentV1::ZERO,
        "lineage.head",
    );
    reject(
        &|l| l.public.credit_digest_root = [0xff; 32],
        "lineage.credit_digest_root",
    );
    reject(
        &|l| l.public.pending_outgoing_root = [0; 32],
        "lineage.pending_outgoing_root",
    );
    reject(
        &|l| l.public.enabled_controls = 0x100,
        "lineage.enabled_controls",
    );
    let mut version = lineage.clone();
    version.public.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    // Slots: present exactly for Send, Unload and Retiring.
    let present = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage.clone(),
    };
    present
        .validate_for(KagemushaWalletOperationKindV1::Send)
        .expect("send slot");
    KagemushaWalletLineageSlotV1::None
        .validate_for(KagemushaWalletOperationKindV1::Receive)
        .expect("receive slot");
    assert!(is_invalid(
        present.validate_for(KagemushaWalletOperationKindV1::Load),
        "lineage.slot"
    ));
    assert!(is_invalid(
        KagemushaWalletLineageSlotV1::None.validate_for(KagemushaWalletOperationKindV1::Unload),
        "lineage.slot"
    ));
    assert_eq!(present.lineage(), Some(&lineage));
    assert_eq!(KagemushaWalletLineageSlotV1::None.lineage(), None);
}

#[test]
fn kagemusha_wallet_v1_proof_digest_domains() {
    let f = android();
    let step = stand_in_proof(3);
    let statement = statement_for(&f, send_effect());
    let lineage = lineage_for(&f.credential, &statement);

    // σ-only domain: P_bytes(kgwstep1, LE32 len(σ) || σ) (§4.1, owner answer Q9).
    let mut body = 3_u32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0, 1, 2]);
    for kind in [
        KagemushaWalletOperationKindV1::Bootstrap,
        KagemushaWalletOperationKindV1::Load,
        KagemushaWalletOperationKindV1::Receive,
        KagemushaWalletOperationKindV1::ArchiveSent,
        KagemushaWalletOperationKindV1::RefreshPolicy,
    ] {
        assert_eq!(
            kagemusha_wallet_proof_digest_v1(kind, None, &step).expect("digest"),
            kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1, &body)
        );
        assert!(is_invalid(
            kagemusha_wallet_proof_digest_v1(kind, Some(&lineage), &step),
            "proof_digest.lineage"
        ));
    }

    // Ω‖σ domain: P_bytes(kgwprf_1, LE32 len(Ω) || Ω || LE32 len(σ) || σ).
    let omega = lineage.bytes();
    let mut body = u32::try_from(omega.len())
        .expect("len")
        .to_le_bytes()
        .to_vec();
    body.extend_from_slice(&omega);
    body.extend_from_slice(&3_u32.to_le_bytes());
    body.extend_from_slice(&[0, 1, 2]);
    for kind in [
        KagemushaWalletOperationKindV1::Send,
        KagemushaWalletOperationKindV1::Unload,
        KagemushaWalletOperationKindV1::Retiring,
    ] {
        let digest = kagemusha_wallet_proof_digest_v1(kind, Some(&lineage), &step).expect("digest");
        assert_eq!(
            digest,
            kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, &body)
        );
        // One canonical σ-field value.
        assert!(kagemusha_wallet_is_canonical_field_v1(&digest));
        assert_eq!(
            digest,
            kagemusha_wallet_poseidon_v1(
                KAGEMUSHA_WALLET_PROOF_DOMAIN_V1,
                &kagemusha_wallet_packed_bytes_v1(&body)
            )
            .expect("packed")
        );
        assert!(is_invalid(
            kagemusha_wallet_proof_digest_v1(kind, None, &step),
            "proof_digest.lineage"
        ));
    }
    // The same σ under the two domains never collides, and Ω is bound byte for byte.
    assert_ne!(
        kagemusha_wallet_proof_digest_v1(KagemushaWalletOperationKindV1::Load, None, &step)
            .expect("digest"),
        kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Send,
            Some(&lineage),
            &step
        )
        .expect("digest")
    );
    let mut other = lineage.clone();
    other.proof[0] ^= 1;
    assert_ne!(
        kagemusha_wallet_proof_digest_v1(KagemushaWalletOperationKindV1::Send, Some(&other), &step)
            .expect("digest"),
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, &body)
    );
    assert!(is_invalid(
        kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Load,
            None,
            &stand_in_proof(0)
        ),
        "step_proof.bytes"
    ));
}

#[test]
fn kagemusha_wallet_v1_receipt_sign_verify_and_bindings() {
    let f = android();
    let statement = statement_for(&f, send_effect());
    let lineage = lineage_for(&f.credential, &statement);
    let proof = stand_in_proof(64);
    let proof_digest = kagemusha_wallet_proof_digest_v1(
        KagemushaWalletOperationKindV1::Send,
        Some(&lineage),
        &proof,
    )
    .expect("proof digest");
    let signer = KagemushaWalletReceiptSignerV1::from_credential(&f.credential).expect("signer");
    assert_eq!(
        KagemushaWalletReceiptSignerV1::from_lineage(&lineage.public).expect("Ω signer"),
        signer
    );
    let body =
        KagemushaWalletReceiptBodyV1::derive(&signer, &statement, &proof_digest, CAPSULE, [0; 32])
            .expect("receipt body");
    let mut expected = 1_u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&f.credential.body.scheme_id);
    expected.extend_from_slice(&f.credential.body.wallet_id);
    expected.extend_from_slice(&f.credential.body.provider_contract);
    expected.extend_from_slice(&3_u128.to_le_bytes());
    expected.extend_from_slice(&statement.operation_id(&f.credential.body.wallet_id));
    expected.extend_from_slice(&commitment(3).transcript());
    expected.extend_from_slice(&commitment(4).transcript());
    expected.extend_from_slice(&statement.statement_digest());
    expected.extend_from_slice(&proof_digest);
    expected.extend_from_slice(&CAPSULE);
    expected.extend_from_slice(&[0; 32]);
    assert_eq!(body.transcript(), expected);
    assert_eq!(
        body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Receipt, &expected)
    );
    assert_eq!(
        body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Receipt, &expected)
    );

    let receipt = KagemushaWalletReceiptV1::sign(
        &f.credential,
        &statement,
        &proof_digest,
        CAPSULE,
        [0; 32],
        raw_output(&f.payment, &body.signing_message()),
    )
    .expect("receipt");
    assert_eq!(receipt.operation_id, body.operation_id);
    let digest = receipt
        .verify(&signer, &statement, &proof_digest)
        .expect("verify");
    assert_eq!(
        digest,
        kagemusha_wallet_signed_object_digest_v1(
            Role::Receipt,
            &body.signing_message(),
            &receipt.signature
        )
    );
    assert_eq!(
        receipt
            .body(&signer, &statement, &proof_digest)
            .expect("body"),
        body
    );

    // Another key, another proof digest, another statement, another operation identity or
    // another Payment digest fail.
    let wrong_key = KagemushaWalletReceiptV1::sign(
        &f.credential,
        &statement,
        &proof_digest,
        CAPSULE,
        [0; 32],
        raw_output(&signing_key(0x5e), &body.signing_message()),
    );
    assert!(matches!(
        wrong_key,
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::Receipt
        })
    ));
    assert!(matches!(
        receipt.verify(&signer, &statement, &field_value(0x65)),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
    ));
    // `proof_digest` and the Payment digest are canonical σ-field values (owner answer Q9).
    assert!(is_invalid(
        receipt.verify(&signer, &statement, &[0x65; 32]),
        "receipt.proof_digest"
    ));
    let mut wide_payment = receipt;
    wide_payment.payment_digest = [0xff; 32];
    assert!(is_invalid(
        wide_payment.validate(),
        "receipt.payment_digest"
    ));
    let mut later = statement;
    later.next_load = 1;
    assert!(matches!(
        receipt.verify(&signer, &later, &proof_digest),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
    ));
    let mut other_operation = receipt;
    other_operation.operation_id = [0x31; 32];
    assert!(is_invalid(
        other_operation.verify(&signer, &statement, &proof_digest),
        "receipt.operation_id"
    ));
    let mut other_capsule = receipt;
    other_capsule.capsule_digest = [0x32; 32];
    assert!(matches!(
        other_capsule.verify(&signer, &statement, &proof_digest),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
    ));
    let mut with_payment = receipt;
    with_payment.payment_digest = [0x33; 32];
    assert!(is_invalid(
        with_payment.verify(&signer, &statement, &proof_digest),
        "receipt.payment_digest"
    ));
    let mut zero_capsule = receipt;
    zero_capsule.capsule_digest = [0; 32];
    assert!(is_invalid(
        zero_capsule.validate(),
        "receipt.capsule_digest"
    ));
    assert!(is_invalid(
        KagemushaWalletReceiptBodyV1::derive(&signer, &statement, &proof_digest, [0; 32], [0; 32]),
        "receipt.capsule_digest"
    ));
    assert!(is_invalid(
        KagemushaWalletReceiptBodyV1::derive(&signer, &statement, &[0; 32], CAPSULE, [0; 32]),
        "receipt.proof_digest"
    ));
    let mut other_scheme = signer;
    other_scheme.scheme_id = [0x34; 32];
    assert!(matches!(
        KagemushaWalletReceiptBodyV1::derive(
            &other_scheme,
            &statement,
            &proof_digest,
            CAPSULE,
            [0; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut version = receipt;
    version.version = 0;
    assert!(matches!(
        version.verify(&signer, &statement, &proof_digest),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    // A Receive receipt binds the full Payment digest; σ_recv's statement does not.
    let receive = statement_for(&f, sample_effects(&f)[3]);
    let receive_proof =
        kagemusha_wallet_proof_digest_v1(KagemushaWalletOperationKindV1::Receive, None, &proof)
            .expect("digest");
    assert!(is_invalid(
        KagemushaWalletReceiptBodyV1::derive(&signer, &receive, &receive_proof, CAPSULE, [0; 32]),
        "receipt.payment_digest"
    ));
    let receive_body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        &receive,
        &receive_proof,
        CAPSULE,
        RECEIVE_PAYMENT,
    )
    .expect("receive body");
    assert_eq!(receive_body.transcript()[306..], RECEIVE_PAYMENT);
}

#[test]
fn kagemusha_wallet_v1_package_verify_digest_and_flips() {
    let f = android();
    let statement = statement_for(&f, send_effect());
    let package = signed_package(&f, &f.credential, &statement, stand_in_proof(96));
    let digests = package.verify(&f.credential).expect("verify");
    assert_eq!(digests.statement, statement.statement_digest());
    assert_eq!(digests.proof, package.proof_digest().expect("proof digest"));
    let mut transcript = digests.statement.to_vec();
    transcript.extend_from_slice(&digests.proof);
    transcript.extend_from_slice(&digests.receipt);
    assert_eq!(
        digests.package,
        kagemusha_wallet_digest_v1(Role::Package, &transcript)
    );
    assert_eq!(
        kagemusha_wallet_package_digest_v1(&digests.statement, &digests.proof, &digests.receipt),
        digests.package
    );
    assert_eq!(
        package.package_digest(&f.credential).expect("digest"),
        digests.package
    );
    // A consumer without the payer credential verifies τ under Ω.payment_key.
    let (signer, consumer) = package.check_lineage_consumer().expect("consumer");
    assert_eq!(consumer, digests);
    assert_eq!(signer.wallet_id, f.credential.body.wallet_id);
    assert_eq!(
        package.verifying_key_selector(),
        (KagemushaWalletOperationKindV1::Send, 0)
    );

    let frame = norito::encode_canonical(&package).expect("encode");
    let decoded: KagemushaWalletPackageV1 =
        decode_frame_v1(&frame, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1).expect("decode");
    assert_eq!(decoded, package);
    assert_every_flip_rejected_or_rebound(&frame, digests.package, |bytes| {
        let package: KagemushaWalletPackageV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1).ok()?;
        package.package_digest(&f.credential).ok()
    });

    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox, 0x49);
    assert!(is_invalid(
        package.verify(&other.credential),
        "statement.credential_digest"
    ));
    let mut empty_proof = package.clone();
    empty_proof.step_proof = stand_in_proof(0);
    assert!(is_invalid(
        empty_proof.verify(&f.credential),
        "step_proof.bytes"
    ));
    let mut no_lineage = package.clone();
    no_lineage.lineage = KagemushaWalletLineageSlotV1::None;
    assert!(is_invalid(no_lineage.verify(&f.credential), "lineage.slot"));
    assert!(is_invalid(
        no_lineage.check_lineage_consumer(),
        "lineage.slot"
    ));
    let mut stale_burn = package.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut stale_burn.lineage {
        lineage.public.burned_total = 9;
    }
    assert!(is_invalid(stale_burn.validate(), "lineage.burned_total"));
    // A relay-rewritten Ω key fails τ, and a foreign Ω wallet fails the credential binding.
    let mut rewritten_key = package.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut rewritten_key.lineage {
        lineage.public.payment_key = other.credential.body.payment_key;
    }
    assert!(rewritten_key.check_lineage_consumer().is_err());
    assert!(is_invalid(
        rewritten_key.verify(&f.credential),
        "lineage.payment_key"
    ));
    let mut foreign_wallet = package.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut foreign_wallet.lineage {
        lineage.public.wallet_id = [0x5f; 32];
    }
    assert!(is_invalid(
        foreign_wallet.verify(&f.credential),
        "lineage.wallet_id"
    ));
    let mut version = package;
    version.version = 2;
    assert!(matches!(
        version.verify(&f.credential),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "package.version",
            ..
        })
    ));
}

#[test]
fn kagemusha_wallet_v1_receive_package_binds_payment_digest() {
    let f = android();
    let statement = statement_for(&f, sample_effects(&f)[3]);
    let package = signed_package(&f, &f.credential, &statement, stand_in_proof(40));
    assert_eq!(package.receipt.payment_digest, RECEIVE_PAYMENT);
    package.verify(&f.credential).expect("receive package");
    assert_eq!(
        package.verifying_key_selector(),
        (KagemushaWalletOperationKindV1::Receive, 0)
    );
    let mut zero_payment = package.clone();
    zero_payment.receipt.payment_digest = [0; 32];
    assert!(is_invalid(
        zero_payment.validate(),
        "package.receipt.payment_digest"
    ));
    let mut other_payment = package.clone();
    other_payment.receipt.payment_digest = field_value(0x7e);
    assert!(matches!(
        other_payment.verify(&f.credential),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
    ));
    let send = signed_package(
        &f,
        &f.credential,
        &statement_for(&f, send_effect()),
        stand_in_proof(40),
    );
    let mut send_with_payment = send;
    send_with_payment.receipt.payment_digest = field_value(0x7e);
    assert!(is_invalid(
        send_with_payment.validate(),
        "package.receipt.payment_digest"
    ));
    let mut with_lineage = package;
    with_lineage.lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage_for(&f.credential, &statement_for(&f, send_effect())),
    };
    assert!(is_invalid(with_lineage.validate(), "lineage.slot"));
}

#[test]
fn kagemusha_wallet_v1_replacement_credential_package() {
    let f = android();
    let mut body = f.credential.body;
    body.renewal_sequence = 1;
    body.issued_at_ms += 60_000;
    body.fresh_evidence.time_ms = body.issued_at_ms - 500;
    let replacement = f.issue(&body).expect("replacement");
    replacement
        .validate_replacement_of(&f.credential)
        .expect("replacement rules");
    let statement = KagemushaWalletStatementV1 {
        credential_digest: replacement.credential_digest(),
        ..statement_for(
            &f,
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                update: replacement.credential_digest(),
                accepted_time_floor_ms: body.issued_at_ms,
            },
        )
    };
    // The receipt is signed by the unchanged payment key and verified against the new credential.
    let package = signed_package(&f, &replacement, &statement, stand_in_proof(32));
    package.verify(&replacement).expect("replacement package");
    assert!(is_invalid(
        package.verify(&f.credential),
        "statement.credential_digest"
    ));
}

#[test]
fn kagemusha_wallet_v1_package_size_overheads() {
    let f = android();
    let statement = statement_for(&f, send_effect());
    for (lineage_len, step_len) in [(1_000, 3_296), (4_000, 3_296)] {
        let package = signed_package_with(
            &f,
            &f.credential,
            &statement,
            KagemushaWalletLineageSlotV1::Present {
                lineage: lineage_with_len(&f.credential, &statement, lineage_len),
            },
            stand_in_proof(step_len),
            [0; 32],
        );
        let frame = norito::encode_canonical(&package).expect("encode");
        let overhead = frame.len() - lineage_len - step_len;
        println!(
            "KAGEMUSHA wallet V1 Send package with |Ω proof| = {lineage_len}, |σ| = {step_len}: \
             {} bytes (overhead {overhead})",
            frame.len()
        );
        assert!(frame.len() < KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
        assert!(overhead < 1_536, "package overhead {overhead}");
    }
}

#[test]
fn kagemusha_wallet_v1_bootstrap_state_core_and_rest() {
    let f = android();
    let state = bootstrap_state(&f, 0x5c);
    assert_eq!(state.version, KAGEMUSHA_WALLET_VERSION_V1);
    let core = state.core;
    let rest = state.rest;
    let body = &f.credential.body;
    // Scheme and asset are core fields (owner answer Q4).
    assert_eq!(core.scheme_id, body.scheme_id);
    assert_eq!(core.asset_digest, body.asset_digest);
    assert_eq!(core.wallet_id, body.wallet_id);
    assert_eq!(core.credential_digest, f.credential.credential_digest());
    assert_eq!(core.lifecycle, KagemushaWalletLifecycleV1::Active);
    assert_eq!(
        (
            core.balance,
            core.burned_total,
            core.sequence,
            core.next_send,
            core.next_load,
            core.next_redeem
        ),
        (0, 0, 0, 0, 0, 0)
    );
    // Empty chains are the field zero; every map starts at the empty depth-256 root (§3.2),
    // with one load/redeem recovery root (owner answer Q3).
    assert_eq!((core.send_chain, core.recv_chain), ([0; 32], [0; 32]));
    let empty = kagemusha_wallet_empty_map_root_v1();
    for root in [
        core.consumed_credit_root,
        core.pending_outgoing_root,
        core.load_redeem_recovery_root,
        core.fee_claim_root,
        core.quota_usage_root,
    ] {
        assert_eq!(root, empty);
    }
    assert_eq!(empty, KagemushaWalletIndexedTreeV1::new().root());
    assert_eq!(core.quota_windows_root, [0; 32]);
    assert_eq!((core.blacklist_version, core.blacklist_root), (0, [0; 32]));
    // The blacklist issue time and maximum age are core fields (owner answer Q5).
    assert_eq!(core.blacklist_issued_at_ms, 0);
    assert_eq!(
        core.blacklist_max_age_ms,
        body.regulatory_policy.blacklist_max_age_ms
    );
    assert_eq!(core.lease_expires_at_ms, 0);
    assert_eq!(core.accepted_time_floor_ms, 0);
    assert_eq!(core.enabled_controls, 0);
    assert_eq!(
        rest.permitted_controls,
        body.regulatory_policy.permitted_controls
    );
    assert_eq!(
        rest.time_anchor_max_response_ms,
        body.regulatory_policy.time_anchor_max_response_ms
    );
    assert_eq!(state.regulatory_policy(), body.regulatory_policy);
    assert!(!state.send_requires_time_anchor());
    assert!(!state.is_active(0));
    state
        .validate_for_credential(&f.credential)
        .expect("credential");

    let frame = norito::encode_canonical(&state).expect("encode");
    let decoded: KagemushaWalletStateV1 = decode_frame_v1(&frame, 4_096).expect("decode");
    assert_eq!(decoded, state);

    assert!(is_invalid(
        KagemushaWalletStateV1::bootstrap(&f.credential, [0; 32]),
        "state.core.state_nonce"
    ));
    assert!(is_invalid(
        KagemushaWalletStateV1::bootstrap(&f.credential, [0x5c; 32]),
        "state.core.state_nonce"
    ));
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x4a);
    assert!(state.validate_for_credential(&other.credential).is_err());
    let mut other_lease = state;
    other_lease.core.lease_expires_at_ms = 5;
    assert!(other_lease.validate_for_credential(&f.credential).is_err());
    let mut other_asset = state;
    other_asset.core.asset_digest = [0x41; 32];
    assert!(is_invalid(
        other_asset.validate_for_credential(&f.credential),
        "state.core.asset_digest"
    ));
    let mut other_scheme = state;
    other_scheme.core.scheme_id = [0x42; 32];
    assert!(matches!(
        other_scheme.validate_for_credential(&f.credential),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "state.core.scheme_id"
        })
    ));

    let reject = |mutate: &dyn Fn(&mut KagemushaWalletStateV1), field: &str| {
        let mut state = state;
        mutate(&mut state);
        assert!(is_invalid(state.validate(), field), "{field}");
    };
    reject(
        &|s| s.core.enabled_controls = KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1,
        "state.core.enabled_controls",
    );
    reject(&|s| s.core.policy_epoch = 1, "state.scheme_policy");
    reject(&|s| s.rest.scheme_policy = [1; 32], "state.scheme_policy");
    reject(&|s| s.rest.fee_schedule = [1; 32], "state.scheme_policy");
    reject(&|s| s.core.blacklist_version = 1, "state.blacklist");
    reject(&|s| s.core.blacklist_issued_at_ms = 1, "state.blacklist");
    reject(
        &|s| {
            s.core.blacklist_version = 1;
            s.rest.blacklist = [1; 32];
        },
        "state.blacklist",
    );
    reject(
        &|s| s.core.blacklist_max_age_ms = 5,
        "regulatory_policy.blacklist_max_age_ms",
    );
    reject(
        &|s| s.rest.permitted_controls = 0x80,
        "regulatory_policy.permitted_controls",
    );
    reject(&|s| s.rest.quota_share_id = 1, "state.quota_share");
    reject(
        &|s| s.core.quota_windows_root = [1; 32],
        "state.quota_share",
    );
    // The blacklist and quota-window roots are Poseidon roots (§7).
    reject(
        &|s| s.core.quota_windows_root = [0xff; 32],
        "state.core.quota_windows_root",
    );
    reject(
        &|s| s.core.blacklist_root = KAGEMUSHA_WALLET_FIELD_MODULUS_V1,
        "state.core.blacklist_root",
    );
    reject(
        &|s| s.core.quota_usage_root = [0; 32],
        "state.core.quota_usage_root",
    );
    reject(
        &|s| s.core.load_redeem_recovery_root = [0xff; 32],
        "state.core.load_redeem_recovery_root",
    );
    reject(
        &|s| s.core.consumed_credit_root = [0xff; 32],
        "state.core.consumed_credit_root",
    );
    reject(
        &|s| s.core.send_chain = KAGEMUSHA_WALLET_FIELD_MODULUS_V1,
        "state.core.send_chain",
    );
    reject(&|s| s.core.recv_chain = [0xff; 32], "state.core.recv_chain");
    reject(
        &|s| s.core.lease_expires_at_ms = 1,
        "state.core.lease_expires_at_ms",
    );
    reject(&|s| s.core.scheme_id = [0; 32], "state.core.scheme_id");
    reject(
        &|s| s.core.asset_digest = [0; 32],
        "state.core.asset_digest",
    );
    reject(&|s| s.core.wallet_id = [0; 32], "state.core.wallet_id");
    let mut held = state;
    held.core.policy_epoch = 1;
    held.rest.scheme_policy = [1; 32];
    held.rest.fee_schedule = [2; 32];
    held.core.blacklist_version = 3;
    held.rest.blacklist = [3; 32];
    held.core.blacklist_root = field_value(4);
    held.core.blacklist_issued_at_ms = 11;
    held.rest.quota_share_id = 5;
    held.rest.quota_share = [5; 32];
    held.core.quota_windows_root = field_value(6);
    held.core.send_chain = field_value(7);
    held.core.recv_chain = field_value(8);
    held.core.burned_total = 9;
    held.validate().expect("held policy objects");
    assert!(!held.is_active(0));
    let mut version = state;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

/// A stand-in digest of [`controlled_state`] whose two limbs differ: 16 bytes `seed`, then 16
/// bytes `seed ^ 0x40`.
const fn controlled_digest(seed: u8) -> [u8; 32] {
    let mut digest = [seed; 32];
    let mut index = 16;
    while index < 32 {
        digest[index] = seed ^ 0x40;
        index += 1;
    }
    digest
}

/// `base` with every core and rest field other than the four identities set to a distinct
/// value the state rules admit: Retiring, every control permitted and enabled, a held scheme
/// policy, blacklist (with a list-age rule) and quota share, a lease, and distinct map roots,
/// chains and counters.
///
/// No two core elements and no two rest elements of this state are equal, so its element lists
/// pin every position (owner answers Q3, Q4 and Q5 placed the load/redeem root, scheme, asset
/// and the blacklist age fields); the shared vector `field_encodings.controlled_state` is this
/// state over the vectored receiver's identities.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn controlled_state(
    base: &KagemushaWalletStateV1,
) -> KagemushaWalletStateV1 {
    let mut state = *base;
    let core = &mut state.core;
    core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    core.balance = 1_000_001;
    core.burned_total = 1_000_002;
    core.sequence = 1_000_003;
    core.next_send = 1_000_004;
    core.next_load = 1_000_005;
    core.next_redeem = 1_000_006;
    core.send_chain = field_value(0x71);
    core.recv_chain = field_value(0x72);
    core.consumed_credit_root = field_value(0x73);
    core.pending_outgoing_root = field_value(0x74);
    core.load_redeem_recovery_root = field_value(0x75);
    core.fee_claim_root = field_value(0x76);
    core.quota_usage_root = field_value(0x77);
    core.enabled_controls = KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1;
    core.quota_windows_root = field_value(0x78);
    core.blacklist_version = 1_000_007;
    core.blacklist_root = field_value(0x79);
    core.blacklist_issued_at_ms = 1_000_008;
    core.blacklist_max_age_ms = 1_000_009;
    core.lease_expires_at_ms = 1_000_010;
    core.policy_epoch = 1_000_011;
    core.accepted_time_floor_ms = 1_000_012;
    core.state_nonce = field_value(0x7a);
    let rest = &mut state.rest;
    rest.permitted_controls = KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1;
    rest.time_anchor_max_response_ms = 1_000_013;
    rest.scheme_policy = controlled_digest(0x81);
    rest.fee_schedule = controlled_digest(0x82);
    rest.blacklist = controlled_digest(0x83);
    rest.quota_share = controlled_digest(0x84);
    rest.quota_share_id = 1_000_014;
    rest.time_anchor = controlled_digest(0x85);
    state.validate().expect("controlled state");
    state
}

#[test]
fn kagemusha_wallet_v1_state_core_and_rest_field_items() {
    let f = android();
    let state = controlled_state(&bootstrap_state(&f, 0x5c));
    let core = state.core;
    let mut expected = vec![int(2)];
    expected.extend(limb_items(&core.scheme_id));
    expected.extend(limb_items(&core.asset_digest));
    expected.extend(limb_items(&core.wallet_id));
    expected.extend(limb_items(&core.credential_digest));
    // balance, burned_total, sequence, next_send, next_load, next_redeem.
    expected.extend((1_000_001..=1_000_006).map(int));
    // send_chain, recv_chain; the consumed-credit, pending-outgoing, load/redeem-recovery,
    // fee-claim and quota-usage roots (one element each).
    expected.extend((0x71..=0x77).map(field_value));
    // Mask, quota-windows root (one element), blacklist version, root (one element), issue
    // time and maximum age, lease, epoch, floor, nonce.
    expected.extend([
        int(7),
        field_value(0x78),
        int(1_000_007),
        field_value(0x79),
        int(1_000_008),
        int(1_000_009),
        int(1_000_010),
        int(1_000_011),
        int(1_000_012),
        field_value(0x7a),
    ]);
    assert_eq!(state.core_field_items().expect("core"), expected);
    assert_eq!(expected.len(), KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1);
    // Every position holds its own value.
    let distinct: std::collections::BTreeSet<_> = expected.iter().collect();
    assert_eq!(distinct.len(), KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1);
    let core_items = expected;

    let mut expected = vec![int(7), int(1_000_013)];
    for seed in [0x81, 0x82, 0x83, 0x84] {
        expected.extend(limb_items(&controlled_digest(seed)));
    }
    expected.push(int(1_000_014));
    expected.extend(limb_items(&controlled_digest(0x85)));
    assert_eq!(state.rest_field_items().expect("rest"), expected);
    assert_eq!(expected.len(), KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1);
    let distinct: std::collections::BTreeSet<_> = expected.iter().collect();
    assert_eq!(distinct.len(), KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1);

    // The commitment is P(kgwcore1, core || P(kgwrest1, rest)) (owner answer Q10).
    let rest_digest =
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_REST_DOMAIN_V1, &expected).expect("rest");
    assert_eq!(state.rest_digest().ok(), Some(rest_digest));
    let mut preimage = core_items;
    preimage.push(rest_digest);
    let commitment =
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &preimage).expect("core");
    assert_eq!(state.commitment().expect("commitment").value, commitment);
    assert!(state.commitment().expect("commitment").is_complete());

    let mut invalid = state;
    invalid.core.state_nonce = [0; 32];
    assert!(is_invalid(
        invalid.core_field_items(),
        "state.core.state_nonce"
    ));
    assert!(is_invalid(
        invalid.rest_field_items(),
        "state.core.state_nonce"
    ));
    assert!(is_invalid(invalid.commitment(), "state.core.state_nonce"));
    assert_eq!(KAGEMUSHA_WALLET_CORE_DOMAIN_V1.to_le_bytes(), *b"kgwcore1");
    assert_eq!(KAGEMUSHA_WALLET_REST_DOMAIN_V1.to_le_bytes(), *b"kgwrest1");
}

/// One named mutation of a wallet state.
type StateMutation = (&'static str, fn(&mut KagemushaWalletStateV1));

#[test]
fn kagemusha_wallet_v1_state_commitment_binds_every_field() {
    let f = android();
    let state = controlled_state(&bootstrap_state(&f, 0x5c));
    let base = state.commitment().expect("commitment");
    // One valid mutation per core field (in core order), then per rest field.
    let core_mutations: [StateMutation; 28] = [
        ("lifecycle", |s| {
            s.core.lifecycle = KagemushaWalletLifecycleV1::Active;
        }),
        ("scheme_id", |s| s.core.scheme_id[0] ^= 1),
        ("asset_digest", |s| s.core.asset_digest[0] ^= 1),
        ("wallet_id", |s| s.core.wallet_id[0] ^= 1),
        ("credential_digest", |s| s.core.credential_digest[0] ^= 1),
        ("balance", |s| s.core.balance += 1),
        ("burned_total", |s| s.core.burned_total += 1),
        ("sequence", |s| s.core.sequence += 1),
        ("next_send", |s| s.core.next_send += 1),
        ("next_load", |s| s.core.next_load += 1),
        ("next_redeem", |s| s.core.next_redeem += 1),
        ("send_chain", |s| s.core.send_chain = field_value(0x27)),
        ("recv_chain", |s| s.core.recv_chain = field_value(0x27)),
        ("consumed_credit_root", |s| {
            s.core.consumed_credit_root = field_value(0x27);
        }),
        ("pending_outgoing_root", |s| {
            s.core.pending_outgoing_root = field_value(0x27);
        }),
        ("load_redeem_recovery_root", |s| {
            s.core.load_redeem_recovery_root = field_value(0x27);
        }),
        ("fee_claim_root", |s| {
            s.core.fee_claim_root = field_value(0x27);
        }),
        ("quota_usage_root", |s| {
            s.core.quota_usage_root = field_value(0x27);
        }),
        ("enabled_controls", |s| {
            s.core.enabled_controls = KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1;
        }),
        ("quota_windows_root", |s| {
            s.core.quota_windows_root = field_value(0x27);
        }),
        ("blacklist_version", |s| s.core.blacklist_version += 1),
        ("blacklist_root", |s| {
            s.core.blacklist_root = field_value(0x27);
        }),
        ("blacklist_issued_at_ms", |s| {
            s.core.blacklist_issued_at_ms += 1;
        }),
        ("blacklist_max_age_ms", |s| s.core.blacklist_max_age_ms += 1),
        ("lease_expires_at_ms", |s| s.core.lease_expires_at_ms += 1),
        ("policy_epoch", |s| s.core.policy_epoch += 1),
        ("accepted_time_floor_ms", |s| {
            s.core.accepted_time_floor_ms += 1;
        }),
        ("state_nonce", |s| s.core.state_nonce = field_value(0x27)),
    ];
    // Rest fields enter through the rest digest; narrowing the permitted controls also narrows
    // the enabled ones, which must stay within them.
    let rest_mutations: [StateMutation; 8] = [
        ("rest.permitted_controls", |s| {
            s.rest.permitted_controls = KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1;
            s.rest.permitted_controls &= !KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1;
            s.core.enabled_controls = s.rest.permitted_controls;
        }),
        ("rest.time_anchor_max_response_ms", |s| {
            s.rest.time_anchor_max_response_ms += 1;
        }),
        ("rest.scheme_policy", |s| s.rest.scheme_policy = [0x2c; 32]),
        ("rest.fee_schedule", |s| s.rest.fee_schedule = [0x2c; 32]),
        ("rest.blacklist", |s| s.rest.blacklist = [0x2c; 32]),
        ("rest.quota_share", |s| s.rest.quota_share = [0x2c; 32]),
        ("rest.quota_share_id", |s| s.rest.quota_share_id += 1),
        ("rest.time_anchor", |s| s.rest.time_anchor = [0x2c; 32]),
    ];
    let mut seen = std::collections::BTreeSet::from([base.value]);
    for (name, mutate) in core_mutations.iter().chain(&rest_mutations) {
        let mut changed = state;
        mutate(&mut changed);
        changed.validate().expect(name);
        let commitment = changed.commitment().expect(name);
        assert!(seen.insert(commitment.value), "{name}");
    }
    // Only a rest field changes the rest digest.
    for (name, mutate) in &rest_mutations[1..] {
        let mut changed = state;
        mutate(&mut changed);
        assert_ne!(
            changed.rest_digest().ok(),
            state.rest_digest().ok(),
            "{name}"
        );
    }
    for (name, mutate) in &core_mutations {
        let mut changed = state;
        mutate(&mut changed);
        assert_eq!(
            changed.rest_digest().ok(),
            state.rest_digest().ok(),
            "{name}"
        );
    }
}

#[test]
fn kagemusha_wallet_v1_spendable_value_uses_lineage_burned_total() {
    let f = android();
    let mut state = bootstrap_state(&f, 0x5c);
    state.core.balance = 100;
    // The stale core burned_total is not used: Ω(pred)'s lineage-adjusted value is (§3.2).
    state.core.burned_total = 0;
    let statement = statement_for(&f, send_effect());
    let mut omega = lineage_for(&f.credential, &statement).public;
    // Ω is the one recorded for this head: its head is the state's computed commitment.
    omega.head = state.commitment().expect("head");
    omega.burned_total = 30;
    assert_eq!(state.spendable_with(&omega).expect("spendable"), 70);
    state.check_unload(70, &omega).expect("full unload");
    assert!(is_invalid(
        state.check_unload(71, &omega),
        "state.unload_amount"
    ));
    assert!(is_invalid(
        state.check_unload(0, &omega),
        "state.unload_amount"
    ));
    omega.burned_total = 101;
    assert!(matches!(
        state.spendable_with(&omega),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow {
            field: "state.spendable"
        })
    ));
    omega.burned_total = 0;
    let mut other_head = omega;
    other_head.head = commitment(3);
    assert!(is_invalid(
        state.spendable_with(&other_head),
        "lineage.head"
    ));
    let mut foreign = omega;
    foreign.wallet_id = [0x62; 32];
    assert!(is_invalid(
        state.spendable_with(&foreign),
        "lineage.wallet_id"
    ));
    let mut renewed = omega;
    renewed.credential_digest = [0x63; 32];
    assert!(is_invalid(
        state.spendable_with(&renewed),
        "lineage.credential_digest"
    ));
}

#[test]
fn kagemusha_wallet_v1_map_leaves_keys_and_values() {
    let credit = field_value(0x01);
    // The consumed-credit leaf binds (amount, receive sequence) and no Payment digest (§3).
    let consumed = KagemushaWalletConsumedCreditLeafV1 {
        credit_id: credit,
        amount: 2,
        receive_sequence: 3,
    };
    assert_eq!(consumed.key(), credit);
    assert_eq!(
        consumed.field_items().ok(),
        Some(vec![credit, int(2), int(3)])
    );
    assert_eq!(
        consumed.leaf_value().ok(),
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1,
            &[credit, int(2), int(3)]
        )
        .ok()
    );
    let pending = KagemushaWalletPendingOutgoingLeafV1 {
        credit_id: credit,
        receiver_wallet_id: [2; 32],
        send_ordinal: 3,
        amount: 4,
        fee: 5,
        request_digest: [6; 32],
    };
    let mut descriptor = vec![credit];
    descriptor.extend(limb_items(&[2; 32]));
    descriptor.extend([int(3), int(4), int(5)]);
    descriptor.extend(limb_items(&[6; 32]));
    assert_eq!(pending.field_items().ok(), Some(descriptor.clone()));
    assert_eq!(pending.key(), credit);
    assert_eq!(
        pending.leaf_value().ok(),
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
            &descriptor
        )
        .ok()
    );
    // One load/redeem recovery map keyed by (kind, ordinal) (owner answer Q3).
    let load = KagemushaWalletLoadLeafV1 {
        ordinal: 7,
        voucher_digest: [8; 32],
        amount: 9,
    };
    let mut items = vec![int(7)];
    items.extend(limb_items(&[8; 32]));
    items.push(int(9));
    assert_eq!(load.field_items(), items);
    assert_eq!(
        Some(load.leaf_value()),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1, &items).ok()
    );
    assert_eq!(load.key(), kagemusha_wallet_pair_key_v1(1, 7));
    let redeem = KagemushaWalletRedeemLeafV1 {
        ordinal: 7,
        nullifier: [2; 32],
        amount: 3,
        online_charge: 4,
    };
    let mut items = vec![int(7)];
    items.extend(limb_items(&[2; 32]));
    items.extend([int(3), int(4)]);
    assert_eq!(redeem.field_items(), items);
    assert_eq!(
        Some(redeem.leaf_value()),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1, &items).ok()
    );
    assert_eq!(redeem.key(), kagemusha_wallet_pair_key_v1(2, 7));
    assert_ne!(load.key(), redeem.key());
    assert_eq!(
        (
            KagemushaWalletRecoveryKindV1::Load.tag(),
            KagemushaWalletRecoveryKindV1::Redeem.tag()
        ),
        (1, 2)
    );
    let mut recovery = KagemushaWalletIndexedTreeV1::new();
    recovery
        .insert(load.key(), load.leaf_value())
        .expect("load leaf");
    recovery
        .insert(redeem.key(), redeem.leaf_value())
        .expect("redeem leaf");
    let root = recovery.root();
    for (key, value) in [
        (load.key(), load.leaf_value()),
        (redeem.key(), redeem.leaf_value()),
    ] {
        let (leaf, opening) = recovery.membership(&key).expect("membership");
        assert_eq!((leaf.key, leaf.value), (key, value));
        crate::kagemusha::kagemusha_wallet_v1::kagemusha_wallet_indexed_verify_membership_v1(
            &root, &leaf, &opening,
        )
        .expect("recovery membership");
    }
    let fee = KagemushaWalletFeeClaimLeafV1 {
        credit_id: credit,
        fee: 2,
        fee_schedule_digest: [3; 32],
    };
    let mut items = vec![credit, int(2)];
    items.extend(limb_items(&[3; 32]));
    assert_eq!(fee.field_items().ok(), Some(items.clone()));
    assert_eq!(fee.key(), credit);
    assert_eq!(
        fee.leaf_value().ok(),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1, &items).ok()
    );
    let usage = KagemushaWalletQuotaUsageLeafV1 {
        window_kind: KagemushaWalletQuotaWindowKindV1::Monthly,
        window_start_ms: 10,
        window_end_ms: 20,
        used: 30,
    };
    assert_eq!(usage.field_items(), vec![int(2), int(10), int(20), int(30)]);
    assert_eq!(usage.key(), kagemusha_wallet_pair_key_v1(2, 10));
    assert_eq!(
        Some(usage.leaf_value()),
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1,
            &[int(2), int(10), int(20), int(30)]
        )
        .ok()
    );
    // A credit identifier is a canonical σ-field value.
    for invalid in [[0; 32], [0xff; 32]] {
        assert!(is_invalid(
            KagemushaWalletConsumedCreditLeafV1 {
                credit_id: invalid,
                ..consumed
            }
            .leaf_value(),
            "consumed_credit.credit_id"
        ));
        assert!(is_invalid(
            KagemushaWalletPendingOutgoingLeafV1 {
                credit_id: invalid,
                ..pending
            }
            .leaf_value(),
            "send_descriptor.credit_id"
        ));
        assert!(is_invalid(
            KagemushaWalletFeeClaimLeafV1 {
                credit_id: invalid,
                ..fee
            }
            .leaf_value(),
            "fee_claim.credit_id"
        ));
    }

    // Chain descriptors: the send entry is the pending-outgoing descriptor (§3).
    let send = KagemushaWalletSendChainEntryV1 {
        credit_id: credit,
        receiver_wallet_id: [2; 32],
        send_ordinal: 3,
        amount: 4,
        fee: 5,
        request_digest: [6; 32],
    };
    assert_eq!(send.field_items().ok(), Some(descriptor.clone()));
    let preimage = send
        .append_preimage(&field_value(0x31))
        .expect("send append");
    assert_eq!(preimage[0], field_value(0x31));
    assert_eq!(preimage[1..], descriptor[..]);
    assert_eq!(
        send.append(&field_value(0x31)).ok(),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1, &preimage).ok()
    );
    assert!(is_invalid(send.append_preimage(&[0xff; 32]), "chain"));
    assert!(is_invalid(send.append(&[0xff; 32]), "chain"));
    let from_empty = send.append(&[0; 32]).expect("empty chain");
    assert_ne!(from_empty, send.append(&field_value(0x31)).expect("chain"));
    let recv = KagemushaWalletRecvChainEntryV1 {
        credit_id: credit,
        payer_wallet_id: [7; 32],
        amount: 8,
    };
    let mut items = vec![credit];
    items.extend(limb_items(&[7; 32]));
    items.push(int(8));
    assert_eq!(recv.field_items().ok(), Some(items.clone()));
    let preimage = recv.append_preimage(&[0; 32]).expect("recv append");
    assert_eq!(preimage.len(), 5);
    assert_eq!(
        recv.append(&[0; 32]).ok(),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1, &preimage).ok()
    );
    assert!(is_invalid(
        KagemushaWalletRecvChainEntryV1 {
            credit_id: [0xff; 32],
            ..recv
        }
        .append(&[0; 32]),
        "recv_chain.credit_id"
    ));
    let credited = KagemushaWalletCreditDigestLeafV1 {
        credit_id: credit,
        payment_digest: field_value(9),
        burned: true,
    };
    assert_eq!(credited.key(), credit);
    assert_eq!(
        credited.field_items().ok(),
        Some(vec![credit, field_value(9), int(1)])
    );
    let unburned = KagemushaWalletCreditDigestLeafV1 {
        burned: false,
        ..credited
    };
    assert_eq!(unburned.field_items().expect("items")[2], int(0));
    assert_ne!(unburned.leaf_value().ok(), credited.leaf_value().ok());
    assert!(is_invalid(
        KagemushaWalletCreditDigestLeafV1 {
            payment_digest: [0xff; 32],
            ..credited
        }
        .leaf_value(),
        "credit_digest.payment_digest"
    ));

    let domains = [
        KagemushaWalletConsumedCreditLeafV1::DOMAIN,
        KagemushaWalletPendingOutgoingLeafV1::DOMAIN,
        KagemushaWalletLoadLeafV1::DOMAIN,
        KagemushaWalletRedeemLeafV1::DOMAIN,
        KagemushaWalletFeeClaimLeafV1::DOMAIN,
        KagemushaWalletQuotaUsageLeafV1::DOMAIN,
        KagemushaWalletSendChainEntryV1::DOMAIN,
        KagemushaWalletRecvChainEntryV1::DOMAIN,
        KagemushaWalletCreditDigestLeafV1::DOMAIN,
    ];
    assert_eq!(
        domains,
        [
            KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1,
            KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1,
            KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1,
            KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
        ]
    );
    // Existing iroha_core_zk Poseidon domains the wallet domains must not reuse.
    let existing: Vec<u64> = [
        b"kgmemp_1",
        b"kgmleaf1",
        b"kgmnode1",
        b"kgmstate",
        b"kgmmntl1",
        b"kgminte1",
        b"kgmmntn1",
        b"kgmhpln1",
        b"kgmhmsg0",
        b"kgmhmsg1",
        b"kgmhseed",
        b"kgmhjob1",
        b"kgmhpc20",
        b"kgmhpc21",
        b"kgmrlc_2",
        b"kgmbnd_1",
        b"kgmeqn_1",
        b"kgminp_1",
        b"kgmsrc_1",
        b"kgpcrlc1",
        b"cfownr03",
        b"cfnote03",
        b"cfnull03",
        b"cfleaf03",
        b"cfnode03",
        b"cfasst03",
        b"cfnet_03",
    ]
    .iter()
    .map(|tag| u64::from_le_bytes(**tag))
    .collect();
    for (name, domain) in KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1 {
        assert!(!existing.contains(&domain), "reused domain {name}");
    }
}

#[test]
fn kagemusha_wallet_v1_state_objects_round_trip() {
    let f = android();
    for effect in sample_effects(&f) {
        let statement = statement_for(&f, effect);
        let frame = norito::encode_canonical(&statement).expect("encode");
        let decoded: KagemushaWalletStatementV1 = decode_frame_v1(&frame, 4_096).expect("decode");
        assert_eq!(decoded, statement);
        assert_eq!(decoded.statement_digest(), statement.statement_digest());
    }
    let leaf = KagemushaWalletPendingOutgoingLeafV1 {
        credit_id: field_value(1),
        receiver_wallet_id: [2; 32],
        send_ordinal: u128::MAX,
        amount: 4,
        fee: 5,
        request_digest: [6; 32],
    };
    let frame = norito::encode_canonical(&leaf).expect("encode");
    let decoded: KagemushaWalletPendingOutgoingLeafV1 =
        decode_frame_v1(&frame, 1_024).expect("decode");
    assert_eq!(decoded, leaf);
    let consumed = KagemushaWalletConsumedCreditLeafV1 {
        credit_id: field_value(1),
        amount: u128::MAX,
        receive_sequence: 9,
    };
    let frame = norito::encode_canonical(&consumed).expect("encode");
    let decoded: KagemushaWalletConsumedCreditLeafV1 =
        decode_frame_v1(&frame, 1_024).expect("decode");
    assert_eq!(decoded, consumed);
    let proof = stand_in_proof(17);
    let frame = norito::encode_canonical(&proof).expect("encode");
    let decoded: KagemushaWalletStepProofV1 = decode_frame_v1(&frame, 1_024).expect("decode");
    assert_eq!(decoded, proof);
    let lineage = lineage_for(&f.credential, &statement_for(&f, send_effect()));
    let frame = norito::encode_canonical(&lineage).expect("encode");
    let decoded: KagemushaWalletLineageV1 = decode_frame_v1(&frame, 4_096).expect("decode");
    assert_eq!(decoded, lineage);
    let commitment_frame = norito::encode_canonical(&commitment(5)).expect("encode");
    let decoded: KagemushaWalletStateCommitmentV1 =
        decode_frame_v1(&commitment_frame, 1_024).expect("decode");
    assert_eq!(decoded, commitment(5));
    assert!(commitment(5).is_complete());
    assert!(!KagemushaWalletStateCommitmentV1::ZERO.is_complete());
    assert!(KagemushaWalletStateCommitmentV1::default().is_zero());
    let wide = KagemushaWalletStateCommitmentV1 { value: [0xff; 32] };
    assert!(!wide.is_canonical());
    assert!(!wide.is_complete());
}
