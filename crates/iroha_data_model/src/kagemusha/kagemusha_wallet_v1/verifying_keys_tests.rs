//! Verifying-key allowlist tests (owner answers Q6, Q11 and A5).

use iroha_crypto::Hash;

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_CREDITED_RECEIVE_FIXED_BYTES_V1,
    KAGEMUSHA_WALLET_CREDITED_STATUS_FIXED_BYTES_V1, KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1,
    KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletValidationErrorV1,
    codec_tests::norito_tag,
    identity::{
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1,
        KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, KagemushaWalletEvidenceKindV1,
        identity_tests::identity_fixture, kagemusha_wallet_provider_contract_v1,
        kagemusha_wallet_relation_id_v1,
    },
    state::{
        KagemushaWalletEffectV1, KagemushaWalletLifecycleV1, KagemushaWalletLineageSlotV1,
        state_tests::{
            LINEAGE_PROOF_LEN, RECEIVE_PAYMENT, bootstrap_statement, field_value, send_effect,
            signed_package, signed_package_with, stand_in_proof, transition_statement,
        },
    },
};

/// σ length of every stand-in entry.
const SIGMA: u32 = 48;
/// σ length of every stand-in proof of the vectors (and of the test scheme's allowlist).
pub(in crate::kagemusha::kagemusha_wallet_v1) const STAND_IN_SIGMA_BYTES: usize = 48;
/// Ω transport length of every stand-in lineage proof of the vectors (Payment, Lineage,
/// `CreditStatus` and fold record).
pub(in crate::kagemusha::kagemusha_wallet_v1) const STAND_IN_LINEAGE_BYTES: usize = 48;

#[track_caller]
fn assert_invalid<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected => {}
        other => panic!("expected invalid `{expected}`, got {other:?}"),
    }
}

fn entry(
    kind: KagemushaWalletOperationKindV1,
    enabled_controls: u32,
    proof_bytes: u32,
) -> KagemushaWalletVerifyingKeyEntryV1 {
    KagemushaWalletVerifyingKeyEntryV1 {
        kind,
        enabled_controls,
        verifying_key_digest: [kind.tag() ^ enabled_controls.to_le_bytes()[0]; 32]
            .map(|byte| byte | 0x80),
        proof_bytes,
    }
}

/// One entry per operation, plus Send with the quota mask and the quota and lease mask.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn sample_allowlist()
-> KagemushaWalletVerifyingKeyAllowlistV1 {
    let mut steps = Vec::new();
    for kind in KagemushaWalletOperationKindV1::ALL {
        steps.push(entry(kind, 0, SIGMA));
        if kind == KagemushaWalletOperationKindV1::Send {
            steps.push(entry(kind, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, SIGMA + 1));
            steps.push(entry(
                kind,
                KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1 | KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1,
                SIGMA + 2,
            ));
        }
    }
    KagemushaWalletVerifyingKeyAllowlistV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        steps,
        lineage_verifying_key_digest: [0x4c; 32],
        lineage_proof_bytes: u32::try_from(LINEAGE_PROOF_LEN).expect("len"),
    }
}

/// Stand-in allowlist whose digest the test scheme's relation identity and the vectored
/// artifact manifest bind (defect d1): every operation with the vectored σ length, Send also
/// with every control enabled, and the vectored Ω transport length (defect d2). The
/// verifying-key digests are labelled stand-ins.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn scheme_allowlist()
-> KagemushaWalletVerifyingKeyAllowlistV1 {
    let sigma = u32::try_from(STAND_IN_SIGMA_BYTES).expect("σ length");
    let mut steps = Vec::new();
    for kind in KagemushaWalletOperationKindV1::ALL {
        let masks: &[u32] = match kind {
            KagemushaWalletOperationKindV1::Send => &[0, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1],
            _ => &[0],
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
        lineage_proof_bytes: u32::try_from(STAND_IN_LINEAGE_BYTES).expect("Ω length"),
    };
    allowlist.validate().expect("scheme allowlist");
    allowlist
}

/// `verifying_key_set_digest` of [`scheme_allowlist`], which the test scheme binds.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn scheme_verifying_key_set_digest() -> [u8; 32] {
    scheme_allowlist()
        .verifying_key_set_digest()
        .expect("scheme allowlist digest")
}

#[test]
fn kagemusha_wallet_v1_scheme_allowlist_is_bound_by_the_test_scheme() {
    let allowlist = scheme_allowlist();
    assert_eq!(allowlist.steps.len(), 9);
    let f = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x4b);
    let (eq, ep, native, inventory) = ([0x21; 32], [0x22; 32], [0x23; 32], [0x25; 32]);
    assert_eq!(
        f.scheme.relation_id,
        kagemusha_wallet_relation_id_v1(
            &eq,
            &ep,
            &native,
            &scheme_verifying_key_set_digest(),
            &inventory
        )
    );
    assert_eq!(
        allowlist
            .entry(
                KagemushaWalletOperationKindV1::Send,
                KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1
            )
            .map(|entry| entry.proof_bytes)
            .ok(),
        Some(u32::try_from(STAND_IN_SIGMA_BYTES + 1).expect("len"))
    );
    // Receive has only the empty mask.
    assert_invalid(
        allowlist.entry(KagemushaWalletOperationKindV1::Receive, 1),
        "verifying_keys.selector",
    );
}

#[test]
fn kagemusha_wallet_v1_verifying_key_allowlist_layout_and_digest() {
    let allowlist = sample_allowlist();
    allowlist.validate().expect("allowlist");
    assert_eq!(KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES_V1, 41);
    assert_eq!(KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1, 11);
    let transcript = allowlist.transcript().expect("transcript");
    let mut expected = 1_u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&10_u32.to_le_bytes());
    for step in &allowlist.steps {
        expected.push(step.kind.tag());
        expected.extend_from_slice(&step.enabled_controls.to_le_bytes());
        expected.extend_from_slice(&step.verifying_key_digest);
        expected.extend_from_slice(&step.proof_bytes.to_le_bytes());
    }
    expected.extend_from_slice(&[0x4c; 32]);
    expected.extend_from_slice(&40_u32.to_le_bytes());
    assert_eq!(transcript, expected);
    assert_eq!(transcript.len(), 2 + 4 + 10 * 41 + 32 + 4);
    assert_eq!(
        allowlist.verifying_key_set_digest().ok(),
        Some(kagemusha_wallet_digest_v1(Role::VerifyingKeySet, &expected))
    );
    // Selectors ascend by (tag, mask): Send's masks follow its empty mask; Receive has only
    // the empty mask.
    let selectors: Vec<(u8, u32)> = allowlist
        .steps
        .iter()
        .map(KagemushaWalletVerifyingKeyEntryV1::selector)
        .collect();
    assert_eq!(selectors[2..7], [(3, 0), (3, 1), (3, 3), (4, 0), (5, 0)]);
    assert_eq!(norito_tag(&allowlist.steps[2].kind), 3);

    // Canonical frame round trip and the bound.
    let frame = allowlist.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1);
    let decoded: KagemushaWalletVerifyingKeyAllowlistV1 = decode_frame_v1(
        &frame,
        KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
    )
    .expect("decode");
    assert_eq!(decoded, allowlist);
}

#[test]
fn kagemusha_wallet_v1_verifying_key_selector_masks() {
    use KagemushaWalletOperationKindV1 as Kind;
    for kind in Kind::ALL {
        for mask in 0..=KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 {
            // Send selects by its mask; every other operation, Receive included, has only the
            // empty mask.
            let expected = match kind {
                Kind::Send => true,
                _ => mask == 0,
            };
            assert_eq!(
                selector_mask_is_valid(kind, mask),
                expected,
                "{kind:?}/{mask}"
            );
            assert_eq!(entry(kind, mask, SIGMA).validate().is_ok(), expected);
        }
        for mask in [KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 + 1, u32::MAX] {
            assert!(!selector_mask_is_valid(kind, mask));
            assert_invalid(
                entry(kind, mask, SIGMA).validate(),
                "verifying_keys.enabled_controls",
            );
        }
    }
}

#[test]
fn kagemusha_wallet_v1_verifying_key_allowlist_accepts_all_eleven_selectors() {
    use KagemushaWalletOperationKindV1 as Kind;
    let mut allowlist = sample_allowlist();
    allowlist.steps.retain(|entry| entry.enabled_controls == 0);
    for mask in 1..=KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 {
        allowlist.steps.push(entry(Kind::Send, mask, SIGMA));
    }
    allowlist
        .steps
        .sort_by_key(KagemushaWalletVerifyingKeyEntryV1::selector);
    assert_eq!(
        allowlist.steps.len(),
        KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1
    );
    allowlist.validate().expect("all supported selectors");
    let frame = allowlist
        .to_canonical_bytes()
        .expect("full allowlist frame");
    let decoded: KagemushaWalletVerifyingKeyAllowlistV1 = decode_frame_v1(
        &frame,
        KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
    )
    .expect("full allowlist decode");
    assert_eq!(decoded, allowlist);
}

#[test]
fn kagemusha_wallet_v1_verifying_key_allowlist_rules() {
    use KagemushaWalletOperationKindV1 as Kind;
    let reject = |mutate: &dyn Fn(&mut KagemushaWalletVerifyingKeyAllowlistV1), field: &str| {
        let mut allowlist = sample_allowlist();
        mutate(&mut allowlist);
        assert_invalid(allowlist.validate(), field);
        assert_invalid(allowlist.verifying_key_set_digest(), field);
    };
    reject(&|a| a.steps.swap(0, 1), "verifying_keys.order");
    reject(
        &|a| {
            let duplicate = a.steps[2];
            a.steps.insert(2, duplicate);
        },
        "verifying_keys.order",
    );
    reject(
        &|a| a.steps.retain(|e| e.kind != Kind::Retiring),
        "verifying_keys.missing",
    );
    reject(
        &|a| a.steps.retain(|e| e.selector() != (3, 0)),
        "verifying_keys.missing",
    );
    reject(
        &|a| a.steps[0].enabled_controls = 1,
        "verifying_keys.enabled_controls",
    );
    reject(
        &|a| a.steps[4].enabled_controls = KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 + 1,
        "verifying_keys.enabled_controls",
    );
    // Receive, like every operation other than Send, has only the empty mask.
    assert_eq!(
        sample_allowlist().steps[5].selector(),
        (Kind::Receive.tag(), 0)
    );
    for mask in [
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1,
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1,
        KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
    ] {
        reject(
            &|a| a.steps[5].enabled_controls = mask,
            "verifying_keys.enabled_controls",
        );
    }
    reject(
        &|a| {
            a.steps
                .retain(|entry| entry.selector() != (Kind::Receive.tag(), 0))
        },
        "verifying_keys.missing",
    );
    reject(
        &|a| a.steps[1].verifying_key_digest = [0; 32],
        "verifying_keys.verifying_key_digest",
    );
    reject(
        &|a| a.steps[1].proof_bytes = 0,
        "verifying_keys.proof_bytes",
    );
    reject(
        &|a| a.steps[1].proof_bytes = 10_001,
        "verifying_keys.proof_bytes",
    );
    reject(
        &|a| a.lineage_verifying_key_digest = [0; 32],
        "verifying_keys.lineage_verifying_key_digest",
    );
    reject(
        &|a| a.lineage_proof_bytes = 0,
        "verifying_keys.lineage_proof_bytes",
    );
    // Nonzero Send masks are optional and need no other entry.
    let mut operations_only = sample_allowlist();
    operations_only
        .steps
        .retain(|e| e.selector() != (3, 1) && e.selector() != (3, 3));
    operations_only
        .validate()
        .expect("one empty-mask entry per operation");
    // Ω fits the Credited::Status bound with the fixed 32-sibling opening.
    assert_eq!(
        KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1,
        10_034 - KAGEMUSHA_WALLET_CREDITED_STATUS_FIXED_BYTES_V1
    );
    let cap = u32::try_from(KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1).expect("source cap");
    let mut at_cap = sample_allowlist();
    at_cap.lineage_proof_bytes = cap;
    at_cap.validate().expect("Ω exactly at the cap");
    reject(
        &|a| a.lineage_proof_bytes = cap + 1,
        "verifying_keys.lineage_proof_bytes",
    );
    reject(
        &|a| {
            let more = a.steps[3];
            a.steps.extend(core::iter::repeat_n(more, 2));
        },
        "verifying_keys.steps",
    );
    let mut version = sample_allowlist();
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    // R9 (owner answer Q6): |Ω| + the largest σ_send fits 10,034 − F_payment.
    assert_eq!(
        KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1,
        10_034 - KAGEMUSHA_WALLET_PAYMENT_FIXED_BYTES_V1
    );
    let budget = u32::try_from(KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1).expect("budget");
    let mut at_budget = sample_allowlist();
    at_budget.steps[4].proof_bytes = 3_520;
    at_budget.lineage_proof_bytes = budget - 3_520;
    at_budget
        .validate()
        .expect("joint proofs exactly at the budget");
    let mut over = at_budget.clone();
    over.lineage_proof_bytes += 1;
    assert_invalid(over.validate(), "verifying_keys.lineage_proof_bytes");
    // The joint budget binds Send; every selector also respects the uniform source capacity.
    let mut receive = at_budget;
    assert_eq!(receive.steps[5].kind, Kind::Receive);
    receive.steps[5].proof_bytes = 9_000;
    assert_invalid(receive.validate(), "verifying_keys.proof_bytes");
    receive.steps[5].proof_bytes = 3_520;
    receive.validate().expect("Receive at its source capacity");
}

#[test]
fn kagemusha_wallet_v1_verifying_key_receive_budget_preserves_exact_selectors() {
    use KagemushaWalletOperationKindV1 as Kind;

    let budget = KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1;
    assert_eq!(
        budget,
        10_034 - KAGEMUSHA_WALLET_CREDITED_RECEIVE_FIXED_BYTES_V1
    );
    assert_eq!(budget, 9_355);
    let capacity = KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1;
    assert_eq!(capacity, 3_520);
    assert!(capacity < budget);
    // Receive has one selector, the empty mask.
    let mut allowlist = sample_allowlist();
    let selected = allowlist
        .steps
        .iter_mut()
        .find(|entry| entry.selector() == (Kind::Receive.tag(), 0))
        .expect("Receive selector");
    selected.proof_bytes = u32::try_from(capacity).expect("source capacity");
    let digest = selected.verifying_key_digest;
    allowlist
        .validate()
        .expect("Receive exactly at its source capacity");
    let proof = stand_in_proof(capacity);
    assert_eq!(
        allowlist
            .check_step_proof(Kind::Receive, 0, &proof)
            .expect("exact selected proof length"),
        digest
    );
    assert_invalid(
        allowlist.check_step_proof(Kind::Receive, 0, &stand_in_proof(capacity - 1)),
        "step_proof.length",
    );
    assert_invalid(
        allowlist.check_step_proof(Kind::Receive, 0, &stand_in_proof(capacity + 1)),
        "step_proof.length",
    );
    for mask in [
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1,
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1,
        KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
    ] {
        assert_invalid(
            allowlist.check_step_proof(Kind::Receive, mask, &proof),
            "verifying_keys.selector",
        );
    }
    allowlist
        .steps
        .iter_mut()
        .find(|entry| entry.selector() == (Kind::Receive.tag(), 0))
        .expect("Receive selector")
        .proof_bytes += 1;
    assert_invalid(allowlist.validate(), "verifying_keys.proof_bytes");
    assert_invalid(
        allowlist.verifying_key_set_digest(),
        "verifying_keys.proof_bytes",
    );
}

#[test]
fn kagemusha_wallet_v1_verifying_key_lineage_cap_and_joint_budget_are_independent() {
    use KagemushaWalletOperationKindV1 as Kind;
    let cap = u32::try_from(KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1).expect("source cap");
    let budget = u32::try_from(KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1).expect("budget");
    assert_eq!(budget, 8_640);
    let mut allowlist = sample_allowlist();
    allowlist.lineage_proof_bytes = cap;
    let largest_send = budget - cap;
    for entry in &mut allowlist.steps {
        if entry.kind == Kind::Send {
            entry.proof_bytes = largest_send;
        }
    }
    allowlist
        .validate()
        .expect("exact Credited and Payment bounds");
    let mut over_cap = allowlist.clone();
    over_cap.lineage_proof_bytes += 1;
    for entry in &mut over_cap.steps {
        if entry.kind == Kind::Send {
            entry.proof_bytes -= 1;
        }
    }
    assert_invalid(over_cap.validate(), "verifying_keys.lineage_proof_bytes");
    assert_invalid(
        over_cap.verifying_key_set_digest(),
        "verifying_keys.lineage_proof_bytes",
    );
    let mut over_joint = allowlist;
    over_joint
        .steps
        .iter_mut()
        .find(|entry| entry.kind == Kind::Send)
        .expect("Send")
        .proof_bytes += 1;
    assert_invalid(over_joint.validate(), "verifying_keys.proof_bytes");
}

#[test]
fn kagemusha_wallet_v1_verifying_key_selection_and_lengths() {
    use KagemushaWalletOperationKindV1 as Kind;
    let allowlist = sample_allowlist();
    let send = allowlist
        .entry(Kind::Send, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1)
        .expect("send quota");
    assert_eq!(send.proof_bytes, SIGMA + 1);
    assert_eq!(
        allowlist.entry(Kind::Load, 0).expect("load").proof_bytes,
        SIGMA
    );
    assert_invalid(allowlist.entry(Kind::Load, 1), "verifying_keys.selector");
    assert_invalid(allowlist.entry(Kind::Send, 2), "verifying_keys.selector");
    // Receive selects with the empty mask only.
    for mask in [1, 2, 3, 4, 5, 6, 7, 8, u32::MAX] {
        assert_invalid(
            allowlist.entry(Kind::Receive, mask),
            "verifying_keys.selector",
        );
    }

    let sigma = stand_in_proof(usize::try_from(SIGMA).expect("len"));
    assert_eq!(
        allowlist.check_step_proof(Kind::Receive, 0, &sigma).ok(),
        Some(entry(Kind::Receive, 0, SIGMA).verifying_key_digest)
    );
    assert_invalid(
        allowlist.check_step_proof(Kind::Send, 1, &sigma),
        "step_proof.length",
    );
    assert_invalid(
        allowlist.check_step_proof(Kind::Receive, 0, &stand_in_proof(47)),
        "step_proof.length",
    );

    // A Send package selects by its mask and checks Ω(pred)'s exact transport length.
    let f = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x4b);
    let statement =
        transition_statement(&f, 3, 0, KagemushaWalletLifecycleV1::Active, send_effect());
    let package = signed_package(&f, &f.credential, &statement, sigma.clone());
    assert!(matches!(
        package.lineage,
        KagemushaWalletLineageSlotV1::Present { .. }
    ));
    assert_eq!(package.verifying_key_selector(), (Kind::Send, 0));
    assert_eq!(
        allowlist.check_package(&package).ok(),
        Some(entry(Kind::Send, 0, SIGMA).verifying_key_digest)
    );
    let mut short_omega = allowlist.clone();
    short_omega.lineage_proof_bytes -= 1;
    assert_invalid(short_omega.check_package(&package), "lineage.proof_length");
    let mut quota_statement = statement;
    quota_statement.enabled_controls = KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1;
    let quota_package = signed_package(
        &f,
        &f.credential,
        &quota_statement,
        stand_in_proof(usize::try_from(SIGMA + 1).expect("len")),
    );
    assert_eq!(
        quota_package.verifying_key_selector(),
        (Kind::Send, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1)
    );
    assert_eq!(
        allowlist.check_package(&quota_package).ok(),
        Some(entry(Kind::Send, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, SIGMA + 1).verifying_key_digest)
    );
    let bootstrap = signed_package(&f, &f.credential, &bootstrap_statement(&f), sigma);
    assert!(matches!(
        bootstrap.statement.effect,
        KagemushaWalletEffectV1::Bootstrap { .. }
    ));
    assert_eq!(
        allowlist.check_package(&bootstrap).ok(),
        Some(entry(Kind::Bootstrap, 0, SIGMA).verifying_key_digest)
    );
    // A Receive package selects its one entry, the empty mask, whatever the statement's mask;
    // selecting it takes no Request.
    for mask in [
        0,
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1,
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1,
        KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
    ] {
        let receive_effect = KagemushaWalletEffectV1::Receive {
            credit_id: field_value(0x75),
            payer_wallet_id: [0x76; 32],
            amount: 3,
        };
        let mut statement =
            transition_statement(&f, 3, 0, KagemushaWalletLifecycleV1::Active, receive_effect);
        statement.enabled_controls = mask;
        let package = signed_package_with(
            &f,
            &f.credential,
            &statement,
            KagemushaWalletLineageSlotV1::None,
            stand_in_proof(usize::try_from(SIGMA).expect("len")),
            RECEIVE_PAYMENT,
        );
        assert_eq!(package.verifying_key_selector(), (Kind::Receive, 0));
        assert_eq!(
            allowlist.check_package(&package).ok(),
            Some(entry(Kind::Receive, 0, SIGMA).verifying_key_digest)
        );
    }
}

#[test]
fn kagemusha_wallet_v1_verifying_key_allowlist_binds_the_manifest() {
    let allowlist = sample_allowlist();
    let digest = allowlist.verifying_key_set_digest().expect("digest");
    let (eq, ep, native, inventory) = ([0x21; 32], [0x22; 32], [0x23; 32], [0x25; 32]);
    let manifest = KagemushaWalletArtifactManifestBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: *Hash::prehashed([11; 32]).as_ref(),
        relation_id: kagemusha_wallet_relation_id_v1(&eq, &ep, &native, &digest, &inventory),
        eq_protocol_digest: eq,
        ep_protocol_digest: ep,
        native_profile_digest: native,
        verifying_key_set_digest: digest,
        artifact_inventory_digest: inventory,
        provider_contract: kagemusha_wallet_provider_contract_v1(),
        signer_certificate: [0x31; 32],
    };
    allowlist.require_manifest(&manifest).expect("manifest");
    let frame = allowlist.to_canonical_bytes().expect("frame");
    assert_eq!(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(&frame, &manifest)
            .expect("decode"),
        allowlist
    );
    let mut other = allowlist.clone();
    other.steps[0].proof_bytes += 1;
    assert_invalid(
        other.require_manifest(&manifest),
        "artifact_manifest.verifying_key_set_digest",
    );
    let other_frame = other.to_canonical_bytes().expect("frame");
    assert_invalid(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(&other_frame, &manifest),
        "artifact_manifest.verifying_key_set_digest",
    );
    let mut oversized = frame.clone();
    oversized.resize(KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1 + 1, 0);
    assert!(matches!(
        KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(&oversized, &manifest),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
}
