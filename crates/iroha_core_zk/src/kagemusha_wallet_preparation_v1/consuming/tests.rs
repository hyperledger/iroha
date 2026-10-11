//! Consuming derivation, real signature checks and strict sigma differential cases.
//!
//! Raw model fixtures exercise the private arithmetic owner; their placeholder
//! lineage bytes never enter the public folded-source verifier or wallet intake.

use ff::Field;
use iroha_kagemusha_proof::admin_sigma::{RetiringCircuit, UnloadCircuit};
use iroha_plonk::check::{CheckMode, check_circuit};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use super::*;

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap()
}

fn fixture<T>(name: &str) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let all = vectors();
    let row = all["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .unwrap();
    let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
        .unwrap()
}

fn signer() -> SigningKey {
    let all = vectors();
    let row = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("regulator"))
        .unwrap();
    SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap()
}

struct Source {
    scheme: KagemushaWalletSchemeV1,
    credential: KagemushaWalletCredentialV1,
    before: KagemushaWalletStateV1,
    lineage: KagemushaWalletLineagePublicV1,
    tree: KagemushaWalletIndexedTreeV1,
}

impl Source {
    fn new() -> Self {
        let scheme = fixture("KagemushaWalletSchemeV1");
        let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
        let request: KagemushaWalletRequestV1 = norito::decode_from_bytes(
            retained_original(
                &capsule.retained_inputs,
                KagemushaWalletRetainedInputRoleV1::Request,
            )
            .unwrap(),
        )
        .unwrap();
        let credential = request.receiver_credential;
        credential
            .verify(
                &scheme,
                request
                    .certificates
                    .certificate(
                        &credential.body.issuer_certificate,
                        KagemushaWalletSignerRoleV1::Enrollment,
                    )
                    .unwrap(),
            )
            .unwrap();
        let mut before =
            KagemushaWalletStateV1::bootstrap(&credential, Fp::from(101).to_repr()).unwrap();
        before.core.balance = 1500;
        before.core.burned_total = 4;
        before.core.sequence = 5;
        before.core.next_redeem = 7;
        let mut tree = KagemushaWalletIndexedTreeV1::new();
        let old_load = KagemushaWalletLoadLeafV1 {
            ordinal: 0,
            receipt_digest: Fp::from(79).to_repr(),
            amount: 1500,
        };
        tree.insert(old_load.key(), old_load.leaf_value().unwrap())
            .unwrap();
        before.core.load_redeem_recovery_root = tree.root();
        let mut pending = KagemushaWalletIndexedTreeV1::new();
        pending
            .insert(Fp::from(71).to_repr(), Fp::from(73).to_repr())
            .unwrap();
        let lineage = KagemushaWalletLineagePublicV1 {
            version: 1,
            scheme_id: before.core.scheme_id,
            relation_id: scheme.relation_id,
            head: before.commitment().unwrap(),
            wallet_id: before.core.wallet_id,
            credential_digest: before.core.credential_digest,
            payment_key: credential.body.payment_key,
            lifecycle: before.core.lifecycle,
            policy_epoch: before.core.policy_epoch,
            enabled_controls: before.core.enabled_controls,
            burned_total: 30,
            pending_outgoing_root: pending.root(),
            credit_digest_root: Fp::from(83).to_repr(),
        };
        Self {
            scheme,
            credential,
            before,
            lineage,
            tree,
        }
    }

    fn insertion(&self, amount: u128, charge: u128) -> KagemushaWalletIndexedInsertV1 {
        let leaf = KagemushaWalletRedeemLeafV1 {
            ordinal: self.before.core.next_redeem,
            nullifier: kagemusha_wallet_unload_nullifier_v1(
                &self.before.core.scheme_id,
                &self.before.core.wallet_id,
                self.before.core.next_redeem,
            ),
            amount,
            online_charge: charge,
        };
        self.tree
            .clone()
            .insert(leaf.key(), leaf.leaf_value().unwrap())
            .unwrap()
    }

    fn quote(&self, amount: u128) -> (KagemushaWalletChargeQuoteV1, Vec<u8>) {
        let certificate: KagemushaWalletSignerCertificateV1 =
            fixture("KagemushaWalletSignerCertificateV1");
        let body = KagemushaWalletChargeQuoteBodyV1 {
            version: 1,
            scheme_id: self.scheme.scheme_id(),
            asset_digest: self.before.core.asset_digest,
            wallet_id: self.before.core.wallet_id,
            kind: KagemushaWalletChargeKindV1::Unload,
            ordinal: self.before.core.next_redeem,
            net_amount: amount,
            online_charge: 7,
            beneficiary_account_digest: [37; 32],
            issued_at_ms: 109,
            signer_certificate: certificate.certificate_digest(),
        };
        (
            Self::sign_quote(body, &certificate),
            norito::to_bytes(&KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap())
                .unwrap(),
        )
    }

    fn sign_quote(
        body: KagemushaWalletChargeQuoteBodyV1,
        certificate: &KagemushaWalletSignerCertificateV1,
    ) -> KagemushaWalletChargeQuoteV1 {
        let signature: Signature = signer().sign(&body.signing_message());
        KagemushaWalletChargeQuoteV1::sign(
            body,
            certificate,
            KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
        )
        .unwrap()
    }

    fn derive(&self, action: ConsumingActionV1<'_>) -> Result<Derived, Error> {
        derive(
            &self.scheme,
            &self.credential,
            &self.before,
            &self.lineage,
            action,
            Fp::from(97).to_repr(),
        )
    }

    fn witness(&self, derived: &Derived) -> ConsumingWitness {
        let opening = |state: &KagemushaWalletStateV1, lineage: &KagemushaWalletLineagePublicV1| {
            StateWitness {
                core: fields(state.core_field_items().unwrap()).unwrap(),
                rest: fields(state.rest_field_items().unwrap()).unwrap(),
                lineage: lineage_public_fields(lineage, Fp::from(103).to_repr()).unwrap(),
            }
        };
        ConsumingWitness {
            predecessor: opening(&self.before, &self.lineage),
            successor: opening(&derived.state, &derived.projection),
            statement: fields(derived.statement.field_items().unwrap()).unwrap(),
        }
    }
}

#[test]
fn unload_uses_adjusted_value_and_exact_paths_and_matches_the_strict_sigma() {
    let source = Source::new();
    let insertion = source.insertion(1470, 0);
    let derived = source
        .derive(ConsumingActionV1::Unload {
            amount: 1470,
            insertion: &insertion,
            charge: None,
        })
        .unwrap();
    assert_eq!(derived.state.core.balance, 30);
    assert_eq!(derived.state.core.burned_total, 30);
    assert_eq!(
        derived.state.core.pending_outgoing_root,
        source.lineage.pending_outgoing_root
    );
    assert_eq!(derived.state.core.next_redeem, 8);
    let mut restored = derived.state.clone();
    restored.core.balance = source.before.core.balance;
    restored.core.burned_total = source.before.core.burned_total;
    restored.core.pending_outgoing_root = source.before.core.pending_outgoing_root;
    restored.core.sequence = source.before.core.sequence;
    restored.core.next_redeem = source.before.core.next_redeem;
    restored.core.state_nonce = source.before.core.state_nonce;
    restored.core.load_redeem_recovery_root = source.before.core.load_redeem_recovery_root;
    assert_eq!(restored, source.before);
    assert_eq!(
        native_inputs::retained_insertion(&derived.openings).unwrap(),
        insertion
    );
    assert!(derived.charge.is_none());
    assert_eq!(
        derived.projection.credit_digest_root,
        source.lineage.credit_digest_root
    );
    let circuit = UnloadCircuit::new(&source.witness(&derived));
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
fn retiring_synchronizes_lineage_without_removing_value_or_pending_claims() {
    let source = Source::new();
    let derived = source.derive(ConsumingActionV1::Retiring).unwrap();
    assert_eq!(
        derived.state.core.lifecycle,
        KagemushaWalletLifecycleV1::Retiring
    );
    assert_eq!(derived.state.core.balance, source.before.core.balance);
    assert_eq!(derived.state.core.burned_total, source.lineage.burned_total);
    assert_eq!(
        derived.state.core.pending_outgoing_root,
        source.lineage.pending_outgoing_root
    );
    let mut restored = derived.state.clone();
    restored.core.lifecycle = source.before.core.lifecycle;
    restored.core.burned_total = source.before.core.burned_total;
    restored.core.pending_outgoing_root = source.before.core.pending_outgoing_root;
    restored.core.sequence = source.before.core.sequence;
    restored.core.state_nonce = source.before.core.state_nonce;
    assert_eq!(restored, source.before);
    assert!(derived.openings.is_empty());
    let witness = source.witness(&derived);
    let circuit = RetiringCircuit::new(&witness);
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let step = ConsumingStepV1 {
        manifest_digest: [41; 32],
        source_capsule_digest: [43; 32],
        witness,
        state: derived.state,
        statement: derived.statement,
        projection: derived.projection,
        charge: derived.charge,
        openings: derived.openings,
    };
    assert_eq!(step.manifest_digest(), [41; 32]);
    assert_eq!(step.source_capsule_digest(), [43; 32]);
    assert_eq!(
        step.statement().successor,
        step.state().commitment().unwrap()
    );
    assert_eq!(step.successor_projection().head, step.statement().successor);
    assert_eq!(
        step.witness().statement,
        fields::<26>(step.statement().field_items().unwrap()).unwrap()
    );
    assert!(step.charge_originals().is_none());
    assert!(step.map_openings().is_empty());
}

#[test]
fn signed_unload_charge_preserves_exact_originals_and_debits_face_amount_only() {
    let source = Source::new();
    let (quote, certificates) = source.quote(100);
    let bytes = quote.to_canonical_bytes().unwrap();
    let insertion = source.insertion(100, 7);
    let derived = source
        .derive(ConsumingActionV1::Unload {
            amount: 100,
            insertion: &insertion,
            charge: Some(UnloadChargeOriginalsV1 {
                quote: &bytes,
                certificate_set: &certificates,
            }),
        })
        .unwrap();
    assert_eq!(derived.state.core.balance, 1400);
    quote
        .require_unload_effect(&derived.statement.effect, &source.before.core.wallet_id)
        .unwrap();
    assert_eq!(derived.charge, Some((bytes.clone(), certificates.clone())));
    let circuit = UnloadCircuit::new(&source.witness(&derived));
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let step = ConsumingStepV1 {
        manifest_digest: [41; 32],
        source_capsule_digest: [43; 32],
        witness: source.witness(&derived),
        state: derived.state,
        statement: derived.statement,
        projection: derived.projection,
        charge: derived.charge,
        openings: derived.openings,
    };
    assert_eq!(
        step.charge_originals(),
        Some((bytes.as_slice(), certificates.as_slice()))
    );
}

#[test]
fn unload_rejects_zero_excess_adjusted_value_overflows_replays_and_bad_paths() {
    for mutation in 0..9 {
        let mut source = Source::new();
        let mut insertion = source.insertion(100, 0);
        let amount = match mutation {
            0 => 0,
            1 => 1471,
            _ => 100,
        };
        match mutation {
            2 => source.before.core.sequence = u128::MAX,
            3 => source.before.core.next_redeem = u128::MAX,
            4 => insertion.low_opening.siblings[0] = Fp::ONE.to_repr(),
            5 => insertion.slot_opening.siblings[0] = Fp::ONE.to_repr(),
            6 => insertion.slot_opening.slot = insertion.low_opening.slot,
            7 => source.lineage.burned_total = 1501,
            8 => {
                source
                    .tree
                    .insert(Fp::from(2).to_repr(), Fp::from(3).to_repr())
                    .unwrap();
                source.before.core.load_redeem_recovery_root = source.tree.root();
            }
            _ => {}
        }
        source.lineage.head = source.before.commitment().unwrap();
        assert!(
            source
                .derive(ConsumingActionV1::Unload {
                    amount,
                    insertion: &insertion,
                    charge: None
                })
                .is_err(),
            "mutation{mutation}"
        );
    }
    let mut source = Source::new();
    let insertion = source.insertion(100, 0);
    let derived = source
        .derive(ConsumingActionV1::Unload {
            amount: 100,
            insertion: &insertion,
            charge: None,
        })
        .unwrap();
    source.before = derived.state;
    source.lineage = derived.projection;
    assert!(
        source
            .derive(ConsumingActionV1::Unload {
                amount: 100,
                insertion: &insertion,
                charge: None
            })
            .is_err()
    );
}

#[test]
fn retirement_is_one_way_and_both_operations_reject_invalid_nonces_and_source() {
    let mut source = Source::new();
    source.before.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    source.lineage.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    source.lineage.head = source.before.commitment().unwrap();
    assert!(source.derive(ConsumingActionV1::Retiring).is_err());
    let insertion = source.insertion(100, 0);
    assert!(
        source
            .derive(ConsumingActionV1::Unload {
                amount: 100,
                insertion: &insertion,
                charge: None
            })
            .is_ok()
    );
    let source = Source::new();
    for nonce in [[0; 32], [0xff; 32]] {
        for action in [
            ConsumingActionV1::Retiring,
            ConsumingActionV1::Unload {
                amount: 100,
                insertion: &insertion,
                charge: None,
            },
        ] {
            assert!(
                derive(
                    &source.scheme,
                    &source.credential,
                    &source.before,
                    &source.lineage,
                    action,
                    nonce
                )
                .is_err()
            );
        }
    }
    let mut foreign = source.lineage;
    foreign.head.value = Fp::ONE.to_repr();
    assert!(
        derive(
            &source.scheme,
            &source.credential,
            &source.before,
            &foreign,
            ConsumingActionV1::Retiring,
            Fp::ONE.to_repr()
        )
        .is_err()
    );
}

#[test]
fn even_validly_signed_foreign_charge_terms_reject() {
    let source = Source::new();
    let certificate: KagemushaWalletSignerCertificateV1 =
        fixture("KagemushaWalletSignerCertificateV1");
    let (quote, certificates) = source.quote(100);
    let insertion = source.insertion(100, 7);
    for mutation in 0..5 {
        let mut body = quote.body;
        match mutation {
            0 => body.asset_digest[0] ^= 1,
            1 => body.wallet_id[0] ^= 1,
            2 => body.ordinal += 1,
            3 => body.net_amount += 1,
            _ => body.kind = KagemushaWalletChargeKindV1::Load,
        }
        let bytes = Source::sign_quote(body, &certificate)
            .to_canonical_bytes()
            .unwrap();
        assert!(
            source
                .derive(ConsumingActionV1::Unload {
                    amount: 100,
                    insertion: &insertion,
                    charge: Some(UnloadChargeOriginalsV1 {
                        quote: &bytes,
                        certificate_set: &certificates
                    })
                })
                .is_err(),
            "mutation{mutation}"
        );
    }
}

#[test]
fn malformed_quote_or_certificate_originals_never_become_retained_authority() {
    let source = Source::new();
    let (quote, certificates) = source.quote(100);
    let original = quote.to_canonical_bytes().unwrap();
    for mutation in 0..7 {
        let mut bytes = original.clone();
        let mut set = certificates.clone();
        match mutation {
            0 => bytes.push(0),
            1 => bytes.clear(),
            2 => {
                let mut bad = quote;
                bad.body.issued_at_ms += 1;
                bytes = bad.to_canonical_bytes().unwrap();
            }
            3 => set.push(0),
            4 => set.clear(),
            5 => {
                set = norito::to_bytes(&KagemushaWalletCertificateSetV1::new(vec![]).unwrap())
                    .unwrap()
            }
            _ => set = vec![0; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1],
        }
        assert!(
            charge_terms(
                &source.scheme,
                &source.before,
                100,
                Some(UnloadChargeOriginalsV1 {
                    quote: &bytes,
                    certificate_set: &set
                })
            )
            .is_err(),
            "mutation{mutation}"
        );
    }
}

#[test]
fn review_unload_uses_the_same_real_quote_and_adjusted_balance_as_the_producer() {
    let source = Source::new();
    let (quote, certificates) = source.quote(100);
    let original = quote.to_canonical_bytes().unwrap();
    let charge = UnloadChargeOriginalsV1 {
        quote: &original,
        certificate_set: &certificates,
    };
    let (fee, digest) = checked_unload_terms(
        &source.scheme,
        &source.before,
        &source.lineage,
        100,
        Some(charge),
    )
    .unwrap();
    assert_eq!(fee, 7);
    assert_eq!(digest, quote.charge_quote_digest());
    let insertion = source.insertion(100, fee);
    let derived = source
        .derive(ConsumingActionV1::Unload {
            amount: 100,
            insertion: &insertion,
            charge: Some(charge),
        })
        .unwrap();
    assert!(
        matches!(derived.statement.effect, KagemushaWalletEffectV1::Unload { amount: 100, online_charge: 7, charge_quote, .. } if charge_quote == digest)
    );
    assert_eq!(derived.state.core.balance, source.before.core.balance - 100);
    assert_eq!(
        kagemusha_wallet_unload_account_payout_v1(100, fee).unwrap(),
        93
    );
    let mut changed = source.lineage;
    changed.burned_total = source.before.core.balance - 99;
    assert!(
        checked_unload_terms(&source.scheme, &source.before, &changed, 100, Some(charge)).is_err()
    );
}

#[test]
fn review_unload_rejects_quote_replay_and_validly_signed_foreign_terms() {
    let source = Source::new();
    let (quote, certificates) = source.quote(100);
    let original = quote.to_canonical_bytes().unwrap();
    let certificate: KagemushaWalletSignerCertificateV1 =
        fixture("KagemushaWalletSignerCertificateV1");
    let charge = UnloadChargeOriginalsV1 {
        quote: &original,
        certificate_set: &certificates,
    };
    let mut advanced = source.before;
    advanced.core.next_redeem += 1;
    let mut advanced_lineage = source.lineage;
    advanced_lineage.head = advanced.commitment().unwrap();
    assert!(
        checked_unload_terms(
            &source.scheme,
            &advanced,
            &advanced_lineage,
            100,
            Some(charge)
        )
        .is_err()
    );
    for mutation in 0..4 {
        let mut body = quote.body;
        match mutation {
            0 => body.wallet_id[0] ^= 1,
            1 => body.net_amount += 1,
            2 => body.ordinal += 1,
            _ => body.asset_digest[0] ^= 1,
        }
        let changed = Source::sign_quote(body, &certificate);
        changed.verify(&source.scheme, &certificate).unwrap();
        let bytes = changed.to_canonical_bytes().unwrap();
        assert!(
            checked_unload_terms(
                &source.scheme,
                &source.before,
                &source.lineage,
                100,
                Some(UnloadChargeOriginalsV1 {
                    quote: &bytes,
                    certificate_set: &certificates
                })
            )
            .is_err()
        );
    }
}
