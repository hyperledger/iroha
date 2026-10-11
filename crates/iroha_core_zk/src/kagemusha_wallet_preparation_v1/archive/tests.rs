//! Canonical custody conversion and hostile-original tests, without proof admission.

use ff::Field;
use iroha_pasta::{Ep, Eq, Fq};
use iroha_plonk::pcs::ipa::PinnedParams;
use iroha_plonk_recursion::AccumulatorT;

use super::*;

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap()
}

fn object<T>(name: &str) -> T
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
    decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn messages() -> Vec<KagemushaWalletMessageV1> {
    vectors()["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let envelope: KagemushaWalletEnvelopeV1 =
                decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
            envelope.message
        })
        .collect()
}

fn request() -> KagemushaWalletRequestV1 {
    messages()
        .into_iter()
        .find_map(|m| match m {
            KagemushaWalletMessageV1::Request { request } => Some(request),
            _ => None,
        })
        .unwrap()
}

fn originals() -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletCredentialV1,
    Vec<KagemushaWalletRetainedInputV1>,
) {
    let scheme = object("KagemushaWalletSchemeV1");
    let payer = object("KagemushaWalletCredentialV1");
    let payment: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let certificates = messages()
        .into_iter()
        .find_map(|m| match m {
            KagemushaWalletMessageV1::Offer { offer } => Some(offer.certificates),
            _ => None,
        })
        .unwrap();
    use KagemushaWalletRetainedInputRoleV1 as R;
    let originals = vec![
        (R::Request, norito::to_bytes(&request()).unwrap()),
        (R::Payment, payment.to_canonical_bytes().unwrap()),
        (R::Credential, norito::to_bytes(&payer).unwrap()),
        (R::CertificateSet, norito::to_bytes(&certificates).unwrap()),
    ]
    .into_iter()
    .map(|(role, bytes)| KagemushaWalletRetainedInputV1 { role, bytes })
    .collect();
    (scheme, payer, originals)
}

fn status_proposal() -> ArchiveIncomingWitnessV1 {
    // Syntax-only undecided proposals. This test never presents them as deciding claims.
    let p = AccumulatorT::<Ep>::new(
        PinnedParams::<Ep>::derive(1).unwrap().params().g()[0],
        [Fq::ONE; 16],
    )
    .unwrap();
    let v = AccumulatorT::<Eq>::new(
        PinnedParams::<Eq>::derive(1).unwrap().params().g()[0],
        [Fp::ONE; 16],
    )
    .unwrap();
    ArchiveIncomingWitnessV1::Status(Box::new(native::StatusWitness {
        public: [Fp::ZERO; 18],
        public_valid: false,
        opening: p.as_input(),
        modes: [IncomingMode::Trivial; 3],
        pallas_corrections: [*p.g(); 2],
        vesta_correction: *v.g(),
        pallas: p,
        vesta: v,
    }))
}

#[test]
fn local_payment_preserves_every_proof_byte_and_historical_payer_identity() {
    let (scheme, payer, inputs) = originals();
    let source = retained::originals(&scheme, &payer, &inputs).unwrap();
    let payment: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    assert_eq!(source.native.sigma, payment.send.step_proof.bytes);
    assert_eq!(
        source.native.omega,
        payment.send.lineage.lineage().unwrap().bytes()
    );
    assert_eq!(source.native.payment.len(), 163);
    assert_eq!(source.pending, payment.pending_outgoing_leaf().unwrap());
    assert_eq!(source.payment_digest, payment.payment_digest().unwrap());
    let mut current = payer;
    // Only exercise the identity comparator. Public intake requires a separate
    // independently authenticated current owner before calling this private helper.
    current.body.renewal_sequence += 1;
    assert_ne!(current.credential_digest(), payer.credential_digest());
    assert!(retained::originals(&scheme, &current, &inputs).is_ok());
    current.body.wallet_id[0] ^= 1;
    assert!(retained::originals(&scheme, &current, &inputs).is_err());
    for index in 0..inputs.len() {
        let mut altered = inputs.clone();
        altered.remove(index);
        assert!(retained::originals(&scheme, &payer, &altered).is_err());
        let mut altered = inputs.clone();
        altered.push(inputs[index].clone());
        assert!(retained::originals(&scheme, &payer, &altered).is_err());
        let mut altered = inputs.clone();
        altered[index].bytes.push(0);
        assert!(retained::originals(&scheme, &payer, &altered).is_err());
    }
}

#[test]
fn both_credited_transcripts_match_native_model_without_admitting_proposals() {
    let (scheme, payer, inputs) = originals();
    let source = retained::originals(&scheme, &payer, &inputs).unwrap();
    let payment: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let mut cases = 0;
    for message in messages() {
        let KagemushaWalletMessageV1::Credited { credited } = message else {
            continue;
        };
        let expected = credited
            .verify_for(&scheme, &source.request, &payment)
            .unwrap()
            .0;
        let raw = norito::to_bytes(&credited).unwrap();
        assert_eq!(
            evidence::credited_digest(&raw, &source.request, &source.payment_digest).unwrap(),
            expected
        );
        let proposal = match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { .. } => {
                ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Corrected))
            }
            KagemushaWalletCreditedEvidenceV1::Status { .. } => status_proposal(),
        };
        let converted = evidence::original(
            &raw,
            &source.request,
            &source.payment_digest,
            &expected,
            proposal,
        )
        .unwrap();
        match (&credited.evidence, converted) {
            (
                KagemushaWalletCreditedEvidenceV1::Receive { package },
                native::Evidence::Receive {
                    sigma,
                    credited,
                    receipt,
                    mode,
                    ..
                },
            ) => {
                assert_eq!(mode, IncomingMode::Corrected);
                assert_eq!(sigma, package.step_proof.bytes);
                assert_eq!(
                    &receipt[receipt.len() - 64..],
                    package.receipt.signature.as_raw_bytes()
                );
                assert_eq!(credited.len(), 99);
                assert!(
                    evidence::original(
                        &raw,
                        &source.request,
                        &source.payment_digest,
                        &expected,
                        status_proposal()
                    )
                    .is_err()
                );
            }
            (
                KagemushaWalletCreditedEvidenceV1::Status { status },
                native::Evidence::Status {
                    omega,
                    status: tape,
                    credit_opening,
                    witness,
                    ..
                },
            ) => {
                assert_eq!(omega, status.lineage.bytes());
                assert_eq!(credit_opening, status.opening.transcript().unwrap());
                assert_eq!(tape.len(), 162);
                assert_eq!(
                    kagemusha_wallet_poseidon_bytes_v1(u64::from_le_bytes(*b"kgwcsts1"), &tape),
                    status.credit_status_digest().unwrap()
                );
                assert_eq!(witness.modes, [IncomingMode::Trivial; 3]);
                assert!(!witness.public_valid);
                assert!(
                    evidence::original(
                        &raw,
                        &source.request,
                        &source.payment_digest,
                        &expected,
                        ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Accept))
                    )
                    .is_err()
                );
            }
            _ => panic!("conversion must retain evidence kind"),
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn removal_custody_matches_independent_native_tree_and_authenticates_all_paths() {
    let (_, _, inputs) = originals();
    let payment: KagemushaWalletPaymentV1 = decode(&inputs[1].bytes).unwrap();
    let pending = payment.pending_outgoing_leaf().unwrap();
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    let mut native_tree = iroha_kagemusha_proof::tree::IndexedTree::<Fp>::new();
    let key = pending.credit_id;
    let value = pending.leaf_value().unwrap();
    tree.insert(key, value).unwrap();
    native_tree
        .insert(Fp::from_repr(key).unwrap(), Fp::from_repr(value).unwrap())
        .unwrap();
    let before = tree.root();
    let witness = tree.remove(&key).unwrap();
    let expected = native_tree.remove(&Fp::from_repr(key).unwrap()).unwrap();
    let paths = vec![
        witness
            .predecessor_opening
            .leaf_transcript(&witness.predecessor),
        witness.leaf_opening.leaf_transcript(&witness.leaf),
    ];
    assert_eq!(removal_original(&paths).unwrap(), witness);
    let (actual, after) = removal(&witness, &before, &pending).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(after, tree.root());
    assert_eq!(after, native_tree.root().to_repr());
    for malformed in [
        vec![],
        paths[..1].to_vec(),
        vec![paths[1].clone(), paths[0].clone()],
        vec![paths[0].clone(), witness.leaf_opening.empty_transcript()],
    ] {
        assert!(
            removal_original(&malformed)
                .and_then(|path| removal(&path, &before, &pending))
                .is_err()
        );
    }
    for index in 0..32 {
        let mut changed = witness;
        changed.leaf_opening.siblings[index] =
            Fp::from(u64::try_from(index + 2).unwrap()).to_repr();
        assert!(removal(&changed, &before, &pending).is_err());
        let mut changed = witness;
        changed.predecessor_opening.siblings[index] =
            Fp::from(u64::try_from(index + 2).unwrap()).to_repr();
        assert!(removal(&changed, &before, &pending).is_err());
    }
    let mut changed = witness;
    changed.leaf.value = Fp::ONE.to_repr();
    assert!(removal(&changed, &before, &pending).is_err());
}

#[test]
fn invalid_receive_signature_and_proof_are_retained_for_the_soft_owners() {
    let (scheme, payer, inputs) = originals();
    let source = retained::originals(&scheme, &payer, &inputs).unwrap();
    let mut credited = messages()
        .into_iter()
        .find_map(|m| match m {
            KagemushaWalletMessageV1::Credited { credited }
                if matches!(
                    credited.evidence,
                    KagemushaWalletCreditedEvidenceV1::Receive { .. }
                ) =>
            {
                Some(credited)
            }
            _ => None,
        })
        .unwrap();
    let KagemushaWalletCreditedEvidenceV1::Receive { package } = &mut credited.evidence else {
        unreachable!()
    };
    package.step_proof.bytes = vec![255; 33];
    package.receipt.signature = source.request.signature;
    let proof = package.proof_digest().unwrap();
    let signer =
        KagemushaWalletReceiptSignerV1::from_credential(&source.request.receiver_credential)
            .unwrap();
    assert!(
        package
            .receipt
            .verify(&signer, &package.statement, &proof)
            .is_err()
    );
    let body = package
        .receipt
        .body(&signer, &package.statement, &proof)
        .unwrap();
    let receipt_digest = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Receipt,
        &body.signing_message(),
        &package.receipt.signature,
    );
    let package_digest = kagemusha_wallet_package_digest_v1(
        &package.statement.statement_digest().unwrap(),
        &proof,
        &receipt_digest,
    )
    .unwrap();
    let mut tape = vec![1, 0, 1];
    for word in [
        source.pending.credit_id,
        source.payment_digest,
        package_digest,
    ] {
        tape.extend(word);
    }
    let expected = kagemusha_wallet_poseidon_bytes_v1(u64::from_le_bytes(*b"kgwcrdd1"), &tape);
    let raw = norito::to_bytes(&credited).unwrap();
    assert_eq!(
        evidence::credited_digest(&raw, &source.request, &source.payment_digest).unwrap(),
        expected
    );
    let evidence = evidence::original(
        &raw,
        &source.request,
        &source.payment_digest,
        &expected,
        ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Trivial)),
    )
    .unwrap();
    let native::Evidence::Receive {
        sigma,
        receipt,
        credited,
        ..
    } = evidence
    else {
        unreachable!()
    };
    assert_eq!(sigma, vec![255; 33]);
    assert_eq!(
        &receipt[receipt.len() - 64..],
        source.request.signature.as_raw_bytes()
    );
    assert_eq!(credited, tape);
    let mut wrong = expected;
    wrong[0] ^= 1;
    assert!(
        evidence::original(
            &raw,
            &source.request,
            &source.payment_digest,
            &wrong,
            ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Trivial))
        )
        .is_err()
    );
}

#[test]
fn invalid_status_membership_and_receipt_identity_are_not_silently_repaired() {
    let (scheme, payer, inputs) = originals();
    let source = retained::originals(&scheme, &payer, &inputs).unwrap();
    let mut credited = messages()
        .into_iter()
        .find_map(|m| match m {
            KagemushaWalletMessageV1::Credited { credited }
                if matches!(
                    credited.evidence,
                    KagemushaWalletCreditedEvidenceV1::Status { .. }
                ) =>
            {
                Some(credited)
            }
            _ => None,
        })
        .unwrap();
    let KagemushaWalletCreditedEvidenceV1::Status { status } = &mut credited.evidence else {
        unreachable!()
    };
    status.opening.slot = 0;
    status.opening.siblings[..32].fill(255);
    status.receipt.operation_id = Fp::from(313).to_repr();
    assert!(status.validate().is_err());
    let body = KagemushaWalletReceiptBodyV1 {
        version: status.receipt.version,
        scheme_id: status.lineage.public.scheme_id,
        wallet_id: status.lineage.public.wallet_id,
        provider_contract: kagemusha_wallet_provider_contract_v1(),
        sequence: status.statement.sequence,
        operation_id: status.receipt.operation_id,
        predecessor: status.statement.predecessor,
        successor: status.statement.successor,
        statement_digest: status.statement.statement_digest().unwrap(),
        proof_digest: status.proof_digest,
        capsule_digest: status.receipt.capsule_digest,
        payment_digest: status.receipt.payment_digest,
    };
    let receipt_digest = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Receipt,
        &body.signing_message(),
        &status.receipt.signature,
    );
    let mut opening = status.opening.credit_id.to_vec();
    opening.extend(status.opening.payment_digest);
    opening.push(u8::from(status.opening.burned));
    opening.extend(status.opening.next_key);
    opening.extend(status.opening.slot.to_le_bytes());
    opening.extend(&status.opening.siblings);
    let hash = |domain: &[u8; 8], bytes: &[u8]| {
        kagemusha_wallet_poseidon_bytes_v1(u64::from_le_bytes(*domain), bytes)
    };
    let mut tape = status.version.to_le_bytes().to_vec();
    for word in [
        body.statement_digest,
        status.proof_digest,
        receipt_digest,
        status.lineage.lineage_digest(),
        hash(b"kgwcopn1", &opening),
    ] {
        tape.extend(word);
    }
    let mut credited_tape = vec![1, 0, 2];
    for word in [
        source.pending.credit_id,
        source.payment_digest,
        hash(b"kgwcsts1", &tape),
    ] {
        credited_tape.extend(word);
    }
    let expected = hash(b"kgwcrdd1", &credited_tape);
    let raw = norito::to_bytes(&credited).unwrap();
    let native::Evidence::Status {
        credit_opening,
        status,
        receipt,
        ..
    } = evidence::original(
        &raw,
        &source.request,
        &source.payment_digest,
        &expected,
        status_proposal(),
    )
    .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(credit_opening, opening);
    assert_eq!(status, tape);
    assert_eq!(&receipt[..body.transcript().len()], body.transcript());
}

#[test]
fn incoming_evidence_versions_and_statement_predicates_are_preserved_for_both_routes() {
    let (scheme, payer, inputs) = originals();
    let source = retained::originals(&scheme, &payer, &inputs).unwrap();
    for message in messages() {
        let KagemushaWalletMessageV1::Credited { mut credited } = message else {
            continue;
        };
        let before = evidence::credited_digest(
            &norito::to_bytes(&credited).unwrap(),
            &source.request,
            &source.payment_digest,
        )
        .unwrap();
        credited.version = 7;
        let proposal = match &mut credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                package.statement.version = 9;
                package.statement.enabled_controls = 99;
                package.receipt.version = 23;
                assert!(package.statement.field_items().is_err());
                ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Trivial))
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => {
                status.statement.version = 9;
                status.statement.enabled_controls = 99;
                status.receipt.version = 23;
                status.version = 29;
                assert!(status.statement.field_items().is_err());
                status_proposal()
            }
        };
        let bytes = norito::to_bytes(&credited).unwrap();
        let after =
            evidence::credited_digest(&bytes, &source.request, &source.payment_digest).unwrap();
        assert_ne!(before, after);
        let native = evidence::original(
            &bytes,
            &source.request,
            &source.payment_digest,
            &after,
            proposal,
        )
        .unwrap();
        let (statement, receipt, credited) = match native {
            native::Evidence::Receive {
                statement,
                receipt,
                credited,
                ..
            } => (statement, receipt, credited),
            native::Evidence::Status {
                statement,
                receipt,
                credited,
                status,
                ..
            } => {
                assert_eq!(&status[..2], &29_u16.to_le_bytes());
                (statement, receipt, credited)
            }
        };
        assert_eq!(statement[0], Fp::from(9));
        assert_eq!(statement[11], Fp::from(99));
        assert_eq!(&receipt[..2], &23_u16.to_le_bytes());
        assert_eq!(&credited[..2], &7_u16.to_le_bytes());
    }
}

#[test]
fn private_archive_derivation_removes_only_bound_pending_and_preserves_value() {
    let (scheme, payer, inputs) = originals();
    let held = retained::originals(&scheme, &payer, &inputs).unwrap();
    let mut before = KagemushaWalletStateV1::bootstrap(&payer, Fp::from(17).to_repr()).unwrap();
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    tree.insert(held.pending.credit_id, held.pending.leaf_value().unwrap())
        .unwrap();
    before.core.pending_outgoing_root = tree.root();
    let removal = tree.remove(&held.pending.credit_id).unwrap();
    let nonce = Fp::from(19).to_repr();
    let credited = Fp::from(23).to_repr();
    let (after, statement) = prepare::derive(
        &payer,
        &before,
        &held.pending,
        credited,
        &removal,
        nonce,
        scheme.relation_id,
    )
    .unwrap();
    assert_eq!(after.core.pending_outgoing_root, tree.root());
    assert_eq!(statement.predecessor, before.commitment().unwrap());
    assert_eq!(statement.successor, after.commitment().unwrap());
    assert_eq!(
        statement.effect,
        KagemushaWalletEffectV1::ArchiveSent {
            credit_id: held.pending.credit_id,
            credited
        }
    );
    let mut restored = after;
    restored.core.sequence = before.core.sequence;
    restored.core.pending_outgoing_root = before.core.pending_outgoing_root;
    restored.core.state_nonce = before.core.state_nonce;
    assert_eq!(restored, before);
    for wrong_nonce in [[0; 32], before.core.state_nonce, [255; 32]] {
        assert!(
            prepare::derive(
                &payer,
                &before,
                &held.pending,
                credited,
                &removal,
                wrong_nonce,
                scheme.relation_id
            )
            .is_err()
        );
    }
    let mut wrong = removal;
    wrong.leaf.value = Fp::from(29).to_repr();
    assert!(
        prepare::derive(
            &payer,
            &before,
            &held.pending,
            credited,
            &wrong,
            nonce,
            scheme.relation_id
        )
        .is_err()
    );
    before.core.sequence = u128::MAX;
    assert!(
        prepare::derive(
            &payer,
            &before,
            &held.pending,
            credited,
            &removal,
            nonce,
            scheme.relation_id
        )
        .is_err()
    );
}
