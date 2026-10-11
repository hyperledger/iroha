//! Exact tape parity and invalid-original preservation at the restoration boundary.

use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn object<T>(name: &str) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .unwrap();
    let original = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    norito::decode_canonical_with_limits(&original, norito::canonical_decode_limits(original.len()))
        .unwrap()
}

fn project(value: &KagemushaWalletPaymentV1) -> IncomingOriginalV1 {
    payment(&norito::to_bytes(value).unwrap()).unwrap()
}

#[test]
fn canonical_original_projection_matches_existing_model_digests_and_tapes() {
    let original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let payer = object("KagemushaWalletCredentialV1");
    let projected = project(&original);
    let digests = original.digests().unwrap();
    assert_eq!(projected.payment, original);
    assert_eq!(projected.payment_digest, digests.payment);
    assert_eq!(
        projected
            .incoming_statement
            .map(|value| value.to_repr())
            .to_vec(),
        original.send.statement.field_items().unwrap()
    );
    assert_eq!(
        projected.omega,
        original.send.lineage.lineage().unwrap().bytes()
    );
    let signer = KagemushaWalletReceiptSignerV1::from_credential(&payer).unwrap();
    let body = original
        .send
        .receipt
        .body(&signer, &original.send.statement, &digests.package.proof)
        .unwrap();
    assert_eq!(
        projected.receipt,
        signed_tape(body.transcript(), &original.send.receipt.signature)
    );
    assert_eq!(
        projected.compact,
        kagemusha_wallet_payment_transcript_v1(
            &digests.request,
            &original.payer_payment_key,
            &original.payer_credential_digest,
            &digests.package.package,
        )
    );
}

#[test]
fn receipt_identity_comes_only_from_the_carried_lineage_original() {
    let mut original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let before = project(&original);
    original.payer_credential_digest = Fp::from(731).to_repr();
    let signer = SigningKey::from_slice(&[0x59; 32]).unwrap();
    original.payer_payment_key = KagemushaDevicePublicKeyV1::from_sec1_bytes(
        signer.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    assert!(original.digests().is_err());
    let after = project(&original);
    assert_eq!(before.receipt, after.receipt);
    assert_ne!(before.compact, after.compact);
    assert_ne!(before.payment_digest, after.payment_digest);
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut original.send.lineage {
        lineage.public.wallet_id = [0x61; 32];
        lineage.public.scheme_id = [0x63; 32];
    }
    let changed = project(&original);
    assert_eq!(&changed.receipt[2..34], &[0x63; 32]);
    assert_eq!(&changed.receipt[34..66], &[0x61; 32]);
    assert_ne!(after.receipt, changed.receipt);
    assert_ne!(after.payment_digest, changed.payment_digest);
}

#[test]
fn invalid_objects_and_signatures_reach_the_original_tapes_without_repair() {
    let original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let before = project(&original);
    let mut changed = original.clone();
    changed.version = 19;
    changed.send.receipt.version = 23;
    changed.send.receipt.operation_id[0] ^= 1;
    changed.send.receipt.capsule_digest[0] ^= 1;
    changed.send.receipt.payment_digest = Fp::from(31).to_repr();
    let key = SigningKey::from_slice(&[37; 32]).unwrap();
    let signature: Signature = key.sign(b"wrong incoming receipt message");
    let signature = signature.normalize_s().unwrap_or(signature);
    changed.send.receipt.signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    assert!(changed.digests().is_err());
    let after = project(&changed);
    assert_eq!(after.payment, changed);
    assert_eq!(&after.compact[..2], &19_u16.to_le_bytes());
    assert_eq!(&after.receipt[..2], &23_u16.to_le_bytes());
    assert_eq!(&after.receipt[114..146], &changed.send.receipt.operation_id);
    assert_eq!(
        &after.receipt[274..306],
        &changed.send.receipt.capsule_digest
    );
    assert_eq!(
        &after.receipt[306..338],
        &changed.send.receipt.payment_digest
    );
    assert_eq!(
        &after.receipt[338..],
        changed.send.receipt.signature.as_raw_bytes()
    );
    assert_ne!(after.payment_digest, before.payment_digest);
    assert_ne!(after.compact, before.compact);
}

#[test]
fn malformed_and_empty_proofs_remain_exact_and_change_the_bound_digest() {
    let original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let before = project(&original);
    let mut changed = original.clone();
    changed.send.step_proof.bytes = vec![0xff, 0, 0x80];
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut changed.send.lineage {
        lineage.proof = vec![0x7f, 0x11];
    }
    let after = project(&changed);
    assert_eq!(after.payment.send.step_proof.bytes, [0xff, 0, 0x80]);
    assert_eq!(&after.omega[320..], [0x7f, 0x11]);
    assert_ne!(after.payment_digest, before.payment_digest);
    changed.send.step_proof.bytes.clear();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut changed.send.lineage {
        lineage.proof.clear();
    }
    assert!(changed.digests().is_err());
    let empty = project(&changed);
    assert!(empty.payment.send.step_proof.bytes.is_empty());
    assert_eq!(empty.omega.len(), 320);
    assert_ne!(empty.payment_digest, after.payment_digest);
}

#[test]
fn statement_semantics_are_preserved_but_unrepresentable_fields_and_frames_reject() {
    let mut original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    original.send.statement.version = 9;
    original.send.statement.enabled_controls = 99;
    if let KagemushaWalletEffectV1::Send {
        amount,
        accepted_lower_ms,
        accepted_upper_ms,
        ..
    } = &mut original.send.statement.effect
    {
        *amount = 0;
        *accepted_lower_ms = 100;
        *accepted_upper_ms = 1;
    }
    assert!(original.send.statement.field_items().is_err());
    let projected = project(&original);
    assert_eq!(projected.incoming_statement[0], Fp::from(9));
    assert_eq!(projected.incoming_statement[11], Fp::from(99));
    assert_eq!(projected.incoming_statement[21], Fp::from(0));
    assert_eq!(projected.incoming_statement[24], Fp::from(100));
    assert_eq!(projected.incoming_statement[25], Fp::from(1));
    original.send.statement.credential_digest = [0xff; 32];
    assert!(payment(&norito::to_bytes(&original).unwrap()).is_err());
    assert!(payment(&[]).is_err());
    assert!(payment(&vec![0; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1]).is_err());
    let mut bytes = norito::to_bytes(&object::<KagemushaWalletPaymentV1>(
        "KagemushaWalletPaymentV1",
    ))
    .unwrap();
    bytes.push(0);
    assert!(payment(&bytes).is_err());
}
impl PreparationV1<'_> {
    /// Exercise only released-source restoration, with a genuinely verified local source.
    /// This assertion does not manufacture a complete producer grant or admit a fold.
    pub(crate) fn assert_incoming_restoration_boundary(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        receiver_signer: &SigningKey,
    ) {
        let signature = |key: &SigningKey, message: &[u8]| {
            let value: Signature = key.sign(message);
            let value = value.normalize_s().unwrap_or(value);
            KagemushaDeviceSignatureV1::from_raw_bytes(&value.to_bytes()).unwrap()
        };
        let scheme = self.installed.verifier().scheme();
        let payer_signer = SigningKey::from_slice(&[0x39; 32]).unwrap();
        let mut payer = owner.credential;
        payer.body.payment_key = KagemushaDevicePublicKeyV1::from_sec1_bytes(
            payer_signer
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        payer.body.account_digest = [0x40; 32];
        payer.body.enrollment_id = [0x41; 32];
        payer.body.wallet_id = kagemusha_wallet_id_v1(
            &payer.body.scheme_id,
            &payer.body.asset_digest,
            &payer.body.payment_key,
            &payer.body.enrollment_id,
        );
        payer.signature = signature(
            &SigningKey::from_slice(&[0x12; 32]).unwrap(),
            &payer.body.signing_message(),
        );
        let certificates = KagemushaWalletCertificateSetV1::new(vec![owner.certificate]).unwrap();
        let body = KagemushaWalletRequestBodyV1 {
            version: 1,
            scheme_id: scheme.scheme_id(),
            asset_digest: owner.credential.body.asset_digest,
            payer_wallet_id: payer.body.wallet_id,
            payer_account_digest: payer.body.account_digest,
            receiver_wallet_id: owner.credential.body.wallet_id,
            receiver_account_digest: owner.credential.body.account_digest,
            send_ordinal: 0,
            receiver_credential_digest: owner.credential.credential_digest(),
            amount: 7,
            fee_schedule: [0; 32],
            fee: 0,
            policy_epoch: 0,
            scheme_policy: [0; 32],
            receiver_accepted_time_ms: 0,
            receiver_blacklist_version: 0,
            receiver_blacklist_root: [0; 32],
            certificates: certificates.digest().unwrap(),
            nonce: [0x43; 32],
        };
        let request = KagemushaWalletRequestV1 {
            body,
            receiver_credential: owner.credential,
            fee_schedule: KagemushaWalletFeeScheduleSlotV1::None,
            certificates: certificates.clone(),
            signature: signature(receiver_signer, &body.signing_message()),
        };
        request.verify(scheme).unwrap();
        let mut payer_state =
            KagemushaWalletStateV1::bootstrap(&payer, Fp::from(201).to_repr()).unwrap();
        payer_state.core.balance = 100;
        let mut incoming: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
        incoming.request = request.signed();
        incoming.payer_payment_key = payer.body.payment_key;
        incoming.payer_credential_digest = payer.credential_digest();
        incoming.send.statement = KagemushaWalletStatementV1 {
            version: 1,
            relation_id: scheme.relation_id,
            scheme_id: scheme.scheme_id(),
            credential_digest: payer.credential_digest(),
            asset_digest: payer.body.asset_digest,
            lifecycle: payer_state.core.lifecycle,
            sequence: 1,
            next_load: 0,
            enabled_controls: 0,
            lineage_burned_total: 0,
            lineage_pending_outgoing_root: payer_state.core.pending_outgoing_root,
            predecessor: payer_state.commitment().unwrap(),
            successor: KagemushaWalletStateCommitmentV1 {
                value: Fp::from(202).to_repr(),
            },
            effect: KagemushaWalletEffectV1::Send {
                credit_id: request.credit_id(),
                receiver_wallet_id: owner.credential.body.wallet_id,
                send_ordinal: 0,
                amount: 7,
                fee: 0,
                request: request.request_digest(),
                accepted_lower_ms: 0,
                accepted_upper_ms: 0,
            },
        };
        incoming.send.lineage = KagemushaWalletLineageSlotV1::Present {
            lineage: KagemushaWalletLineageV1 {
                public: KagemushaWalletLineagePublicV1 {
                    version: 1,
                    scheme_id: scheme.scheme_id(),
                    relation_id: scheme.relation_id,
                    head: incoming.send.statement.predecessor,
                    wallet_id: payer.body.wallet_id,
                    credential_digest: payer.credential_digest(),
                    payment_key: payer.body.payment_key,
                    lifecycle: payer_state.core.lifecycle,
                    policy_epoch: 0,
                    enabled_controls: 0,
                    burned_total: 0,
                    pending_outgoing_root: payer_state.core.pending_outgoing_root,
                    credit_digest_root: kagemusha_wallet_empty_map_root_v1(),
                },
                proof: vec![0xff, 0],
            },
        };
        incoming.send.step_proof.bytes = vec![0x7f, 0x80];
        incoming.send.receipt.operation_id = incoming
            .send
            .statement
            .operation_id(&payer.body.wallet_id)
            .unwrap();
        incoming.send.receipt.payment_digest = [0; 32];
        // Sign exactly the raw proof lengths/digest. The invalid proofs remain invalid
        // even though this original receipt and every surrounding binding are signed.
        let original = norito::to_bytes(&incoming).unwrap();
        let projected = payment(&original).unwrap();
        let message = kagemusha_wallet_signing_message_v1(
            KagemushaWalletSigningDomainV1::Receipt,
            &projected.receipt[..338],
        );
        incoming.send.receipt.signature = signature(&payer_signer, &message);
        incoming
            .verify(scheme, &payer, &certificates, &request)
            .unwrap();
        let consumed = KagemushaWalletConsumedCreditLeafV1 {
            credit_id: request.credit_id(),
            amount: 7,
            receive_sequence: source.frozen.capsule.successor_state.core.sequence + 1,
        };
        let mut tree = KagemushaWalletIndexedTreeV1::new();
        let maps = ReceiveMapsV1 {
            consumed: tree
                .insert(consumed.key(), consumed.leaf_value().unwrap())
                .unwrap(),
        };
        let request_bytes = norito::to_bytes(&request).unwrap();
        let payer_bytes = payer.to_canonical_bytes().unwrap();
        let cert_bytes = norito::to_bytes(&certificates).unwrap();
        for variant in 0..3 {
            let objects_invalid = variant == 1;
            let mut original = incoming.clone();
            if objects_invalid {
                original.version = 19;
                original.send.receipt.version = 23;
            }
            if variant == 2 {
                original.request.body.nonce[0] ^= 1;
                assert_ne!(original.request, request.signed());
            }
            let bytes = norito::to_bytes(&original).unwrap();
            assert!(
                self.prepare_receive(
                    owner,
                    source,
                    &request_bytes,
                    &bytes,
                    &payer_bytes,
                    &cert_bytes,
                    None,
                    maps,
                    Fp::from(203).to_repr(),
                    MemoryBudget::DEFAULT
                )
                .is_err()
            );
            let restored = self
                .restore_receive(
                    owner,
                    source,
                    &request_bytes,
                    &bytes,
                    &payer_bytes,
                    &cert_bytes,
                    None,
                    maps,
                    Fp::from(203).to_repr(),
                    MemoryBudget::DEFAULT,
                )
                .unwrap();
            assert_eq!(
                restored.originals(),
                (request_bytes.as_slice(), Some(bytes.as_slice()))
            );
            assert_eq!(
                restored.state().core.balance,
                source.frozen.capsule.successor_state.core.balance + 7
            );
            assert_eq!(restored.state().core.consumed_credit_root, tree.root());
            let projected = payment(restored.originals().1.unwrap()).unwrap();
            assert_eq!(projected.payment, original);
            assert_eq!(projected.payment.send.step_proof.bytes, [0x7f, 0x80]);
            assert_eq!(&projected.omega[320..], [0xff, 0]);
            assert_receipt_decode(&projected, !objects_invalid);
        }
        // Incoming softness cannot suppress source-custody failures.
        let mut changed_source = source.clone();
        changed_source.retained.frame[0] ^= 1;
        assert!(
            self.restore_receive(
                owner,
                &changed_source,
                &request_bytes,
                &norito::to_bytes(&incoming).unwrap(),
                &payer_bytes,
                &cert_bytes,
                None,
                maps,
                Fp::from(203).to_repr(),
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
        eprintln!(
            "RECEIVE_RESTORATION genuine_own_sigma_receipt=true invalid_incoming_proofs_retained=true represented_objects_soft=true strict_ingress_rejects=true full_worker_qualified=false"
        );
    }
}

#[derive(Clone)]
struct ReceiptDecode {
    tape: Vec<u8>,
}
#[derive(Clone, Debug)]
struct ReceiptConfig {
    verifier: iroha_plonk_recursion::verifier::VerifierConfig<iroha_pasta::Ep>,
    bytes: iroha_plonk_gadgets::bytes::tape::BytesConfig,
    instance: iroha_plonk::cs::Column<iroha_plonk::cs::Instance>,
}
impl iroha_plonk::frontend::Circuit<Fp> for ReceiptDecode {
    type Config = ReceiptConfig;
    type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut iroha_plonk::cs::ConstraintSystem<Fp>) -> Self::Config {
        let verifier =
            iroha_plonk_recursion::verifier::VerifierConfig::configure_serialized_foreign_tagged(
                meta, 4,
            )
            .unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = iroha_plonk_gadgets::bytes::tape::BytesConfig::configure(meta, a, b);
        let instance = meta.instance_column(3);
        meta.enable_equality(instance);
        ReceiptConfig {
            verifier,
            bytes,
            instance,
        }
    }
    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl iroha_plonk::frontend::Layouter<Fp>,
    ) -> Result<(), iroha_plonk::frontend::Error> {
        use iroha_kagemusha_proof::operation_relation::objects::{ObjectKind, SignedObjectCells};
        use iroha_plonk::frontend::Value;
        let mut chip = iroha_plonk_recursion::verifier::VerifierChip::new(cfg.verifier);
        let mut bytes = iroha_plonk_gadgets::bytes::tape::BytesChip::new(cfg.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "retained incoming receipt",
            |mut region| {
                let kind = ObjectKind::Receipt;
                let run = bytes.run(
                    &mut region,
                    &self
                        .tape
                        .iter()
                        .copied()
                        .map(Value::known)
                        .collect::<Vec<_>>(),
                    &kind.primary_segments(),
                    &kind.secondary_segments(),
                )?;
                let lanes = chip.operation_lanes()?;
                let (object, valid) = SignedObjectCells::decode_soft(
                    &mut iroha_plonk_gadgets::UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    kind,
                    &run,
                )?;
                Ok([
                    valid.word().clone(),
                    object.message().clone(),
                    object.digest().clone(),
                ])
            },
        )?;
        for (index, value) in out.iter().enumerate() {
            layouter.constrain_instance(value.cell(), cfg.instance, index)?;
        }
        Ok(())
    }
}
fn assert_receipt_decode(original: &IncomingOriginalV1, valid: bool) {
    let message = kagemusha_wallet_signing_message_v1(
        KagemushaWalletSigningDomainV1::Receipt,
        &original.receipt[..338],
    );
    let digest = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Receipt,
        &message,
        &original.payment.send.receipt.signature,
    );
    let circuit = ReceiptDecode {
        tape: original.receipt.clone(),
    };
    let expected = vec![vec![
        Fp::from(u64::from(valid)),
        word(message).unwrap(),
        word(digest).unwrap(),
    ]];
    assert!(
        iroha_plonk::check::check_circuit(
            &circuit,
            16,
            &expected,
            iroha_plonk::check::CheckMode::Strict,
        )
        .unwrap()
        .is_satisfied()
    );
    let mut wrong = expected;
    wrong[0][0] = Fp::from(u64::from(!valid));
    assert!(
        iroha_plonk::check::check_circuit(
            &circuit,
            16,
            &wrong,
            iroha_plonk::check::CheckMode::Strict
        )
        .is_ok_and(|report| !report.is_satisfied())
    );
}

#[test]
fn projected_invalid_receipt_retains_false_and_original_digest_in_native_decoder() {
    let mut original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    assert_receipt_decode(&project(&original), true);
    original.send.receipt.version = 9;
    assert_receipt_decode(&project(&original), false);
}

#[test]
fn malformed_key_and_signature_encodings_are_custody_errors_before_soft_predicates() {
    // Keep the outer frame/CRC valid, so failure is the typed payload boundary.
    fn replace(original: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        assert_eq!(old.len(), new.len());
        let header = norito::core::Header::read(original).unwrap();
        let payload_at = original.len() - usize::try_from(header.length).unwrap();
        let mut changed = original.to_vec();
        let index = changed[payload_at..]
            .windows(old.len())
            .position(|window| window == old)
            .unwrap()
            + payload_at;
        changed[index..index + old.len()].copy_from_slice(new);
        let checksum = norito::core::hardware_crc64(&changed[payload_at..]);
        let checksum_at = norito::core::Header::SIZE - 9;
        changed[checksum_at..checksum_at + 8].copy_from_slice(&checksum.to_le_bytes());
        norito::core::from_bytes_view(&changed).unwrap();
        changed
    }
    let original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let frame = norito::to_bytes(&original).unwrap();
    let key = original.payer_payment_key.as_sec1_bytes();
    let mut off_curve = [0; 65];
    off_curve[0] = 4;
    let mut bad_prefix = *key;
    bad_prefix[0] = 2;
    for invalid in [off_curve, bad_prefix] {
        let changed = replace(&frame, key, &invalid);
        assert!(matches!(payment(&changed), Err(Error::Authority)));
    }
    let signature = original.send.receipt.signature.as_raw_bytes();
    let low = Signature::from_slice(signature).unwrap();
    let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    let mut zero_r = *signature;
    zero_r[..32].fill(0);
    let mut zero_s = *signature;
    zero_s[32..].fill(0);
    for invalid in [zero_r, zero_s, high.to_bytes().into()] {
        let changed = replace(&frame, signature, &invalid);
        assert!(matches!(payment(&changed), Err(Error::Authority)));
    }
}

#[test]
fn unsupported_outer_carriers_are_custody_errors_without_normalization() {
    let original: KagemushaWalletPaymentV1 = object("KagemushaWalletPaymentV1");
    let mut changed = original.clone();
    changed.send.version = 7;
    assert!(matches!(
        payment(&norito::to_bytes(&changed).unwrap()),
        Err(Error::Authority)
    ));
    changed = original.clone();
    changed.send.lineage = KagemushaWalletLineageSlotV1::None;
    assert!(matches!(
        payment(&norito::to_bytes(&changed).unwrap()),
        Err(Error::Authority)
    ));
    changed = original;
    changed.send.statement.effect = KagemushaWalletEffectV1::Bootstrap {
        enrollment_id: [0; 32],
        enrollment_marker: [0; 32],
    };
    assert!(matches!(
        payment(&norito::to_bytes(&changed).unwrap()),
        Err(Error::Authority)
    ));
}
