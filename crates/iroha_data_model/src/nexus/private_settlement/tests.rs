//! Runtime and confidentiality regressions for atomic private settlement.

use super::*;

#[test]
fn proof_digest_helper_is_domain_and_length_separated() {
    let proof = b"atomic-private-settlement-proof";
    assert_eq!(
        private_settlement_proof_digest_v1(proof),
        private_settlement_proof_digest_v1(proof)
    );
    assert_ne!(private_settlement_proof_digest_v1(proof), Hash::new(proof));
    let mut suffixed = proof.to_vec();
    suffixed.push(0);
    assert_ne!(
        private_settlement_proof_digest_v1(proof),
        private_settlement_proof_digest_v1(&suffixed)
    );
}
use crate::privacy::{PrivacyEncryptionKeyV1, PrivacyRecipientIdV1};
use crate::{
    account::{AccountController, MultisigMember, MultisigPolicy},
    block::BlockHeader,
};
use iroha_crypto::{Algorithm, HashOf, HybridKeyPair, KeyPair};
use iroha_model_base::domain::DomainId;

fn network(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([
        seed,
    ])))
}

fn hash(seed: u8) -> Hash {
    Hash::new([seed])
}

fn legacy_signature_preimage<T: norito::NoritoSerialize>(domain: &[u8], body: &T) -> Vec<u8> {
    let body = norito::encode_canonical(body).expect("legacy canonical body encoding");
    let mut preimage = Vec::with_capacity(domain.len() + 8 + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(body.len())
            .expect("fixture body length fits u64")
            .to_le_bytes(),
    );
    preimage.extend_from_slice(&body);
    preimage
}

#[test]
fn audit_payer_input_json_requires_explicit_dummy_domain() {
    let input = PrivateSettlementAuditPayerInputV1 {
        input_ordinal: 0,
        active: true,
        commitment: PrivacyCommitmentV1::new([1; 32]),
        nullifier: PrivacyNullifierV1::new([2; 32]),
        note_spending_authority: [3; 32],
        dummy_domain: None,
    };
    let value = norito::json::to_value(&input).expect("encode payer input JSON");
    assert_eq!(value.get("dummy_domain"), Some(&norito::json::Value::Null));
    let decoded = norito::json::from_value::<PrivateSettlementAuditPayerInputV1>(value.clone())
        .expect("explicit null dummy domain decodes");
    assert_eq!(decoded, input);

    let mut omitted = value;
    omitted
        .as_object_mut()
        .expect("payer input is a JSON object")
        .remove("dummy_domain");
    let error = norito::json::from_value::<PrivateSettlementAuditPayerInputV1>(omitted)
        .expect_err("omitted dummy domain must reject");
    assert!(error.to_string().contains("missing field `dummy_domain`"));
}

#[test]
fn audit_note_opening_json_requires_explicit_dummy_domain() {
    let opening = active_opening(4, 9);
    let value = norito::json::to_value(&opening).expect("encode audit note opening JSON");
    assert_eq!(value.get("dummy_domain"), Some(&norito::json::Value::Null));
    let decoded = norito::json::from_value::<PrivateSettlementAuditNoteOpeningV1>(value.clone())
        .expect("explicit null dummy domain decodes");
    assert_eq!(decoded, opening);

    let mut omitted = value;
    omitted
        .as_object_mut()
        .expect("audit note opening is a JSON object")
        .remove("dummy_domain");
    let error = norito::json::from_value::<PrivateSettlementAuditNoteOpeningV1>(omitted)
        .expect_err("omitted dummy domain must reject");
    assert!(error.to_string().contains("missing field `dummy_domain`"));
}

fn route(dataspace: u64) -> PrivateSettlementRouteV1 {
    PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(dataspace),
        lane_id: LaneId::new(u32::try_from(dataspace).expect("fixture lane fits u32")),
        lane_incarnation: Hash::new(dataspace.to_le_bytes()),
    }
}

fn manifest(count: usize) -> AtomicPrivateSettlementV1 {
    let sponsor_key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let mut manifest = AtomicPrivateSettlementV1 {
        version: AtomicPrivateSettlementV1::VERSION,
        network_id: network(1),
        bundle_id: hash(2),
        authority_context_height: 10,
        expiry_height: 100,
        sponsor: AccountId::new(sponsor_key.public_key().clone()),
        public_fee_intent: FeePaymentIntent::authority(Vec::new(), None),
        fee_intent_digest: hash(3),
        reimbursement_terms_commitment: hash(4),
        reimbursement_leg_ordinal: 0,
        legs: (0..count)
            .map(|index| {
                let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
                PrivateSettlementLegCommitmentV1 {
                    ordinal,
                    route: route(u64::try_from(index + 1).expect("fixture route fits u64")),
                    pool_id: PrivacyPoolIdV1::new([ordinal.saturating_add(1); 32]),
                    asset_binding_commitment: hash(ordinal.saturating_add(40)),
                    audit_policy_digest: hash(ordinal.saturating_add(70)),
                    payload_digest: hash(ordinal.saturating_add(90)),
                    availability_certificate_digest: hash(ordinal.saturating_add(100)),
                    delta_digest: hash(ordinal.saturating_add(110)),
                }
            })
            .collect(),
    };
    manifest.fee_intent_digest = manifest
        .computed_fee_intent_digest()
        .expect("fixture fee intent hashes");
    manifest.bundle_id = manifest
        .computed_bundle_id()
        .expect("fixture bundle hashes");
    manifest
}

fn measured_bytes32(label: &[u8], index: usize, slot: u8) -> [u8; 32] {
    let digest = Hash::new_from_chunks(&[
        b"private-settlement-wire-size-fixture-v1",
        label,
        &u64::try_from(index)
            .expect("fixture index fits u64")
            .to_le_bytes(),
        &[slot],
    ]);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    bytes
}

fn measured_validator_material() -> (Vec<PeerId>, Vec<Vec<u8>>) {
    let keypairs = (0_u8..4)
        .map(|index| {
            KeyPair::from_seed(
                vec![0xB0_u8.saturating_add(index); 32],
                Algorithm::BlsNormal,
            )
        })
        .collect::<Vec<_>>();
    let validators = keypairs
        .iter()
        .map(|key| PeerId::from(key.public_key().clone()))
        .collect::<Vec<_>>();
    let validator_pops = keypairs
        .iter()
        .map(|key| {
            iroha_crypto::bls_normal_pop_prove(key.private_key())
                .expect("fixture BLS proof of possession")
        })
        .collect::<Vec<_>>();
    (validators, validator_pops)
}

fn measured_authority(
    route: PrivateSettlementRouteV1,
    validators: &[PeerId],
    validator_pops: &[Vec<u8>],
) -> PrivateSettlementCommitteeAuthorityV1 {
    let validators = validators.to_vec();
    PrivateSettlementCommitteeAuthorityV1 {
        route,
        validator_set_hash: HashOf::new(&validators),
        validators,
        validator_pops: validator_pops.to_vec(),
    }
}

fn measured_delta(manifest: &AtomicPrivateSettlementV1, index: usize) -> PrivateSettlementDeltaV1 {
    let leg = &manifest.legs[index];
    let output_commitments = (0_u8..3)
        .map(|slot| PrivacyCommitmentV1::new(measured_bytes32(b"commitment", index, slot)))
        .collect::<Vec<_>>();
    let encrypted_outputs = output_commitments
        .iter()
        .copied()
        .enumerate()
        .map(|(slot, commitment)| {
            let slot = u8::try_from(slot).expect("fixture slot fits u8");
            let mut ciphertext =
                vec![slot.saturating_add(1); PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
            ciphertext[..4].copy_from_slice(b"IPNE");
            PrivacyEncryptedOutputV1 {
                recipient: PrivacyRecipientIdV1::new(measured_bytes32(b"recipient", index, slot)),
                ephemeral_public_key: PrivacyEncryptionKeyV1::new(measured_bytes32(
                    b"encryption-key",
                    index,
                    slot,
                )),
                commitment,
                ciphertext,
            }
        })
        .collect::<Vec<_>>();
    PrivateSettlementDeltaV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        bundle_id: manifest.bundle_id,
        leg_ordinal: leg.ordinal,
        route: leg.route,
        pool_id: leg.pool_id,
        asset_binding_commitment: leg.asset_binding_commitment,
        old_root: PrivacyRootV1::new(measured_bytes32(b"old-root", index, 0)),
        new_root: PrivacyRootV1::new(measured_bytes32(b"new-root", index, 0)),
        old_epoch: 7,
        new_epoch: 8,
        nullifiers: (0_u8..2)
            .map(|slot| PrivacyNullifierV1::new(measured_bytes32(b"nullifier", index, slot)))
            .collect(),
        output_commitments,
        encrypted_outputs,
        statement_digest: Hash::prehashed(measured_bytes32(b"statement", index, 0)),
        proof_digest: Hash::prehashed(measured_bytes32(b"proof", index, 0)),
        capsule_digest: Hash::prehashed(measured_bytes32(b"capsule", index, 0)),
        audit_policy_digest: leg.audit_policy_digest,
        audit_key_epoch: 3,
    }
}

pub fn measured_receipt(count: usize) -> PrivateSettlementReceiptV1 {
    let mut manifest = manifest(count);
    let deltas = (0..count)
        .map(|index| measured_delta(&manifest, index))
        .collect::<Vec<_>>();
    for (leg, delta) in manifest.legs.iter_mut().zip(&deltas) {
        leg.delta_digest = delta.digest().expect("fixture delta hashes");
    }
    manifest.validate().expect("measured manifest validates");
    let manifest_digest = manifest.manifest_digest().expect("fixture manifest hashes");
    let (validators, validator_pops) = measured_validator_material();
    let authorities = manifest
        .legs
        .iter()
        .map(|leg| measured_authority(leg.route, &validators, &validator_pops))
        .collect::<Vec<_>>();
    let authority_catalog =
        PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &authorities)
            .expect("fixture authority catalog compacts");
    let prepared_bundle_digest = hash(0xE1);
    let legs = deltas
        .into_iter()
        .zip(&authorities)
        .enumerate()
        .map(|(index, (delta, authority))| {
            let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
            let common = PrivateSettlementPhaseBodyV1 {
                network_id: manifest.network_id,
                bundle_id: manifest.bundle_id,
                manifest_digest,
                leg_ordinal: ordinal,
                route: manifest.legs[index].route,
                delta_digest: delta.digest().expect("fixture delta hashes"),
                authority_digest: authority.digest().expect("fixture authority hashes"),
                prepared_bundle_digest: Hash::prehashed([0; Hash::LENGTH]),
                phase: PrivateSettlementPhaseV1::Prepare,
                authority_context_height: manifest.authority_context_height,
                expiry_height: manifest.expiry_height,
            };
            let prepare = PrivateSettlementPhaseCertificateV1 {
                body: common,
                authority_catalog_index: ordinal,
                signers_bitmap: 0b0111,
                aggregate_signature: vec![0xA1; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
            };
            let mut commit_body = common;
            commit_body.phase = PrivateSettlementPhaseV1::Commit;
            commit_body.prepared_bundle_digest = prepared_bundle_digest;
            let commit = PrivateSettlementPhaseCertificateV1 {
                body: commit_body,
                authority_catalog_index: ordinal,
                signers_bitmap: 0b1011,
                aggregate_signature: vec![0xA2; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
            };
            PrivateSettlementLegReceiptV1 {
                delta,
                prepare,
                commit,
            }
        })
        .collect();
    PrivateSettlementReceiptV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest,
        authority_catalog,
        legs,
        finalized_height: 50,
    }
}

fn policy(dataspace: DataSpaceId) -> (PrivateSettlementAuditPolicyV1, Vec<KeyPair>) {
    let signing_keys = vec![
        KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519),
        KeyPair::from_seed(vec![0x62; 32], Algorithm::Ed25519),
    ];
    let mut auditors = Vec::new();
    for (index, signing) in signing_keys.iter().enumerate() {
        let mut rng = iroha_crypto::rng_from_seed_slice(&[
            0xA0_u8.saturating_add(u8::try_from(index).expect("fixture index fits u8"))
        ]);
        let encryption = HybridKeyPair::generate(&mut rng).expect("hybrid fixture key");
        auditors.push(PrivateSettlementAuditorV1 {
            auditor_id: AccountId::new(signing.public_key().clone()),
            signing_key: signing.public_key().clone(),
            encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(encryption.public()),
        });
    }
    auditors.sort_by(|left, right| left.auditor_id.cmp(&right.auditor_id));
    let body = PrivateSettlementAuditPolicyBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        dataspace_id: dataspace,
        policy_id: hash(7),
        revision: 1,
        key_epoch: 1,
        activation_height: 5,
        retirement_height: Some(500),
        min_approvals: 1,
        auditors,
    };
    (
        PrivateSettlementAuditPolicyV1::new(body).expect("fixture policy is valid"),
        signing_keys,
    )
}

fn pool_governance_fixture() -> (
    PrivateSettlementAuditPolicyV1,
    PrivateSettlementPoolGovernanceV1,
    AssetDefinitionId,
) {
    let (policy, _) = policy(DataSpaceId::new(1));
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("bank-a", "regulated").expect("fixture domain"),
        "cbdc".parse().expect("fixture asset name"),
    );
    let governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
        route(1),
        PrivacyPoolIdV1::new([0x91; 32]),
        asset_definition_id.clone(),
        [0xA1; 32],
        &policy,
        PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: 10,
            retirement_height: Some(400),
        },
    )
    .expect("fixture pool governance is valid");
    (policy, governance, asset_definition_id)
}

fn active_opening(seed: u8, value: u128) -> PrivateSettlementAuditNoteOpeningV1 {
    PrivateSettlementAuditNoteOpeningV1 {
        active: true,
        commitment: PrivacyCommitmentV1::new([seed; 32]),
        value,
        spending_authority: [seed.wrapping_add(1); 32],
        rho: [seed.wrapping_add(2); 32],
        blinding: [seed.wrapping_add(3); 32],
        memo_digest: [seed.wrapping_add(4); 32],
        dummy_domain: None,
    }
}

fn dummy_opening(seed: u8) -> PrivateSettlementAuditNoteOpeningV1 {
    PrivateSettlementAuditNoteOpeningV1 {
        active: false,
        commitment: PrivacyCommitmentV1::new([seed; 32]),
        value: 0,
        spending_authority: [seed.wrapping_add(2); 32],
        rho: [seed.wrapping_add(3); 32],
        blinding: [seed.wrapping_add(4); 32],
        memo_digest: [seed.wrapping_add(5); 32],
        dummy_domain: Some(hash(seed.wrapping_add(1))),
    }
}

fn placeholder_view_key_authorization(
    signing: &KeyPair,
) -> PrivateSettlementAuditViewKeyAuthorizationV1 {
    let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: Hash::new(OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1),
        network_id: network(1),
        bundle_id: hash(1),
        leg_ordinal: 0,
        route: route(1),
        output_ordinal: 0,
        role: PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
        authorized_account: AccountId::new(signing.public_key().clone()),
        recipient_view_key: [1; 32],
        output_active: true,
        note_spending_authority: [2; 32],
        expiry_height: 1,
    };
    PrivateSettlementAuditViewKeyAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditViewKeySignatureV1::new(
            signing.public_key().clone(),
            SignatureOf::try_new(signing.private_key(), &body)
                .expect("placeholder authorization signs"),
        )],
    )
}

fn placeholder_payer_authorization(
    signing: &KeyPair,
) -> PrivateSettlementAuditPayerAuthorizationV1 {
    let body = PrivateSettlementAuditPayerAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: Hash::new(PAYER_INPUT_AUTHORIZATION_DOMAIN_V1),
        network_id: network(1),
        bundle_id: hash(1),
        leg_ordinal: 0,
        route: route(1),
        payer: AccountId::new(signing.public_key().clone()),
        expiry_height: 1,
        inputs: vec![
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 0,
                active: true,
                commitment: PrivacyCommitmentV1::new([1; 32]),
                nullifier: PrivacyNullifierV1::new([2; 32]),
                note_spending_authority: [3; 32],
                dummy_domain: None,
            },
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 1,
                active: false,
                commitment: PrivacyCommitmentV1::new([4; 32]),
                nullifier: PrivacyNullifierV1::new([5; 32]),
                note_spending_authority: [6; 32],
                dummy_domain: Some(hash(7)),
            },
        ],
    };
    PrivateSettlementAuditPayerAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            signing.public_key().clone(),
            SignatureOf::try_new(signing.private_key(), &body)
                .expect("placeholder payer authorization signs"),
        )],
    )
}

fn authorize_payer_inputs(
    plaintext: &mut PrivateSettlementAuditPlaintextV1,
    nullifiers: &[PrivacyNullifierV1],
    signer: &KeyPair,
) {
    let body = plaintext
        .payer_authorization_body(nullifiers)
        .expect("fixture payer authorization body");
    plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), &body)
                .expect("fixture payer authorization signs"),
        )],
    );
}

fn authorize_output_view_keys(
    plaintext: &mut PrivateSettlementAuditPlaintextV1,
    signers: [&KeyPair; PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1],
) {
    for (index, signer) in signers.into_iter().enumerate() {
        let body = plaintext
            .output_view_key_authorization_body(index)
            .expect("fixture authorization body");
        plaintext.outputs[index].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![PrivateSettlementAuditViewKeySignatureV1::new(
                    signer.public_key().clone(),
                    SignatureOf::try_new(signer.private_key(), &body)
                        .expect("fixture authorization signs"),
                )],
            );
    }
}

fn audit_plaintext_fixture() -> (AtomicPrivateSettlementV1, PrivateSettlementAuditPlaintextV1) {
    let mut manifest = manifest(2);
    let sponsor = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
    let payer = KeyPair::from_seed(vec![0xB1; 32], Algorithm::Ed25519);
    let recipient = KeyPair::from_seed(vec![0xB2; 32], Algorithm::Ed25519);
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("bank-a", "regulated").expect("fixture domain"),
        "cbdc".parse().expect("fixture asset name"),
    );
    let mut plaintext = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: 0,
        route: manifest.legs[0].route,
        pool_id: manifest.legs[0].pool_id,
        payer: AccountId::new(payer.public_key().clone()),
        payer_authorization: placeholder_payer_authorization(&payer),
        recipient: AccountId::new(recipient.public_key().clone()),
        sponsor: manifest.sponsor.clone(),
        asset_definition_id,
        asset_binding_salt: [0xC1; 32],
        amount: 100,
        sponsor_reimbursement_amount: 20,
        fee_intent_digest: manifest.fee_intent_digest,
        settlement_expiry_height: manifest.expiry_height,
        reimbursement_terms_salt: [0xC4; 32],
        memo: b"invoice-2026-08".to_vec(),
        policy_references: {
            let mut references = vec![hash(0xC2), hash(0xC3)];
            references.sort_unstable();
            references
        },
        inputs: vec![active_opening(0xD0, 120), dummy_opening(0xD1)],
        outputs: vec![
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
                recipient_view_key: [0xE1; 32],
                view_key_authorization: placeholder_view_key_authorization(&recipient),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: [0xF1; 32],
                },
                note: active_opening(0xD2, 100),
            },
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::PayerChange,
                recipient_view_key: [0xE2; 32],
                view_key_authorization: placeholder_view_key_authorization(&payer),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: [0xF2; 32],
                },
                note: dummy_opening(0xD3),
            },
            PrivateSettlementAuditOutputV1 {
                role: PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
                recipient_view_key: [0xE3; 32],
                view_key_authorization: placeholder_view_key_authorization(&sponsor),
                encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                    ephemeral_secret: [0xF3; 32],
                },
                note: active_opening(0xD4, 20),
            },
        ],
    };
    manifest.legs[0].asset_binding_commitment = plaintext
        .asset_binding_commitment()
        .expect("fixture asset binding");
    manifest.reimbursement_terms_commitment = plaintext
        .reimbursement_terms_commitment()
        .expect("fixture reimbursement terms");
    manifest.bundle_id = manifest.computed_bundle_id().expect("fixture bundle id");
    plaintext.bundle_id = manifest.bundle_id;
    authorize_payer_inputs(
        &mut plaintext,
        &[
            PrivacyNullifierV1::new([0xA1; 32]),
            PrivacyNullifierV1::new([0xA2; 32]),
        ],
        &payer,
    );
    authorize_output_view_keys(&mut plaintext, [&recipient, &payer, &sponsor]);
    (manifest, plaintext)
}

/// A leg payload around `proof` whose statement, delta, capsule and availability
/// certificate are well-formed records that bind nothing of `manifest(2)`.
fn unbound_leg_payload(proof: Vec<u8>) -> PrivateSettlementLegPayloadV1 {
    let (statement, encrypted_outputs) = fixed_output_statement();
    let delta = PrivateSettlementDeltaV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        bundle_id: statement.bundle_id,
        leg_ordinal: statement.leg_ordinal,
        route: statement.route,
        pool_id: statement.pool_id,
        asset_binding_commitment: statement.asset_binding_commitment,
        old_root: statement.old_root,
        new_root: statement.new_root,
        old_epoch: statement.old_epoch,
        new_epoch: statement.new_epoch,
        nullifiers: statement.nullifiers.clone(),
        output_commitments: statement.output_commitments.clone(),
        encrypted_outputs,
        statement_digest: statement.digest().expect("statement hashes"),
        proof_digest: private_settlement_proof_digest_v1(&proof),
        capsule_digest: statement.audit_capsule_digest,
        audit_policy_digest: statement.audit_policy_digest,
        audit_key_epoch: statement.audit_key_epoch,
    };
    let audit_capsule = PrivateSettlementAuditCapsuleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        aad: PrivateSettlementAuditAadV1 {
            network_id: statement.network_id,
            bundle_id: statement.bundle_id,
            leg_ordinal: statement.leg_ordinal,
            route: statement.route,
            authority_digest: hash(0xD1),
            authority_context_height: statement.authority_context_height,
            audit_policy_digest: statement.audit_policy_digest,
            audit_key_epoch: statement.audit_key_epoch,
            plaintext_commitment: statement.audit_plaintext_commitment,
        },
        padding: PrivateSettlementCapsulePaddingV1::KiB4,
        nonce: [0; PRIVATE_SETTLEMENT_XCHACHA_NONCE_BYTES_V1],
        ciphertext: Vec::new(),
        wrapped_deks: Vec::new(),
    };
    let availability = PrivateSettlementSidecarAvailabilityV1 {
        body: PrivateSettlementSidecarAvailabilityBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: statement.network_id,
            bundle_id: statement.bundle_id,
            leg_ordinal: statement.leg_ordinal,
            route: statement.route,
            authority_digest: hash(0xD1),
            authority_context_height: statement.authority_context_height,
            payload_digest: hash(0xD2),
            payload_bytes: 1,
            retention_until_height: statement.expiry_height,
        },
        signers_bitmap: 0b0111,
        aggregate_signature: vec![1; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
    };
    PrivateSettlementLegPayloadV1 {
        statement,
        proof,
        delta,
        audit_capsule,
        availability,
    }
}

#[test]
fn leg_payload_proof_of_exactly_the_bound_passes_the_size_check_and_one_byte_more_is_refused() {
    let manifest = manifest(2);
    manifest.validate().expect("two legs are admitted");
    let (policy, _) = policy(manifest.legs[0].route.dataspace_id);
    policy.validate().expect("fixture policy is valid");

    // A proof of exactly the bound passes the size check. The fixture binds nothing of
    // the manifest, so validation goes on and refuses it for a binding, not for its size.
    let mut payload = unbound_leg_payload(vec![0x5A; PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1]);
    let at_bound = payload.validate_against(&manifest, &policy);
    assert!(
        at_bound.is_err() && at_bound != Err(PrivateSettlementValidationError::InvalidProofSize),
        "a proof of exactly the bound is not refused for its size: {at_bound:?}"
    );
    // One byte more is refused for its size, before anything else of the payload is read.
    payload.proof.push(0x5A);
    assert_eq!(
        payload.proof.len(),
        PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1 + 1
    );
    assert_eq!(
        payload.validate_against(&manifest, &policy),
        Err(PrivateSettlementValidationError::InvalidProofSize)
    );
    // An empty proof is refused by the same check.
    payload.proof.clear();
    assert_eq!(
        payload.validate_against(&manifest, &policy),
        Err(PrivateSettlementValidationError::InvalidProofSize)
    );
}

#[test]
fn manifest_enforces_two_through_255_canonical_legs() {
    assert_eq!(
        manifest(1).validate(),
        Err(PrivateSettlementValidationError::ParticipantCount { count: 1 })
    );
    manifest(2).validate().expect("two legs are admitted");
    manifest(255).validate().expect("255 legs are admitted");

    let mut reordered = manifest(3);
    reordered.legs.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(PrivateSettlementValidationError::NonCanonicalOrdinal {
            index: 0,
            actual: 1,
        })
    );

    let mut duplicate_dataspace = manifest(2);
    duplicate_dataspace.legs[1].route.dataspace_id = duplicate_dataspace.legs[0].route.dataspace_id;
    duplicate_dataspace.bundle_id = duplicate_dataspace
        .computed_bundle_id()
        .expect("fixture bundle hashes");
    assert_eq!(
        duplicate_dataspace.validate(),
        Err(PrivateSettlementValidationError::DuplicateDataspace)
    );
}

fn assert_audit_plaintext_redaction_and_roundtrip(plaintext: &PrivateSettlementAuditPlaintextV1) {
    assert_eq!(
        format!("{plaintext:?}"),
        "PrivateSettlementAuditPlaintextV1(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", plaintext.outputs[0].view_key_authorization),
        "PrivateSettlementAuditViewKeyAuthorizationV1(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", plaintext.payer_authorization),
        "PrivateSettlementAuditPayerAuthorizationV1(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", plaintext.outputs[0].encryption_opening),
        "PrivateSettlementAuditEncryptionOpeningV1(<redacted>)"
    );
    let encoded = norito::encode_canonical(plaintext).expect("audit plaintext encodes");
    let decoded = norito::decode_canonical::<PrivateSettlementAuditPlaintextV1>(&encoded)
        .expect("audit plaintext decodes canonically");
    assert_eq!(decoded, *plaintext);
}

#[test]
fn auditor_plaintext_is_fixed_balanced_bound_and_redacted() {
    let (manifest, plaintext) = audit_plaintext_fixture();
    plaintext.validate().expect("valid fixed plaintext");
    plaintext
        .validate_against_manifest(&manifest)
        .expect("plaintext binds exact manifest leg");
    let commitment = plaintext.commitment().expect("plaintext commitment");
    let reimbursement = plaintext
        .reimbursement_terms_commitment()
        .expect("reimbursement terms commitment");
    let one_carrier_reimbursement = canonical_hash(
        REIMBURSEMENT_TERMS_COMMITMENT_DOMAIN_V1,
        &plaintext.reimbursement_terms_material(1),
    )
    .expect("one-carrier reimbursement terms commitment");
    assert_eq!(PRIVATE_SETTLEMENT_SUCCESS_FEE_BEARING_CARRIERS_V1, 2);
    assert_ne!(
        reimbursement, one_carrier_reimbursement,
        "reimbursement terms must bind both fee-bearing success carriers"
    );
    let mut changed = plaintext.clone();
    changed.memo.push(b'!');
    assert_ne!(
        commitment,
        changed.commitment().expect("changed plaintext commitment")
    );
    let mut changed_output_secret = plaintext.clone();
    changed_output_secret.outputs[0].note.blinding[0] ^= 1;
    assert_ne!(
        commitment,
        changed_output_secret
            .commitment()
            .expect("changed output opening commitment")
    );
    let mut changed_derived_output = plaintext.clone();
    changed_derived_output.outputs[0].note.memo_digest[0] ^= 1;
    changed_derived_output.outputs[0].note.commitment = PrivacyCommitmentV1::new([0xFA; 32]);
    assert_eq!(
        commitment,
        changed_derived_output
            .commitment()
            .expect("derived output fields are excluded from the projection")
    );
    let mut changed_authorization = plaintext.clone();
    changed_authorization.outputs[0]
        .view_key_authorization
        .body
        .expiry_height -= 1;
    assert_ne!(
        commitment,
        changed_authorization
            .commitment()
            .expect("changed authorization material commitment")
    );
    let mut changed_payer_authorization = plaintext.clone();
    changed_payer_authorization.payer_authorization.body.inputs[0].nullifier =
        PrivacyNullifierV1::new([0xFB; 32]);
    assert_ne!(
        commitment,
        changed_payer_authorization
            .commitment()
            .expect("changed payer authorization commitment")
    );
    let mut changed_encryption_opening = plaintext.clone();
    changed_encryption_opening.outputs[0]
        .encryption_opening
        .ephemeral_secret[0] ^= 1;
    assert_ne!(
        commitment,
        changed_encryption_opening
            .commitment()
            .expect("changed encryption opening commitment")
    );
    assert_audit_plaintext_redaction_and_roundtrip(&plaintext);

    let mut unbalanced = plaintext.clone();
    unbalanced.outputs[0].note.value += 1;
    assert_eq!(
        unbalanced.validate(),
        Err(PrivateSettlementValidationError::InvalidAuditPlaintext)
    );
    let mut literal_asset_substitution = plaintext;
    literal_asset_substitution.asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("bank-a", "regulated").expect("fixture domain"),
        "other".parse().expect("fixture asset name"),
    );
    assert_eq!(
        literal_asset_substitution.validate_against_manifest(&manifest),
        Err(PrivateSettlementValidationError::AuditPlaintextBindingMismatch)
    );
}

#[test]
fn confidential_canonical_staging_preserves_audit_commitment_bytes() {
    let (_, plaintext) = audit_plaintext_fixture();
    let material = plaintext.commitment_material();
    let mut previous_encoding =
        norito::encode_canonical(&material).expect("legacy canonical encoding succeeds");
    let guarded_encoding =
        encode_confidential_canonical(&material).expect("guarded canonical encoding succeeds");

    assert_eq!(guarded_encoding.as_slice(), previous_encoding.as_slice());

    let encoded_len =
        u64::try_from(previous_encoding.len()).expect("fixture encoding length fits u64");
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_PLAINTEXT_COMMITMENT_DOMAIN_V1);
    hasher.update(encoded_len.to_le_bytes());
    hasher.update(&previous_encoding);
    assert_eq!(
        plaintext.commitment().expect("guarded commitment succeeds"),
        Hash::prehashed(hasher.finalize().into())
    );

    zeroize_value_for_confidential_discard(&mut previous_encoding);
}

#[test]
fn audit_commitment_material_confidential_discard_scrubs_secret_projection() {
    fn account_is_scrubbed(account: &AccountId) -> bool {
        match account.controller() {
            AccountController::Single(key) => key
                .try_to_bytes()
                .map_or(true, |(_, payload)| payload.iter().all(|byte| *byte == 0)),
            AccountController::Multisig(policy) => {
                policy.version() == 0 && policy.threshold() == 0 && policy.members().is_empty()
            }
        }
    }

    let (_, plaintext) = audit_plaintext_fixture();
    let mut material = plaintext.commitment_material();
    let mut reimbursement =
        plaintext.reimbursement_terms_material(PRIVATE_SETTLEMENT_SUCCESS_FEE_BEARING_CARRIERS_V1);
    let mut asset_binding = PrivateSettlementAssetBindingMaterialV1 {
        route: plaintext.route,
        pool_id: plaintext.pool_id,
        asset_definition_id: plaintext.asset_definition_id.clone(),
        asset_binding_salt: plaintext.asset_binding_salt,
    };

    material.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(&material.payer));
    assert!(account_is_scrubbed(&material.recipient));
    assert!(account_is_scrubbed(&material.sponsor));
    assert!(account_is_scrubbed(
        &material.payer_authorization.body.payer
    ));
    assert_eq!(material.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(material.asset_binding_salt, [0; 32]);
    assert_eq!(material.amount, 0);
    assert_eq!(material.sponsor_reimbursement_amount, 0);
    assert_eq!(material.reimbursement_terms_salt, [0; 32]);
    assert!(material.memo.is_empty());
    assert!(material.policy_references.is_empty());
    assert!(material.inputs.iter().all(|opening| {
        !opening.active
            && opening.value == 0
            && opening.spending_authority == [0; 32]
            && opening.rho == [0; 32]
            && opening.blinding == [0; 32]
            && opening.memo_digest == [0; 32]
            && opening.dummy_domain.is_none()
    }));
    assert!(material.outputs.iter().all(|output| {
        output.recipient_view_key == [0; 32]
            && output.view_key_authorization.body.recipient_view_key == [0; 32]
            && output.view_key_authorization.body.note_spending_authority == [0; 32]
            && !output.view_key_authorization.body.output_active
            && account_is_scrubbed(&output.view_key_authorization.body.authorized_account)
            && output
                .view_key_authorization
                .signatures
                .iter()
                .all(|signature| signature.signature.payload().is_empty())
            && output.encryption_opening.ephemeral_secret == [0; 32]
            && !output.active
            && output.value == 0
            && output.spending_authority == [0; 32]
            && output.rho == [0; 32]
            && output.blinding == [0; 32]
            && output.dummy_domain.is_none()
    }));

    reimbursement.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(&reimbursement.sponsor));
    assert_eq!(reimbursement.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(reimbursement.sponsor_reimbursement_amount, 0);
    assert_eq!(reimbursement.reimbursement_terms_salt, [0; 32]);

    asset_binding.zeroize_for_confidential_discard();
    assert_eq!(asset_binding.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(asset_binding.asset_binding_salt, [0; 32]);
}

#[test]
fn confidential_canonical_error_path_scrubs_staged_bytes() {
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "test::iroha_data_model::FailAfterLengthPass")]
    struct FailAfterLengthPass {
        calls: std::cell::Cell<usize>,
    }

    impl norito::core::SerializePayload for FailAfterLengthPass {
        fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
            let call = self.calls.get();
            self.calls.set(call.saturating_add(1));
            encoder.write_all(&[0xA5; 32])?;
            if call == 2 {
                return Err(norito::Error::Message(
                    "intentional confidential encoding failure".into(),
                ));
            }
            Ok(())
        }
    }

    let material = FailAfterLengthPass {
        calls: std::cell::Cell::new(0),
    };
    let drops_before = CONFIDENTIAL_NONZERO_BUFFER_ZEROIZED_DROPS.with(std::cell::Cell::get);
    let error = match encode_confidential_canonical(&material) {
        Ok(_) => panic!("the output pass must fail after staging confidential bytes"),
        Err(error) => error,
    };
    assert!(matches!(error, norito::Error::Message(_)));
    assert_eq!(material.calls.get(), 3);
    let drops_after = CONFIDENTIAL_NONZERO_BUFFER_ZEROIZED_DROPS.with(std::cell::Cell::get);
    assert_eq!(drops_after, drops_before + 1);
}

fn public_key_is_scrubbed(key: &PublicKey) -> bool {
    key.try_to_bytes()
        .map_or(true, |(_, payload)| payload.iter().all(|byte| *byte == 0))
}

fn account_is_scrubbed(account: &AccountId) -> bool {
    match account.controller() {
        AccountController::Single(key) => public_key_is_scrubbed(key),
        AccountController::Multisig(policy) => {
            policy.version() == 0 && policy.threshold() == 0 && policy.members().is_empty()
        }
    }
}

fn note_opening_is_scrubbed(opening: &PrivateSettlementAuditNoteOpeningV1) -> bool {
    !opening.active
        && opening.value == 0
        && opening.spending_authority == [0; 32]
        && opening.rho == [0; 32]
        && opening.blinding == [0; 32]
        && opening.memo_digest == [0; 32]
        && opening.dummy_domain.is_none()
}

fn assert_secret_fields_are_scrubbed(plaintext: &PrivateSettlementAuditPlaintextV1) {
    assert!(account_is_scrubbed(&plaintext.payer));
    assert!(account_is_scrubbed(&plaintext.recipient));
    assert!(account_is_scrubbed(&plaintext.sponsor));
    assert_eq!(plaintext.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(plaintext.asset_binding_salt, [0; 32]);
    assert_eq!(plaintext.amount, 0);
    assert_eq!(plaintext.sponsor_reimbursement_amount, 0);
    assert_eq!(plaintext.reimbursement_terms_salt, [0; 32]);
    assert!(plaintext.memo.is_empty());
    assert!(plaintext.policy_references.is_empty());
    assert!(account_is_scrubbed(
        &plaintext.payer_authorization.body.payer
    ));
    assert!(
        plaintext
            .payer_authorization
            .body
            .inputs
            .iter()
            .all(|input| {
                !input.active
                    && input.note_spending_authority == [0; 32]
                    && input.dummy_domain.is_none()
            })
    );
    assert!(
        plaintext
            .payer_authorization
            .signatures
            .iter()
            .all(|entry| public_key_is_scrubbed(&entry.signer)
                && entry.signature.payload().is_empty())
    );
    assert!(plaintext.inputs.iter().all(note_opening_is_scrubbed));
    assert!(plaintext.outputs.iter().all(|output| {
        output.recipient_view_key == [0; 32]
            && output.view_key_authorization.body.recipient_view_key == [0; 32]
            && !output.view_key_authorization.body.output_active
            && output.view_key_authorization.body.note_spending_authority == [0; 32]
            && account_is_scrubbed(&output.view_key_authorization.body.authorized_account)
            && output
                .view_key_authorization
                .signatures
                .iter()
                .all(|entry| {
                    public_key_is_scrubbed(&entry.signer) && entry.signature.payload().is_empty()
                })
            && output.encryption_opening.ephemeral_secret == [0; 32]
            && note_opening_is_scrubbed(&output.note)
    }));
}

fn payer_input_is_scrubbed(input: &PrivateSettlementAuditPayerInputV1) -> bool {
    !input.active && input.note_spending_authority == [0; 32] && input.dummy_domain.is_none()
}

#[test]
fn auditor_plaintext_confidential_discard_scrubs_every_secret_field_idempotently() {
    let (_, mut plaintext) = audit_plaintext_fixture();
    let multisig_members = [0xB3, 0xB4]
        .map(|seed| {
            let keypair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
            MultisigMember::new(keypair.public_key().clone(), 1).expect("multisig member")
        })
        .to_vec();
    plaintext.recipient = AccountId::new_multisig(
        MultisigPolicy::new(2, multisig_members).expect("multisig recipient"),
    );

    assert!(!plaintext.memo.is_empty());
    assert!(!plaintext.policy_references.is_empty());
    assert!(
        plaintext
            .payer_authorization
            .body
            .inputs
            .iter()
            .any(|input| input.active && input.dummy_domain.is_none())
    );
    assert!(
        plaintext
            .payer_authorization
            .body
            .inputs
            .iter()
            .any(|input| !input.active && input.dummy_domain.is_some())
    );
    assert!(
        plaintext
            .inputs
            .iter()
            .any(|input| input.active && input.dummy_domain.is_none())
    );
    assert!(
        plaintext
            .inputs
            .iter()
            .any(|input| !input.active && input.dummy_domain.is_some())
    );
    assert!(plaintext.outputs.iter().any(|output| {
        output.view_key_authorization.body.output_active
            && output.note.active
            && output.note.dummy_domain.is_none()
    }));
    assert!(plaintext.outputs.iter().any(|output| {
        !output.view_key_authorization.body.output_active
            && !output.note.active
            && output.note.dummy_domain.is_some()
    }));
    assert!(matches!(
        plaintext.recipient.controller(),
        AccountController::Multisig(policy) if !policy.members().is_empty()
    ));

    plaintext.zeroize_for_confidential_discard();
    assert_secret_fields_are_scrubbed(&plaintext);

    plaintext.zeroize_for_confidential_discard();
    assert_secret_fields_are_scrubbed(&plaintext);
}

fn assert_confidential_child_drop_owners() {
    assert!(core::mem::needs_drop::<PrivateSettlementAuditPayerInputV1>());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditPayerAuthorizationBodyV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditPayerSignatureV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditPayerAuthorizationV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditViewKeyAuthorizationBodyV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditViewKeySignatureV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditViewKeyAuthorizationV1,
    >());
    assert!(core::mem::needs_drop::<
        PrivateSettlementAuditEncryptionOpeningV1,
    >());
    assert!(core::mem::needs_drop::<PrivateSettlementAuditNoteOpeningV1>());
    assert!(core::mem::needs_drop::<PrivateSettlementAuditOutputV1>());
}

#[test]
fn restricted_child_owners_scrub_standalone_copies_idempotently() {
    assert_confidential_child_drop_owners();

    let (_, plaintext) = audit_plaintext_fixture();

    let mut payer_input = plaintext.payer_authorization.body.inputs[0].clone();
    payer_input.zeroize_for_confidential_discard();
    payer_input.zeroize_for_confidential_discard();
    assert!(payer_input_is_scrubbed(&payer_input));

    let mut payer_body = plaintext.payer_authorization.body.clone();
    payer_body.zeroize_for_confidential_discard();
    payer_body.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(&payer_body.payer));
    assert!(payer_body.inputs.iter().all(payer_input_is_scrubbed));

    let mut payer_signature = plaintext.payer_authorization.signatures[0].clone();
    payer_signature.zeroize_for_confidential_discard();
    payer_signature.zeroize_for_confidential_discard();
    assert!(public_key_is_scrubbed(&payer_signature.signer));
    assert!(payer_signature.signature.payload().is_empty());

    let mut payer_authorization = plaintext.payer_authorization.clone();
    payer_authorization.zeroize_for_confidential_discard();
    payer_authorization.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(&payer_authorization.body.payer));
    assert!(
        payer_authorization
            .body
            .inputs
            .iter()
            .all(payer_input_is_scrubbed)
    );
    assert!(payer_authorization.signatures.iter().all(|entry| {
        public_key_is_scrubbed(&entry.signer) && entry.signature.payload().is_empty()
    }));

    let output = &plaintext.outputs[0];
    let mut view_body = output.view_key_authorization.body.clone();
    view_body.zeroize_for_confidential_discard();
    view_body.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(&view_body.authorized_account));
    assert_eq!(view_body.recipient_view_key, [0; 32]);
    assert!(!view_body.output_active);
    assert_eq!(view_body.note_spending_authority, [0; 32]);

    let mut view_signature = output.view_key_authorization.signatures[0].clone();
    view_signature.zeroize_for_confidential_discard();
    view_signature.zeroize_for_confidential_discard();
    assert!(public_key_is_scrubbed(&view_signature.signer));
    assert!(view_signature.signature.payload().is_empty());

    let mut view_authorization = output.view_key_authorization.clone();
    view_authorization.zeroize_for_confidential_discard();
    view_authorization.zeroize_for_confidential_discard();
    assert!(account_is_scrubbed(
        &view_authorization.body.authorized_account
    ));
    assert_eq!(view_authorization.body.recipient_view_key, [0; 32]);
    assert_eq!(view_authorization.body.note_spending_authority, [0; 32]);
    assert!(view_authorization.signatures.iter().all(|entry| {
        public_key_is_scrubbed(&entry.signer) && entry.signature.payload().is_empty()
    }));

    let mut encryption_opening = output.encryption_opening.clone();
    encryption_opening.zeroize_for_confidential_discard();
    encryption_opening.zeroize_for_confidential_discard();
    assert_eq!(encryption_opening.ephemeral_secret, [0; 32]);

    let mut note_opening = output.note.clone();
    note_opening.zeroize_for_confidential_discard();
    note_opening.zeroize_for_confidential_discard();
    assert!(note_opening_is_scrubbed(&note_opening));

    let mut output = output.clone();
    output.zeroize_for_confidential_discard();
    output.zeroize_for_confidential_discard();
    assert_eq!(output.recipient_view_key, [0; 32]);
    assert!(account_is_scrubbed(
        &output.view_key_authorization.body.authorized_account
    ));
    assert_eq!(output.encryption_opening.ephemeral_secret, [0; 32]);
    assert!(note_opening_is_scrubbed(&output.note));
}

#[test]
fn restricted_pool_governance_owner_scrubs_opening_idempotently() {
    assert!(core::mem::needs_drop::<PrivateSettlementPoolGovernanceBodyV1>());
    assert!(core::mem::needs_drop::<PrivateSettlementPoolGovernanceV1>());

    let (_, governance, _) = pool_governance_fixture();
    let mut body = governance.body.clone();
    body.zeroize_for_confidential_discard();
    body.zeroize_for_confidential_discard();
    assert_eq!(body.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(body.asset_binding_salt, [0; 32]);

    let mut record = governance.clone();
    record.zeroize_for_confidential_discard();
    record.zeroize_for_confidential_discard();
    assert_eq!(record.body.asset_definition_id.aid_bytes, [0; 16]);
    assert_eq!(record.body.asset_binding_salt, [0; 32]);
}

#[test]
fn proof_binding_excludes_post_proof_artifacts_but_manifest_digest_binds_them() {
    let original = manifest(2);
    let mut changed = original.clone();
    changed.legs[0].payload_digest = hash(250);
    changed.legs[0].availability_certificate_digest = hash(251);
    changed.legs[0].delta_digest = hash(252);
    changed
        .validate()
        .expect("post-proof manifest remains valid");
    assert_eq!(
        original.computed_bundle_id().expect("bundle hashes"),
        changed.computed_bundle_id().expect("bundle hashes")
    );
    assert_eq!(
        original
            .proof_binding_digest()
            .expect("proof binding hashes"),
        changed
            .proof_binding_digest()
            .expect("proof binding hashes")
    );
    assert_ne!(
        original.manifest_digest().expect("manifest hashes"),
        changed.manifest_digest().expect("manifest hashes")
    );
}

#[test]
fn proof_binding_commits_every_ordered_settlement_intent_field() {
    let original = manifest(2);
    let original_digest = original
        .proof_binding_digest()
        .expect("proof binding hashes");
    let assert_changed = |mut changed: AtomicPrivateSettlementV1| {
        changed.bundle_id = changed.computed_bundle_id().expect("bundle hashes");
        changed.validate().expect("changed manifest remains valid");
        assert_ne!(
            original_digest,
            changed
                .proof_binding_digest()
                .expect("proof binding hashes")
        );
    };

    let mut changed = original.clone();
    changed.network_id = network(2);
    assert_changed(changed);

    let mut changed = original.clone();
    changed.authority_context_height += 1;
    assert_changed(changed);

    let mut changed = original.clone();
    changed.expiry_height += 1;
    assert_changed(changed);

    let mut changed = original.clone();
    let sponsor_key = KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519);
    changed.sponsor = AccountId::new(sponsor_key.public_key().clone());
    assert_changed(changed);

    let mut changed = original.clone();
    changed.public_fee_intent =
        FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    changed.fee_intent_digest = changed
        .computed_fee_intent_digest()
        .expect("fee intent hashes");
    assert_changed(changed);

    let mut changed = original.clone();
    changed.reimbursement_terms_commitment = hash(253);
    assert_changed(changed);

    let mut changed = original.clone();
    changed.reimbursement_leg_ordinal = 1;
    assert_changed(changed);

    let mut changed = original.clone();
    changed.legs[0].route.lane_id = LaneId::new(99);
    assert_changed(changed);

    let mut changed = original.clone();
    changed.legs[0].pool_id = PrivacyPoolIdV1::new([0xF1; 32]);
    assert_changed(changed);

    let mut changed = original.clone();
    changed.legs[0].asset_binding_commitment = hash(254);
    assert_changed(changed);

    let mut changed = original;
    changed.legs[0].audit_policy_digest = hash(255);
    assert_changed(changed);
}

#[test]
fn carrier_and_receipt_wire_sizes_fit_protocol_limit_through_255_legs() {
    let mut previous_receipt_bytes = 0;
    for count in [2, 3, 4, 8, 16, 17, 255] {
        let receipt = measured_receipt(count);
        receipt
            .validate_shape()
            .expect("measured receipt validates");
        let receipt_bytes = norito::encode_canonical(&receipt)
            .expect("measured receipt encodes")
            .len();
        let carrier = PrivateSettlementCommitBundleV1 {
            version: receipt.version,
            manifest: receipt.manifest.clone(),
            authority_catalog: receipt.authority_catalog.clone(),
            legs: receipt.legs.clone(),
        };
        let carrier_bytes = carrier
            .canonical_carrier_bytes_len()
            .expect("measured carrier encodes");
        assert_eq!(
            receipt
                .canonical_carrier_bytes_len()
                .expect("receipt projects the measured carrier"),
            carrier_bytes
        );
        let instruction =
            crate::isi::private_settlement::FinalizeAtomicPrivateSettlementV1::new(carrier.clone());
        let boxed = crate::isi::InstructionBox::from(instruction);
        assert_eq!(
            norito::encode_canonical(&boxed)
                .expect("boxed carrier instruction encodes")
                .len(),
            carrier_bytes
        );
        eprintln!(
            "atomic-private-settlement wire size: legs={count} receipt_bytes={receipt_bytes} carrier_bytes={carrier_bytes}"
        );
        assert!(
            receipt_bytes <= PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1,
            "{count}-leg receipt is {receipt_bytes} bytes"
        );
        assert!(
            carrier_bytes <= PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1,
            "{count}-leg carrier is {carrier_bytes} bytes"
        );
        assert!(receipt_bytes > previous_receipt_bytes);
        previous_receipt_bytes = receipt_bytes;
    }
}

#[test]
fn audit_policy_requires_canonical_distinct_purpose_keys() {
    let (policy, _) = policy(DataSpaceId::new(1));
    policy.validate().expect("fixture policy is valid");

    let mut duplicate = policy.clone();
    duplicate.body.auditors[1].signing_key = duplicate.body.auditors[0].signing_key.clone();
    duplicate.policy_digest =
        canonical_hash(AUDIT_POLICY_DIGEST_DOMAIN_V1, &duplicate.body).expect("policy hashes");
    assert_eq!(
        duplicate.validate(),
        Err(PrivateSettlementValidationError::DuplicateAuditorKey)
    );
}

#[test]
fn pool_governance_roundtrips_and_opens_exact_restricted_mapping() {
    let (policy, governance, asset_definition_id) = pool_governance_fixture();
    governance.validate().expect("governance validates");
    governance
        .validate_against_policy_at(&policy, 10)
        .expect("policy is exact and active");
    assert!(governance.is_active_at(10));
    assert!(!governance.is_active_at(400));
    governance
        .validate_asset_opening(
            route(1),
            PrivacyPoolIdV1::new([0x91; 32]),
            &asset_definition_id,
            [0xA1; 32],
        )
        .expect("restricted opening matches");
    assert_eq!(
        governance.body.audit_policy_digest,
        policy
            .computed_policy_digest()
            .expect("policy digest recomputes")
    );
    assert_eq!(
        governance.body.asset_binding_commitment,
        governance
            .body
            .computed_asset_binding_commitment()
            .expect("asset binding recomputes")
    );
    assert_eq!(
        governance.governance_digest,
        governance
            .computed_governance_digest()
            .expect("governance digest recomputes")
    );

    let encoded = norito::encode_canonical(&governance).expect("governance encodes");
    let decoded = norito::decode_canonical::<PrivateSettlementPoolGovernanceV1>(&encoded)
        .expect("governance decodes canonically");
    assert_eq!(decoded, governance);

    {
        let json = norito::json::to_json(&governance).expect("governance JSON encodes");
        let decoded_json: PrivateSettlementPoolGovernanceV1 =
            norito::json::from_json(&json).expect("governance JSON decodes");
        assert_eq!(decoded_json, governance);
    }
    assert_eq!(
        format!("{governance:?}"),
        "PrivateSettlementPoolGovernanceV1(<restricted>)"
    );
    assert_eq!(
        format!("{:?}", governance.body),
        "PrivateSettlementPoolGovernanceBodyV1(<restricted>)"
    );
}

#[test]
fn pool_governance_rejects_asset_salt_route_and_pool_substitution() {
    let (_, governance, asset_definition_id) = pool_governance_fixture();
    let expected_error = Err(PrivateSettlementValidationError::PoolGovernanceAssetBindingMismatch);

    let wrong_asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("bank-a", "regulated").expect("fixture domain"),
        "other".parse().expect("fixture asset name"),
    );
    assert_eq!(
        governance.validate_asset_opening(
            route(1),
            governance.body.pool_id,
            &wrong_asset,
            governance.body.asset_binding_salt,
        ),
        expected_error
    );

    let mut wrong_salt = governance.body.asset_binding_salt;
    wrong_salt[0] ^= 1;
    assert_eq!(
        governance.validate_asset_opening(
            route(1),
            governance.body.pool_id,
            &asset_definition_id,
            wrong_salt,
        ),
        expected_error
    );

    let mut wrong_route = route(1);
    wrong_route.lane_incarnation = hash(0xE1);
    assert_eq!(
        governance.validate_asset_opening(
            wrong_route,
            governance.body.pool_id,
            &asset_definition_id,
            governance.body.asset_binding_salt,
        ),
        expected_error
    );
    assert_ne!(
        governance.body.asset_binding_commitment,
        private_settlement_asset_binding_commitment_v1(
            wrong_route,
            governance.body.pool_id,
            &asset_definition_id,
            governance.body.asset_binding_salt,
        )
        .expect("substituted route hashes")
    );

    assert_eq!(
        governance.validate_asset_opening(
            route(1),
            PrivacyPoolIdV1::new([0x92; 32]),
            &asset_definition_id,
            governance.body.asset_binding_salt,
        ),
        expected_error
    );
}

#[test]
fn pool_governance_rejects_wrong_policy_epoch_and_stale_lifecycle() {
    let (policy, governance, _) = pool_governance_fixture();

    let mut wrong_policy_body = policy.body.clone();
    wrong_policy_body.policy_id = hash(0xE2);
    let wrong_policy = PrivateSettlementAuditPolicyV1::new(wrong_policy_body)
        .expect("substituted policy remains structural");
    assert_eq!(
        governance.validate_against_policy_at(&wrong_policy, 10),
        Err(PrivateSettlementValidationError::PoolGovernancePolicyMismatch)
    );

    let mut wrong_epoch_body = governance.body.clone();
    wrong_epoch_body.audit_key_epoch += 1;
    let wrong_epoch = PrivateSettlementPoolGovernanceV1::new(wrong_epoch_body)
        .expect("substituted epoch remains structural");
    assert_eq!(
        wrong_epoch.validate_against_policy_at(&policy, 10),
        Err(PrivateSettlementValidationError::PoolGovernancePolicyMismatch)
    );

    let mut wrong_digest_body = governance.body.clone();
    wrong_digest_body.audit_policy_digest = hash(0xE3);
    let wrong_digest = PrivateSettlementPoolGovernanceV1::new(wrong_digest_body)
        .expect("substituted policy digest remains structural");
    assert_eq!(
        wrong_digest.validate_against_policy_at(&policy, 10),
        Err(PrivateSettlementValidationError::PoolGovernancePolicyMismatch)
    );

    assert_eq!(
        governance.validate_against_policy_at(&policy, 9),
        Err(PrivateSettlementValidationError::StalePoolGovernance)
    );
    assert_eq!(
        governance.validate_against_policy_at(&policy, 400),
        Err(PrivateSettlementValidationError::StalePoolGovernance)
    );

    let mut outlives_policy_body = governance.body.clone();
    outlives_policy_body.lifecycle.retirement_height = None;
    let outlives_policy = PrivateSettlementPoolGovernanceV1::new(outlives_policy_body)
        .expect("open-ended mapping remains structural");
    assert_eq!(
        outlives_policy.validate_against_policy_at(&policy, 10),
        Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle)
    );

    let mut invalid_lifecycle = governance.body.clone();
    invalid_lifecycle.lifecycle.activation_height = 0;
    assert_eq!(
        PrivateSettlementPoolGovernanceV1::new(invalid_lifecycle),
        Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle)
    );

    let mut invalid_revision = governance.body.clone();
    invalid_revision.lifecycle.governance_revision = 0;
    assert_eq!(
        PrivateSettlementPoolGovernanceV1::new(invalid_revision),
        Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle)
    );

    let mut invalid_interval = governance.body.clone();
    invalid_interval.lifecycle.retirement_height =
        Some(invalid_interval.lifecycle.activation_height);
    assert_eq!(
        PrivateSettlementPoolGovernanceV1::new(invalid_interval),
        Err(PrivateSettlementValidationError::InvalidPoolGovernanceLifecycle)
    );
}

#[test]
fn auditor_approval_is_purpose_bound_and_signature_checked() {
    let (policy, signing_keys) = policy(DataSpaceId::new(1));
    let auditor = &policy.body.auditors[0];
    let signing = signing_keys
        .iter()
        .find(|key| key.public_key() == &auditor.signing_key)
        .expect("matching signing key");
    let body = PrivateSettlementAuditApprovalBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: network(1),
        bundle_id: hash(9),
        leg_ordinal: 0,
        dataspace_id: DataSpaceId::new(1),
        auditor_id: auditor.auditor_id.clone(),
        audit_policy_digest: policy.policy_digest,
        audit_key_epoch: policy.body.key_epoch,
        proof_digest: hash(10),
        capsule_digest: hash(11),
        delta_digest: hash(12),
        old_root: PrivacyRootV1::new([13; 32]),
        new_root: PrivacyRootV1::new([14; 32]),
        expiry_height: 100,
    };
    let approval = PrivateSettlementAuditApprovalV1 {
        signature: SignatureOf::try_new(signing.private_key(), &body)
            .expect("fixture approval signs"),
        body,
    };
    approval.verify(&policy, 20).expect("approval verifies");
    assert_eq!(
        format!("{policy:?}"),
        "PrivateSettlementAuditPolicyV1(<restricted>)"
    );
    assert_eq!(
        format!("{:?}", policy.body),
        "PrivateSettlementAuditPolicyBodyV1(<restricted>)"
    );
    assert_eq!(
        format!("{auditor:?}"),
        "PrivateSettlementAuditorV1(<restricted>)"
    );
    assert_eq!(
        format!("{:?}", approval.body),
        "PrivateSettlementAuditApprovalBodyV1(<restricted>)"
    );
    assert_eq!(
        format!("{approval:?}"),
        "PrivateSettlementAuditApprovalV1(<restricted>)"
    );

    let mut substituted = approval.clone();
    substituted.body.proof_digest = hash(99);
    assert_eq!(
        substituted.verify(&policy, 20),
        Err(PrivateSettlementValidationError::InvalidAuditSignature)
    );
}

#[test]
fn phase_certificate_requires_three_of_four_signers() {
    let certificate = PrivateSettlementPhaseCertificateV1 {
        body: PrivateSettlementPhaseBodyV1 {
            network_id: network(1),
            bundle_id: hash(2),
            manifest_digest: hash(3),
            leg_ordinal: 0,
            route: route(1),
            delta_digest: hash(4),
            authority_digest: hash(5),
            prepared_bundle_digest: Hash::prehashed([0; Hash::LENGTH]),
            phase: PrivateSettlementPhaseV1::Prepare,
            authority_context_height: 10,
            expiry_height: 100,
        },
        authority_catalog_index: 0,
        signers_bitmap: 0b0111,
        aggregate_signature: vec![1; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
    };
    certificate.validate_shape().expect("three signers qualify");
    let mut prepare_with_bundle_digest = certificate.clone();
    prepare_with_bundle_digest.body.prepared_bundle_digest = hash(6);
    assert_eq!(
        prepare_with_bundle_digest.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPhaseCertificate)
    );
    let mut commit_without_bundle_digest = certificate.clone();
    commit_without_bundle_digest.body.phase = PrivateSettlementPhaseV1::Commit;
    assert_eq!(
        commit_without_bundle_digest.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPhaseCertificate)
    );
    commit_without_bundle_digest.body.prepared_bundle_digest = hash(6);
    commit_without_bundle_digest
        .validate_shape()
        .expect("Commit requires the non-zero complete Prepare-barrier digest");

    let mut two = certificate;
    two.signers_bitmap = 0b0011;
    assert_eq!(
        two.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPhaseCertificate)
    );
    let mut four = two;
    four.signers_bitmap = 0b1111;
    assert_eq!(
        four.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPhaseCertificate)
    );
}

#[test]
fn authority_catalog_deduplicates_rosters_and_reconstructs_route_bound_authorities() {
    let manifest = manifest(3);
    let (validators, validator_pops) = measured_validator_material();
    let authorities = manifest
        .legs
        .iter()
        .map(|leg| measured_authority(leg.route, &validators, &validator_pops))
        .collect::<Vec<_>>();
    let catalog =
        PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &authorities)
            .expect("shared roster compacts");

    assert_eq!(catalog.rosters.len(), 1);
    assert_eq!(catalog.leg_roster_indices, vec![0, 0, 0]);
    catalog
        .validate_for_manifest(&manifest)
        .expect("canonical catalog validates");
    for (index, expected) in authorities.iter().enumerate() {
        assert_eq!(
            catalog
                .authority_for_leg(&manifest, index)
                .expect("leg authority resolves"),
            *expected
        );
    }

    let encoded = norito::encode_canonical(&catalog).expect("catalog encodes");
    let decoded = norito::decode_canonical::<PrivateSettlementAuthorityCatalogV1>(&encoded)
        .expect("catalog decodes");
    assert_eq!(decoded, catalog);
}

#[test]
fn authority_catalog_rejects_conflicts_and_noncanonical_references() {
    let manifest = manifest(2);
    let (validators, validator_pops) = measured_validator_material();
    let authorities = manifest
        .legs
        .iter()
        .map(|leg| measured_authority(leg.route, &validators, &validator_pops))
        .collect::<Vec<_>>();
    let catalog =
        PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &authorities)
            .expect("shared roster compacts");

    let mut conflicting = authorities.clone();
    conflicting[1].validator_pops[0][0] ^= 1;
    assert_eq!(
        PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &conflicting),
        Err(PrivateSettlementValidationError::InvalidAuthorityCatalog)
    );

    let mut duplicate_roster = catalog.clone();
    duplicate_roster.rosters.push(catalog.rosters[0].clone());
    duplicate_roster.leg_roster_indices = vec![0, 1];
    assert_eq!(
        duplicate_roster.validate_for_manifest(&manifest),
        Err(PrivateSettlementValidationError::InvalidAuthorityCatalog)
    );

    let mut noncanonical = catalog.clone();
    noncanonical
        .rosters
        .push(PrivateSettlementCommitteeRosterV1 {
            validator_set_hash: HashOf::new(&vec![
                PeerId::from(
                    KeyPair::from_seed(vec![0xC1; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC2; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC3; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC4; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
            ]),
            validators: vec![
                PeerId::from(
                    KeyPair::from_seed(vec![0xC1; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC2; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC3; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
                PeerId::from(
                    KeyPair::from_seed(vec![0xC4; 32], Algorithm::BlsNormal)
                        .public_key()
                        .clone(),
                ),
            ],
            validator_pops: vec![vec![0xC1; PRIVATE_SETTLEMENT_BLS_BYTES_V1]; 4],
        });
    noncanonical.leg_roster_indices = vec![1, 0];
    assert_eq!(
        noncanonical.validate_for_manifest(&manifest),
        Err(PrivateSettlementValidationError::InvalidAuthorityCatalog)
    );

    let mut out_of_range = catalog;
    out_of_range.leg_roster_indices[1] = 1;
    assert_eq!(
        out_of_range.validate_for_manifest(&manifest),
        Err(PrivateSettlementValidationError::InvalidAuthorityCatalog)
    );
}

#[test]
fn phase_vote_and_prepare_barrier_roundtrip_with_closed_shape() {
    let receipt = measured_receipt(2);
    let body = receipt.legs[0].prepare.body;
    assert_eq!(
        body.signature_preimage().expect("phase preimage encodes"),
        legacy_signature_preimage(PHASE_SIGNATURE_DOMAIN_V1, &body),
    );
    let authority = receipt
        .authority_catalog
        .authority_for_leg(&receipt.manifest, 0)
        .expect("fixture authority resolves");
    let vote = PrivateSettlementPhaseVoteV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        body,
        signer: authority.validators[0].clone(),
        signature: vec![0xA5; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
    };
    vote.validate_shape().expect("phase vote shape");
    let vote_bytes = norito::encode_canonical(&vote).expect("vote encodes");
    let decoded_vote: PrivateSettlementPhaseVoteV1 =
        norito::decode_canonical(&vote_bytes).expect("vote decodes");
    assert_eq!(decoded_vote, vote);

    let barrier = PrivateSettlementPrepareBarrierV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: receipt.manifest,
        authority_catalog: receipt.authority_catalog,
        deltas: receipt.legs.iter().map(|leg| leg.delta.clone()).collect(),
        prepare_certificates: receipt.legs.iter().map(|leg| leg.prepare.clone()).collect(),
        prepared_bundle_digest: hash(0xE5),
    };
    barrier.validate_shape().expect("barrier shape");
    let digest = barrier
        .computed_prepared_bundle_digest()
        .expect("barrier digest");
    let mut quorum_equivalent_encoding = barrier.clone();
    quorum_equivalent_encoding.prepare_certificates[0].signers_bitmap = 0b1011;
    quorum_equivalent_encoding.prepare_certificates[0].aggregate_signature =
        vec![0x5A; PRIVATE_SETTLEMENT_BLS_BYTES_V1];
    assert_eq!(
        quorum_equivalent_encoding
            .computed_prepared_bundle_digest()
            .expect("normalized barrier digest"),
        digest,
        "the digest binds the certified body, not its quorum encoding"
    );
    assert!(barrier.quorum_equivalent_to(&quorum_equivalent_encoding));
    let mut substituted_statement = quorum_equivalent_encoding.clone();
    substituted_statement.prepare_certificates[0]
        .body
        .delta_digest = hash(0x44);
    assert!(!barrier.quorum_equivalent_to(&substituted_statement));
    let json = norito::json::to_json(&barrier).expect("barrier JSON encodes");
    let decoded: PrivateSettlementPrepareBarrierV1 =
        norito::json::from_json(&json).expect("barrier JSON decodes");
    assert_eq!(decoded, barrier);

    let mut incomplete = barrier;
    incomplete.prepare_certificates.pop();
    assert_eq!(
        incomplete.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPrepareBarrier)
    );
}

#[test]
fn prepare_and_receipt_shapes_reject_cross_leg_recipient_reuse() {
    let mut receipt = measured_receipt(2);
    let reused = receipt.legs[0].delta.encrypted_outputs[0].recipient;
    receipt.legs[1].delta.encrypted_outputs[0].recipient = reused;
    assert_eq!(
        receipt.validate_shape(),
        Err(PrivateSettlementValidationError::DuplicateStateItem)
    );

    let barrier = PrivateSettlementPrepareBarrierV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: receipt.manifest,
        authority_catalog: receipt.authority_catalog,
        deltas: receipt.legs.iter().map(|leg| leg.delta.clone()).collect(),
        prepare_certificates: receipt.legs.iter().map(|leg| leg.prepare.clone()).collect(),
        prepared_bundle_digest: hash(0xE5),
    };
    assert_eq!(
        barrier.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidPrepareBarrier)
    );
}

#[test]
fn sidecar_availability_signature_is_purpose_and_bundle_bound() {
    let manifest = manifest(2);
    let body = PrivateSettlementSidecarAvailabilityBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: 0,
        route: manifest.legs[0].route,
        authority_digest: hash(0xD1),
        authority_context_height: manifest.authority_context_height,
        payload_digest: manifest.legs[0].payload_digest,
        payload_bytes: 1,
        retention_until_height: manifest.expiry_height,
    };
    let certificate = PrivateSettlementSidecarAvailabilityV1 {
        body,
        signers_bitmap: 0b0111,
        aggregate_signature: vec![1; PRIVATE_SETTLEMENT_BLS_BYTES_V1],
    };
    certificate
        .validate_shape()
        .expect("availability certificate shape");
    let preimage = certificate
        .signature_preimage()
        .expect("availability preimage encodes");
    assert!(preimage.starts_with(SIDECAR_AVAILABILITY_SIGNATURE_DOMAIN_V1));
    let body_bytes = norito::encode_canonical(&certificate.body).expect("body encodes");
    let length_offset = SIDECAR_AVAILABILITY_SIGNATURE_DOMAIN_V1.len();
    assert_eq!(
        &preimage[length_offset..length_offset + std::mem::size_of::<u64>()],
        &u64::try_from(body_bytes.len())
            .expect("fixture body length fits u64")
            .to_le_bytes()
    );
    assert_eq!(
        &preimage[length_offset + std::mem::size_of::<u64>()..],
        body_bytes.as_slice()
    );

    let mut substituted = certificate.clone();
    substituted.body.bundle_id = hash(0xD2);
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("substituted body encodes")
    );
    let mut missing = certificate;
    missing.body.bundle_id = Hash::prehashed([0; Hash::LENGTH]);
    assert_eq!(
        missing.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidAvailabilityCertificate)
    );
}

#[test]
fn auditor_view_attestation_is_purpose_height_lifecycle_and_responder_bound() {
    let (validators, validator_pops) = measured_validator_material();
    let authority = measured_authority(route(1), &validators, &validator_pops);
    let body = PrivateSettlementAuditorViewAttestationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: network(1),
        payload_digest: hash(0xD3),
        view_digest: hash(0xD4),
        authority_digest: authority.digest().expect("authority digest"),
        lifecycle_code: PRIVATE_SETTLEMENT_LIFECYCLE_COLLECTING_V1,
        authoritative_height: 19,
        responder: validators[0].clone(),
    };
    body.validate_shape().expect("attestation body shape");
    let preimage = body.signature_preimage().expect("attestation preimage");
    assert!(preimage.starts_with(AUDITOR_VIEW_ATTESTATION_SIGNATURE_DOMAIN_V1));
    assert_eq!(
        preimage,
        legacy_signature_preimage(AUDITOR_VIEW_ATTESTATION_SIGNATURE_DOMAIN_V1, &body),
    );

    let mut substituted = body.clone();
    substituted.authoritative_height += 1;
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("height-substituted preimage")
    );
    substituted = body.clone();
    substituted.lifecycle_code = PRIVATE_SETTLEMENT_LIFECYCLE_AUDITED_V1;
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("lifecycle-substituted preimage")
    );
    substituted = body.clone();
    substituted.responder = validators[1].clone();
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("responder-substituted preimage")
    );

    let mut invalid = body;
    invalid.lifecycle_code = PRIVATE_SETTLEMENT_LIFECYCLE_EXPIRED_V1.saturating_add(1);
    assert_eq!(
        invalid.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidAuditorViewAttestation)
    );
}

#[test]
fn audit_approval_acknowledgement_attestation_binds_request_view_and_responder() {
    let (validators, validator_pops) = measured_validator_material();
    let authority = measured_authority(route(1), &validators, &validator_pops);
    let body = PrivateSettlementAuditApprovalAcknowledgementAttestationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: network(1),
        payload_digest: hash(0xE3),
        approval_digest: hash(0xE4),
        acknowledgement_digest: hash(0xE5),
        authority_digest: authority.digest().expect("authority digest"),
        lifecycle_code: PRIVATE_SETTLEMENT_LIFECYCLE_AUDITED_V1,
        authoritative_height: 23,
        responder: validators[0].clone(),
    };
    body.validate_shape().expect("acknowledgement body shape");
    let preimage = body
        .signature_preimage()
        .expect("acknowledgement attestation preimage");
    assert!(preimage.starts_with(AUDIT_APPROVAL_ACKNOWLEDGEMENT_ATTESTATION_SIGNATURE_DOMAIN_V1));
    assert_eq!(
        preimage,
        legacy_signature_preimage(
            AUDIT_APPROVAL_ACKNOWLEDGEMENT_ATTESTATION_SIGNATURE_DOMAIN_V1,
            &body,
        ),
    );

    let mut substituted = body.clone();
    substituted.approval_digest = hash(0xE6);
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("approval-substituted preimage")
    );
    substituted = body.clone();
    substituted.acknowledgement_digest = hash(0xE7);
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("acknowledgement-substituted preimage")
    );
    substituted = body.clone();
    substituted.responder = validators[1].clone();
    assert_ne!(
        preimage,
        substituted
            .signature_preimage()
            .expect("responder-substituted preimage")
    );

    let mut invalid = body;
    invalid.lifecycle_code = PRIVATE_SETTLEMENT_LIFECYCLE_PREPARED_V1;
    assert_eq!(
        invalid.validate_shape(),
        Err(PrivateSettlementValidationError::InvalidAuditApprovalAcknowledgementAttestation)
    );
}

fn fixed_output_statement() -> (
    PrivateSettlementProofStatementV1,
    Vec<PrivacyEncryptedOutputV1>,
) {
    let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
    let output_commitments = vec![
        PrivacyCommitmentV1::new([9; 32]),
        PrivacyCommitmentV1::new([10; 32]),
        PrivacyCommitmentV1::new([11; 32]),
    ];
    let mut ciphertext = vec![1; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
    ciphertext[..4].copy_from_slice(b"IPNE");
    let encrypted_outputs = (0..PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1)
        .map(|index| PrivacyEncryptedOutputV1 {
            recipient: PrivacyRecipientIdV1::new([20 + u8::try_from(index).unwrap(); 32]),
            ephemeral_public_key: PrivacyEncryptionKeyV1::new(
                [30 + u8::try_from(index).unwrap(); 32],
            ),
            commitment: output_commitments[index],
            ciphertext: ciphertext.clone(),
        })
        .collect::<Vec<_>>();
    let statement = PrivateSettlementProofStatementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        profile,
        proof_profile_digest: profile.digest(),
        network_id: network(1),
        bundle_id: hash(2),
        leg_ordinal: 0,
        route: route(1),
        authority_context_height: 10,
        pool_id: PrivacyPoolIdV1::new([3; 32]),
        asset_binding_commitment: hash(4),
        old_root: PrivacyRootV1::new([5; 32]),
        new_root: PrivacyRootV1::new([6; 32]),
        old_epoch: 1,
        new_epoch: 2,
        nullifiers: vec![
            PrivacyNullifierV1::new([7; 32]),
            PrivacyNullifierV1::new([8; 32]),
        ],
        output_commitments,
        encrypted_outputs: encrypted_outputs.clone(),
        audit_plaintext_commitment: hash(16),
        audit_input_commitment: [17; 32],
        audit_capsule_digest: hash(12),
        audit_policy_digest: hash(13),
        audit_key_epoch: 1,
        fee_intent_digest: hash(14),
        reimbursement_terms_commitment: hash(15),
        reimbursement_leg_ordinal: 0,
        expiry_height: 100,
    };
    (statement, encrypted_outputs)
}

fn assert_fixed_output_commitment(
    statement: &PrivateSettlementProofStatementV1,
) -> PrivateSettlementProofStatementV1 {
    statement.validate().expect("statement shape is valid");
    let statement_bytes = norito::encode_canonical(statement).expect("statement encodes");
    let decoded_statement =
        norito::decode_canonical::<PrivateSettlementProofStatementV1>(&statement_bytes)
            .expect("statement decodes");
    assert_eq!(decoded_statement, *statement);
    assert_eq!(decoded_statement.new_root, PrivacyRootV1::new([6; 32]));
    assert_eq!(decoded_statement.new_epoch, 2);
    assert_eq!(decoded_statement.audit_input_commitment, [17; 32]);
    let json_statement = norito::json::to_value(statement).expect("statement JSON encodes");
    assert_eq!(
        norito::json::from_value::<PrivateSettlementProofStatementV1>(json_statement.clone())
            .expect("statement JSON decodes"),
        *statement
    );
    for digest in [[0x22; 32], [0x23; 32]] {
        let mut raw_digest_statement = statement.clone();
        raw_digest_statement.audit_input_commitment = digest;
        raw_digest_statement
            .validate()
            .expect("either SHA-256 low-bit parity is canonical");
        let bytes =
            norito::encode_canonical(&raw_digest_statement).expect("raw digest statement encodes");
        let decoded = norito::decode_canonical::<PrivateSettlementProofStatementV1>(&bytes)
            .expect("raw digest statement decodes");
        assert_eq!(decoded.audit_input_commitment, digest);
        assert_eq!(decoded, raw_digest_statement);
        let json = norito::json::to_value(&raw_digest_statement)
            .expect("raw digest statement JSON encodes");
        let decoded = norito::json::from_value::<PrivateSettlementProofStatementV1>(json)
            .expect("raw digest statement JSON decodes");
        assert_eq!(decoded.audit_input_commitment, digest);
        assert_eq!(decoded, raw_digest_statement);
    }
    let mut omitted_input_commitment = json_statement;
    omitted_input_commitment
        .as_object_mut()
        .expect("statement JSON is an object")
        .remove("audit_input_commitment");
    assert!(
        norito::json::from_value::<PrivateSettlementProofStatementV1>(omitted_input_commitment)
            .is_err(),
        "the first-release statement cannot omit its AIR input-opening binding"
    );
    let mut zero_input_commitment = statement.clone();
    zero_input_commitment.audit_input_commitment = [0; 32];
    assert_eq!(
        zero_input_commitment.validate(),
        Err(PrivateSettlementValidationError::ZeroCommitment)
    );
    let mut substituted_input_commitment = statement.clone();
    substituted_input_commitment.audit_input_commitment = [18; 32];
    assert_ne!(
        statement.digest().expect("statement digest"),
        substituted_input_commitment
            .digest()
            .expect("substituted statement digest"),
        "the statement digest binds the exact input-opening commitment"
    );
    substituted_input_commitment
}

fn assert_fixed_output_delta(
    statement: &PrivateSettlementProofStatementV1,
    encrypted_outputs: &[PrivacyEncryptedOutputV1],
    substituted_input_commitment: &PrivateSettlementProofStatementV1,
) {
    let mut delta = PrivateSettlementDeltaV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        bundle_id: statement.bundle_id,
        leg_ordinal: statement.leg_ordinal,
        route: statement.route,
        pool_id: statement.pool_id,
        asset_binding_commitment: statement.asset_binding_commitment,
        old_root: statement.old_root,
        new_root: statement.new_root,
        old_epoch: statement.old_epoch,
        new_epoch: statement.new_epoch,
        nullifiers: statement.nullifiers.clone(),
        output_commitments: statement.output_commitments.clone(),
        encrypted_outputs: encrypted_outputs.to_vec(),
        statement_digest: statement.digest().expect("statement hashes"),
        proof_digest: hash(16),
        capsule_digest: statement.audit_capsule_digest,
        audit_policy_digest: statement.audit_policy_digest,
        audit_key_epoch: statement.audit_key_epoch,
    };
    delta.validate_against(statement).expect("delta aligns");
    assert_eq!(
        delta.validate_against(substituted_input_commitment),
        Err(PrivateSettlementValidationError::DeltaStatementMismatch)
    );
    let mut reused_statement_recipient = statement.clone();
    reused_statement_recipient.encrypted_outputs[1].recipient =
        reused_statement_recipient.encrypted_outputs[0].recipient;
    assert_eq!(
        reused_statement_recipient.validate(),
        Err(PrivateSettlementValidationError::DuplicateStateItem)
    );
    let mut reused_delta_recipient = delta.clone();
    reused_delta_recipient.encrypted_outputs[1].recipient =
        reused_delta_recipient.encrypted_outputs[0].recipient;
    assert_eq!(
        reused_delta_recipient.validate_public_shape(),
        Err(PrivateSettlementValidationError::DuplicateStateItem)
    );
    let mut substituted_successor = delta.clone();
    substituted_successor.new_root = PrivacyRootV1::new([17; 32]);
    assert_eq!(
        substituted_successor.validate_against(statement),
        Err(PrivateSettlementValidationError::DeltaStatementMismatch)
    );
    let mut substituted_epoch = delta.clone();
    substituted_epoch.old_epoch = 2;
    substituted_epoch.new_epoch = 3;
    assert_eq!(
        substituted_epoch.validate_against(statement),
        Err(PrivateSettlementValidationError::DeltaStatementMismatch)
    );
    delta.encrypted_outputs[2].ciphertext.pop();
    assert_eq!(
        delta.validate_against(statement),
        Err(PrivateSettlementValidationError::InvalidEncryptedOutput { index: 2 })
    );
}

#[test]
fn fixed_output_codec_rejects_variable_or_unbound_ciphertext() {
    let (statement, encrypted_outputs) = fixed_output_statement();
    let substituted_input_commitment = assert_fixed_output_commitment(&statement);
    let mut zero_successor = statement.clone();
    zero_successor.new_root = PrivacyRootV1::new([0; 32]);
    assert_eq!(
        zero_successor.validate(),
        Err(PrivateSettlementValidationError::ZeroCommitment)
    );
    let mut unchanged_successor = statement.clone();
    unchanged_successor.new_root = unchanged_successor.old_root;
    assert_eq!(
        unchanged_successor.validate(),
        Err(PrivateSettlementValidationError::InvalidEpoch)
    );
    let mut skipped_epoch = statement.clone();
    skipped_epoch.new_epoch = 3;
    assert_eq!(
        skipped_epoch.validate(),
        Err(PrivateSettlementValidationError::InvalidEpoch)
    );
    assert_fixed_output_delta(
        &statement,
        &encrypted_outputs,
        &substituted_input_commitment,
    );
    let mut malformed_statement = statement;
    malformed_statement.encrypted_outputs[2].ciphertext.pop();
    assert_eq!(
        malformed_statement.validate(),
        Err(PrivateSettlementValidationError::InvalidEncryptedOutput { index: 2 })
    );
}

#[test]
fn receipt_rejects_each_independent_delta_manifest_mismatch() {
    let baseline = measured_receipt(2);
    baseline.validate_shape().expect("valid receipt fixture");
    for coordinate in 0..7 {
        let mut changed = baseline.clone();
        let delta = &mut changed.legs[0].delta;
        match coordinate {
            0 => delta.bundle_id = hash(0xA9),
            1 => delta.leg_ordinal = 1,
            2 => delta.route = route(9),
            3 => delta.pool_id = PrivacyPoolIdV1::new([0xA9; 32]),
            4 => delta.asset_binding_commitment = hash(0xA9),
            5 => delta.audit_policy_digest = hash(0xA9),
            6 => delta.proof_digest = hash(0xA9),
            _ => unreachable!(),
        }
        delta
            .validate_public_shape()
            .expect("delta remains independently well formed");
        if coordinate < 6 {
            // Keep every repeated digest internally coherent so each coordinate
            // mismatch is detected independently of the delta-digest comparison.
            // This is a shape-only fixture; these are not authenticated signatures.
            changed.manifest.legs[0].delta_digest = delta.digest().unwrap();
            let manifest_digest = changed.manifest.manifest_digest().unwrap();
            for leg in &mut changed.legs {
                let delta_digest = leg.delta.digest().unwrap();
                for body in [&mut leg.prepare.body, &mut leg.commit.body] {
                    body.manifest_digest = manifest_digest;
                    body.delta_digest = delta_digest;
                }
            }
            changed
                .manifest
                .validate()
                .expect("manifest remains independently canonical");
        }
        assert_eq!(
            changed.validate_shape(),
            Err(PrivateSettlementValidationError::ReceiptBindingMismatch),
            "coordinate {coordinate}"
        );
    }
}

#[test]
fn audit_plaintext_requires_the_first_active_input_for_all_slot_combinations() {
    let (_, baseline) = audit_plaintext_fixture();
    baseline.validate().expect("valid one-active-input fixture");
    let nullifiers = baseline
        .payer_authorization
        .body
        .inputs
        .iter()
        .map(|input| input.nullifier)
        .collect::<Vec<_>>();
    let signer = KeyPair::from_seed(vec![0xB1; 32], Algorithm::Ed25519);
    for first_active in [false, true] {
        for second_active in [false, true] {
            let mut changed = baseline.clone();
            changed.inputs[0] = if first_active {
                active_opening(0xD0, if second_active { 60 } else { 120 })
            } else {
                dummy_opening(0xD0)
            };
            changed.inputs[1] = if second_active {
                active_opening(0xD1, if first_active { 60 } else { 120 })
            } else {
                dummy_opening(0xD1)
            };
            for input in &changed.inputs {
                input
                    .validate()
                    .expect("each opening has valid active/dummy shape");
            }
            if first_active {
                authorize_payer_inputs(&mut changed, &nullifiers, &signer);
                assert_eq!(changed.validate(), Ok(()), "second active: {second_active}");
            } else {
                assert_eq!(
                    changed.validate(),
                    Err(PrivateSettlementValidationError::InvalidAuditPlaintext),
                    "first inactive must fail before authorization or balance; second active: {second_active}"
                );
            }
        }
    }
}

#[test]
fn audit_plaintext_checks_fixed_slot_lengths_before_indexing() {
    let (_, baseline) = audit_plaintext_fixture();
    for input_count in [0, 1] {
        let mut changed = baseline.clone();
        changed.inputs.truncate(input_count);
        assert_eq!(
            changed.validate(),
            Err(PrivateSettlementValidationError::InvalidAuditPlaintext)
        );
    }
    for output_count in [0, 1, 2] {
        let mut changed = baseline.clone();
        changed.outputs.truncate(output_count);
        assert_eq!(
            changed.validate(),
            Err(PrivateSettlementValidationError::InvalidAuditPlaintext)
        );
    }
}

#[test]
fn audit_output_authorizations_bind_every_role_and_nonzero_recipient_key() {
    let (_, baseline) = audit_plaintext_fixture();
    baseline.validate_output_authorizations().unwrap();
    for index in 0..PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1 {
        for invalid_key in [false, true] {
            let mut changed = baseline.clone();
            if invalid_key {
                changed.outputs[index].recipient_view_key = [0; 32];
            } else {
                changed.outputs[index].role = baseline.outputs[(index + 1) % 3].role;
            }
            assert_eq!(
                changed.validate_output_authorizations(),
                Err(PrivateSettlementValidationError::InvalidAuditPlaintext),
                "output {index}, invalid key: {invalid_key}"
            );
        }
    }
}

#[test]
fn proof_intent_roundtrip_has_only_existing_terms_and_keeps_exact_commitment_projection() {
    let complete = manifest(2);
    let intent = complete.proof_intent();
    intent.validate().expect("valid exact intent");
    assert_eq!(
        intent.computed_bundle_id().unwrap(),
        complete.computed_bundle_id().unwrap()
    );
    assert_eq!(
        intent.proof_binding_digest().unwrap(),
        complete.proof_binding_digest().unwrap()
    );
    let bytes = norito::encode_canonical(&intent).unwrap();
    assert_eq!(
        norito::decode_canonical::<PrivateSettlementProofIntentV1>(&bytes).unwrap(),
        intent
    );
    let json = norito::json::to_json(&intent).unwrap();
    assert!(
        !json.contains("payload_digest")
            && !json.contains("availability_certificate_digest")
            && !json.contains("delta_digest"),
        "pre-proof intent cannot encode artifact placeholders"
    );
    assert_eq!(
        norito::json::from_json::<PrivateSettlementProofIntentV1>(&json).unwrap(),
        intent
    );
}

#[test]
fn proof_intent_requires_actual_artifacts_before_provisional_or_final_publication() {
    let complete = manifest(2);
    let intent = complete.proof_intent();
    let mut actual = complete.legs.clone();
    for leg in &mut actual {
        leg.availability_certificate_digest = Hash::prehashed([0; Hash::LENGTH]);
    }
    let provisional = intent
        .clone()
        .bind_provisional_artifacts(actual.clone())
        .unwrap();
    provisional.validate_provisional().unwrap();
    assert!(
        provisional.validate().is_err(),
        "proof completion is not availability certification"
    );
    assert!(intent.clone().bind_provisional_artifacts(vec![]).is_err());
    for field in 0..2 {
        let mut missing = actual.clone();
        if field == 0 {
            missing[0].payload_digest = Hash::prehashed([0; Hash::LENGTH]);
        } else {
            missing[0].delta_digest = Hash::prehashed([0; Hash::LENGTH]);
        }
        assert!(
            intent.clone().bind_provisional_artifacts(missing).is_err(),
            "missing real artifact cannot produce a provisional manifest"
        );
    }
    let mut foreign = actual.clone();
    foreign[0].asset_binding_commitment = hash(231);
    assert!(
        intent.clone().bind_provisional_artifacts(foreign).is_err(),
        "cross-intent artifacts rejected"
    );
    assert!(
        intent.bind_provisional_artifacts(complete.legs).is_err(),
        "new preparation cannot import unverified final availability"
    );
}

#[test]
fn proof_intent_constructor_derives_commitments_without_a_complete_manifest() {
    let original = manifest(2).proof_intent();
    let constructed = PrivateSettlementProofIntentV1::new(
        original.network_id,
        original.authority_context_height,
        original.expiry_height,
        original.sponsor.clone(),
        original.public_fee_intent.clone(),
        original.reimbursement_terms_commitment,
        original.reimbursement_leg_ordinal,
        original.legs.clone(),
    )
    .unwrap();
    assert_eq!(constructed, original);
    assert!(
        PrivateSettlementProofIntentV1::new(
            original.network_id,
            original.expiry_height,
            original.expiry_height,
            original.sponsor.clone(),
            original.public_fee_intent.clone(),
            original.reimbursement_terms_commitment,
            original.reimbursement_leg_ordinal,
            original.legs.clone()
        )
        .is_err()
    );
}

#[test]
fn preproof_reimbursement_projection_matches_exact_existing_plaintext_commitment() {
    let (_, plaintext) = audit_plaintext_fixture();
    let direct = |amount, salt| {
        private_settlement_reimbursement_terms_commitment_v1(
            plaintext.network_id,
            plaintext.leg_ordinal,
            plaintext.route,
            &plaintext.sponsor,
            &plaintext.asset_definition_id,
            amount,
            plaintext.fee_intent_digest,
            plaintext.settlement_expiry_height,
            salt,
        )
        .unwrap()
    };
    let expected = plaintext.reimbursement_terms_commitment().unwrap();
    // The retained canonical projection remains the independent byte/layout oracle.
    assert_eq!(
        expected,
        canonical_hash(
            REIMBURSEMENT_TERMS_COMMITMENT_DOMAIN_V1,
            &plaintext
                .reimbursement_terms_material(PRIVATE_SETTLEMENT_SUCCESS_FEE_BEARING_CARRIERS_V1)
        )
        .unwrap()
    );
    assert_eq!(
        direct(
            plaintext.sponsor_reimbursement_amount,
            plaintext.reimbursement_terms_salt
        ),
        expected
    );
    assert_ne!(
        direct(
            plaintext.sponsor_reimbursement_amount + 1,
            plaintext.reimbursement_terms_salt
        ),
        expected
    );
    let mut salt = plaintext.reimbursement_terms_salt;
    salt[0] ^= 1;
    assert_ne!(
        direct(plaintext.sponsor_reimbursement_amount, salt),
        expected
    );
}

#[test]
fn preproof_authorization_constructors_match_the_complete_plaintext_projection() {
    let (_, plaintext) = audit_plaintext_fixture();
    let nullifiers = plaintext
        .payer_authorization
        .body
        .inputs
        .iter()
        .map(|input| input.nullifier)
        .collect::<Vec<_>>();
    let payer = PrivateSettlementAuditPayerAuthorizationBodyV1::from_openings(
        plaintext.network_id,
        plaintext.bundle_id,
        plaintext.leg_ordinal,
        plaintext.route,
        &plaintext.payer,
        plaintext.settlement_expiry_height,
        &plaintext.inputs,
        &nullifiers,
    )
    .unwrap();
    assert_eq!(
        payer,
        plaintext.payer_authorization_body(&nullifiers).unwrap()
    );
    assert_eq!(payer, plaintext.payer_authorization.body);
    assert!(
        PrivateSettlementAuditPayerAuthorizationBodyV1::from_openings(
            plaintext.network_id,
            plaintext.bundle_id,
            plaintext.leg_ordinal,
            plaintext.route,
            &plaintext.payer,
            plaintext.settlement_expiry_height,
            &plaintext.inputs,
            &nullifiers[..1]
        )
        .is_err()
    );
    for (index, output) in plaintext.outputs.iter().enumerate() {
        let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1::from_output(
            plaintext.network_id,
            plaintext.bundle_id,
            plaintext.leg_ordinal,
            plaintext.route,
            plaintext.settlement_expiry_height,
            &plaintext.recipient,
            &plaintext.payer,
            &plaintext.sponsor,
            index,
            output.recipient_view_key,
            &output.note,
        )
        .unwrap();
        assert_eq!(
            body,
            plaintext.output_view_key_authorization_body(index).unwrap()
        );
        assert_eq!(body, output.view_key_authorization.body);
    }
    let output = &plaintext.outputs[0];
    assert!(
        PrivateSettlementAuditViewKeyAuthorizationBodyV1::from_output(
            plaintext.network_id,
            plaintext.bundle_id,
            plaintext.leg_ordinal,
            plaintext.route,
            plaintext.settlement_expiry_height,
            &plaintext.recipient,
            &plaintext.payer,
            &plaintext.sponsor,
            3,
            output.recipient_view_key,
            &output.note
        )
        .is_err()
    );
}

#[test]
fn preproof_fee_projection_uses_the_original_canonical_commitment() {
    let manifest = manifest(3);
    let expected =
        canonical_hash(FEE_INTENT_DIGEST_DOMAIN_V1, &manifest.public_fee_intent).unwrap();
    assert_eq!(
        PrivateSettlementProofIntentV1::fee_intent_digest(&manifest.public_fee_intent).unwrap(),
        expected
    );
    assert_eq!(
        manifest
            .proof_intent()
            .computed_fee_intent_digest()
            .unwrap(),
        expected
    );
}
