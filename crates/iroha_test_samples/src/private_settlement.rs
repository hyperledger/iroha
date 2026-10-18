//! Structural private-settlement fixtures shared by SDK and preparation tests.
//!
//! Opaque proof and capsule bytes establish transport and custody shape only.
//! Committee keys, proof-of-possession and signatures are real; no native proof,
//! authenticated World state or monetary execution is claimed.
//! Routes and committee keys are deterministic; hybrid auditor keys use hedged
//! generation, so separately constructed material need not share policy digests.

use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    nexus::*,
    privacy::{
        PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
        PrivacyEncryptedOutputV1, PrivacyEncryptionKeyV1, PrivacyNullifierV1, PrivacyPoolIdV1,
        PrivacyRecipientIdV1, PrivacyRootV1,
    },
    transaction::FeePaymentIntent,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};

/// Create one deterministic route for a fixture leg.
///
/// # Panics
/// Panics when the fixture index cannot fit the route identifiers.
pub fn finalization_route_v1(index: usize) -> PrivateSettlementRouteV1 {
    let dataspace = u64::try_from(index + 41).expect("fixture dataspace fits u64");
    PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(dataspace),
        lane_id: LaneId::new(u32::try_from(index + 11).expect("fixture lane fits u32")),
        lane_incarnation: Hash::new_from_chunks(&[
            b"client-finalization-route-v1",
            &dataspace.to_le_bytes(),
        ]),
    }
}

/// Create four deterministic BLS validators and their real proofs of possession.
///
/// # Panics
/// Panics when deterministic key or proof-of-possession construction fails.
pub fn finalization_authority_v1(
    route: PrivateSettlementRouteV1,
    ordinal: u8,
) -> (
    PrivateSettlementCommitteeAuthorityV1,
    Vec<iroha_crypto::KeyPair>,
) {
    let keys = (0_u8..4)
        .map(|index| {
            iroha_crypto::KeyPair::from_seed(
                vec![0x90_u8.saturating_add(ordinal * 4).saturating_add(index); 32],
                Algorithm::BlsNormal,
            )
        })
        .collect::<Vec<_>>();
    let validators = keys
        .iter()
        .map(|key| iroha_model_base::peer::PeerId::from(key.public_key().clone()))
        .collect::<Vec<_>>();
    let authority = PrivateSettlementCommitteeAuthorityV1 {
        route,
        validator_set_hash: iroha_crypto::HashOf::new(&validators),
        validators,
        validator_pops: keys
            .iter()
            .map(|key| {
                iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("finalization fixture validator PoP")
            })
            .collect(),
    };
    (authority, keys)
}

/// Create the fixed two-input, three-output structural delta for a manifest leg.
///
/// # Panics
/// Panics for a missing leg, an oversized fixture index or invalid fixture shape.
pub fn finalization_delta_v1(
    manifest: &AtomicPrivateSettlementV1,
    index: usize,
) -> PrivateSettlementDeltaV1 {
    let leg = &manifest.legs[index];
    let base = 0x20_u8.saturating_add(
        u8::try_from(index)
            .expect("fixture index fits u8")
            .saturating_mul(16),
    );
    let output_commitments = (0_u8..3)
        .map(|slot| PrivacyCommitmentV1::new([base.saturating_add(slot); 32]))
        .collect::<Vec<_>>();
    let encrypted_outputs = output_commitments
        .iter()
        .copied()
        .enumerate()
        .map(|(slot, commitment)| {
            let slot = u8::try_from(slot).expect("fixture slot fits u8");
            let seed = base.saturating_add(8).saturating_add(slot);
            let mut ciphertext = vec![seed; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
            ciphertext[..4].copy_from_slice(b"IPNE");
            PrivacyEncryptedOutputV1 {
                recipient: PrivacyRecipientIdV1::new([seed; 32]),
                ephemeral_public_key: PrivacyEncryptionKeyV1::new([seed.saturating_add(1); 32]),
                commitment,
                ciphertext,
            }
        })
        .collect::<Vec<_>>();
    let delta = PrivateSettlementDeltaV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        bundle_id: manifest.bundle_id,
        leg_ordinal: leg.ordinal,
        route: leg.route,
        pool_id: leg.pool_id,
        asset_binding_commitment: leg.asset_binding_commitment,
        old_root: PrivacyRootV1::new([base.saturating_add(11); 32]),
        new_root: PrivacyRootV1::new([base.saturating_add(12); 32]),
        old_epoch: 7,
        new_epoch: 8,
        nullifiers: vec![
            PrivacyNullifierV1::new([base.saturating_add(13); 32]),
            PrivacyNullifierV1::new([base.saturating_add(14); 32]),
        ],
        output_commitments,
        encrypted_outputs,
        statement_digest: Hash::new_from_chunks(&[
            b"client-finalization-statement-v1",
            &[leg.ordinal],
        ]),
        proof_digest: Hash::new_from_chunks(&[b"client-finalization-proof-v1", &[leg.ordinal]]),
        capsule_digest: Hash::new_from_chunks(&[b"client-finalization-capsule-v1", &[leg.ordinal]]),
        audit_policy_digest: leg.audit_policy_digest,
        audit_key_epoch: 3,
    };
    delta
        .validate_public_shape()
        .expect("finalization fixture delta validates");
    delta
}

/// Create a two-leg structural manifest bound to the supplied network and sponsor.
///
/// # Panics
/// Panics when the deterministic manifest or delta cannot validate.
pub fn finalization_manifest_v1(
    network_id: &NetworkId,
    sponsor: &AccountId,
) -> (AtomicPrivateSettlementV1, Vec<PrivateSettlementDeltaV1>) {
    let mut manifest = AtomicPrivateSettlementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: *network_id,
        bundle_id: Hash::new(b"client-finalization-bundle-placeholder"),
        authority_context_height: 10,
        expiry_height: 100,
        sponsor: sponsor.clone(),
        public_fee_intent: FeePaymentIntent::authority(Vec::new(), None),
        fee_intent_digest: Hash::new(b"client-finalization-fee-placeholder"),
        reimbursement_terms_commitment: Hash::new(b"client-finalization-reimbursement-terms"),
        reimbursement_leg_ordinal: 0,
        legs: (0_usize..2)
            .map(|index| {
                let ordinal = u8::try_from(index).expect("fixture ordinal fits u8");
                PrivateSettlementLegCommitmentV1 {
                    ordinal,
                    route: finalization_route_v1(index),
                    pool_id: PrivacyPoolIdV1::new([0x11_u8.saturating_add(ordinal); 32]),
                    asset_binding_commitment: Hash::new_from_chunks(&[
                        b"client-finalization-asset-v1",
                        &[ordinal],
                    ]),
                    audit_policy_digest: Hash::new_from_chunks(&[
                        b"client-finalization-policy-v1",
                        &[ordinal],
                    ]),
                    payload_digest: Hash::new_from_chunks(&[
                        b"client-finalization-payload-v1",
                        &[ordinal],
                    ]),
                    availability_certificate_digest: Hash::new_from_chunks(&[
                        b"client-finalization-availability-v1",
                        &[ordinal],
                    ]),
                    delta_digest: Hash::new_from_chunks(&[
                        b"client-finalization-delta-placeholder-v1",
                        &[ordinal],
                    ]),
                }
            })
            .collect(),
    };
    manifest.fee_intent_digest = manifest
        .computed_fee_intent_digest()
        .expect("finalization fixture fee hashes");
    manifest.bundle_id = manifest
        .computed_bundle_id()
        .expect("finalization fixture bundle hashes");
    let deltas = (0..manifest.legs.len())
        .map(|index| finalization_delta_v1(&manifest, index))
        .collect::<Vec<_>>();
    for (leg, delta) in manifest.legs.iter_mut().zip(&deltas) {
        leg.delta_digest = delta.digest().expect("finalization fixture delta hashes");
    }
    manifest
        .validate()
        .expect("finalization fixture manifest validates");

    (manifest, deltas)
}

/// Create structural provisional material with opaque proofs and genuine availability shares.
///
/// No native proof is generated or verified. Binding order follows the Core sidecar
/// fixture, and padded capsule shape follows the shared response-validation fixture.
///
/// # Panics
/// Panics when crypto construction or structural validation fails.
pub fn availability_material_fixture_v1(
    network_id: &NetworkId,
    sponsor: &AccountId,
) -> (
    PrivateSettlementProvisionalLegMaterialV1,
    Vec<PrivateSettlementAvailabilityShareV1>,
) {
    use iroha_data_model::nexus::{
        PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1, PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1,
        PrivateSettlementAuditAadV1, PrivateSettlementAuditCapsuleV1,
        PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementAuditorV1, PrivateSettlementCapsulePaddingV1,
        PrivateSettlementHybridPublicKeyV1, PrivateSettlementProofProfileV1,
        PrivateSettlementProofStatementV1, PrivateSettlementWrappedDekV1,
    };
    let (mut manifest, _) = finalization_manifest_v1(network_id, sponsor);
    let route = manifest.legs[0].route;
    let (authority, keys) = finalization_authority_v1(route, 0);
    let auditor = KeyPair::from_seed(vec![0xE1; 32], Algorithm::Ed25519);
    let auditor_id = AccountId::new(auditor.public_key().clone());
    let mut rng = iroha_crypto::rng_from_seed_slice(b"client availability fixture auditor");
    let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng).expect("fixture hybrid key");
    let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        dataspace_id: route.dataspace_id,
        policy_id: Hash::new(b"client availability fixture policy"),
        revision: 1,
        key_epoch: 3,
        activation_height: 5,
        retirement_height: None,
        min_approvals: 1,
        auditors: vec![PrivateSettlementAuditorV1 {
            auditor_id: auditor_id.clone(),
            signing_key: auditor.public_key().clone(),
            encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public()),
        }],
    })
    .expect("fixture audit policy");
    manifest.legs[0].audit_policy_digest = policy.policy_digest;
    for leg in &mut manifest.legs {
        leg.availability_certificate_digest = Hash::prehashed([0; Hash::LENGTH]);
    }
    manifest.bundle_id = manifest.computed_bundle_id().expect("fixture bundle id");
    for index in 0..manifest.legs.len() {
        let digest = finalization_delta_v1(&manifest, index)
            .digest()
            .expect("fixture delta digest");
        manifest.legs[index].delta_digest = digest;
    }
    let mut delta = finalization_delta_v1(&manifest, 0);
    let authority_digest = authority.digest().expect("fixture authority digest");
    let plaintext_commitment = Hash::new(b"client availability fixture plaintext");
    let padding = PrivateSettlementCapsulePaddingV1::KiB4;
    let audit_capsule = PrivateSettlementAuditCapsuleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        aad: PrivateSettlementAuditAadV1 {
            network_id: manifest.network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: 0,
            route,
            authority_digest,
            authority_context_height: manifest.authority_context_height,
            audit_policy_digest: policy.policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            plaintext_commitment,
        },
        padding,
        nonce: [0xE2; 24],
        ciphertext: vec![0xE3; padding.ciphertext_bytes()],
        wrapped_deks: vec![PrivateSettlementWrappedDekV1 {
            auditor_id,
            ephemeral_x25519: [0xE4; 32],
            ml_kem_ciphertext: vec![0xE5; PRIVATE_SETTLEMENT_ML_KEM_768_CIPHERTEXT_BYTES_V1],
            nonce: [0xE6; 24],
            wrapped_dek: vec![0xE7; PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1],
        }],
    };
    let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
    let statement = PrivateSettlementProofStatementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        profile,
        proof_profile_digest: profile.digest(),
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: 0,
        route,
        authority_context_height: manifest.authority_context_height,
        pool_id: delta.pool_id,
        asset_binding_commitment: delta.asset_binding_commitment,
        old_root: delta.old_root,
        new_root: delta.new_root,
        old_epoch: delta.old_epoch,
        new_epoch: delta.new_epoch,
        nullifiers: delta.nullifiers.clone(),
        output_commitments: delta.output_commitments.clone(),
        encrypted_outputs: delta.encrypted_outputs.clone(),
        audit_plaintext_commitment: plaintext_commitment,
        audit_input_commitment: [0xE8; 32],
        audit_capsule_digest: audit_capsule.digest().expect("fixture capsule digest"),
        audit_policy_digest: policy.policy_digest,
        audit_key_epoch: policy.body.key_epoch,
        fee_intent_digest: manifest.fee_intent_digest,
        reimbursement_terms_commitment: manifest.reimbursement_terms_commitment,
        reimbursement_leg_ordinal: manifest.reimbursement_leg_ordinal,
        expiry_height: manifest.expiry_height,
    };
    let proof = b"availability-request-proof-canary".to_vec();
    delta.statement_digest = statement.digest().expect("fixture statement digest");
    delta.proof_digest = iroha_data_model::nexus::private_settlement_proof_digest_v1(&proof);
    delta.capsule_digest = statement.audit_capsule_digest;
    manifest.legs[0].delta_digest = delta.digest().expect("fixture bound delta digest");
    let availability_body = PrivateSettlementSidecarAvailabilityBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: 0,
        route,
        authority_digest,
        authority_context_height: manifest.authority_context_height,
        payload_digest: Hash::new(b"client availability fixture provisional digest"),
        payload_bytes: 1,
        retention_until_height: manifest.expiry_height,
    };
    let mut material = PrivateSettlementProvisionalLegMaterialV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest,
        audit_policy: policy,
        committee_authority: authority,
        statement,
        proof,
        delta,
        audit_capsule,
        availability_body,
    };
    let payload_digest = material.payload_digest().expect("fixture payload digest");
    material.manifest.legs[0].payload_digest = payload_digest;
    material.availability_body.payload_digest = payload_digest;
    material.availability_body.payload_bytes = u32::try_from(
        material
            .sidecar_material_bytes_len()
            .expect("fixture material size"),
    )
    .expect("fixture size fits u32");
    material
        .validate()
        .expect("complete provisional material must validate");
    let preimage = material
        .availability_body
        .signature_preimage()
        .expect("fixture preimage");
    let shares = keys
        .iter()
        .enumerate()
        .map(|(index, key)| PrivateSettlementAvailabilityShareV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            body: material.availability_body,
            signer: material.committee_authority.validators[index].clone(),
            signature: Signature::try_new(key.private_key(), &preimage)
                .expect("fixture availability signature")
                .payload()
                .to_vec(),
        })
        .collect();
    (material, shares)
}

/// Create explicitly unauthenticated storage and transport context originals.
///
/// # Panics
/// Panics when the underlying structural material fixture cannot be constructed.
pub fn context_fixture(
    network_id: &NetworkId,
    sponsor: &AccountId,
) -> PrivateSettlementContextProofV1 {
    use iroha_data_model::{
        consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
        nexus::*,
        privacy::PrivacyRootV1,
        sumeragi_finality::WorldStateSnapshotV1,
        sumeragi_lanes::SumeragiLaneState,
    };
    let (material, _) = availability_material_fixture_v1(network_id, sponsor);
    let route = material.statement.route;
    let pool_id = material.statement.pool_id;
    let governance = PrivateSettlementPoolGovernanceProjectionV1 {
        version: 1,
        route,
        pool_id,
        asset_binding_commitment: Hash::new(b"storage asset"),
        audit_policy_digest: material.audit_policy.policy_digest,
        audit_key_epoch: 1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: 2,
            retirement_height: None,
        },
        governance_digest: Hash::new(b"storage governance"),
        prior_revisions: Vec::new(),
    };
    let pool = PrivateSettlementPoolStateV1 {
        version: 1,
        route,
        pool_id,
        restricted_pool_policy_digest: governance.governance_digest,
        epoch: 1,
        root: PrivacyRootV1::new([4; 32]),
        tree_size: 0,
        leaf: None,
        ommers: Vec::new(),
    };
    let committee_keys = std::array::from_fn(|index| {
        let id = ConsensusKeyId::new(ConsensusKeyRole::Committee, format!("storage-{index}"));
        PrivateSettlementCommitteeKeyProofV1 {
            index: vec![id.clone()],
            record: ConsensusKeyRecord {
                id,
                public_key: material.committee_authority.validators[index]
                    .public_key()
                    .clone(),
                pop: Some(material.committee_authority.validator_pops[index].clone()),
                activation_height: 2,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Pending,
            },
        }
    });
    PrivateSettlementContextProofV1 {
        pool: PrivateSettlementPoolCutProofV1 {
            world: WorldStateSnapshotV1 {
                schema_hash: Hash::new(b"storage fixture"),
                entries: Vec::new(),
            },
            governance,
            pool,
        },
        lanes: SumeragiLaneState::default(),
        committee_keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (NetworkId, AccountId) {
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"shared private settlement fixtures"),
        ));
        let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
        (network, AccountId::new(key.public_key().clone()))
    }

    #[test]
    fn deterministic_routes_and_real_committee_pop_are_bound() {
        let route = finalization_route_v1(0);
        assert_eq!(route, finalization_route_v1(0));
        assert_ne!(route, finalization_route_v1(1));
        let (authority, keys) = finalization_authority_v1(route, 0);
        authority.validate().unwrap();
        assert_eq!(authority.route, route);
        assert_eq!(authority.validators.len(), 4);
        for (key, (validator, pop)) in keys
            .iter()
            .zip(authority.validators.iter().zip(&authority.validator_pops))
        {
            assert_eq!(key.public_key(), validator.public_key());
            iroha_crypto::bls_normal_pop_verify(validator.public_key(), pop).unwrap();
        }
    }

    #[test]
    fn manifest_and_deltas_retain_supplied_network_sponsor_and_exact_digests() {
        let (network, sponsor) = identity();
        let (manifest, deltas) = finalization_manifest_v1(&network, &sponsor);
        manifest.validate().unwrap();
        assert_eq!(manifest.network_id, network);
        assert_eq!(manifest.sponsor, sponsor);
        assert_eq!(manifest.legs.len(), 2);
        for (index, delta) in deltas.iter().enumerate() {
            assert_eq!(*delta, finalization_delta_v1(&manifest, index));
            assert_eq!(manifest.legs[index].delta_digest, delta.digest().unwrap());
            assert_eq!(delta.bundle_id, manifest.bundle_id);
        }
    }

    #[test]
    fn material_shares_and_untrusted_context_keep_the_same_committee() {
        let (network, sponsor) = identity();
        let (material, shares) = availability_material_fixture_v1(&network, &sponsor);
        material.validate().unwrap();
        assert_eq!(shares.len(), 4);
        let message = material.availability_body.signature_preimage().unwrap();
        for share in shares {
            assert_eq!(share.body, material.availability_body);
            Signature::try_from_bytes(&share.signature)
                .unwrap()
                .verify(share.signer.public_key(), &message)
                .unwrap();
        }
        let context = context_fixture(&network, &sponsor);
        assert_eq!(context.pool.pool.route, material.statement.route);
        assert_eq!(context.pool.pool.pool_id, material.statement.pool_id);
        assert_eq!(
            material.statement.audit_policy_digest,
            material.audit_policy.policy_digest
        );
        assert_eq!(
            material.audit_capsule.aad.audit_policy_digest,
            material.audit_policy.policy_digest
        );
        // Context constructs its own hybrid auditor key with live entropy; only
        // the route and committee are shared across separate fixture invocations.
        assert_ne!(
            context.pool.governance.audit_policy_digest,
            Hash::prehashed([0; Hash::LENGTH])
        );
        assert_eq!(context.pool.governance.route, context.pool.pool.route);
        assert_eq!(context.pool.governance.pool_id, context.pool.pool.pool_id);
        assert_eq!(
            context.pool.pool.restricted_pool_policy_digest,
            context.pool.governance.governance_digest
        );
        for (index, proof) in context.committee_keys.iter().enumerate() {
            assert_eq!(
                proof.record.public_key,
                *material.committee_authority.validators[index].public_key()
            );
            assert_eq!(
                proof.record.pop,
                Some(material.committee_authority.validator_pops[index].clone())
            );
        }
        assert!(
            context.pool.world.entries.is_empty(),
            "fixture is untrusted storage data"
        );
    }
}
