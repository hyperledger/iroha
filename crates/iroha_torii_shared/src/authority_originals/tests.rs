//! Codec/correlation fixtures use genuine native certificates over explicit synthetic data.
//! They grant no installed-node, compiled World schema, permission or release qualification.
use super::*;
use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::AccountDetails,
    asset::{Asset, AssetBalancePolicy, AssetBalanceScope},
    common::Owned,
    nexus::FeeSponsorEligibility,
    sumeragi::{SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::{
        SumeragiFinalityAttestationBody, WorldStateElementKindV1, WorldStateSnapshotEntryV1,
        test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
};
use iroha_model_base::{metadata::Metadata, peer::PeerId, topology::DataSpaceId};
use norito::codec::Encode as _;
use std::sync::OnceLock;

fn account_fixture() -> &'static (
    NativeAuthorityOriginalsRequestV1,
    NativeAuthorityOriginalsV1,
) {
    static VALUE: OnceLock<(
        NativeAuthorityOriginalsRequestV1,
        NativeAuthorityOriginalsV1,
    )> = OnceLock::new();
    VALUE.get_or_init(|| {
        let alias = AccountAlias::new(
            "retail".parse().unwrap(),
            Some("leumi".parse().unwrap()),
            DataSpaceId::new(77),
        );
        let owner = AccountId::new(
            KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let account_value = Owned::new(AccountDetails::new(
            Metadata::default(),
            Some(alias.clone()),
            None,
            vec![],
        ));
        let rekey_record = AccountRekeyRecord::new(alias.clone(), owner.clone());
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"explicitly synthetic authority codec schema"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.accounts".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&owner).unwrap()),
                value_hash: world_state_value_hash_v1(&account_value).unwrap(),
            }],
        };
        let mut native = NativeFinalityFixture::start("authority original codec fixture");
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let request = NativeAuthorityOriginalsRequestV1 {
            network_id: native.network_id(),
            challenge: [7; 32],
            selector: NativeAuthorityOriginalsSelectorV1::AccountAlias(
                "retail@leumi.is2".parse().unwrap(),
            ),
        };
        let (request_sha256, challenge) =
            native_authority_originals_request_digests_v1(&request.canonical_wire().unwrap())
                .unwrap();
        let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
        let node_id = PeerId::new(node.public_key().clone());
        let config = Hash::new(b"fixture node config");
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge,
            network_id: native.network_id(),
            node_fingerprint: Hash::new(node_id.encode()),
            node_id,
            build_fingerprint: Hash::new(b"fixture binary"),
            config_fingerprint: config,
            genesis_block_hash: native.genesis().hash(),
            genesis_finality_proof: native.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: 1,
                config_fingerprint: config,
                beacon_horizon: None,
                instance: native.verifier().instance().0,
                height: 3,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: 2,
                applied_height: 2,
                awaiting: false,
                signer: Some(node.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: SumeragiFootprint::default(),
            },
            finality_proof: proof,
        };
        let attestation = SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(node.private_key(), body.signing_hash()).unwrap(),
            body,
        };
        attestation.verify().unwrap();
        let response = NativeAuthorityOriginalsV1 {
            request_sha256,
            selector: request.selector.clone(),
            attestation,
            world_snapshot: snapshot,
            originals: NativeAuthorityOriginalsFamilyV1::AccountAlias(NativeAccountAliasStateV1 {
                alias: alias.clone(),
                binding_keys: vec![alias],
                selected: Some(NativeAccountAliasOriginalV1 {
                    bound_account: owner,
                    rekey_record,
                    account_value,
                    // These bytes test the data-only wire, not native NameRecord membership.
                    lease_value: vec![2, 4, 6],
                }),
            }),
        };
        response.validate_request_correlation(&request).unwrap();
        (request, response)
    })
}
fn correlated(
    request: &NativeAuthorityOriginalsRequestV1,
    mut value: NativeAuthorityOriginalsV1,
) -> NativeAuthorityOriginalsV1 {
    let (digest, challenge) =
        native_authority_originals_request_digests_v1(&request.canonical_wire().unwrap()).unwrap();
    value.request_sha256 = digest;
    value.selector = request.selector.clone();
    value.attestation.body.challenge = challenge;
    let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
    value.attestation.signature =
        SignatureOf::try_from_hash(node.private_key(), value.attestation.body.signing_hash())
            .unwrap();
    value
}

#[test]
fn canonical_request_digests_bind_native_selector_network_and_fresh_entropy() {
    let (request, _) = account_fixture();
    let wire = request.canonical_wire().unwrap();
    assert_eq!(
        decode_native_authority_originals_request_v1(&wire).unwrap(),
        *request
    );
    let digests = native_authority_originals_request_digests_v1(&wire).unwrap();
    assert_eq!(digests.0, <[u8; 32]>::from(Sha256::digest(&wire)));
    assert_ne!(digests.0, digests.1);
    let mut other = request.clone();
    other.challenge = [8; 32];
    assert_ne!(
        native_authority_originals_request_digests_v1(&other.canonical_wire().unwrap()).unwrap(),
        digests
    );
    other = request.clone();
    other.selector =
        NativeAuthorityOriginalsSelectorV1::AccountAlias("other@leumi.is2".parse().unwrap());
    assert_ne!(
        native_authority_originals_request_digests_v1(&other.canonical_wire().unwrap()).unwrap(),
        digests
    );
    other = request.clone();
    other.challenge = [0; 32];
    assert!(other.canonical_wire().is_err());
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(decode_native_authority_originals_request_v1(&trailing).is_err());
    assert!(
        decode_native_authority_originals_request_v1(&vec![
            0;
            NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}
#[test]
fn borrowed_account_exact_wire_json_and_stored_label_survive() {
    let (request, value) = account_fixture();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(state) = &value.originals else {
        unreachable!()
    };
    let keys = state.binding_keys.iter().collect::<Vec<_>>();
    let original = state.selected.as_ref().unwrap();
    let selected = NativeAccountAliasOriginalRefV1::new(
        &original.bound_account,
        &original.rekey_record,
        &original.account_value,
        &original.lease_value,
    );
    let borrowed = NativeAuthorityOriginalsRefV1::new(
        &value.request_sha256,
        &value.selector,
        &value.attestation,
        &value.world_snapshot,
        NativeAuthorityOriginalsFamilyRefV1::AccountAlias(NativeAccountAliasStateRefV1::new(
            &state.alias,
            &keys,
            Some(selected),
        )),
    );
    let wire = norito::encode_canonical(value).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), wire);
    assert_eq!(
        norito::json::to_json(&borrowed).unwrap(),
        norito::json::to_json(value).unwrap()
    );
    assert!(norito::json::to_json_bounded(&borrowed, 4).is_err());
    let decoded = decode_unverified_native_authority_originals_v1(&wire).unwrap();
    decoded.validate_request_correlation(request).unwrap();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(decoded) = decoded.originals else {
        unreachable!()
    };
    assert_eq!(
        decoded.selected.unwrap().account_value.as_ref().label,
        Some(state.alias.clone())
    );
}
#[test]
fn account_correlation_rejects_substitution_and_omitted_or_duplicate_bindings() {
    let (request, value) = account_fixture();
    let mut changed = value.clone();
    changed.request_sha256 = [0; 32];
    assert!(changed.validate_request_correlation(request).is_err());
    changed = value.clone();
    changed.attestation.body.challenge = request.challenge;
    assert!(changed.validate_request_correlation(request).is_err());
    changed = value.clone();
    changed.selector =
        NativeAuthorityOriginalsSelectorV1::AccountAlias("other@leumi.is2".parse().unwrap());
    assert!(changed.validate_request_correlation(request).is_err());
    changed = value.clone();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(state) = &mut changed.originals else {
        unreachable!()
    };
    state.binding_keys.clear();
    assert!(changed.validate_request_correlation(request).is_err());
    changed = value.clone();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(state) = &mut changed.originals else {
        unreachable!()
    };
    state.binding_keys.push(state.alias.clone());
    assert!(changed.validate_request_correlation(request).is_err());
    changed = value.clone();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(state) = &mut changed.originals else {
        unreachable!()
    };
    state.selected = None;
    state.binding_keys.clear();
    changed.validate_request_correlation(request).unwrap();
}
#[test]
fn borrowed_fee_funding_values_are_exact_and_missing_source_bucket_is_refused() {
    let (base, value) = account_fixture();
    let NativeAuthorityOriginalsFamilyV1::AccountAlias(account) = &value.originals else {
        unreachable!()
    };
    let source = account.selected.as_ref().unwrap();
    let program_id =
        FeeSponsorProgramId::new(source.bound_account.clone(), "staff-fees".parse().unwrap());
    let fee_asset: AssetDefinitionId = "839FV3NJC8NfgWQvghXU2hEFQm9a".parse().unwrap();
    let definition = AssetDefinition::numeric(
        fee_asset.clone(),
        "Synthetic fee",
        AssetBalancePolicy::Global,
        None,
    )
    .build(&program_id.sponsor);
    let asset_id = AssetId::with_scope(
        fee_asset.clone(),
        program_id.sponsor.clone(),
        AssetBalanceScope::Global,
    );
    let (_, asset_value) = Asset::new(asset_id.clone(), 1_u32).into_key_value();
    let request = NativeAuthorityOriginalsRequestV1 {
        selector: NativeAuthorityOriginalsSelectorV1::GlobalFeeProgram {
            program_id: program_id.clone(),
            fee_asset: fee_asset.clone(),
        },
        ..base.clone()
    };
    let state = NativeGlobalFeeProgramStateV1 {
        program_id: program_id.clone(),
        fee_asset,
        asset_keys: vec![asset_id],
        program_keys: vec![program_id.clone()],
        revision_keys: vec![FeeSponsorProgramRevisionKey::new(program_id.clone(), 1)],
        enrollment_keys: vec![],
        vault_keys: vec![],
        budget_counter_keys: vec![],
        sponsor_account_value: source.account_value.clone(),
        fee_asset_definition: definition,
        source_asset_value: asset_value,
        program: Some(FeeSponsorProgram::new(
            program_id.clone(),
            program_id.sponsor.clone(),
        )),
        revisions: vec![FeeSponsorProgramRevision {
            program_id,
            revision: 1,
            eligibility: FeeSponsorEligibility::EnrolledOnly,
            rules: vec![],
            asset_budgets: vec![],
        }],
        enrollments: vec![],
        vaults: vec![],
    };
    let mut value = correlated(&request, value.clone());
    value.originals = NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state);
    value.validate_request_correlation(&request).unwrap();
    let NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state) = &value.originals else {
        unreachable!()
    };
    let assets = state.asset_keys.iter().collect::<Vec<_>>();
    let programs = state.program_keys.iter().collect::<Vec<_>>();
    let revisions = state.revision_keys.iter().collect::<Vec<_>>();
    let enrollments = state.enrollment_keys.iter().collect::<Vec<_>>();
    let vaults = state.vault_keys.iter().collect::<Vec<_>>();
    let counters = state.budget_counter_keys.iter().collect::<Vec<_>>();
    let rows = state.revisions.iter().collect::<Vec<_>>();
    let enrollment_rows = state.enrollments.iter().collect::<Vec<_>>();
    let vault_rows = state.vaults.iter().collect::<Vec<_>>();
    let borrowed = NativeAuthorityOriginalsRefV1::new(
        &value.request_sha256,
        &value.selector,
        &value.attestation,
        &value.world_snapshot,
        NativeAuthorityOriginalsFamilyRefV1::GlobalFeeProgram(
            NativeGlobalFeeProgramStateRefV1::new(
                &state.program_id,
                &state.fee_asset,
                &assets,
                &programs,
                &revisions,
                &enrollments,
                &vaults,
                &counters,
                &state.sponsor_account_value,
                &state.fee_asset_definition,
                &state.source_asset_value,
                state.program.as_ref(),
                &rows,
                &enrollment_rows,
                &vault_rows,
            ),
        ),
    );
    assert_eq!(
        norito::encode_canonical(&borrowed).unwrap(),
        norito::encode_canonical(&value).unwrap()
    );
    assert_eq!(
        norito::json::to_json(&borrowed).unwrap(),
        norito::json::to_json(&value).unwrap()
    );
    let mut absent = value.clone();
    let NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state) = &mut absent.originals else {
        unreachable!()
    };
    state.asset_keys.clear();
    assert!(absent.validate_request_correlation(&request).is_err());
    let mut omitted = value.clone();
    let NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state) = &mut omitted.originals else {
        unreachable!()
    };
    state.revisions.clear();
    assert!(omitted.validate_request_correlation(&request).is_err());
    let NativeAuthorityOriginalsFamilyV1::GlobalFeeProgram(state) = value.originals else {
        unreachable!()
    };
    assert_eq!(
        state.sponsor_account_value.as_ref().label,
        Some(account.alias.clone())
    );
}

fn identifier_original_pair() -> (
    iroha_data_model::identifier::IdentifierPolicy,
    iroha_data_model::ram_lfe::RamLfeProgramPolicy,
) {
    use iroha_crypto::{PolicyCommitment, RamLfeBackend, RamLfeVerificationMode};
    use iroha_data_model::{
        identifier::{IdentifierNormalization, IdentifierPolicy},
        ram_lfe::RamLfeProgramPolicy,
    };
    let key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let program_id: iroha_data_model::ram_lfe::RamLfeProgramId =
        "original-program".parse().unwrap();
    let policy = IdentifierPolicy::new(
        "email#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::EmailAddress,
        program_id.clone(),
    );
    let program = RamLfeProgramPolicy::new(
        program_id,
        owner,
        RamLfeBackend::HkdfSha3_512PrfV1,
        RamLfeVerificationMode::Proof,
        PolicyCommitment {
            backend: RamLfeBackend::HkdfSha3_512PrfV1,
            policy_hash: Hash::new(b"synthetic authority originals policy"),
            public_parameters: vec![3, 5, 7],
        },
        key.public_key().clone(),
    );
    (policy, program)
}

#[test]
fn identifier_originals_borrowed_encoding_and_correlation_preserve_both_rows() {
    let (policy, program) = identifier_original_pair();
    let (request, original) = account_fixture();
    let mut request = request.clone();
    request.selector = NativeAuthorityOriginalsSelectorV1::IdentifierPolicy(policy.id.clone());
    let wire = request.canonical_wire().unwrap();
    assert_eq!(
        decode_native_authority_originals_request_v1(&wire).unwrap(),
        request
    );
    let mut response = correlated(&request, original.clone());
    response.originals =
        NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(NativeIdentifierPolicyStateV1 {
            policy,
            program,
        });
    response.validate_request_correlation(&request).unwrap();
    let NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(state) = &response.originals else {
        unreachable!()
    };
    let borrowed = NativeAuthorityOriginalsRefV1::new(
        &response.request_sha256,
        &response.selector,
        &response.attestation,
        &response.world_snapshot,
        NativeAuthorityOriginalsFamilyRefV1::IdentifierPolicy(
            NativeIdentifierPolicyStateRefV1::new(&state.policy, &state.program),
        ),
    );
    let wire = norito::encode_canonical(&response).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), wire);
    assert_eq!(
        norito::json::to_json(&borrowed).unwrap(),
        norito::json::to_json(&response).unwrap()
    );
    assert!(norito::json::to_json_bounded(&borrowed, 4).is_err());
    let decoded = decode_unverified_native_authority_originals_v1(&wire).unwrap();
    assert_eq!(decoded, response);
    decoded.validate_request_correlation(&request).unwrap();
    // This is correlation/codec coverage, not World membership or policy activation.
    assert!(!state.policy.active && !state.program.active);
    let mut changed = request.clone();
    changed.challenge = [44; 32];
    assert!(response.validate_request_correlation(&changed).is_err());
    for mode in 0..5 {
        let mut bad = response.clone();
        let NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(state) = &mut bad.originals else {
            unreachable!()
        };
        match mode {
            0 => state.policy.id = "other#retail".parse().unwrap(),
            1 => state.policy.program_id = "foreign-program".parse().unwrap(),
            2 => state.program.program_id = "foreign-program".parse().unwrap(),
            3 => {
                state.policy.note =
                    Some("x".repeat(NATIVE_AUTHORITY_ORIGINALS_MAX_ROW_BYTES_V1 + 1))
            }
            4 => {
                state.program.commitment.public_parameters =
                    vec![9; NATIVE_AUTHORITY_ORIGINALS_MAX_ROW_BYTES_V1 + 1]
            }
            _ => unreachable!(),
        }
        assert!(
            bad.validate_request_correlation(&request).is_err(),
            "mode {mode}"
        );
    }
    let bad = correlated(&request, original.clone());
    assert!(
        bad.validate_request_correlation(&request).is_err(),
        "foreign family"
    );
}
