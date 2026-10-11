//! Genesis dataspace declaration and certified-cut checks over genuine signed genesis.
use super::*;
use crate::{
    isi::{InstructionBox, RegisterBox},
    nexus::{
        DataSpaceMetadata, LaneLifecycleParameterV1, NexusRuntimeCatalogV1,
        RuntimeDataSpaceAdditionV1, RuntimeLaneManifestV1,
    },
    parameter::system::ConsensusMode,
    sumeragi_finality::{
        FinalityReadError, SignedGenesisPinsV1, WorldStateElementKindV1, WorldStateSnapshotEntryV1,
        WorldStateSnapshotV1, authenticate_signed_genesis_v1,
        test_fixtures::{
            NativeFinalityFixture, NexusAmxContextFixture, fixture_dataspace_id,
            lane_policy_instruction, taira_fixture_lane_policy,
        },
        world_state_value_hash_v1,
    },
    transaction::{Executable, TransactionBuilder},
};
use iroha_crypto::{Algorithm, KeyPair};

const CHAIN: &str = "genesis-dataspace-fixture";

fn committee_keys() -> Vec<KeyPair> {
    (1..=4_u8)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect()
}

fn policy_instruction() -> InstructionBox {
    lane_policy_instruction(taira_fixture_lane_policy(&committee_keys()))
}

fn bpng() -> GenesisDataspaceSelectorV1 {
    GenesisDataspaceSelectorV1 {
        alias: "bpng".into(),
        dataspace_id: fixture_dataspace_id("bpng"),
        lane_id: LaneId::new(5),
        lane_alias: "bpng".into(),
        visibility: LaneVisibility::Public,
        account_routes: Vec::new(),
    }
}

fn pins(fixture: &NativeFinalityFixture) -> (Vec<u8>, SignedGenesisPinsV1) {
    let wire = fixture.genesis().encode_wire().unwrap();
    let mut roster: Vec<_> = committee_keys()
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect();
    roster.sort();
    let pins = SignedGenesisPinsV1 {
        chain_id: fixture.chain_id().to_owned(),
        network_id: fixture.network_id(),
        genesis_hash: fixture.genesis().hash(),
        signed_genesis_sha256: Sha256::digest(&wire).into(),
        genesis_public_key: KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
        roster,
        mode: ConsensusMode::Permissioned,
    };
    (wire, pins)
}

fn declare(
    context: &NexusAmxContextFixture,
    extra: Vec<InstructionBox>,
) -> (NativeFinalityFixture, AuthenticatedSignedGenesisV1) {
    let fixture =
        NativeFinalityFixture::start_with_genesis_extension(CHAIN, context.context_hash(), extra);
    let (wire, pins) = pins(&fixture);
    let genesis = authenticate_signed_genesis_v1(&wire, &pins).unwrap();
    (fixture, genesis)
}

fn verify(
    context: &NexusAmxContextFixture,
    extra: Vec<InstructionBox>,
    selector: &GenesisDataspaceSelectorV1,
) -> Result<GenesisDataspaceAuthorityV1, GenesisDataspaceError> {
    let (_, genesis) = declare(context, extra);
    verify_genesis_dataspace_v1(&genesis, &context.preimage(), selector)
}

#[test]
fn signed_genesis_authenticates_only_against_every_exact_pin() {
    let fixture = NativeFinalityFixture::start(CHAIN);
    let (wire, pins) = pins(&fixture);
    let genesis = authenticate_signed_genesis_v1(&wire, &pins).unwrap();
    assert_eq!(genesis.validators().len(), 4);
    assert_eq!(genesis.signed_genesis_sha256(), pins.signed_genesis_sha256);
    assert_eq!(genesis.block().hash(), pins.genesis_hash);
    let refused = |changed: SignedGenesisPinsV1, wire: &[u8]| {
        assert!(
            matches!(
                authenticate_signed_genesis_v1(wire, &changed),
                Err(FinalityReadError::Invalid(_))
            ),
            "{changed:?}"
        );
    };
    let mut changed = pins.clone();
    changed.signed_genesis_sha256[0] ^= 1;
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.genesis_public_key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
        .public_key()
        .clone();
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.genesis_hash = HashOf::from_untyped_unchecked(Hash::new(b"different-genesis"));
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different-network",
    )));
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.mode = ConsensusMode::Npos;
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.chain_id = " padded".into();
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.roster.swap(0, 1);
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.roster[1] = changed.roster[0].clone();
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.roster.pop();
    refused(changed, &wire);
    let mut changed = pins.clone();
    changed.roster[0] = PeerId::new(
        KeyPair::from_seed(vec![5; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    changed.roster.sort();
    refused(changed, &wire);
    let mut trailing = wire.clone();
    trailing.push(0);
    let mut changed = pins;
    changed.signed_genesis_sha256 = Sha256::digest(&trailing).into();
    refused(changed, &trailing);
}

// These contexts fund their exact shared counter controls. The preexisting Model
// decoder and portable authority graphs are not claimed to be fully physically funded.
fn original_pinned_genesis_debits(
    wire: &[u8],
    pool: &iroha_allocation::AllocationBudget,
) -> (
    usize,
    usize,
    crate::sumeragi::epoch::ValidatorEpochContextV1,
) {
    let limits = norito::canonical_decode_limits(wire.len());
    let context = norito::core::DecodeBudgetContext::try_new_owned(limits, pool).unwrap();
    let (body, epoch) = context.with(|| {
        let block = norito::core::with_decode_limits_scope(limits, || {
            crate::block::decode_framed_signed_block(wire)
        })
        .unwrap();
        let body = usize::try_from(context.consumed_allocated_bytes()).unwrap();
        let epoch = crate::sumeragi_finality::authenticated_genesis(&block)
            .unwrap()
            .into_parts()
            .0;
        (body, epoch)
    });
    let complete = usize::try_from(context.consumed_allocated_bytes()).unwrap();
    assert!(
        complete > body && body > 0,
        "original binary and signed JSON decoders must both run"
    );
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
    (body, complete, epoch)
}

fn pinned_genesis_limits(wire: &[u8], allocation: usize) -> norito::DecodeLimits {
    let limits = norito::canonical_decode_limits(wire.len());
    norito::DecodeLimits::new(
        limits.max_sequence_elements(),
        limits.max_field_bytes(),
        limits.max_total_elements(),
        allocation,
        limits.max_nesting_depth(),
    )
}

#[test]
fn pinned_signed_genesis_uses_one_original_decode_and_retains_metadata() {
    let fixture = NativeFinalityFixture::start(CHAIN);
    let (wire, pins) = pins(&fixture);
    let expected_metadata =
        crate::sumeragi_finality::signed_genesis_consensus_metadata(fixture.genesis()).unwrap();
    let pool = iroha_allocation::AllocationBudget::new(
        norito::core::DecodeBudgetContext::allocation_layout().size(),
    );
    let (_, complete, expected_epoch) = original_pinned_genesis_debits(&wire, &pool);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        pinned_genesis_limits(&wire, complete),
        &pool,
    )
    .unwrap();
    let result = context.with(|| authenticate_signed_genesis_v1(&wire, &pins));
    assert!(
        result.is_ok(),
        "pinned genesis must retain its one original canonical decode: {:?}",
        result.as_ref().err()
    );
    let original = result.unwrap();
    assert_eq!(original.epoch(), &expected_epoch);
    assert_eq!(original.metadata(), &expected_metadata);
    assert_eq!(original.pins(), &pins);
    assert_eq!(original.block().encode_wire().unwrap(), wire);
    assert_eq!(original.validators().len(), pins.roster.len());
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(complete).unwrap()
    );
    drop(original);
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
}

fn original_error_in_chain<'a, T: std::error::Error + 'static>(
    mut error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    loop {
        if let Some(original) = error.downcast_ref::<T>() {
            return Some(original);
        }
        error = error.source()?;
    }
}

#[test]
fn pinned_signed_genesis_preserves_original_binary_refusal() {
    let fixture = NativeFinalityFixture::start(CHAIN);
    let (wire, pins) = pins(&fixture);
    let pool = iroha_allocation::AllocationBudget::new(
        norito::core::DecodeBudgetContext::allocation_layout().size(),
    );
    let limits = pinned_genesis_limits(&wire, 0);
    let reference = norito::core::DecodeBudgetContext::try_new_owned(limits, &pool).unwrap();
    let cause = reference
        .with(|| {
            norito::core::with_decode_limits_scope(
                norito::canonical_decode_limits(wire.len()),
                || crate::block::decode_framed_signed_block(&wire),
            )
        })
        .unwrap_err();
    assert_eq!(
        cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    let expected = cause.into_error().decode_resource_error().unwrap();
    drop(reference);
    assert_eq!(pool.reserved_bytes(), 0);
    let context = norito::core::DecodeBudgetContext::try_new_owned(limits, &pool).unwrap();
    let error = context
        .with(|| authenticate_signed_genesis_v1(&wire, &pins))
        .unwrap_err();
    let original = original_error_in_chain::<norito::core::DecodeAttemptError>(&error);
    assert!(
        original.is_some_and(
            |cause| cause.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit
        ),
        "pinned genesis must preserve its original binary refusal: {error:?}"
    );
    let actual = original_error_in_chain::<norito::core::Error>(&error)
        .unwrap()
        .decode_resource_error()
        .unwrap();
    assert_eq!(
        actual, expected,
        "original decoder refusal fields must survive pin authentication"
    );
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn pinned_signed_genesis_preserves_original_json_refusal_and_retry() {
    let fixture = NativeFinalityFixture::start(CHAIN);
    let (wire, pins) = pins(&fixture);
    let pool = iroha_allocation::AllocationBudget::new(
        norito::core::DecodeBudgetContext::allocation_layout().size(),
    );
    let (body, complete, _) = original_pinned_genesis_debits(&wire, &pool);
    let context =
        norito::core::DecodeBudgetContext::try_new_owned(pinned_genesis_limits(&wire, body), &pool)
            .unwrap();
    let error = context
        .with(|| authenticate_signed_genesis_v1(&wire, &pins))
        .unwrap_err();
    assert!(
        matches!(
            original_error_in_chain::<norito::json::Error>(&error),
            Some(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ),
        "pinned genesis must preserve its original signed JSON refusal: {error:?}"
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(body).unwrap()
    );
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
    // A separately admitted read of the same untouched original succeeds. This does
    // not claim resumable partial Model graphs or reset a refused attempt's counters.
    let retry = norito::core::DecodeBudgetContext::try_new_owned(
        pinned_genesis_limits(&wire, complete),
        &pool,
    )
    .unwrap();
    let original = retry
        .with(|| authenticate_signed_genesis_v1(&wire, &pins))
        .unwrap();
    assert_eq!(original.block().encode_wire().unwrap(), wire);
    assert_eq!(original.pins(), &pins);
    assert_eq!(
        retry.consumed_allocated_bytes(),
        u64::try_from(complete).unwrap()
    );
    drop(original);
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn signed_genesis_rejects_executed_block_and_invalid_registration_proof() {
    let fixture = NativeFinalityFixture::start(CHAIN);
    let (_, pins) = pins(&fixture);
    let rebind = |block: &crate::block::SignedBlock, pins: &SignedGenesisPinsV1| {
        let wire = block.encode_wire().unwrap();
        let mut pins = pins.clone();
        pins.genesis_hash = block.hash();
        pins.network_id = NetworkId::from_genesis_hash(block.hash());
        pins.signed_genesis_sha256 = Sha256::digest(&wire).into();
        (wire, pins)
    };
    let executed =
        crate::block::decode_framed_signed_block(&fixture.genesis_proof().block_wire).unwrap();
    let (wire, changed) = rebind(&executed, &pins);
    assert!(authenticate_signed_genesis_v1(&wire, &changed).is_err());

    let original = fixture.genesis().external_transactions().next().unwrap();
    let Executable::Instructions(instructions) = original.instructions() else {
        panic!("fixture genesis uses explicit signed instructions");
    };
    let mut changed_instructions = instructions.to_vec();
    let (index, mut invalid) = changed_instructions
        .iter()
        .enumerate()
        .find_map(
            |(index, instruction)| match instruction.as_any().downcast_ref::<RegisterBox>() {
                Some(RegisterBox::Peer(registration)) => Some((index, registration.clone())),
                _ => None,
            },
        )
        .expect("fixture registers its BLS committee");
    invalid.pop[0] ^= 1;
    changed_instructions[index] = invalid.into();
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new_genesis(
        original.authority().clone(),
        original.fee_payment_intent().clone(),
    );
    builder.set_creation_time(original.creation_time());
    let transaction = builder
        .with_instructions(changed_instructions)
        .sign(signer.private_key());
    let block =
        crate::block::SignedBlock::try_genesis(vec![transaction], signer.private_key(), None, None)
            .unwrap();
    let (wire, changed) = rebind(&block, &pins);
    assert!(authenticate_signed_genesis_v1(&wire, &changed).is_err());
}

#[test]
fn taira_genesis_declares_public_bpng_lane_five() {
    let context = NexusAmxContextFixture::taira();
    let authority = verify(&context, vec![policy_instruction()], &bpng()).unwrap();
    assert_eq!(
        authority.dataspace_id(),
        DataSpaceId::new(8_648_377_547_929_788_715)
    );
    assert_eq!(authority.lane_id(), LaneId::new(5));
    assert_eq!(authority.visibility(), LaneVisibility::Public);
    assert_eq!(
        authority.nexus_amx_context_sha256(),
        <[u8; 32]>::from(Sha256::digest(context.preimage()))
    );
    assert_eq!(
        authority.nexus_amx_context_hash(),
        Hash::prehashed(context.context_hash())
    );
    let projection: norito::json::Value =
        norito::json::from_str(&authority.projection_json().unwrap()).unwrap();
    assert_eq!(
        projection["schema"],
        norito::json::Value::from(GENESIS_DATASPACE_VERIFICATION_SCHEMA_V1)
    );
    assert_eq!(
        projection["dataspace_id"],
        norito::json::Value::from("8648377547929788715")
    );
    assert_eq!(projection["lane_id"], norito::json::Value::from(5_u64));
    assert_eq!(
        projection["visibility"],
        norito::json::Value::from("public")
    );
    // A Restricted participant with a scoped account route is verified the same way.
    let dpn = GenesisDataspaceSelectorV1 {
        alias: "dpn".into(),
        dataspace_id: fixture_dataspace_id("dpn"),
        lane_id: LaneId::new(3),
        lane_alias: "dpn".into(),
        visibility: LaneVisibility::Restricted,
        account_routes: Vec::new(),
    };
    verify(&context, vec![policy_instruction()], &dpn).unwrap();
}

#[test]
fn declaration_rejects_foreign_context_and_root_scope() {
    let context = NexusAmxContextFixture::taira();
    let (_, genesis) = declare(&context, vec![policy_instruction()]);
    let mut other = context.clone();
    other.autoscale = (false, 1, 9);
    assert_eq!(
        verify_genesis_dataspace_v1(&genesis, &other.preimage(), &bpng()),
        Err(GenesisDataspaceError::ContextHash)
    );
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NativeFinalityFixture::start(CHAIN).network_id(),
        dataspace_id: fixture_dataspace_id("bpng"),
    };
    let fixture = NativeFinalityFixture::start_with_scope("private-root", scope);
    let (wire, pins) = pins(&fixture);
    let private = authenticate_signed_genesis_v1(&wire, &pins).unwrap();
    assert_eq!(
        verify_genesis_dataspace_v1(&private, &context.preimage(), &bpng()),
        Err(GenesisDataspaceError::NotGlobalRoot)
    );
}

#[test]
fn declaration_rejects_selector_and_catalog_mismatches() {
    let context = NexusAmxContextFixture::taira();
    let extra = || vec![policy_instruction()];
    let mut selector = bpng();
    selector.visibility = LaneVisibility::Restricted;
    assert!(matches!(
        verify(&context, extra(), &selector),
        Err(GenesisDataspaceError::Lane(_))
    ));
    let mut selector = bpng();
    selector.lane_id = LaneId::new(8);
    assert!(matches!(
        verify(&context, extra(), &selector),
        Err(GenesisDataspaceError::Lane(_))
    ));
    let mut selector = bpng();
    selector.lane_alias = "bpng-lane".into();
    assert!(matches!(
        verify(&context, extra(), &selector),
        Err(GenesisDataspaceError::Lane(_))
    ));
    let mut selector = bpng();
    selector.dataspace_id = DataSpaceId::new(10);
    assert!(matches!(
        verify(&context, extra(), &selector),
        Err(GenesisDataspaceError::Selector(_))
    ));
    let mut selector = bpng();
    selector.account_routes = vec!["*@dpn".into()];
    assert!(matches!(
        verify(&context, extra(), &selector),
        Err(GenesisDataspaceError::Selector(_))
    ));
    // The catalog declares a different identity under the bpng alias.
    let mut renamed = context.clone();
    for (_, alias) in &mut renamed.dataspaces {
        if alias == "bpng" {
            *alias = "bpng2".into();
        } else if alias == "cbsi" {
            *alias = "bpng".into();
        }
    }
    assert!(matches!(
        verify(&renamed, extra(), &bpng()),
        Err(GenesisDataspaceError::Dataspace(_))
    ));
    let mut second_lane = context.clone();
    let mut duplicate = second_lane.lanes[5].clone();
    duplicate.id = LaneId::new(8);
    duplicate.alias = "bpng-two".into();
    second_lane.lane_count = 9;
    second_lane.lanes.push(duplicate);
    assert!(matches!(
        verify(&second_lane, extra(), &bpng()),
        Err(GenesisDataspaceError::Lane(_))
    ));
    let mut autoscale = context.clone();
    autoscale.autoscale = (true, 5, 8);
    assert!(matches!(
        verify(&autoscale, extra(), &bpng()),
        Err(GenesisDataspaceError::Lane(_))
    ));
}

#[test]
fn declaration_rejects_missing_shadowed_or_diverting_routes() {
    let context = NexusAmxContextFixture::taira();
    let bpng_id = fixture_dataspace_id("bpng");
    let extra = || vec![policy_instruction()];
    let mut required = bpng();
    required.account_routes = vec!["*@bpng".into()];
    assert!(matches!(
        verify(&context, extra(), &required),
        Err(GenesisDataspaceError::Routing(_))
    ));
    let mut routed = context.clone();
    routed
        .rules
        .push((5, Some(bpng_id), Some("*@bpng".into()), None));
    // Instruction-only governance/deploy rules precede the account route: they shadow it.
    assert!(matches!(
        verify(&routed, extra(), &required),
        Err(GenesisDataspaceError::Routing(_))
    ));
    let mut first = context.clone();
    first
        .rules
        .insert(0, (5, Some(bpng_id), Some("*@bpng".into()), None));
    verify(&first, extra(), &required).unwrap();
    let mut diverted = context.clone();
    diverted.rules.push((
        3,
        Some(fixture_dataspace_id("dpn")),
        Some("*@mibank.bpng".into()),
        None,
    ));
    assert!(matches!(
        verify(&diverted, extra(), &bpng()),
        Err(GenesisDataspaceError::Routing(_))
    ));
    let mut paired = context.clone();
    paired
        .rules
        .push((5, None, None, Some("transfer::asset@bpng".into())));
    verify(&paired, extra(), &bpng()).unwrap();
}

#[test]
fn declaration_rejects_missing_duplicate_or_mismatched_lane_policy_and_catalog_mutation() {
    let context = NexusAmxContextFixture::taira();
    assert!(matches!(
        verify(&context, Vec::new(), &bpng()),
        Err(GenesisDataspaceError::LanePolicy(_))
    ));
    assert!(matches!(
        verify(
            &context,
            vec![policy_instruction(), policy_instruction()],
            &bpng()
        ),
        Err(GenesisDataspaceError::LanePolicy(_))
    ));
    let mut repointed = taira_fixture_lane_policy(&committee_keys());
    repointed.fixed[2].dataspace = fixture_dataspace_id("dpn");
    assert!(matches!(
        verify(&context, vec![lane_policy_instruction(repointed)], &bpng()),
        Err(GenesisDataspaceError::LanePolicy(_))
    ));
    let mut foreign = taira_fixture_lane_policy(&committee_keys());
    foreign.fixed[2].committee =
        taira_fixture_lane_policy(&[KeyPair::from_seed(vec![9; 32], Algorithm::BlsNormal)]).fixed
            [2]
        .committee
        .clone();
    assert!(matches!(
        verify(&context, vec![lane_policy_instruction(foreign)], &bpng()),
        Err(GenesisDataspaceError::LanePolicy(_))
    ));
    let mut diverting = taira_fixture_lane_policy(&committee_keys());
    diverting
        .routes
        .push(crate::sumeragi_lanes::SumeragiLaneRoute {
            lane: LaneId::new(3),
            account: Some("*@bpng".into()),
            instruction: None,
        });
    assert!(matches!(
        verify(&context, vec![lane_policy_instruction(diverting)], &bpng()),
        Err(GenesisDataspaceError::LanePolicy(_))
    ));
    for id in [
        LaneLifecycleParameterV1::parameter_id(),
        crate::nexus::NexusCatalogTransitionV1::parameter_id(),
    ] {
        let mutation = SetParameter::new(Parameter::Custom(CustomParameter::new(
            id,
            iroha_primitives::json::Json::new(norito::json::Value::Null),
        )))
        .into();
        assert_eq!(
            verify(&context, vec![policy_instruction(), mutation], &bpng()),
            Err(GenesisDataspaceError::CatalogMutation)
        );
    }
}

struct Cut {
    fixture: NativeFinalityFixture,
    authority: GenesisDataspaceAuthorityV1,
}

fn cut_authority(selector: &GenesisDataspaceSelectorV1) -> Cut {
    let context = NexusAmxContextFixture::taira();
    let (fixture, genesis) = declare(&context, vec![policy_instruction()]);
    let authority = verify_genesis_dataspace_v1(&genesis, &context.preimage(), selector).unwrap();
    Cut { fixture, authority }
}

fn parameters_with(custom: impl IntoIterator<Item = CustomParameter>) -> Parameters {
    let mut parameters = Parameters::default();
    for custom in custom {
        parameters.custom.insert(custom.id().clone(), custom);
    }
    parameters
}

fn certify_parameters(
    fixture: &mut NativeFinalityFixture,
    parameters: &Parameters,
) -> (VerifiedSumeragiBlock, VerifiedWorldStateSnapshotV1) {
    let snapshot = WorldStateSnapshotV1 {
        schema_hash: Hash::new(b"synthetic genesis dataspace schema"),
        entries: vec![WorldStateSnapshotEntryV1 {
            field_id: "world.parameters".into(),
            kind: WorldStateElementKindV1::Cell,
            key_hash: None,
            value_hash: world_state_value_hash_v1(parameters).unwrap(),
        }],
    };
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify_with_world_root(block, snapshot.root().unwrap());
    let tip = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let world = snapshot.authenticate(&tip).unwrap();
    (tip, world)
}

#[test]
fn certified_cut_rechecks_the_governed_lane_policy() {
    let Cut {
        mut fixture,
        authority,
    } = cut_authority(&bpng());
    let policy = taira_fixture_lane_policy(&committee_keys());
    let parameters = parameters_with([policy.clone().into_custom_parameter()]);
    let (tip, world) = certify_parameters(&mut fixture, &parameters);
    let verified = authority.verify_cut(&tip, &world, &parameters).unwrap();
    assert_eq!(
        (verified.height(), verified.lane_id()),
        (tip.height(), LaneId::new(5))
    );
    assert_eq!(verified.committee().len(), 4);

    let changed = parameters_with([]);
    assert!(matches!(
        authority.verify_cut(&tip, &world, &changed),
        Err(GenesisDataspaceError::Cut(_))
    ));
    let (next_tip, _) = certify_parameters(&mut fixture, &parameters);
    assert!(matches!(
        authority.verify_cut(&next_tip, &world, &parameters),
        Err(GenesisDataspaceError::Cut(_))
    ));

    let mutations: [fn(&mut SumeragiLanePolicy); 3] = [
        |policy| policy.fixed[2].dataspace = fixture_dataspace_id("dpn"),
        |policy| policy.fixed[3].dataspace = fixture_dataspace_id("bpng"),
        |policy| {
            policy.fixed[2].committee =
                taira_fixture_lane_policy(&[KeyPair::from_seed(vec![9; 32], Algorithm::BlsNormal)])
                    .fixed[2]
                    .committee
                    .clone();
        },
    ];
    for mutate in mutations {
        let mut changed_policy = policy.clone();
        mutate(&mut changed_policy);
        let parameters = parameters_with([changed_policy.into_custom_parameter()]);
        let (tip, world) = certify_parameters(&mut fixture, &parameters);
        assert!(matches!(
            authority.verify_cut(&tip, &world, &parameters),
            Err(GenesisDataspaceError::LanePolicy(_))
        ));
    }
}

#[test]
fn certified_cut_rejects_runtime_catalog_collisions_and_restricted_lanes() {
    let Cut {
        mut fixture,
        authority,
    } = cut_authority(&bpng());
    let policy = taira_fixture_lane_policy(&committee_keys()).into_custom_parameter();
    let bpng_hash = crate::sns::NameSelectorV1::new(crate::sns::DATASPACE_ALIAS_SUFFIX_ID, "bpng")
        .unwrap()
        .name_hash();
    let collision = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: Hash::new(b"baseline dataspaces"),
        baseline_manifests_hash: Hash::new(b"baseline manifests"),
        dataspaces: vec![RuntimeDataSpaceAdditionV1 {
            descriptor: DataSpaceMetadata {
                id: DataSpaceId::from_hash(&bpng_hash),
                alias: "bpng".into(),
                description: None,
                fault_tolerance: 1,
            },
            manifest_hash: bpng_hash,
        }],
        manifests: Vec::new(),
    };
    let manifest = NexusRuntimeCatalogV1 {
        dataspaces: Vec::new(),
        manifests: vec![RuntimeLaneManifestV1 {
            lane_id: LaneId::new(5),
            manifest: iroha_primitives::json::Json::from_str_norito(r#"{"lane":"bpng"}"#).unwrap(),
        }],
        ..collision.clone()
    };
    for runtime in [collision, manifest] {
        let parameters =
            parameters_with([policy.clone(), runtime.into_custom_parameter().unwrap()]);
        let (tip, world) = certify_parameters(&mut fixture, &parameters);
        assert!(matches!(
            authority.verify_cut(&tip, &world, &parameters),
            Err(GenesisDataspaceError::RuntimeCatalog(_))
        ));
    }

    let Cut {
        mut fixture,
        authority,
    } = cut_authority(&GenesisDataspaceSelectorV1 {
        alias: "dpn".into(),
        dataspace_id: fixture_dataspace_id("dpn"),
        lane_id: LaneId::new(3),
        lane_alias: "dpn".into(),
        visibility: LaneVisibility::Restricted,
        account_routes: Vec::new(),
    });
    let parameters = parameters_with([policy]);
    let (tip, world) = certify_parameters(&mut fixture, &parameters);
    assert_eq!(
        authority.verify_cut(&tip, &world, &parameters),
        Err(GenesisDataspaceError::RestrictedManifestAuthorityUnavailable)
    );
}
