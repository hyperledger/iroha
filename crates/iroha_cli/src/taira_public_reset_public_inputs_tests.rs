//! Public preparation tests use native signed genesis fixtures and owner-controlled ancestor custody.

use super::*;
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{
    block::{SignedBlock, consensus::SumeragiGenesisContextParameters},
    parameter::{Parameter, system::SumeragiConsensusMode},
};
use std::num::NonZeroU64;

fn key(seed: u8, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], algorithm).expect("valid deterministic fixture seed")
}

fn line(value: impl std::fmt::Display) -> Vec<u8> {
    format!("{value}\n").into_bytes()
}

#[derive(Clone)]
struct Fixture {
    block: SignedBlock,
    manifest: iroha_genesis::RawGenesisTransaction,
    genesis: KeyPair,
    canary: KeyPair,
    nexus_context: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(Self::build).clone()
    }

    fn build() -> Self {
        Self::build_with_epoch(20)
    }

    /// The fixture genesis plus sixteen seated Parliament citizens (`specs/sccp.md` §4.14.5),
    /// executed with the fixture's fresh citizenship escrow that `peer0.toml` names.
    fn seated() -> Self {
        static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                Self::build_with_escrow(
                    20,
                    seated_citizen_instructions(),
                    Some(crate::taira::parliament_seating::fixture_citizenship_escrow()),
                )
            })
            .clone()
    }

    fn build_with_epoch(epoch: u64) -> Self {
        Self::build_with_epoch_and_instructions(epoch, Vec::new())
    }

    fn build_with_epoch_and_instructions(
        epoch: u64,
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
    ) -> Self {
        Self::build_with_escrow(epoch, instructions, None)
    }

    /// Build and execute the fixture genesis; `citizenship_escrow`, when given, replaces the
    /// default `gov.citizenship_escrow_account` the genesis executes with.
    fn build_with_escrow(
        epoch: u64,
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
        citizenship_escrow: Option<AccountId>,
    ) -> Self {
        let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let genesis = key(101, Algorithm::Ed25519);
        let canary = key(102, Algorithm::Ed25519);
        let topology = (110..114)
            .map(|seed| {
                let validator = key(seed, Algorithm::BlsNormal);
                iroha_genesis::GenesisTopologyEntry::new(
                    PeerId::new(validator.public_key().clone()),
                    iroha_crypto::bls_normal_pop_prove(validator.private_key()).unwrap(),
                )
            })
            .collect();
        let mut npos = iroha_data_model::parameter::system::SumeragiNposParameters::default();
        npos.max_validators = 4;
        npos.epoch_length_blocks = NonZeroU64::new(epoch).unwrap();
        npos.evidence_horizon_blocks = epoch;
        npos.slashing_delay_blocks = 1;
        npos.validate().unwrap();
        let mut builder = iroha_genesis::GenesisBuilder::new_without_executor(CHAIN_ID.into(), ".")
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .set_topology(topology)
            .append_parameter(Parameter::Sumeragi(
                iroha_data_model::parameter::system::SumeragiParameter::EpochLengthBlocks(
                    NonZeroU64::new(epoch).unwrap(),
                ),
            ))
            .append_parameter(Parameter::Custom(npos.into_custom_parameter()));
        if !instructions.is_empty() {
            // Genesis serializes topology registrations after a transaction's
            // explicit instructions. Staking must execute in the next batch,
            // after those peers and their consensus keys exist.
            builder = builder.next_transaction();
        }
        for instruction in instructions {
            builder = builder.append_instruction(instruction);
        }
        let manifest = builder
            .build_raw()
            .unwrap()
            .with_chain_discriminant(CHAIN_DISCRIMINANT)
            .with_consensus_mode(SumeragiConsensusMode::Npos)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        // Match Kagami's signing boundary: the unpublished draft may have unbound
        // policy commitments. Only the native validator's typed mismatch may supply
        // their actual values; the newly signed final fixture must pass unchanged.
        let (nexus_hash, execution_hash) =
            execute_fixture_genesis(&manifest, &genesis, citizenship_escrow.as_ref())
                .map(|(_, nexus, execution, _)| (nexus, execution))
                .unwrap_or_else(|derived_policies| derived_policies);
        let mut context = manifest.sumeragi_context_parameters();
        context.nexus_amx_context_hash = nexus_hash.into();
        context.execution_policy_hash = execution_hash.into();
        let manifest = manifest
            .with_sumeragi_context_parameters(context)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        let (mut block, final_nexus_hash, final_execution_hash, nexus_context) =
            execute_fixture_genesis(&manifest, &genesis, citizenship_escrow.as_ref())
                .expect("newly signed fixture must reproduce both exact native policies");
        assert_eq!(nexus_hash, final_nexus_hash);
        assert_eq!(execution_hash, final_execution_hash);
        block
            .replace_signatures(
                iroha_data_model::block::BlockSignatures::try_from_iter([
                    iroha_data_model::block::BlockSignature::new(
                        0,
                        iroha_crypto::SignatureOf::try_from_hash(
                            genesis.private_key(),
                            block.hash(),
                        )
                        .unwrap(),
                    ),
                ])
                .expect("at most 31 block signatures"),
            )
            .unwrap();
        iroha_genesis::validate_prepared_genesis_bundle(
            &block.encode_wire().unwrap(),
            &manifest,
            genesis.public_key(),
            block.hash(),
        )
        .unwrap();
        // The same production validator called by assembly must accept this fixture.
        iroha_core::release_identity::genesis_identity(
            &block.encode_wire().unwrap(),
            genesis.public_key(),
        )
        .unwrap();
        Self {
            block,
            manifest,
            genesis,
            canary,
            nexus_context,
        }
    }

    fn network(&self) -> NetworkId {
        NetworkId::from_genesis_hash(self.block.hash())
    }

    /// Raw manifest bytes with Taira account literals, as the generator writes them.
    fn manifest_json(&self) -> Vec<u8> {
        let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        json_line(&self.manifest).unwrap()
    }

    fn derive(&self) -> Result<PublicInputsV1> {
        derive(
            &self.block.encode_wire().unwrap(),
            &self.manifest_json(),
            &line(self.network()),
            &line(self.genesis.public_key()),
            &line(self.canary.public_key()),
            &self.nexus_context,
        )
    }

    #[cfg(unix)]
    fn write(&self, root: &Path) -> PreparePublicInputs {
        let localnet = root.join("localnet");
        fs::create_dir(&localnet).unwrap();
        fs::set_permissions(&localnet, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            ("genesis.signed.nrt", self.block.encode_wire().unwrap()),
            ("genesis.json", self.manifest_json()),
            ("nexus-amx-context.v1.bin", self.nexus_context.clone()),
            ("genesis.expected_hash", line(self.network())),
            ("genesis.public_key", line(self.genesis.public_key())),
            (
                "peer0.toml",
                crate::taira::parliament_seating::canonical_seating_config_toml().into_bytes(),
            ),
        ] {
            fs::write(localnet.join(name), bytes).unwrap();
        }
        let canary_public_key = root.join("canary.public_key");
        fs::write(&canary_public_key, line(self.canary.public_key())).unwrap();
        PreparePublicInputs {
            localnet_dir: localnet,
            canary_public_key: Some(canary_public_key),
            intent: None,
            output_dir: root.join("public-inputs"),
        }
    }
}

/// Sixteen genesis citizens bonded at the canonical Taira bond (`specs/sccp.md` §4.14.5), under
/// the default citizenship asset and the fresh fixture escrow that the seated fixture genesis
/// executes with and its `peer0.toml` names.
fn seated_citizen_instructions() -> Vec<iroha_data_model::isi::InstructionBox> {
    use iroha_data_model::{
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
        domain::Domain,
        isi::Register,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{NumericSpec, Quantity};

    let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::governance::citizenship_asset_id(),
    )
    .unwrap();
    let escrow = crate::taira::parliament_seating::fixture_citizenship_escrow();
    let citizens = (150_u8..166)
        .map(|seed| AccountId::new(key(seed, Algorithm::Ed25519).public_key().clone()))
        .collect::<Vec<_>>();
    let mut instructions: Vec<iroha_data_model::isi::InstructionBox> = vec![
        Register::domain(Domain::new(
            DomainId::parse_fully_qualified("sora.universal").unwrap(),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            asset.clone(),
            "xor",
            NumericSpec::default(),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ];
    instructions.extend(
        crate::taira::parliament_seating::citizen_genesis_instructions(
            &citizens,
            &asset,
            crate::taira::parliament_seating::SeatingProfile::canonical()
                .unwrap()
                .citizenship_bond(),
            &Quantity::from(1_000_u32),
            Some(&escrow),
            None,
        )
        .unwrap(),
    );
    instructions
}

// Exercise the same public Core validation/execution boundary as Kagami. A raw
// GenesisBuilder proposal is not release evidence: only actual execution may
// populate results and determine the two signed consensus context commitments.
fn execute_fixture_genesis(
    manifest: &iroha_genesis::RawGenesisTransaction,
    key: &KeyPair,
    citizenship_escrow: Option<&AccountId>,
) -> std::result::Result<(SignedBlock, Hash, Hash, Vec<u8>), (Hash, Hash)> {
    use iroha_config::{
        kura::InitMode,
        parameters::{actual, defaults},
    };
    use iroha_core::{
        block::ValidBlock,
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::Registrable as _,
        state::{State, World},
        sumeragi::network_topology::Topology,
    };
    use iroha_data_model::{account::Account, domain::Domain};
    // Sign the same computed native policy as Kagami; the data-model fallback
    // constant is not the configured Core policy used by this execution fixture.
    let provisional = manifest
        .clone()
        .build_and_sign_with_confidential_policy_hash(
            key,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        )
        .unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&authority)],
        [Account::new(authority.clone()).build(&authority)],
        [],
    );
    let reprofile = |literal: &str| {
        iroha_data_model::account::address::AccountAddress::from_i105_for_discriminant(
            literal,
            Some(iroha_config::parameters::defaults::common::chain_discriminant()),
        )
        .unwrap()
        .to_i105_for_discriminant(CHAIN_DISCRIMINANT)
        .unwrap()
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    for literal in [
        &mut nexus.staking.stake_escrow_account_id,
        &mut nexus.staking.slash_sink_account_id,
        &mut nexus.fees.fee_sink_account_id,
    ] {
        *literal = reprofile(literal);
    }
    if let Some(authority) = nexus.relay_worker.authority_account_id.as_mut() {
        *authority = reprofile(authority);
    }
    let kura_config = actual::Kura {
        init_mode: InitMode::Strict,
        // The temporary constructor supplies and retains its isolated directory.
        store_dir: iroha_config::base::WithOrigin::inline(PathBuf::new()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        native_context_archive_max_bytes:
            iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        history_checkpoint_cache_capacity:
            iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::kura::FASTPQ_ARTIFACT_POLICY,
        debug_output_new_blocks: false,
        fsync_mode: defaults::kura::FSYNC_MODE,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,
    };
    let kura = Kura::new_temporary_with_configured_lane_catalog(
        &kura_config,
        &nexus.lane_config,
        &nexus.configured_lane_catalog,
    )
    .expect("initialize authenticated temporary Kura for native genesis");
    let mut state = State::try_new_with_chain_and_network_id_with_default_telemetry(
        iroha_core::state::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        world,
        kura,
        LiveQueryStore::start_test(),
        manifest.chain_id().clone(),
        NetworkId::from_genesis_hash(provisional.0.hash()),
    )
    .unwrap();
    // Match Kagami's configured startup: install the policy owner before any
    // runtime projection, then bind physical storage to this exact genesis network.
    let manifests = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
        &nexus.lane_catalog,
        &nexus.governance,
        &nexus.registry,
    );
    manifests
        .validate_active_coverage_for_catalog(&nexus.lane_catalog)
        .unwrap();
    state.install_lane_manifests_for_testing(&std::sync::Arc::new(manifests));
    let mut pipeline = actual::Pipeline::default();
    pipeline.workers = 1;
    pipeline.gas.tech_account_id = reprofile(&pipeline.gas.tech_account_id);
    state.set_pipeline(pipeline);
    state
        .prepare_configured_primary_geometry_anchor(&nexus.configured_lane_catalog)
        .expect("bind signed genesis network and configured primary geometry");
    state
        .restore_kura_lane_segments_before_startup_replay()
        .expect("restore authenticated primary before genesis execution");
    state
        .set_nexus_from_config(nexus)
        .expect("install the exact configured genesis Nexus baseline");
    state.set_crypto(actual::Crypto::default());
    if let Some(escrow) = citizenship_escrow {
        // Validators of a seated network name a fresh escrow, never the published default.
        state.set_gov(actual::Governance {
            citizenship_escrow_account: escrow.clone(),
            ..actual::Governance::default()
        });
    }
    let topology = Topology::new(
        iroha_core::sumeragi::startup::genesis_committee_peers(&provisional.0).unwrap(),
    );
    let validation = ValidBlock::validate_signed_genesis(
        provisional.0,
        &topology,
        &authority,
        &iroha_primitives::time::TimeSource::new_system(),
        &state,
        iroha_data_model::block::consensus::ConsensusMode::Npos,
    )
    .unpack(|_| {});
    let (valid, staged) = match validation {
        Ok(executed) => executed,
        Err((block, error)) => {
            if let iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                actual_execution,
                actual_nexus,
                ..
            } = *error
            {
                return Err((actual_nexus, actual_execution));
            }
            let output_errors = block
                .failed_outputs()
                .map(|(index, reason)| format!("output[{index}]: {reason:?}"))
                .collect::<Vec<_>>();
            panic!(
                "native fixture genesis execution failed: {error:?}; {}",
                output_errors.join("; ")
            )
        }
    };
    let nexus_context = iroha_core::sumeragi::staged_genesis_nexus_amx_context_preimage(&staged);
    let nexus_hash = Hash::new(&nexus_context);
    let execution_hash =
        iroha_core::sumeragi::staged_genesis_execution_policy_hash(&staged).unwrap();
    drop(staged);
    Ok((valid.into(), nexus_hash, execution_hash, nexus_context))
}

pub(crate) fn deployment_genesis_fixture() -> (SignedBlock, KeyPair) {
    let fixture = Fixture::new();
    (fixture.block, fixture.genesis)
}

/// Reuse the exact executed genesis and independently checked native manifest binding.
pub(crate) fn deployment_validated_genesis_fixture() -> iroha_genesis::ValidatedGenesisBundle {
    let fixture = Fixture::new();
    iroha_genesis::validate_prepared_genesis_bundle(
        &fixture.block.encode_wire().unwrap(),
        &fixture.manifest,
        fixture.genesis.public_key(),
        fixture.block.hash(),
    )
    .unwrap()
}

/// Execute and sign explicit active lane bindings with authority keys distinct from peer keys.
pub(crate) fn deployment_lane_genesis_fixture() -> (SignedBlock, KeyPair) {
    static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
    let fixture = FIXTURE.get_or_init(|| {
        use iroha_data_model::{
            account::{Account, address::AccountAddress},
            asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
            domain::Domain,
            isi::{ActivatePublicLaneValidator, Mint, Register, RegisterPublicLaneValidator},
        };
        use iroha_model_base::{domain::DomainId, metadata::Metadata, topology::LaneId};
        use iroha_primitives::numeric::{NumericSpec, Quantity};

        let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let escrow = AccountAddress::from_i105_for_discriminant(
            &iroha_config::parameters::defaults::nexus::staking::stake_escrow_account_id(),
            Some(iroha_config::parameters::defaults::common::chain_discriminant()),
        )
        .unwrap()
        .to_i105_for_discriminant(CHAIN_DISCRIMINANT)
        .unwrap();
        let escrow = AccountId::parse_encoded(&escrow).unwrap();
        let stake_asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::staking::stake_asset_id(),
        )
        .unwrap();
        let mut instructions: Vec<iroha_data_model::isi::InstructionBox> = vec![
            Register::domain(Domain::new(
                DomainId::parse_fully_qualified("nexus.universal").unwrap(),
            ))
            .into(),
            Register::account(Account::new(escrow.clone())).into(),
            Register::asset_definition(AssetDefinition::new(
                stake_asset.clone(),
                "Fixture stake",
                NumericSpec::fractional(9),
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        ];
        for seed in 110..114 {
            let validator = AccountId::new(key(seed + 20, Algorithm::Ed25519).public_key().clone());
            let peer = PeerId::new(key(seed, Algorithm::BlsNormal).public_key().clone());
            instructions.extend([
                Register::account(Account::new(validator.clone())).into(),
                Mint::asset_quantity(1_u64, AssetId::new(stake_asset.clone(), validator.clone()))
                    .into(),
                RegisterPublicLaneValidator::new(
                    LaneId::SINGLE,
                    validator.clone(),
                    peer,
                    validator.clone(),
                    Quantity::from(1_u64),
                    Metadata::default(),
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_asset.clone(), validator.clone()),
                        AssetId::new(stake_asset.clone(), escrow.clone()),
                        Quantity::from(1_u64),
                    ),
                )
                .into(),
                ActivatePublicLaneValidator::new(LaneId::SINGLE, validator).into(),
            ]);
        }
        Fixture::build_with_epoch_and_instructions(20, instructions)
    });
    (fixture.block.clone(), fixture.genesis.clone())
}

#[test]
fn native_fixture_rejects_changed_signed_policies_after_draft_binding() {
    let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let fixture = Fixture::new();
    let bound = fixture.manifest.sumeragi_context_parameters();
    let expected = (
        Hash::prehashed(bound.nexus_amx_context_hash),
        Hash::prehashed(bound.execution_policy_hash),
    );
    assert!(execute_fixture_genesis(&fixture.manifest, &fixture.genesis, None).is_ok());
    for change_execution in [true, false] {
        let mut changed = bound.clone();
        let foreign = Hash::new(b"foreign signed fixture policy").into();
        if change_execution {
            changed.execution_policy_hash = foreign;
        } else {
            changed.nexus_amx_context_hash = foreign;
        }
        let manifest = fixture
            .manifest
            .clone()
            .with_sumeragi_context_parameters(changed)
            .with_consensus_meta()
            .expect("valid fixture consensus parameters");
        assert_eq!(
            execute_fixture_genesis(&manifest, &fixture.genesis, None).unwrap_err(),
            expected,
            "native execution must reject either changed commitment"
        );
    }
}

#[test]
fn derives_native_genesis_identity_and_exact_canary_request() {
    let fixture = Fixture::new();
    let report = fixture.derive().unwrap();
    assert_eq!(report.genesis_hash, fixture.block.hash().to_string());
    assert_ne!(report.genesis_hash, report.signed_genesis_sha256);
    assert_eq!(report.network_id, fixture.network());
    assert_eq!(
        report.canary_onboarding_request.alias,
        crate::taira::canary_alias(fixture.canary.public_key())
    );
    assert!(report.canary_onboarding_request.permissions.is_empty());
    let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    assert_eq!(
        report.canary_onboarding_request.account_id,
        AccountId::new(fixture.canary.public_key().clone()).to_string()
    );
    let decoded: PublicInputsV1 = json::from_slice(&json_line(&report).unwrap()).unwrap();
    assert_eq!(decoded, report);
}

#[test]
fn rejects_wrong_network_key_and_resultless_genesis() {
    let fixture = Fixture::new();
    let wire = fixture.block.encode_wire().unwrap();
    let wrong =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"wrong network")));
    assert!(
        derive(
            &wire,
            &json_line(&fixture.manifest).unwrap(),
            &line(wrong),
            &line(fixture.genesis.public_key()),
            &line(fixture.canary.public_key()),
            &fixture.nexus_context,
        )
        .unwrap_err()
        .to_string()
        .contains("differs from checked network")
    );
    assert!(
        derive(
            &wire,
            &json_line(&fixture.manifest).unwrap(),
            &line(fixture.network()),
            &line(fixture.canary.public_key()),
            &line(fixture.canary.public_key()),
            &fixture.nexus_context,
        )
        .is_err()
    );
    let resultless = fixture
        .block
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    assert!(
        derive(
            &resultless,
            &json_line(&fixture.manifest).unwrap(),
            &line(fixture.network()),
            &line(fixture.genesis.public_key()),
            &line(fixture.canary.public_key()),
            &fixture.nexus_context,
        )
        .is_err()
    );
}

#[test]
fn rejects_noncanonical_identity_and_non_ed25519_canary() {
    let fixture = Fixture::new();
    for text in [
        Vec::new(),
        b"invalid\n".to_vec(),
        line(fixture.network()).repeat(2),
        fixture.network().to_string().into_bytes(),
    ] {
        assert!(
            derive(
                &fixture.block.encode_wire().unwrap(),
                &json_line(&fixture.manifest).unwrap(),
                &text,
                &line(fixture.genesis.public_key()),
                &line(fixture.canary.public_key()),
                &fixture.nexus_context,
            )
            .is_err()
        );
    }
    let unsupported = key(104, Algorithm::Secp256k1);
    assert!(
        derive(
            &fixture.block.encode_wire().unwrap(),
            &json_line(&fixture.manifest).unwrap(),
            &line(fixture.network()),
            &line(fixture.genesis.public_key()),
            &line(unsupported.public_key()),
            &fixture.nexus_context,
        )
        .unwrap_err()
        .to_string()
        .contains("must use Ed25519")
    );
    assert!(canonical_public_key(b"not-a-key\n").is_err());
    assert!(canonical_line(&vec![b'a'; 1025]).is_err());
}

#[cfg(unix)]
#[test]
fn publishes_complete_public_bundle_and_reuses_identical_request() {
    let temp = private_custody_test_dir("taira-public-inputs-publish-");
    let root = temp.path();
    let fixture = Fixture::seated();
    let args = fixture.write(root);
    let original = fs::read(args.localnet_dir.join("genesis.signed.nrt")).unwrap();
    let mut first = Vec::new();
    prepare(&args, &mut first).unwrap();
    let before = fs::metadata(args.output_dir.join("public-inputs.json"))
        .unwrap()
        .ino();
    let mut second = Vec::new();
    prepare(&args, &mut second).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        before,
        fs::metadata(args.output_dir.join("public-inputs.json"))
            .unwrap()
            .ino()
    );
    assert_eq!(load(&args.output_dir).unwrap(), fixture.derive().unwrap());
    assert_eq!(
        fs::read(args.localnet_dir.join("genesis.signed.nrt")).unwrap(),
        original
    );
    for name in OUTPUT_FILES {
        assert_eq!(
            fs::metadata(args.output_dir.join(name)).unwrap().mode() & 0o7777,
            0o644
        );
    }
}

#[cfg(unix)]
#[test]
fn refuses_changed_bundle_and_never_overwrites_existing_output() {
    let temp = private_custody_test_dir("taira-public-inputs-refusal-");
    let args = Fixture::seated().write(temp.path());
    prepare(&args, &mut Vec::new()).unwrap();
    let original = fs::read(args.output_dir.join("public-inputs.json")).unwrap();
    fs::write(
        args.canary_public_key.as_ref().unwrap(),
        line(key(103, Algorithm::Ed25519).public_key()),
    )
    .unwrap();
    let error = prepare(&args, &mut Vec::new()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "output already contains a different public input bundle"
    );
    assert_eq!(
        fs::read(args.output_dir.join("public-inputs.json")).unwrap(),
        original
    );
    fs::write(args.output_dir.join("genesis.hash"), b"wrong\n").unwrap();
    let error = load(&args.output_dir).unwrap_err();
    assert_eq!(
        error.to_string(),
        "public input bundle artifact differs from its identity"
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlink_input_and_partial_or_surplus_output() {
    let temp = private_custody_test_dir("taira-public-inputs-invalid-");
    let args = Fixture::seated().write(temp.path());
    let key = fs::read(args.canary_public_key.as_ref().unwrap()).unwrap();
    fs::remove_file(args.canary_public_key.as_ref().unwrap()).unwrap();
    std::os::unix::fs::symlink(
        args.localnet_dir.join("genesis.public_key"),
        args.canary_public_key.as_ref().unwrap(),
    )
    .unwrap();
    let error = prepare(&args, &mut Vec::new()).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "public reset input must be a direct regular file: `{}`",
            args.canary_public_key.as_ref().unwrap().display()
        )
    );
    assert!(!args.output_dir.exists());
    fs::remove_file(args.canary_public_key.as_ref().unwrap()).unwrap();
    fs::write(args.canary_public_key.as_ref().unwrap(), key).unwrap();
    prepare(&args, &mut Vec::new()).unwrap();
    fs::write(args.output_dir.join("unexpected"), b"extra").unwrap();
    let error = load(&args.output_dir).unwrap_err();
    assert_eq!(
        error.to_string(),
        "public input bundle has missing or unexpected files"
    );
    fs::remove_file(args.output_dir.join("unexpected")).unwrap();
    fs::remove_file(args.output_dir.join("genesis.hash")).unwrap();
    let error = load(&args.output_dir).unwrap_err();
    assert_eq!(
        error.to_string(),
        "public input bundle has missing or unexpected files"
    );
}

#[test]
fn cli_public_input_preparation_never_accepts_private_credentials() {
    use clap::Parser as _;
    let args = [
        "iroha",
        "taira",
        "public-reset",
        "prepare-public-inputs",
        "--localnet-dir",
        "/localnet",
        "--canary-public-key",
        "/canary.pub",
        "--output-dir",
        "/output",
    ];
    assert!(crate::Args::try_parse_from(args).is_ok());
    let draft_args = [
        "iroha",
        "taira",
        "public-reset",
        "prepare-public-inputs",
        "--localnet-dir",
        "/localnet",
        "--intent",
        "/unsigned.json",
        "--output-dir",
        "/output",
    ];
    assert!(crate::Args::try_parse_from(draft_args).is_ok());
    let mut both = draft_args.to_vec();
    both.extend(["--canary-public-key", "/canary.pub"]);
    assert!(crate::Args::try_parse_from(both).is_err());
    assert!(
        crate::Args::try_parse_from([
            "iroha",
            "taira",
            "public-reset",
            "prepare-beacon-inputs",
            "--intent",
            "/unsigned.json",
            "--public-inputs",
            "/public-inputs",
            "--output",
            "/beacon-inputs.json"
        ])
        .is_ok()
    );
    let mut private = args.to_vec();
    private.extend(["--private-key", "forbidden"]);
    assert!(crate::Args::try_parse_from(private).is_err());
}

#[test]
fn beacon_bootstrap_window_reserves_real_current_canary_and_install() {
    // Each case executes and signs its own real genesis; changing only a raw
    // manifest would fail authentication before reaching the production guard.
    for epoch in [6, 7, 12] {
        let _profile = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let fixture = Fixture::build_with_epoch(epoch);
        let mut inventory = sample_inventory_fixture();
        let roster =
            iroha_core::sumeragi::startup::genesis_committee_peers(&fixture.block).unwrap();
        for (client, peer) in inventory.validator_clients.iter_mut().zip(roster) {
            client.peer_id = peer.to_string();
        }
        let result = host::beacon::prepare_public_beacon_inputs(
            &fixture.block.encode_wire().unwrap(),
            &json_line(&fixture.manifest).unwrap(),
            fixture.genesis.public_key(),
            fixture.block.hash(),
            &inventory.authorization_nonce,
            &inventory.validators,
            &inventory.validator_clients,
        );
        if epoch == 6 {
            let error = result.expect_err("pulse 5 leaves no preceding installation carrier");
            assert!(format!("{error:#}").contains("first mandatory beacon pulse after height 5"));
        } else {
            result.expect("the native signed epoch permits installation before the pulse");
        }
    }
}

#[test]
fn beacon_public_preparation_derives_native_network_bound_seats_and_rejects_substitution() {
    let fixture = Fixture::new();
    let wire = fixture.block.encode_wire().unwrap();
    let manifest = json_line(&fixture.manifest).unwrap();
    let mut inventory = sample_inventory_fixture();
    let mut ordered =
        iroha_core::sumeragi::startup::genesis_committee_peers(&fixture.block).unwrap();
    ordered.reverse(); // Role order must not be mistaken for native signing order.
    for (client, peer) in inventory.validator_clients.iter_mut().zip(&ordered) {
        client.peer_id = peer.to_string();
    }
    let prepare = |nonce: &str, clients: &[ValidatorClientV1], raw: &[u8]| {
        host::beacon::prepare_public_beacon_inputs(
            &wire,
            raw,
            fixture.genesis.public_key(),
            fixture.block.hash(),
            nonce,
            &inventory.validators,
            clients,
        )
    };
    let first = prepare(
        &inventory.authorization_nonce,
        &inventory.validator_clients,
        &manifest,
    )
    .unwrap();
    let value = json::to_value(&first).unwrap();
    assert_eq!(
        json::to_value(
            &prepare(
                &inventory.authorization_nonce,
                &inventory.validator_clients,
                &manifest
            )
            .unwrap()
        )
        .unwrap(),
        value
    );
    let units = value.get("final_units").unwrap().as_array().unwrap();
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(fixture.block.hash());
    let network_root = hex::encode(network_id.as_bytes());
    let attempt = hex::encode(<[u8; 32]>::from(iroha_crypto::Hash::new_from_chunks(&[
        b"iroha.global-beacon.genesis-attempt.v1\0",
        network_id.as_bytes(),
    ])));
    let roster = iroha_core::sumeragi::startup::genesis_committee_peers(&fixture.block).unwrap();
    for (index, unit) in units.iter().enumerate() {
        let seat = roster
            .iter()
            .position(|peer| peer == &ordered[index])
            .unwrap()
            + 1;
        assert_eq!(
            unit.get("signer_index").unwrap().as_u64(),
            Some(seat as u64)
        );
        assert_eq!(
            unit.get("validator").unwrap().as_str(),
            Some(inventory.validators[index].slug.as_str())
        );
        assert_eq!(
            unit.get("config_file").unwrap().as_str(),
            Some("beacon.toml")
        );
        let expected = format!(
            "/var/lib/taira/.public-reset-control-v1/beacon/{network_root}/ceremony/attempt-{attempt}-seat-{seat}/iroha-global-beacon-partial-signer-v1.norito"
        );
        assert_eq!(
            unit.get("credential_path").unwrap().as_str(),
            Some(expected.as_str())
        );
    }
    let other_nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_eq!(other_nonce.len(), 32);
    validate_nonce(other_nonce).expect("valid independent fixture nonce");
    assert_ne!(other_nonce, inventory.authorization_nonce.as_str());
    let other =
        json::to_value(&prepare(other_nonce, &inventory.validator_clients, &manifest).unwrap())
            .unwrap();
    assert_eq!(value.get("request"), other.get("request"));
    assert_eq!(value.get("final_units"), other.get("final_units"));
    assert_ne!(
        value.get("authorization_nonce"),
        other.get("authorization_nonce")
    );
    let mut wrong = inventory.validator_clients.clone();
    wrong[0].peer_id = wrong[1].peer_id.clone();
    assert!(prepare(&inventory.authorization_nonce, &wrong, &manifest).is_err());
    let invalid = fixture
        .manifest
        .clone()
        .with_consensus_mode(SumeragiConsensusMode::Permissioned);
    assert!(
        invalid
            .clone()
            .with_consensus_meta()
            .unwrap_err()
            .to_string()
            .contains("permissioned genesis must omit `sumeragi_npos_parameters`")
    );
    assert!(
        prepare(
            &inventory.authorization_nonce,
            &inventory.validator_clients,
            &json_line(&invalid).unwrap()
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn public_bundle_requires_authenticated_raw_manifest_without_four_file_fallback() {
    let directory = private_custody_test_dir("public-manifest-");
    let fixture = Fixture::seated();
    let args = fixture.write(directory.path());
    prepare(&args, &mut Vec::new()).unwrap();
    let raw = fs::read(args.output_dir.join("genesis.json")).unwrap();
    assert_eq!(
        load(&args.output_dir).unwrap().raw_manifest_sha256,
        sha256_hex(&raw)
    );
    fs::remove_file(args.output_dir.join("genesis.json")).unwrap();
    assert!(load(&args.output_dir).is_err());
    fs::write(args.output_dir.join("genesis.json"), &raw).unwrap();
    fs::set_permissions(
        args.output_dir.join("genesis.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(load(&args.output_dir).is_ok());
    let mut changed = raw.clone();
    changed.push(b' ');
    fs::write(args.output_dir.join("genesis.json"), changed).unwrap();
    assert!(
        load(&args.output_dir).is_err(),
        "semantically identical but unbound manifest bytes are rejected"
    );
    fs::write(args.output_dir.join("genesis.json"), raw).unwrap();
    let invalid = fixture
        .manifest
        .clone()
        .with_consensus_mode(SumeragiConsensusMode::Permissioned);
    assert!(
        invalid
            .clone()
            .with_consensus_meta()
            .unwrap_err()
            .to_string()
            .contains("permissioned genesis must omit `sumeragi_npos_parameters`")
    );
    fs::write(
        args.localnet_dir.join("genesis.json"),
        json_line(&invalid).unwrap(),
    )
    .unwrap();
    assert!(
        prepare(&args, &mut Vec::new()).is_err(),
        "another manifest cannot replace an authenticated bundle"
    );
}

#[cfg(unix)]
#[test]
fn public_bundle_derives_canary_from_topology_intent_without_key_file() {
    let _chain_guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
    let directory = private_custody_test_dir("public-draft-canary-");
    let fixture = Fixture::seated();
    let mut args = fixture.write(directory.path());
    let mut inventory = sample_inventory_fixture();
    inventory.canary_onboarding_request = fixture.derive().unwrap().canary_onboarding_request;
    let mut value = json::to_value(&inputs::ResetTopologyIntentV1::from(&inventory)).unwrap();
    let draft = directory.path().join("intent.json");
    inputs::write_new_private(&draft, &json_line(&value).unwrap()).unwrap();
    let key_path = args.canary_public_key.take().unwrap();
    fs::remove_file(key_path).unwrap();
    args.intent = Some(draft.clone());
    prepare(&args, &mut Vec::new()).unwrap();
    assert_eq!(
        load(&args.output_dir).unwrap().canary_public_key,
        *fixture.canary.public_key()
    );
    value.as_object_mut().unwrap().insert(
        "beacon_bootstrap".into(),
        json::to_value(&inventory.beacon_bootstrap).unwrap(),
    );
    fs::write(draft, json_line(&value).unwrap()).unwrap();
    assert!(prepare(&args, &mut Vec::new()).is_err());
}

#[cfg(unix)]
#[test]
fn public_bundle_refuses_a_network_that_cannot_seat_the_parliament() {
    // A genesis without citizens cannot seat any body.
    let directory = private_custody_test_dir("public-unseated-genesis-");
    let args = Fixture::build_with_epoch(20).write(directory.path());
    let error = prepare(&args, &mut Vec::new()).unwrap_err();
    assert!(
        format!("{error:#}").contains("citizens_cover_bodies"),
        "{error:#}"
    );
    assert!(!args.output_dir.exists());

    // Seated citizens under a validator profile that keeps the default bodies and faucet.
    let directory = private_custody_test_dir("public-unseated-profile-");
    let args = Fixture::seated().write(directory.path());
    fs::write(
        args.localnet_dir.join("peer0.toml"),
        "[torii.faucet]\nenabled = true\namount = \"25000\"\n",
    )
    .unwrap();
    let error = format!("{:#}", prepare(&args, &mut Vec::new()).unwrap_err());
    for requirement in [
        "citizens_cover_bodies",
        "coordination_council_explicit",
        "adaptive_faucet_difficulty",
        "citizenship_escrow_is_custodial",
    ] {
        assert!(error.contains(requirement), "{requirement}: {error}");
    }
    assert!(!args.output_dir.exists());

    // A seated profile whose escrow is the published default governance account is refused:
    // anyone holding that key could drain every bond.
    let mut published: toml::Table =
        toml::from_str(&crate::taira::parliament_seating::canonical_seating_config_toml()).unwrap();
    crate::taira::parliament_seating::set_citizenship_escrow(
        &mut published,
        &iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
    )
    .unwrap();
    fs::write(
        args.localnet_dir.join("peer0.toml"),
        toml::to_string(&published).unwrap(),
    )
    .unwrap();
    let error = format!("{:#}", prepare(&args, &mut Vec::new()).unwrap_err());
    assert!(error.contains("citizenship_escrow_is_custodial"), "{error}");
    assert!(!error.contains("citizens_cover_bodies"), "{error}");
    assert!(!args.output_dir.exists());

    // Validators that disagree on the consensus seating profile are refused.
    let mut disagreeing = crate::taira::parliament_seating::canonical_seating_config_toml();
    disagreeing = disagreeing.replace("policy_jury_size = 9", "policy_jury_size = 7");
    fs::write(
        args.localnet_dir.join("peer0.toml"),
        crate::taira::parliament_seating::canonical_seating_config_toml(),
    )
    .unwrap();
    fs::write(args.localnet_dir.join("peer1.toml"), disagreeing).unwrap();
    let error = format!("{:#}", prepare(&args, &mut Vec::new()).unwrap_err());
    assert!(error.contains("does not share"), "{error}");
    fs::remove_file(args.localnet_dir.join("peer1.toml")).unwrap();
    prepare(&args, &mut Vec::new()).unwrap();
}
