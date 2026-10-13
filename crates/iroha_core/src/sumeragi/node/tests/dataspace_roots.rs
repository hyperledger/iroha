//! Genuine independent private roots use their own State, storage, queues and native custody.

use super::*;
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope},
    block::consensus::{PrivateRootFeePolicy, SumeragiRootScope},
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    transaction::{FeeChargeKind, FeeChargeLimit},
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use mv::storage::StorageReadOnly as _;

struct DataspaceChain {
    chain: Chain,
    manifest: iroha_genesis::RawGenesisTransaction,
    nexus: iroha_config::parameters::actual::Nexus,
    pipeline: iroha_config::parameters::actual::Pipeline,
    signed_frame: Arc<parking_lot::Mutex<Option<(CoreKey, Frame)>>>,
    scope: SumeragiRootScope,
    fee_asset: AssetDefinitionId,
}

struct CapturingNet {
    net: MemNet,
    signed_frame: Arc<parking_lot::Mutex<Option<(CoreKey, Frame)>>>,
}

impl Net for CapturingNet {
    fn send(&self, to: &CoreKey, frame: &Frame) -> SendOutcome {
        let mut saved = self.signed_frame.lock();
        if saved.is_none()
            && matches!(
                iroha_sumeragi::message::WireMessage::decode(&frame.bytes, frame.bytes.len()),
                Ok(iroha_sumeragi::message::WireMessage::Vote(_))
            )
        {
            *saved = Some((self.net.from.clone(), frame.clone()));
        }
        drop(saved);
        self.net.send(to, frame)
    }
}

fn work_instruction(text: &str) -> InstructionBox {
    Log::new(Level::INFO, text.into()).into()
}

fn work_fee(text: &str) -> u64 {
    let gas = crate::gas::meter_instruction(&work_instruction(text), &crate::gas::DEFAULT_ZK_GAS)
        .expect("gas quote must complete for this fixture");
    assert!(gas > 0, "paid progress requires a positive metered charge");
    // The immutable signed policy burns a positive base charge plus metered gas.
    gas.checked_add(1).unwrap()
}

fn bootstrap_world() -> World {
    let account = SAMPLE_GENESIS_ACCOUNT_ID.clone();
    World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
        [Account::new(account.clone()).build(&account)],
        [],
    )
}

#[path = "dataspace_roots/amx_scope_tests.rs"]
mod amx_scope_tests;
#[path = "dataspace_roots/scope_refusal_tests.rs"]
mod scope_refusal_tests;

impl DataspaceChain {
    fn new(parent: NetworkId, id: DataSpaceId) -> Self {
        Self::with_genesis_instructions(parent, id, Vec::new())
            .expect("original signed private genesis and its physical scope policies")
    }

    fn with_genesis_instructions(
        parent: NetworkId,
        id: DataSpaceId,
        instructions: Vec<InstructionBox>,
    ) -> Result<Self, super::super::super::test_chain::StartFailure> {
        iroha_genesis::init_instruction_registry();
        let chain_id = ChainId::from("independent-private-root");
        // Reusing validator keys across the two roots deliberately makes exact instance
        // separation, rather than different signing keys, carry the isolation assertion.
        let mut keys = (0..4)
            .map(|i| KeyPair::from_seed(vec![0xC0 + i; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let entries = keys
            .iter()
            .map(|key| {
                GenesisTopologyEntry::new(
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let owning_domain = DomainId::try_new("fees", "private-root").unwrap();
        // Permissioned roots use the canonical currency identity. NPoS currency
        // parameters are forbidden here; independent scoped balances carry ownership.
        let fee_asset = AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .unwrap();
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent,
            dataspace_id: id,
        };
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.lane_catalog = LaneCatalog::new(
            1_u32.try_into().unwrap(),
            vec![LaneConfig {
                dataspace_id: id,
                alias: "private-root".into(),
                ..LaneConfig::default()
            }],
        )
        .unwrap();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id,
            alias: "private-root".into(),
            description: None,
            fault_tolerance: 1,
        }])
        .unwrap();
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        nexus.routing_policy.default_dataspace = id;
        nexus.fees.fee_asset_id = fee_asset.canonical_address();
        nexus.fees.fee_sink_account_id = SAMPLE_GENESIS_ACCOUNT_ID.to_string();
        // Global Nexus burns are separate from the root's explicitly scoped gas payment.
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        let pipeline = iroha_config::parameters::actual::Pipeline::default();
        let gas = iroha_config::parameters::actual::Gas {
            tech_account_id: SAMPLE_GENESIS_ACCOUNT_ID.to_string(),
            accepted_assets: vec![fee_asset.canonical_address()],
            units_per_gas: vec![iroha_config::parameters::actual::GasRate {
                asset: fee_asset.canonical_address(),
                units_per_gas: 1,
                twap_local_per_xor: iroha_primitives::numeric::Numeric::one(),
                liquidity: iroha_config::parameters::actual::GasLiquidity::Tier2,
                volatility: iroha_config::parameters::actual::GasVolatility::Stable,
            }],
        };
        let mut context = SumeragiGenesisContextParameters::recommended();
        context.root_scope = scope;
        let builder = GenesisBuilder::new_without_executor(chain_id.clone(), ".")
            .append_parameter(Parameter::Custom(
                PrivateRootFeePolicy {
                    asset_definition_id: fee_asset.clone(),
                    base_fee: 1_u32.into(),
                    per_byte_fee: Quantity::zero(),
                    per_instruction_fee: Quantity::zero(),
                    per_gas_unit_fee: 1_u32.into(),
                }
                .into_custom_parameter()
                .unwrap(),
            ))
            .append_parameter(Parameter::Sumeragi(
                SumeragiParameter::PayloadRetryIntervalMs(200_u64.try_into().unwrap()),
            ))
            .append_instruction(Register::account(Account::new(ALICE_ID.clone())))
            .append_instruction(Register::domain(Domain::new(owning_domain.clone())))
            .append_instruction(Register::asset_definition(AssetDefinition::numeric(
                fee_asset.clone(),
                "private fee",
                AssetBalancePolicy::DataspaceRestricted,
                Some(owning_domain),
            )))
            .append_instruction(Mint::asset_quantity(
                10_000_u32,
                AssetId::with_scope(
                    fee_asset.clone(),
                    ALICE_ID.clone(),
                    AssetBalanceScope::Dataspace(id),
                ),
            ))
            .with_block_cadence_ms(100_u64.try_into().unwrap())
            .set_topology(entries)
            .with_sumeragi_context_parameters(context);
        let builder = crate::pipeline_gas_policy::parameters_for_testing(gas)
            .into_iter()
            .fold(builder, GenesisBuilder::append_parameter);
        let manifest = instructions
            .into_iter()
            .fold(builder, GenesisBuilder::append_instruction)
            .build_raw()
            .unwrap()
            .with_consensus_meta()
            .expect("valid private-root fixture consensus parameters");
        let genesis = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
                None,
                Some(crate::state::default_genesis_confidential_policy_hash()),
                1_000,
            )
            .unwrap()
            .0;
        let custody = keys
            .iter()
            .map(|key| {
                (
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let (genesis, manifest, _, _) =
            super::super::super::test_chain::prepare_configured_genesis(
                bootstrap_world(),
                &chain_id,
                &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
                &custody,
                genesis,
                manifest,
                iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned,
                1_000,
                &pipeline,
                &iroha_config::parameters::actual::FraudMonitoring::default(),
                Some(&nexus),
                None,
                None,
                None,
                None,
            )?;
        Ok(Self {
            chain: Chain {
                genesis,
                keys,
                chain_id,
            },
            manifest,
            nexus,
            pipeline,
            signed_frame: Arc::default(),
            scope,
            fee_asset,
        })
    }

    fn state(&self, previous: Option<&Arc<Kura>>) -> (Arc<State>, Arc<Kura>) {
        let network = NetworkId::from_genesis_hash(self.chain.genesis.hash());
        let (mut state, kura) = match previous {
            None => State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
                bootstrap_world(),
                self.nexus.clone(),
                LiveQueryStore::start_test(),
                self.chain.chain_id.clone(),
                network,
            ),
            Some(kura) => {
                let mut world = bootstrap_world();
                crate::sns::try_seed_default_namespace_policies(
                    &mut world,
                    &self.nexus.fees.fee_asset_id,
                )
                .unwrap();
                let mut state = State::new_with_chain_and_network_id_for_testing(
                    world,
                    Arc::clone(kura),
                    LiveQueryStore::start_test(),
                    self.chain.chain_id.clone(),
                    network,
                );
                state
                    .prepare_configured_primary_geometry_anchor(&self.nexus.configured_lane_catalog)
                    .unwrap();
                state
                    .restore_kura_lane_segments_before_startup_replay()
                    .unwrap();
                (state, Arc::clone(kura))
            }
        };
        state.set_nexus_from_config(self.nexus.clone()).unwrap();
        state.set_pipeline(self.pipeline.clone());
        state.install_lane_manifests_for_testing(&Arc::new(
            LaneManifestRegistry::empty().rebind(&self.nexus.lane_catalog, &self.nexus.governance),
        ));
        (Arc::new(state), kura)
    }

    fn start(&self, previous: Option<&[Disk]>) -> (Vec<Validator>, Option<Vec<Disk>>) {
        let registry = Arc::new(Registry::default());
        let mut fresh_disks = Vec::new();
        let mut validators = Vec::new();
        for (index, key) in self.chain.keys.iter().enumerate() {
            let (state, kura) = self.state(previous.map(|disks| &disks[index].kura));
            let fresh = previous.is_none().then(|| Disk {
                kura,
                dir: tempfile::tempdir().unwrap(),
            });
            let disk = previous.map_or_else(|| fresh.as_ref().unwrap(), |disks| &disks[index]);
            let (_, time_source) = TimeSource::new_mock(Duration::ZERO);
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time_source,
            ));
            let node = start(NodeInputs {
                state: Arc::clone(&state),
                queue: Arc::clone(&queue),
                events: tokio::sync::broadcast::channel(1024).0,
                net: Arc::new(CapturingNet {
                    net: MemNet {
                        from: core_key(key.public_key()).unwrap(),
                        registry: Arc::clone(&registry),
                    },
                    signed_frame: Arc::clone(&self.signed_frame),
                }),
                key_pair: key.clone(),
                beacon_signer: None,
                genesis: Some(self.chain.genesis.clone()),
                genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                consensus_mode: ConsensusMode::Permissioned,
                config: NodeConfig {
                    records_dir: disk.dir.path().join("records"),
                    installation_log: disk.dir.path().join("keys/installation.log"),
                    bodies_dir: disk.dir.path().join("bodies"),
                    local: SumeragiLocalOverrides::default(),
                    assert_fresh_key: previous.is_none(),
                    retired_keys: Vec::new(),
                },
                observer: Arc::new(PrintObserver(index)),
                driver: DriverConfig::default(),
            })
            .expect("start independent private root with its original stores and authority");
            assert_eq!(
                node.instance,
                root_instance(&self.chain.genesis, self.chain.chain_id.as_ref()).unwrap()
            );
            assert!(node.handle().startup_recovery().is_ready());
            assert_eq!(
                super::super::super::lanes::routing::committed_root_scope(&state.view().world),
                Some(self.scope)
            );
            validators.push(Validator { node, state, queue });
            if let Some(fresh) = fresh {
                fresh_disks.push(fresh);
            }
        }
        for (key, validator) in self.chain.keys.iter().zip(&validators) {
            registry.0.lock().insert(
                core_key(key.public_key()).unwrap(),
                Arc::clone(&validator.node.ingress),
            );
        }
        (validators, previous.is_none().then_some(fresh_disks))
    }

    fn signed_work(&self, text: &str) -> SignedTransaction {
        let network = NetworkId::from_genesis_hash(self.chain.genesis.hash());
        TransactionBuilder::new(
            network,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    self.fee_asset.clone(),
                    work_fee(text).into(),
                )],
                None,
            ),
        )
        .with_instructions([work_instruction(text)])
        .sign(ALICE_KEYPAIR.private_key())
    }

    fn submit(&self, validators: &[Validator], text: &str) -> (HashOf<TransactionEntrypoint>, u64) {
        let network = NetworkId::from_genesis_hash(self.chain.genesis.hash());
        let tx = self.signed_work(text);
        let accepted = AcceptedTransaction::accept(
            tx,
            &network,
            Duration::from_secs(10),
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
        )
        .unwrap();
        let hash = accepted.hash_as_entrypoint();
        for validator in validators {
            validator
                .queue
                .push(accepted.clone(), validator.state.view())
                .unwrap_or_else(|failure| panic!("paid local root route: {:?}", failure.err));
            validator.node.handle().transactions_available();
        }
        wait_until(
            validators,
            Duration::from_secs(60),
            "private paid work",
            || committed_everywhere(validators, hash),
        );
        for validator in validators {
            let height = validator.state.view().height();
            let stored = validator
                .state
                .kura()
                .get_block(
                    height.try_into().unwrap(),
                    &validator.state.ivm_execution_budget(),
                )
                .expect("original block read attempt")
                .unwrap();
            assert_eq!(stored.network_entrypoint_count(), 1);
            assert!(
                stored
                    .execution_outputs()
                    .iter()
                    .all(|output| output.result().is_ok()),
                "paid private work must execute successfully, not just finalize a rejection"
            );
        }
        (hash, work_fee(text))
    }

    fn balances(&self, validators: &[Validator], paid: u64) {
        let scope = AssetBalanceScope::Dataspace(self.scope.dataspace_id());
        for validator in validators {
            let view = validator.state.view();
            let balance = |account| {
                view.world()
                    .assets()
                    .get(&AssetId::with_scope(self.fee_asset.clone(), account, scope))
                    .map_or_else(Quantity::zero, |value| value.as_ref().clone())
            };
            assert_eq!(balance(ALICE_ID.clone()), Quantity::from(10_000 - paid));
            assert_eq!(balance(SAMPLE_GENESIS_ACCOUNT_ID.clone()), Quantity::zero());
            assert_eq!(
                view.world()
                    .asset_definition(&self.fee_asset)
                    .unwrap()
                    .total_quantity(),
                &Quantity::from(10_000 - paid),
                "private fees burn only the exact root's currency supply"
            );
        }
    }
}

#[test]
fn independent_dataspace_roots_pay_and_restart_without_sharing_state_or_storage() {
    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let first = DataspaceChain::new(parent, DataSpaceId::new((1_u64 << 40) + 17));
    let second = DataspaceChain::new(parent, DataSpaceId::new((1_u64 << 40) + 18));
    let (a, a_disks) = first.start(None);
    let (b, b_disks) = second.start(None);
    let a_disks = a_disks.unwrap();
    let b_disks = b_disks.unwrap();
    assert_ne!(a[0].node.instance, b[0].node.instance);
    for x in &a {
        for y in &b {
            assert!(!Arc::ptr_eq(&x.state, &y.state));
            assert!(
                !x.state
                    .ivm_execution_budget()
                    .same_pool(&y.state.ivm_execution_budget())
            );
            assert_ne!(x.state.kura().store_root(), y.state.kura().store_root());
            assert!(!Arc::ptr_eq(&x.queue, &y.queue));
        }
    }
    first.balances(&a, 0);
    second.balances(&b, 0);
    let foreign = first.signed_work("foreign root must not accept this valid carrier");
    let accept = |network| {
        AcceptedTransaction::accept(
            foreign.clone(),
            &network,
            Duration::from_secs(10),
            TransactionParameters::default(),
            &iroha_config::parameters::actual::Crypto::default(),
        )
    };
    assert!(accept(NetworkId::from_genesis_hash(first.chain.genesis.hash())).is_ok());
    assert!(accept(NetworkId::from_genesis_hash(second.chain.genesis.hash())).is_err());
    assert!(b.iter().all(|validator| validator.queue.queued_len() == 0));
    let (a_work, a_fee) = first.submit(&a, "only A pays first");
    let (sender, original_frame) = first
        .signed_frame
        .lock()
        .clone()
        .expect("actual signed vote");
    for validator in &b {
        assert_eq!(
            validator.node.ingress.deliver(&sender, &original_frame),
            super::super::super::net::Routed::UnknownInstance,
        );
        let mut substituted_envelope = original_frame.clone();
        substituted_envelope.instance = validator.node.instance;
        assert_eq!(
            validator
                .node
                .ingress
                .deliver(&sender, &substituted_envelope),
            super::super::super::net::Routed::Refused,
            "changing only the transport label cannot rebind the signed message",
        );
    }
    first.balances(&a, a_fee);
    second.balances(&b, 0);
    assert_eq!(committed_heights(&b), vec![1; 4]);
    assert!(b.iter().all(|v| !v.state.has_committed_entrypoint(a_work)));
    let a_roots = world_state_roots(&a);
    let stopped_private_state = Arc::clone(&a[0].state);
    shutdown(a);
    {
        // Even a genuinely paid, quorum-certified private receipt is not Global SCCP
        // authority. Observe the original pool after node workers stop, so unrelated
        // publication cleanup cannot race the refusal/refund assertion.
        use crate::smartcontracts::isi::sccp::read::native::{
            SccpNativeReadControl, SccpNativeReadError, finality,
        };
        use crate::sumeragi::certified_chain::{CertifiedChain, QcVerification};
        let view = stopped_private_state.view();
        let reader = CertifiedChain::new(&view).unwrap();
        let original = reader.certified(2).unwrap();
        assert_eq!(original.verification(), QcVerification::Verified);
        assert_eq!(original.root_scope(), first.scope);
        let budget = stopped_private_state.ivm_execution_budget();
        let occupied = budget.reserved_bytes();
        let stop = std::sync::atomic::AtomicBool::new(false);
        assert!(matches!(
            finality(
                &view,
                std::num::NonZeroU64::new(2),
                &budget,
                SccpNativeReadControl {
                    deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
                    stop: &stop,
                },
            ),
            Err(SccpNativeReadError::UnsupportedScope)
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
    }
    drop(stopped_private_state);
    let (_, b_fee) = second.submit(&b, "B advances while A is stopped");
    second.balances(&b, b_fee);
    let inspection_budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let stored = |disks: &[Disk], height: usize| {
        disks[0]
            .kura
            .get_block(height.try_into().unwrap(), &inspection_budget)
            .expect("original block read attempt")
            .unwrap()
    };
    let mut prefix = super::super::super::certified_chain::CertifiedPrefix::new(
        &first.chain.chain_id,
        NetworkId::from_genesis_hash(first.chain.genesis.hash()),
        stored(&a_disks, 1),
    )
    .unwrap();
    assert!(
        prefix.push(stored(&b_disks, 2)).is_err(),
        "a different root's actual CommitQC and signed availability are not original ancestry"
    );
    prefix
        .push(stored(&a_disks, 2))
        .expect("rejected foreign frame never advances original prefix");
    let (a, _) = first.start(Some(&a_disks));
    assert_eq!(world_state_roots(&a), a_roots);
    first.balances(&a, a_fee);
    let (_, restart_fee) = first.submit(&a, "A pays after exact certified restart");
    first.balances(&a, a_fee + restart_fee);
    second.balances(&b, b_fee);
    assert_eq!(committed_heights(&a), vec![3; 4]);
    assert_eq!(committed_heights(&b), vec![2; 4]);
    shutdown(a);
    shutdown(b);
    assert_same_certified_blocks(&a_disks, 3);
    assert_same_certified_blocks(&b_disks, 2);
    for disk in a_disks.iter().chain(&b_disks) {
        assert!(disk.kura.store_root().join("native-contexts").is_dir());
        assert!(disk.dir.path().join("records").is_dir());
        assert!(disk.dir.path().join("bodies").is_dir());
    }
}

#[test]
fn preaccepted_foreign_input_reaches_private_executor_but_cannot_publish_or_spend() {
    use super::super::super::{
        payload::{self, Assembly},
        test_chain::{CertifiedTestChain, PreparedTestChainConfig, Signers},
    };

    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let foreign_root = DataspaceChain::new(parent, DataSpaceId::new((1_u64 << 40) + 31));
    let local_root = DataspaceChain::new(parent, DataSpaceId::new((1_u64 << 40) + 32));
    let (state, kura) = local_root.state(None);
    let original = iroha_genesis::validate_prepared_genesis_bundle(
        &local_root.chain.genesis.encode_wire().unwrap(),
        &local_root.manifest,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
        local_root.chain.genesis.hash(),
    )
    .unwrap();
    let mut local = CertifiedTestChain::from_prepared(PreparedTestChainConfig {
        genesis: original,
        manifest: local_root.manifest.clone(),
        state: Arc::clone(&state),
        kura: Arc::clone(&kura),
        validator_keys: local_root.chain.keys.clone(),
        clock: ALICE_KEYPAIR.clone(),
        lane_blocks: Arc::new(super::super::super::lanes::merge::NoLanes),
    })
    .unwrap();
    let foreign_carrier = foreign_root.signed_work("original foreign carrier");
    let rejected = AcceptedTransaction::accept(
        foreign_carrier.clone(),
        state.network_id_ref(),
        Duration::from_secs(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
    );
    let Err(crate::tx::AcceptTransactionFail::TransactionDomainMismatch(mismatch)) = rejected
    else {
        panic!("the same signed carrier must fail the local network domain check");
    };
    assert_eq!(
        mismatch.expected,
        iroha_data_model::transaction::TransactionDomain::Network(*state.network_id_ref())
    );
    assert_eq!(mismatch.actual, *foreign_carrier.domain());
    let foreign = AcceptedTransaction::accept(
        foreign_carrier,
        &NetworkId::from_genesis_hash(foreign_root.chain.genesis.hash()),
        Duration::from_secs(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
    )
    .unwrap();
    let foreign_hash = foreign.hash_as_entrypoint();
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    let queue = Arc::new(Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let refusal = queue
        .push(foreign.clone(), state.view())
        .expect_err("preacceptance in a sibling root cannot authorize local queue custody");
    let crate::queue::Error::TransactionDomainMismatch(mismatch) = refusal.err else {
        panic!("private queue must reject the exact foreign signed domain");
    };
    assert_eq!(mismatch.actual, *foreign.as_ref().domain());
    assert_eq!(
        mismatch.expected,
        iroha_data_model::transaction::TransactionDomain::Network(*state.network_id_ref())
    );
    assert!(
        payload::select(
            &state.view(),
            &queue,
            1024 * 1024,
            &crate::sumeragi::payload::MergeProposal::default(),
            iroha_primitives::time::TimeSource::new_system().now()
        )
        .expect("completed routing read")
        .is_empty()
    );
    assert_eq!(queue.queued_len(), 0);
    // Exercise the independent hostile-proposer boundary even though the queue
    // already refused the original carrier. Native execution still authenticates it.
    let selected = [foreign];
    assert_eq!(selected[0].hash_as_entrypoint(), foreign_hash);
    let parent = state
        .view()
        .latest_block()
        .expect("completed original State parent read")
        .unwrap();
    let proposal = payload::assemble(
        &state,
        Assembly {
            parent: &parent,
            view: 0,
            cadence: Duration::from_millis(100),
            proposed_time: std::time::Duration::ZERO,
        },
        &selected,
    )
    .unwrap();
    let before = state.world.state_accumulator.view().get().root();
    let error = local
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::empty())
        .err()
        .expect("the original local executor revalidates the foreign network");
    assert_eq!(
        error,
        "fixture block 2 does not execute: Some(Invalid); native rejection: Some(TransactionValidationFailed)"
    );
    assert_eq!(state.view().height(), 1);
    assert_eq!(kura.blocks_count(), 1);
    assert_eq!(state.world.state_accumulator.view().get().root(), before);
    assert!(!state.has_committed_entrypoint(foreign_hash));
    // Neither queue rejection nor direct native execution retains the foreign input.
    // Same-domain State/Queue identity affinity remains a separate startup concern.
    assert_eq!(queue.queued_len(), 0);
    let local_tx = local_root.signed_work("valid local work after foreign rejection");
    let local_proposal = local.proposal(None, vec![local_tx]);
    let committed = local.commit_proposal(
        local_proposal,
        Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::empty(),
    );
    assert!(
        committed
            .block()
            .execution_outputs()
            .iter()
            .all(|output| output.result().is_ok())
    );
    assert!(!state.has_committed_entrypoint(foreign_hash));
    assert_eq!(state.view().height(), 2);
    let scope = AssetBalanceScope::Dataspace(local_root.scope.dataspace_id());
    let view = state.view();
    let fee = work_fee("valid local work after foreign rejection");
    for (account, expected) in [
        (ALICE_ID.clone(), 10_000 - fee),
        (SAMPLE_GENESIS_ACCOUNT_ID.clone(), 0),
    ] {
        assert_eq!(
            view.world()
                .assets()
                .get(&AssetId::with_scope(
                    local_root.fee_asset.clone(),
                    account,
                    scope
                ))
                .map_or_else(Quantity::zero, |value| value.as_ref().clone()),
            Quantity::from(expected)
        );
    }
    assert_eq!(
        view.world()
            .asset_definition(&local_root.fee_asset)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_000 - fee),
        "the exact local root burns its paid fee"
    );
}
