//! A certified test chain (test support): a real signed genesis applied by
//! [`startup::apply_genesis`], blocks built by the leader's payload builder, executed, prepared,
//! stored and applied through the node's executor and block store, and every block certified by a
//! `CommitQC` of the exact authenticated four-validator committee with real BLS-normal signatures. The
//! [`certified_chain`](super::certified_chain) reader accepts its blocks as it accepts a running
//! node's.
//!
//! The only shortcut is who produces the certificate: the fixture signs the Commit votes itself
//! (with the committee's keys) instead of running the core's rounds. Block times follow the
//! chain's rule (parent time plus the cadence, after every transaction's creation time): the
//! fixture's cadence is one millisecond, and [`CertifiedTestChain::commit_at`] reaches an exact
//! block time with a `Log` transaction of its own clock account when the block's transactions do
//! not.

#[path = "test_chain/lane_authority.rs"]
mod lane_authority;
/// Independent committed-State authority used by certified lane fixtures.
pub use lane_authority::TestLaneStoreAuthorities;
#[path = "test_chain/availability.rs"]
mod availability;
#[path = "test_chain/committee_custody.rs"]
mod committee_custody;
#[cfg(test)]
mod genesis_policy;
mod local_certificate;
#[cfg(test)]
pub(crate) use genesis_policy::{signed_genesis_fixture_for_state, staged_genesis_policies};

use std::{num::NonZeroU64, sync::Arc, time::Duration};

use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
#[cfg(test)]
use iroha_data_model::parameter::system::ConsensusMode;
use iroha_data_model::{
    IntoKeyValue, NetworkId, Registrable,
    account::{Account, AccountId},
    block::consensus::ValidatorPower,
    block::{SignedBlock, consensus::SumeragiGenesisContextParameters},
    domain::Domain,
    isi::{InstructionBox, Log},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
use iroha_logger::Level;
use iroha_model_base::{chain::ChainId, peer::PeerId};
use iroha_primitives::time::TimeSource;
use iroha_sumeragi::{
    api::ExecOutcome,
    availability::AvailableBody,
    crypto::{AttestOutcome, Attestor as _, Signer as _, form_qc},
    message::{BlockHeader, CommitAttestation, Qc, ResultWitness, Vote, VoteKind},
    preimage::payload_hash,
    types::{Committee, Hash32},
};
use mv::storage::StorageReadOnly;

use super::{
    availability_schedule::AvailabilitySchedule,
    block_store::{KuraBlockStore, Staging},
    certified_chain::{CommittedBlock, committed_block},
    crypto::{BlsCrypto, KeyPairSigner},
    driver::{
        SharedCrypto,
        traits::{BlockStore as _, Executor as _},
    },
    executor::{ExecutorContext, StateExecutor, attestation_required},
    node::root_instance,
    payload::{self, Assembly},
    startup::{self, GENESIS_HEIGHT},
};
use crate::{
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, StateReadOnly, World, WorldReadOnly},
    tx::AcceptedTransaction,
};

/// Seeds of the fixed validator committee (BLS-normal keys).
const VALIDATOR_SEEDS: [u8; 4] = [0xC1, 0xC2, 0xC3, 0xC4];
/// Seed of the fixture's clock account (Ed25519).
const CLOCK_SEED: u8 = 0xCC;

/// Which validators sign a block's `CommitQC`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signers {
    /// A quorum: the first three validators in committee order.
    Quorum,
    /// All four validators: an oversized certificate for negative verification tests.
    All,
    /// Three validators other than the first ones (another valid certificate of the same block).
    LastThree,
    /// Two validators: below the quorum, a certificate that does not verify.
    BelowQuorum,
}

impl Signers {
    fn indices(self) -> &'static [u32] {
        match self {
            Self::Quorum => &[0, 1, 2],
            Self::All => &[0, 1, 2, 3],
            Self::LastThree => &[1, 2, 3],
            Self::BelowQuorum => &[0, 1],
        }
    }
}

/// How the test chain starts.
pub struct TestChainConfig {
    /// The chain id.
    pub chain_id: ChainId,
    /// The initial World (accounts, permissions, owners) genesis is applied to. The fixture adds
    /// the genesis domain, the genesis account and its clock account.
    pub world: World,
    /// The genesis key: its account authorizes every genesis transaction.
    pub genesis_key: KeyPair,
    /// Optional original BLS-normal committee custody, ordered canonically before signing genesis.
    /// The signed genesis validator rules still reject invalid committee sizes or keys.
    pub validator_keys: Option<Vec<KeyPair>>,
    /// Instructions of the genesis's ordinary transaction.
    pub genesis_instructions: Vec<InstructionBox>,
    /// Explicit parameters carried by the authoritative signed genesis snapshot.
    pub genesis_parameters: Vec<Parameter>,
    /// Consensus mode carried by the signed genesis and used for execution.
    pub consensus_mode: SumeragiConsensusMode,
    /// Root ownership bound into the original signed genesis (never a runtime override).
    pub root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    /// Creation time of the first genesis transaction in milliseconds.
    pub genesis_time_ms: u64,
    /// Immutable block cadence included in the original signed genesis manifest.
    pub genesis_block_cadence_ms: NonZeroU64,
    /// Original execution configuration, fixed before signed genesis policies are derived.
    pub pipeline: iroha_config::parameters::actual::Pipeline,
    /// Optional physical/routing and fee configuration installed before deriving signed genesis policies.
    pub nexus: Option<iroha_config::parameters::actual::Nexus>,
    /// Optional proof-verification configuration installed before deriving signed genesis policies.
    pub zk: Option<iroha_config::parameters::actual::Zk>,
    /// Optional governance policy installed before deriving signed genesis execution policies.
    pub governance: Option<iroha_config::parameters::actual::Governance>,
    /// Original lane manifest policy installed before deriving signed genesis execution policies.
    pub lane_manifests: Option<Arc<LaneManifestRegistry>>,
    /// Signature algorithms admitted by the original signed genesis configuration.
    pub crypto: Option<iroha_config::parameters::actual::Crypto>,
    /// Fraud admission configuration fixed before signed genesis execution.
    pub fraud_monitoring: iroha_config::parameters::actual::FraudMonitoring,
    /// The node's committed lane blocks, which the chain's blocks merge.
    pub lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
}

impl core::fmt::Debug for TestChainConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestChainConfig")
            .field("chain_id", &self.chain_id)
            .field("genesis_account", &self.genesis_key.public_key())
            .field("genesis_instructions", &self.genesis_instructions.len())
            .field("genesis_parameters", &self.genesis_parameters.len())
            .field("genesis_time_ms", &self.genesis_time_ms)
            .field("genesis_block_cadence_ms", &self.genesis_block_cadence_ms)
            .finish_non_exhaustive()
    }
}

impl TestChainConfig {
    /// A chain over `world` with a fixed chain id and genesis key, genesis at `genesis_time_ms`.
    #[must_use]
    pub fn new(world: World, genesis_time_ms: u64) -> Self {
        Self {
            chain_id: ChainId::from("sumeragi-certified-test-chain"),
            world,
            genesis_key: KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519),
            validator_keys: None,
            genesis_instructions: Vec::new(),
            genesis_parameters: Vec::new(),
            consensus_mode: SumeragiConsensusMode::Permissioned,
            root_scope: iroha_data_model::block::consensus::SumeragiRootScope::Global,
            genesis_time_ms,
            genesis_block_cadence_ms: NonZeroU64::new(1).expect("nonzero fixture cadence"),
            pipeline: iroha_config::parameters::actual::Pipeline::default(),
            nexus: None,
            zk: None,
            governance: None,
            lane_manifests: None,
            crypto: None,
            fraud_monitoring: iroha_config::parameters::actual::FraudMonitoring::default(),
            lane_blocks: Arc::new(crate::sumeragi::lanes::merge::NoLanes),
        }
    }
}

/// Original prepared genesis and its configured, unapplied State for a genuine test chain.
///
/// The caller supplies custody in the exact signed committee order. This configuration cannot
/// replace the signed epoch, network, consensus mode, or execution result with fixture values.
pub struct PreparedTestChainConfig {
    /// Independently authenticated original signed genesis.
    pub genesis: iroha_genesis::ValidatedGenesisBundle,
    /// Exact manifest used to authenticate the original signed genesis.
    pub manifest: iroha_genesis::RawGenesisTransaction,
    /// Configured State before genesis, including its original lane catalogs and policies.
    pub state: Arc<State>,
    /// The same empty Kura retained by `state`.
    pub kura: Arc<Kura>,
    /// Exact BLS private keys, in signed genesis committee order.
    pub validator_keys: Vec<KeyPair>,
    /// Exact independently provisioned Pasta seeds in that same order.
    pub pasta_seeds: Vec<zeroize::Zeroizing<[u8; 32]>>,
    /// Signing key of an account present after original genesis executes.
    pub clock: KeyPair,
    /// The original source of committed lane blocks.
    pub lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
}

impl core::fmt::Debug for PreparedTestChainConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedTestChainConfig")
            .field("genesis_hash", &self.genesis.expected_hash())
            .field("validators", &self.validator_keys.len())
            .field("clock_account", self.clock.public_key())
            .finish_non_exhaustive()
    }
}

/// The fixed validator committee: peers in canonical order with their proofs of possession.
#[must_use]
pub fn fixture_validators() -> Vec<(PeerId, Vec<u8>)> {
    fixture_keys()
        .iter()
        .map(|key| {
            (
                PeerId::new(key.public_key().clone()),
                bls_normal_pop_prove(key.private_key()).expect("PoP of a fixture key"),
            )
        })
        .collect()
}

fn fixture_keys() -> Vec<KeyPair> {
    let mut keys = VALIDATOR_SEEDS
        .iter()
        .map(|seed| KeyPair::from_seed(vec![*seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    keys
}

/// A chain of certified blocks over one State (see the module documentation).
pub struct CertifiedTestChain {
    state: Arc<State>,
    attestor: super::attestation::NativePastaAttestor,
    kura: Arc<Kura>,
    genesis: SignedBlock,
    validated_genesis: iroha_genesis::ValidatedGenesisBundle,
    genesis_account: AccountId,
    executor: StateExecutor,
    events: tokio::sync::broadcast::Receiver<iroha_data_model::events::EventBox>,
    blocks: KuraBlockStore,
    availability: Arc<dyn AvailabilitySchedule>,
    signers: Vec<KeyPairSigner>,
    validators: Vec<(PeerId, Vec<u8>)>,
    crypto: Arc<BlsCrypto>,
    instance: Hash32,
    /// Height, core block hash and `R` of the tip.
    tip: (u64, Hash32, Hash32),
    clock: KeyPair,
    pasta_seeds: Vec<zeroize::Zeroizing<[u8; 32]>>,
    candidate_pasta_seeds: Vec<(PeerId, zeroize::Zeroizing<[u8; 32]>)>,
    lane_blocks: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
}

impl core::fmt::Debug for CertifiedTestChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CertifiedTestChain")
            .field("instance", &self.instance)
            .field("tip", &self.tip)
            .finish_non_exhaustive()
    }
}

/// Why the test chain could not start.
#[derive(Debug, thiserror::Error)]
pub enum TestChainError {
    /// Original signed source preparation could not complete locally.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// The genesis could not be built.
    #[error("genesis: {0}")]
    Genesis(String),
    /// Original signed genesis execution failed before its commitments could be prepared.
    #[error("original native genesis execution: {0}")]
    OriginalGenesisExecution(#[source] Box<crate::block::BlockValidationError>),
    /// Genesis did not apply (for example, one of its instructions failed).
    #[error(transparent)]
    Startup(#[from] startup::StartupError),
}

/// A chain that did not start, with the State genesis left behind (for inspection).
pub struct StartFailure {
    /// Why the chain did not start.
    pub error: TestChainError,
    /// The State with whatever genesis left unapplied.
    pub state: Arc<State>,
}

impl core::fmt::Debug for StartFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl CertifiedTestChain {
    /// Start a chain: build and sign genesis with the fixed committee, apply it to a fresh
    /// State over a fresh Kura, and spawn the executor.
    ///
    /// # Errors
    /// Genesis cannot be built or does not apply; the State (with whatever genesis left
    /// unapplied) is returned for inspection.
    pub fn start(config: TestChainConfig) -> Result<Self, StartFailure> {
        Self::from_prepared(Self::prepare(config)?)
    }

    /// Construct one original signed genesis and its matching pristine configured State.
    /// This owner can be staged without publication to test real execution/refusal boundaries.
    /// No result, certificate, or poststate is supplied by the fixture caller.
    ///
    /// # Errors
    /// Returns the original State when the signed source cannot be prepared.
    pub fn prepare(config: TestChainConfig) -> Result<PreparedTestChainConfig, StartFailure> {
        iroha_genesis::init_instruction_registry();
        let TestChainConfig {
            chain_id,
            mut world,
            genesis_key,
            validator_keys,
            genesis_instructions,
            genesis_parameters,
            consensus_mode,
            root_scope,
            genesis_time_ms,
            genesis_block_cadence_ms,
            pipeline,
            nexus,
            zk,
            governance,
            lane_manifests,
            crypto,
            fraud_monitoring,
            lane_blocks,
        } = config;
        let genesis_account = AccountId::new(genesis_key.public_key().clone());
        let clock = KeyPair::from_seed(vec![CLOCK_SEED; 32], Algorithm::Ed25519);
        let clock_account = AccountId::new(clock.public_key().clone());
        let domain_id = iroha_genesis::GENESIS_DOMAIN_ID.clone();
        if world.domains.view().get(&domain_id).is_none() {
            let domain = Domain::new(domain_id.clone()).build(&genesis_account);
            world.insert_domain_for_testing(domain_id, domain);
        }
        for account in [&genesis_account, &clock_account] {
            if world.accounts.view().get(account).is_none() {
                let (id, value) = Account::new(account.clone())
                    .build(account)
                    .into_key_value();
                world.accounts.insert(id, value);
            }
        }
        let mut keys = validator_keys.unwrap_or_else(fixture_keys);
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let validators = keys
            .iter()
            .map(|key| {
                (
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key())
                        .expect("fixture committee has checked BLS custody"),
                )
            })
            .collect::<Vec<_>>();
        let (genesis, manifest) = match build_genesis(
            &chain_id,
            &genesis_key,
            &validators,
            genesis_instructions,
            genesis_parameters,
            consensus_mode,
            root_scope,
            genesis_time_ms,
            genesis_block_cadence_ms,
        ) {
            Ok(genesis) => genesis,
            Err(error) => {
                let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
                    world,
                    Kura::blank_kura_for_testing(),
                    LiveQueryStore::start_test(),
                    chain_id,
                    NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::new(b"unbuilt genesis"),
                    )),
                ));
                return Err(StartFailure {
                    error: TestChainError::Genesis(error),
                    state,
                });
            }
        };
        let (genesis, manifest, state, kura) = prepare_configured_genesis(
            world,
            &chain_id,
            &genesis_key,
            &validators,
            genesis,
            manifest,
            consensus_mode,
            genesis_time_ms,
            &pipeline,
            &fraud_monitoring,
            nexus.as_ref(),
            zk.as_ref(),
            governance.as_ref(),
            crypto.as_ref(),
            lane_manifests.as_ref(),
        )?;
        let validated_genesis = iroha_genesis::validate_prepared_genesis_bundle(
            &genesis.encode_wire().expect("fixture genesis framing"),
            &manifest,
            genesis_key.public_key(),
            genesis.hash(),
        )
        .expect("fixture signed genesis and manifest agree");
        Ok(PreparedTestChainConfig {
            genesis: validated_genesis,
            manifest,
            state,
            kura,
            validator_keys: keys,
            pasta_seeds: (0..4)
                .map(|index| zeroize::Zeroizing::new([0xA0 + index; 32]))
                .collect(),
            clock,
            lane_blocks,
        })
    }

    /// Apply the original prepared signed genesis and execute its successors through the
    /// production StateExecutor, publication, Kura, and recovery representation.
    ///
    /// All authority and custody checks precede execution. The clock account must be present
    /// in the resulting original genesis state; no account or value is fabricated here.
    /// This four-seat fixture signs votes itself, but never supplies caller-authored R values.
    ///
    /// # Errors
    /// Rejects mismatched source manifest, State/Kura identity, applied state, committee or
    /// custody. Actual genesis execution failures return the same State for inspection.
    pub fn from_prepared(config: PreparedTestChainConfig) -> Result<Self, StartFailure> {
        iroha_genesis::init_instruction_registry();
        let PreparedTestChainConfig {
            genesis: validated_genesis,
            manifest,
            state,
            kura,
            validator_keys: keys,
            pasta_seeds,
            clock,
            lane_blocks,
        } = config;
        let invalid = |message: String| StartFailure {
            error: TestChainError::Genesis(message),
            state: Arc::clone(&state),
        };
        iroha_genesis::validate_prepared_genesis_bundle(
            validated_genesis.canonical_wire(),
            &manifest,
            validated_genesis.public_key(),
            validated_genesis.expected_hash(),
        )
        .map_err(|error| invalid(format!("original prepared manifest: {error:#}")))?;
        let genesis = validated_genesis.block().clone();
        let chain_id = manifest.chain_id().clone();
        let epoch = super::epoch::genesis_epoch(&genesis).map_err(|error| {
            match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                invalid(error.to_string())
            }) {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => StartFailure {
                    error: TestChainError::Deferred(reason),
                    state: Arc::clone(&state),
                },
            }
        })?;
        if state.chain_id_ref() != &chain_id
            || state.view().network_id() != &epoch.network_id
            || !std::ptr::eq(state.kura(), kura.as_ref())
            || state.view().height() != 0
            || kura.blocks_count() != 0
        {
            return Err(invalid(
                "prepared genesis requires its exact chain/network and original empty State/Kura"
                    .into(),
            ));
        }
        if epoch.committee.len() != 4
            || keys.len() != epoch.committee.len()
            || pasta_seeds.len() != epoch.committee.len()
            || keys
                .iter()
                .zip(&epoch.committee)
                .any(|(key, member)| key.public_key() != member.validator.public_key())
        {
            return Err(invalid(
                "fixture custody must cover all four exact ordered signed genesis seats".into(),
            ));
        }
        let generation = Arc::new(epoch.authority);
        for (index, seed) in pasta_seeds.iter().enumerate() {
            crate::zk::kagemusha_v1_recursion::KagemushaMintFinalityLocalAuthorityV1::new(
                Arc::clone(&generation),
                zeroize::Zeroizing::new(**seed),
                u32::try_from(index).expect("four seats"),
            )
            .map_err(|error| invalid(format!("original Pasta custody seat {index}: {error}")))?;
        }
        let validators = epoch
            .committee
            .into_iter()
            .map(|member| (member.validator, member.proof_of_possession))
            .collect::<Vec<_>>();
        let genesis_account = AccountId::new(validated_genesis.public_key().clone());
        let consensus_mode = validated_genesis.consensus_metadata().mode;
        let tip = startup::apply_genesis(
            &state,
            genesis.clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .map_err(|error| StartFailure {
            error: error.into(),
            state: Arc::clone(&state),
        })?;
        if state
            .view()
            .world()
            .accounts()
            .get(&AccountId::new(clock.public_key().clone()))
            .is_none()
        {
            return Err(invalid(
                "fixture clock account is absent after original genesis".into(),
            ));
        }
        let crypto = Arc::new(BlsCrypto::new());
        crypto
            .admit_committee(
                validators
                    .iter()
                    .map(|(peer, pop)| (peer.public_key(), pop.as_slice())),
            )
            .expect("fixture committee admits");
        let shared: SharedCrypto = crypto.clone();
        let instance =
            root_instance(&genesis, &chain_id.to_string()).map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => invalid(error),
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => StartFailure {
                    error: TestChainError::Deferred(reason),
                    state: Arc::clone(&state),
                },
            })?;
        let availability: Arc<dyn AvailabilitySchedule> = Arc::new(
            super::runtime_availability::NativeGlobalAvailability::new(
                Arc::clone(&state),
                instance,
                Arc::clone(&crypto),
            )
            .map_err(|error| invalid(format!("original availability authority: {error}")))?,
        );
        let staging = Staging::new();
        let blocks = KuraBlockStore::new(
            Arc::clone(&kura),
            shared,
            GENESIS_HEIGHT,
            staging.clone(),
            state.ivm_execution_budget(),
            Arc::clone(&availability),
            Arc::new(super::attestation::NativePastaVerifier::new(
                instance,
                *state.network_id_ref(),
            )),
        );
        let (events, event_receiver) = tokio::sync::broadcast::channel(4096);
        let executor = StateExecutor::spawn(ExecutorContext {
            state: Arc::clone(&state),
            native_context_archive: Arc::new(
                crate::query::native_context_archive::NativeContextArchive::open(
                    state.kura(),
                    state.ivm_execution_budget(),
                    state.kura().native_context_archive_max_bytes(),
                )
                .expect("original-pool native context archive"),
            ),
            queue: None,
            staging,
            events,
            genesis_account: genesis_account.clone(),
            consensus_mode: consensus_mode.into(),
            applied: (GENESIS_HEIGHT, tip.block_hash),
            crypto: Some(Arc::clone(&crypto)),
            applied_watch: Arc::new(crate::sumeragi::lanes::global::AppliedWatch::new(
                GENESIS_HEIGHT,
                state.view().latest_block_hash(),
            )),
            lane_blocks: Arc::clone(&lane_blocks),
        })
        .expect("executor thread");
        let signers = keys
            .iter()
            .map(|key| KeyPairSigner::new(key).expect("BLS-normal fixture key"))
            .collect::<Vec<_>>();
        let authority = Arc::new(
            crate::zk::kagemusha_v1_recursion::KagemushaMintFinalityLocalAuthorityV1::new(
                generation,
                zeroize::Zeroizing::new(*pasta_seeds[0]),
                0,
            )
            .expect("actual genesis Pasta fixture custody"),
        );
        let (attestor, publisher) = super::attestation::channel(
            instance,
            signers[0].public_key(),
            true,
            &state.ivm_execution_budget(),
        )
        .expect("original pool fixture mailbox");
        executor
            .attach_attestation(
                super::attestation::NativePastaVerifier::new(
                    instance,
                    NetworkId::from_genesis_hash(genesis.hash()),
                ),
                Some(authority),
                publisher,
            )
            .expect("attach original fixture custody");
        Ok(Self {
            state,
            attestor,
            kura,
            genesis,
            validated_genesis,
            genesis_account,
            executor,
            events: event_receiver,
            blocks,
            availability,
            signers,
            validators,
            crypto,
            instance,
            tip: (GENESIS_HEIGHT, tip.block_hash, tip.result),
            clock,
            pasta_seeds,
            candidate_pasta_seeds: Vec::new(),
            lane_blocks,
        })
    }

    /// Replay the exact certified suffix of another chain through startup's native executor.
    /// Both chains must have executed the same original genesis. Certificates and result
    /// preimages are independently verified before copying their original durable frames;
    /// witness admission uses this State's own finite pool.
    ///
    /// # Errors
    /// Foreign genesis/prefix, invalid original certificate, custody failure, or a replay result
    /// that differs from the certified execution. No replacement certificate is produced.
    pub fn replay_from(&mut self, source: &Self) -> Result<(), String> {
        if self.network_id() != source.network_id()
            || self.state.chain_id_ref() != source.state.chain_id_ref()
        {
            return Err("native replay requires the same original signed genesis".into());
        }
        let view = source.state.view();
        let certified = super::certified_chain::CertifiedChain::new(&view)
            .map_err(|error| error.to_string())?;
        let prefix = certified
            .certified(self.height())
            .map_err(|error| error.to_string())?;
        if prefix.committed().core_hash() != self.tip.1 || prefix.committed().result() != self.tip.2
        {
            return Err("native replay prefix differs from the original applied State".into());
        }
        for height in self.height() + 1..=source.height() {
            let original = certified
                .certified(height)
                .map_err(|error| error.to_string())?;
            self.kura
                .store_block(original.committed().block().clone())
                .map_err(|error| error.to_string())?;
            let (body, commit_qc) = self
                .committed_body(height)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("original replay frame unavailable at {height}"))?;
            self.executor
                .replay(&body, &commit_qc)
                .map_err(|error| error.to_string())?;
            self.tip = (
                height,
                original.committed().core_hash(),
                original.committed().result(),
            );
        }
        Ok(())
    }

    /// Drain the events actually delivered by native publication, preserving their order.
    ///
    /// # Errors
    /// Fails on channel loss or a stopped Worker; missing events never count as parity.
    pub fn take_events(&mut self) -> Result<Vec<iroha_data_model::events::EventBox>, String> {
        let mut events = Vec::new();
        loop {
            match self.events.try_recv() {
                Ok(event) => events.push(event),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return Ok(events),
                Err(error) => return Err(format!("native fixture event delivery: {error}")),
            }
        }
    }

    /// Execute a real NPoS prefix through its authenticated pre-boundary pulse at height 9.
    ///
    /// The DKG session is genuinely proved but seeded as component prestate at height 8;
    /// this fixture does not claim transaction-driven ceremony or live-network qualification.
    /// The returned chain is ready to execute its mandatory attested boundary work at 10.
    pub fn npos_boundary_fixture() -> Self {
        Self::npos_boundary_fixture_with_currency(true)
    }

    /// Build the same authentic prefix with or without the currency in signed genesis.
    /// The absent case reaches the real boundary check without corrupting World indexes.
    fn npos_boundary_fixture_with_currency(include_currency: bool) -> Self {
        use crate::beacon::{
            GlobalThresholdBeaconPartialSignerV1 as _, GlobalThresholdBeaconPulseAggregatorV1,
            RetainedFinalizedGlobalThresholdBeaconSessionV1,
            prepared_session_and_signers_fixture_for_keys_v1,
        };
        use iroha_data_model::consensus::{
            GLOBAL_THRESHOLD_BEACON_VERSION_V1, GlobalThresholdBeaconChainAnchorV1,
            GlobalThresholdBeaconDkgSessionV1, GlobalThresholdBeaconPulseContextV1,
        };
        use iroha_data_model::{
            asset::{AssetBalancePolicy, AssetDefinition},
            isi::Register,
        };
        use iroha_primitives::numeric::NumericSpec;
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.consensus_mode = SumeragiConsensusMode::Npos;
        let policy = SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(10).unwrap(),
            epoch_seed: [0x61; 32],
            evidence_horizon_blocks: 1,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        };
        policy.validate().expect("bounded ten-block fixture policy");
        // A boundary reconciles the signed network currency even when it retains
        // the incumbent committee without an eligible future candidate pool.
        if include_currency {
            config.genesis_instructions.push(
                Register::asset_definition(AssetDefinition::new(
                    policy.xor_asset_definition_id.clone(),
                    "Network XOR",
                    NumericSpec::fractional(9),
                    AssetBalancePolicy::Global,
                    None,
                ))
                .into(),
            );
        }
        config.genesis_parameters.extend([
            Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                policy.epoch_length_blocks,
            )),
            Parameter::Custom(policy.into_custom_parameter()),
        ]);
        let mut chain = Self::start(config).expect("actual signed NPoS genesis");
        while chain.height() < 8 {
            chain.commit(Vec::new());
        }
        let current = chain
            .state
            .view()
            .world()
            .consensus_schedule()
            .ready(9)
            .unwrap()
            .epoch
            .clone();
        let mut pairs = VALIDATOR_SEEDS
            .iter()
            .map(|seed| KeyPair::from_seed(vec![*seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        pairs.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let roster = pairs
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            roster,
            current
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect::<Vec<_>>()
        );
        let id: [u8; 32] =
            iroha_crypto::Hash::new(b"native original Pasta boundary fixture DKG").into();
        let (session, signers) = prepared_session_and_signers_fixture_for_keys_v1(
            GlobalThresholdBeaconDkgSessionV1 {
                version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
                network_id: chain.network_id(),
                session_id: id,
                attempt_id: id,
                authority_generation: current.authority.generation,
                roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
                committee_size: 4,
                threshold: 2,
                start_height: 1,
                commitments_end_height: 2,
                deliveries_end_height: 3,
                acceptances_end_height: 4,
            },
            &pairs,
            &chain.state().ivm_execution_budget(),
        );
        let mut record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
            session: session.clone(),
            activated_at_height: None,
            retired_at_height: None,
        };
        record
            .activate(session.record().adaptive_dkg.finalized_at_height)
            .unwrap();
        chain.setup_world_at(2_000, |transaction| {
            transaction
                .world
                .global_beacon_key_sessions
                .insert(id, record);
            transaction
                .world
                .global_beacon_active_session
                .insert(crate::state::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
        });
        let parent = chain.committed(8);
        let epoch = super::schedule::core_epoch(&current).unwrap().id;
        let mut aggregate = GlobalThresholdBeaconPulseAggregatorV1::new(
            session,
            9,
            GlobalThresholdBeaconChainAnchorV1 {
                height: 8,
                block_hash: parent.block_hash(),
            },
            GlobalThresholdBeaconPulseContextV1 {
                instance: chain.instance.0,
                epoch: epoch.epoch,
                epoch_context_id: epoch.context.0,
                parent_consensus_hash: parent.core_hash().0,
                parent_result: parent.result().0,
            },
        )
        .unwrap();
        for signer in signers.iter().take(2) {
            let partial = signer
                .sign_partial(aggregate.session(), aggregate.payload())
                .unwrap();
            aggregate.accept_partial(partial).unwrap();
        }
        let pulse = aggregate.finalize().unwrap();
        let control = super::epoch_beacon::control::encode(Some(pulse)).unwrap();
        chain.commit_with_control(None, Vec::new(), Signers::Quorum, control);
        assert_eq!(chain.height(), 9);
        chain
    }

    /// The State the chain applies to.
    #[must_use]
    pub fn state(&self) -> &Arc<State> {
        &self.state
    }

    /// The chain's Kura.
    #[must_use]
    pub fn kura(&self) -> &Arc<Kura> {
        &self.kura
    }

    /// The signed genesis block.
    #[must_use]
    pub fn genesis(&self) -> &SignedBlock {
        &self.genesis
    }

    /// The independently validated signed genesis and its exact source manifest binding.
    #[must_use]
    pub fn validated_genesis(&self) -> &iroha_genesis::ValidatedGenesisBundle {
        &self.validated_genesis
    }

    /// The genesis account.
    #[must_use]
    pub fn genesis_account(&self) -> &AccountId {
        &self.genesis_account
    }

    /// The network id (the genesis hash).
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_genesis_hash(self.genesis.hash())
    }

    /// The chain instance `I`.
    #[must_use]
    pub fn instance(&self) -> Hash32 {
        self.instance
    }

    /// The committed height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.tip.0
    }

    /// The original signed-genesis validators and their proofs of possession.
    /// Later certificate authority is resolved from each authenticated scheduling context.
    #[must_use]
    pub fn validators(&self) -> &[(PeerId, Vec<u8>)] {
        &self.validators
    }

    /// The consensus-visible receipt of `height`.
    ///
    /// # Panics
    /// The height is not committed.
    #[must_use]
    pub fn committed(&self, height: u64) -> CommittedBlock {
        committed_block(&self.state.view(), height).expect("a committed fixture height")
    }

    /// Commit `transactions` in one block at the chain's next canonical time, with a quorum
    /// certificate. Returns whether each transaction executed successfully.
    ///
    /// # Panics
    /// A transaction is not accepted or the block does not execute `Valid` (fixture misuse).
    pub fn commit(&mut self, transactions: Vec<SignedTransaction>) -> Vec<bool> {
        self.commit_with(None, transactions, Signers::Quorum)
    }

    /// [`Self::commit`] with block time `time_ms`: the fixture adds a `Log` transaction of its
    /// clock account, created one millisecond earlier, when the block's own transactions would
    /// leave it earlier. A block cannot be earlier than its parent plus the cadence or than a
    /// transaction it carries: the time is then the earliest canonical one.
    ///
    /// # Panics
    /// See [`Self::commit`].
    pub fn commit_at(&mut self, time_ms: u64, transactions: Vec<SignedTransaction>) -> Vec<bool> {
        self.commit_with(Some(time_ms), transactions, Signers::Quorum)
    }

    /// Commit one block (see [`Self::commit_at`]) certified by `signers`.
    ///
    /// # Panics
    /// See [`Self::commit_at`].
    pub fn commit_with(
        &mut self,
        time_ms: Option<u64>,
        transactions: Vec<SignedTransaction>,
        signers: Signers,
    ) -> Vec<bool> {
        self.commit_with_control(time_ms, transactions, signers, Default::default())
    }

    /// Execute and certify a block with its separately authenticated control witness.
    /// Actual transaction or lane work is mandatory; the witness cannot create a block.
    pub fn commit_with_control(
        &mut self,
        time_ms: Option<u64>,
        transactions: Vec<SignedTransaction>,
        signers: Signers,
        control_witness: iroha_sumeragi::types::ControlWitness,
    ) -> Vec<bool> {
        self.commit_with_proposal(time_ms, transactions, signers, control_witness, |_| {})
    }

    /// Prepare the original resultless proposal before constructing its native header.
    /// The complete proposal
    /// still passes ordinary production payload validation and execution before any QC is made.
    ///
    /// # Panics
    /// See [`Self::commit`]. The hook must preserve the original canonical block time.
    pub fn commit_with_proposal(
        &mut self,
        time_ms: Option<u64>,
        transactions: Vec<SignedTransaction>,
        signers: Signers,
        control_witness: iroha_sumeragi::types::ControlWitness,
        prepare: impl FnOnce(&mut SignedBlock),
    ) -> Vec<bool> {
        let submitted = transactions.len();
        let mut proposal = self.proposal(time_ms, transactions);
        let original_time = proposal.header().creation_time();
        prepare(&mut proposal);
        assert_eq!(
            proposal.header().creation_time(),
            original_time,
            "original canonical block time"
        );
        let stored = self.commit_proposal(proposal, signers, control_witness);
        (0..submitted)
            .map(|index| {
                stored
                    .block()
                    .network_output_at(u32::try_from(index).expect("index fits"))
                    .is_some_and(|(_, output)| output.result.is_ok())
            })
            .collect()
    }

    /// Build original nonempty work using the production payload assembler and this chain's
    /// authenticated time, route, lane source and signed transaction rules.
    ///
    /// # Panics
    /// Input admission or original payload assembly fails.
    pub fn proposal(
        &self,
        time_ms: Option<u64>,
        mut transactions: Vec<SignedTransaction>,
    ) -> SignedBlock {
        let height = self.tip.0 + 1;
        let view = self.state.view();
        let parent = view
            .latest_block()
            .expect("completed original State parent read")
            .expect("the applied parent");
        let scheduled = view
            .world()
            .consensus_schedule()
            .ready(height)
            .cloned()
            .expect("the schedule authorizes the next height");
        let transaction_parameters = view.world().parameters().transaction();
        // The leader merges the lane blocks its lane stores have committed; they may raise the
        // block time (the merge time floor).
        let merges = crate::sumeragi::lanes::merge::propose(&view, &*self.lane_blocks, height)
            .expect("original lane store is available while building fixture proposal");
        drop(view);
        let cadence = Duration::from_millis(scheduled.params.block_time_ms);
        let parent_time = parent.header().creation_time();
        let floor = Duration::from_millis(merges.time_floor_ms);
        let inputs_time = |transactions: &[SignedTransaction]| {
            transactions
                .iter()
                .map(|tx| tx.creation_time() + Duration::from_millis(1))
                .fold((parent_time + cadence).max(floor), Duration::max)
        };
        if let Some(time_ms) = time_ms
            && inputs_time(&transactions) < Duration::from_millis(time_ms)
        {
            transactions.push(self.tick(time_ms - 1));
        }
        if transactions.is_empty() {
            transactions.push(self.tick(
                u64::try_from((parent_time + cadence).as_millis()).expect("fixture time fits") - 1,
            ));
        }
        let block_time = inputs_time(&transactions);
        let (_, time_source) = TimeSource::new_mock(block_time);
        let accepted = transactions
            .into_iter()
            .map(|tx| {
                let accepted = AcceptedTransaction::accept_with_time_source(
                    tx,
                    &self.network_id(),
                    Duration::from_secs(1),
                    transaction_parameters,
                    &iroha_config::parameters::actual::Crypto::default(),
                    &time_source,
                )
                .expect("the fixture transaction is accepted");
                accepted
            })
            .collect::<Vec<_>>();
        let assembly = Assembly {
            parent: &parent,
            view: 0,
            cadence,
        };
        let proposal = payload::assemble_with_merges(&self.state, assembly, &accepted, &merges)
            .expect("assembly");
        assert_eq!(
            proposal.header().creation_time(),
            block_time,
            "the fixture predicts the canonical block time"
        );
        proposal
    }

    /// Assemble original external or sealed work using this chain's authenticated successor
    /// schedule and the production entrypoint admission and payload owners.
    ///
    /// # Panics
    /// The input is empty, fails original admission, or cannot be assembled.
    pub fn proposal_entrypoints(
        &self,
        entrypoints: Vec<iroha_data_model::transaction::TransactionEntrypoint>,
    ) -> SignedBlock {
        assert!(
            !entrypoints.is_empty(),
            "native proposals require original work"
        );
        let view = self.state.view();
        let parent = view
            .latest_block()
            .expect("completed original State parent read")
            .expect("original parent");
        let schedule = view
            .world()
            .consensus_schedule()
            .ready(self.height() + 1)
            .expect("authenticated successor schedule");
        let cadence = Duration::from_millis(schedule.params.block_time_ms);
        let validation_time = crate::block::creation_time_after_inputs(
            parent
                .header()
                .creation_time()
                .checked_add(cadence)
                .expect("fixture time fits"),
            &entrypoints,
        )
        .expect("fixture input time fits");
        let accepted = entrypoints
            .into_iter()
            .map(|entrypoint| {
                AcceptedTransaction::accept_entrypoint_at_time(
                    entrypoint,
                    &self.network_id(),
                    view.world().parameters().sumeragi().max_clock_drift(),
                    view.world().parameters().transaction(),
                    &self.state.crypto(),
                    validation_time,
                )
                .expect("original entrypoint admission")
            })
            .collect::<Vec<_>>();
        payload::assemble(
            &self.state,
            Assembly {
                parent: &parent,
                view: 0,
                cadence,
            },
            &accepted,
        )
        .expect("original entrypoint assembly")
    }

    /// Execute and publish original entrypoints with an exact native quorum and no caller outputs.
    ///
    /// # Panics
    /// See [`Self::proposal_entrypoints`] and [`Self::commit_proposal`].
    pub fn commit_entrypoints(
        &mut self,
        entrypoints: Vec<iroha_data_model::transaction::TransactionEntrypoint>,
    ) -> CommittedBlock {
        let proposal = self.proposal_entrypoints(entrypoints);
        self.commit_proposal(proposal, Signers::Quorum, Default::default())
    }

    /// Execute, certify, publish and apply one original resultless proposal through the same
    /// worker used by the node. The native header binds the exact supplied canonical wire.
    ///
    /// Callers supply their original prepared proposal. No execution
    /// result, context proof, or certificate is accepted from the caller; the worker derives R.
    ///
    /// # Panics
    /// The proposal is not authorized by the current native schedule or production execution
    /// rejects it. This helper never publishes a rejected proposal.
    pub fn commit_proposal(
        &mut self,
        proposal: SignedBlock,
        signers: Signers,
        control_witness: iroha_sumeragi::types::ControlWitness,
    ) -> CommittedBlock {
        self.begin_proposal(proposal, control_witness)
            .expect("actual original proposal executes")
            .publish(signers)
            .expect("original execution publishes")
    }

    /// Retain one actual Worker execution before certification or publication.
    /// The returned owner exclusively borrows the chain until it is published or discarded.
    ///
    /// # Errors
    /// Returns the original production execution verdict. No caller-authored R is accepted.
    pub fn begin_proposal(
        &mut self,
        proposal: SignedBlock,
        control_witness: iroha_sumeragi::types::ControlWitness,
    ) -> Result<PendingTestExecution<'_>, String> {
        let height = self.tip.0 + 1;
        assert_eq!(
            proposal.header().height().get(),
            height,
            "original next height"
        );
        let scheduled = self
            .state
            .view()
            .world()
            .consensus_schedule()
            .ready(height)
            .cloned()
            .expect("the schedule authorizes the original proposal");
        let payload_bytes = payload::encode(&proposal).expect("non-empty payload");
        let epoch = super::schedule::core_epoch(&scheduled.epoch)
            .expect("authenticated epoch")
            .id;
        let header = BlockHeader {
            control_witness,
            instance: self.instance,
            epoch,
            height,
            origin_view: 0,
            parent_hash: self.tip.1,
            parent_result: self.tip.2,
            payload_hash: payload_hash(&*self.crypto, &payload_bytes),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload_bytes.len()).expect("payload fits"),
            proposer: 0,
            skipped_leaders: Vec::new(),
            attest: attestation_required(&proposal)
                || height == scheduled.epoch.authorization.last_height,
        };
        let block = self.author_payload(header, payload_bytes);
        let block_hash = block.hash(&*self.crypto);
        let mut diagnostic_events = self.events.resubscribe();
        let result = match self.executor.execute(&block, &block_hash) {
            Some(ExecOutcome::Valid(result)) => result,
            other => {
                use iroha_data_model::events::{
                    EventBox,
                    pipeline::{BlockStatus, PipelineEventBox},
                };
                let mut rejection = None;
                while let Ok(event) = diagnostic_events.try_recv() {
                    if let EventBox::Pipeline(PipelineEventBox::Block(event)) = event {
                        if event.header.height().get() == height {
                            if let BlockStatus::Rejected(reason) = event.status {
                                rejection = Some(reason);
                            }
                        }
                    }
                }
                return Err(format!(
                    "fixture block {height} does not execute: {other:?}; native rejection: {rejection:?}"
                ));
            }
        };
        Ok(PendingTestExecution {
            chain: self,
            block,
            block_hash,
            result,
            certificate: None,
            published: None,
        })
    }

    /// A `CommitQC` of `(height, block_hash, result)` signed by `signers` (view 0).
    #[must_use]
    pub fn commit_qc(
        &self,
        height: u64,
        block_hash: Hash32,
        result: Hash32,
        attest: bool,
        signers: Signers,
    ) -> Qc {
        let context = self.certificate_context(height);
        let epoch = super::schedule::core_epoch(&context).unwrap().id;
        let witness = if attest {
            if height <= self.tip.0 {
                self.committed_body(height)
                    .expect("restore original certified witness into this State pool")
                    .expect("original committed body exists")
                    .1
                    .attestation_witness
            } else {
                let statement = iroha_sumeragi::preimage::att_preimage(
                    &self.instance,
                    &epoch,
                    height,
                    &block_hash,
                    &result,
                );
                let AttestOutcome::Attested(share) =
                    self.attestor
                        .attest(height, self.signers[0].public_key(), &statement)
                else {
                    panic!(
                        "the executed original must publish its actual Pasta receipt before Valid"
                    );
                };
                Some(share.witness)
            }
        } else {
            None
        };
        self.commit_qc_with_witness(height, block_hash, result, attest, signers, witness)
    }

    /// Sign a source-complete certificate over the exact original worker witness supplied by
    /// an execution fixture. It must hash to R; every Pasta signer verifies the same full source.
    pub fn commit_qc_with_witness(
        &self,
        height: u64,
        block_hash: Hash32,
        result: Hash32,
        attest: bool,
        signers: Signers,
        witness: Option<ResultWitness>,
    ) -> Qc {
        assert_eq!(
            attest,
            witness.is_some(),
            "exact mandatory witness presence"
        );
        if let Some(witness) = &witness {
            assert_eq!(
                super::commitment::result_of_preimage(witness.as_slice()),
                result
            );
        }
        let context = self.certificate_context(height);
        assert_eq!(context.committee.len(), 4, "four-seat component fixture");
        let epoch = super::schedule::core_epoch(&context).unwrap().id;
        let committee = Committee::new(
            context
                .committee
                .iter()
                .map(|member| super::crypto::core_key(member.validator.public_key()).unwrap())
                .collect(),
        )
        .expect("the exact authenticated committee");
        if let Some(witness) = &witness {
            let original = super::commitment::ExecutionResultCommitment::decode(witness.as_slice())
                .expect("original native execution witness");
            assert_eq!(
                original.schedule.current, context,
                "certificate seats belong to the exact executed scheduling context"
            );
        }
        let votes = signers
            .indices()
            .iter()
            .map(|&signer| {
                let mut vote = Vote {
                    kind: VoteKind::Commit,
                    instance: self.instance,
                    epoch,
                    height,
                    view: 0,
                    block_hash,
                    result,
                    attest,
                    signer,
                    sig: iroha_sumeragi::types::Signature(
                        [0; iroha_sumeragi::types::SIGNATURE_LEN],
                    ),
                    attestation: None,
                };
                if let Some(witness) = &witness {
                    let message = super::attestation::native_seal_message(
                        self.instance,
                        self.network_id(),
                        &vote.statement(),
                        witness.as_slice(),
                    )
                    .expect("actual original native statement");
                    let result =
                        super::commitment::ExecutionResultCommitment::decode(witness.as_slice())
                            .unwrap();
                    let custody = self
                        .pasta_custody_for_peer(&context.committee[signer as usize].validator)
                        .expect("provisioned exact scheduled Pasta custody");
                    let signer = custody
                        .signer_for_authority(&result.schedule.current.authority)
                        .unwrap();
                    vote.attestation = Some(CommitAttestation {
                        witness: witness.clone(),
                        signature: super::attestation::encode_native_seal(
                            signer.sign(&message).unwrap(),
                        ),
                    });
                }
                vote.sig = self
                    .signer_for_member(&context.committee[signer as usize].validator)
                    .expect("provisioned exact scheduled BLS custody")
                    .sign(&vote.preimage());
                vote
            })
            .collect::<Vec<_>>();
        let refs = votes.iter().collect::<Vec<_>>();
        match form_qc(&*self.crypto, committee.n(), &refs) {
            Ok(qc) => qc,
            // Under- or oversized sets are refused by `form_qc`: aggregate by hand only
            // to supply a genuinely signed malformed certificate to negative tests.
            Err(_) => {
                let mut signers_bitmap = iroha_sumeragi::types::Bitmap::new(committee.n());
                for vote in &votes {
                    signers_bitmap.set(vote.signer);
                }
                let sigs = votes.iter().map(|vote| vote.sig).collect::<Vec<_>>();
                Qc {
                    kind: VoteKind::Commit,
                    instance: self.instance,
                    epoch,
                    height,
                    view: 0,
                    block_hash,
                    result,
                    attest,
                    signers: signers_bitmap,
                    agg_sig: iroha_sumeragi::crypto::Crypto::aggregate(&*self.crypto, &sigs),
                    attestations: votes
                        .iter()
                        .filter_map(|vote| vote.attestation.as_ref().map(|share| share.signature))
                        .collect(),
                    attestation_witness: witness,
                }
            }
        }
    }

    /// Original seed custody matching this chain's signed genesis authority and canonical seat.
    pub fn pasta_custody(
        &self,
        index: u32,
    ) -> crate::zk::kagemusha_v1_recursion::KagemushaMintFinalityLocalAuthorityV1 {
        crate::zk::kagemusha_v1_recursion::KagemushaMintFinalityLocalAuthorityV1::new(
            Arc::new(
                super::epoch::genesis_epoch(&self.genesis)
                    .unwrap()
                    .authority,
            ),
            zeroize::Zeroizing::new(*self.pasta_seeds[index as usize]),
            index,
        )
        .expect("fixture custody matches its actual signed genesis")
    }

    /// Test setup outside consensus: run `edit` on a transaction of an overlay for the next
    /// height at block time `time_ms` and publish only its World changes (no block, no height).
    /// The next [`Self::commit_at`] at `time_ms` commits the block the edited World is read at;
    /// rows the edit records carry that height and time.
    ///
    /// # Panics
    /// The overlay cannot be published.
    pub fn setup_world_at(
        &self,
        time_ms: u64,
        edit: impl FnOnce(&mut crate::state::StateTransaction<'_, '_>),
    ) {
        let view = self.state.view();
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(self.tip.0 + 1).expect("non-zero"),
            view.latest_block_hash(),
            None,
            time_ms,
            0,
        );
        drop(view);
        let mut block = self.state.block(header);
        let mut transaction = block.transaction();
        edit(&mut transaction);
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("fixture World setup publishes");
    }

    /// A signed transaction of `key`'s account on this chain, created at `created_ms`.
    #[must_use]
    pub fn sign(
        &self,
        key: &KeyPair,
        instructions: impl IntoIterator<Item = InstructionBox>,
        created_ms: u64,
    ) -> SignedTransaction {
        let mut builder = TransactionBuilder::new(
            self.network_id(),
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(created_ms));
        let mut builder = builder.with_instructions(instructions);
        let view = self.state.view();
        if let Some(iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            dataspace_id,
            ..
        }) = super::lanes::routing::committed_root_scope(view.world())
        {
            let draft = builder.clone().sign(key.private_key());
            let quote = crate::executor::quote_nexus_fee_admission_draft(
                view.world(),
                view.nexus(),
                view.pipeline(),
                &view.zk().gas,
                draft.payload(),
                created_ms,
                self.height() + 1,
                Some(dataspace_id),
            )
            .expect("private fixture work pays its original signed fee policy");
            builder = builder.with_fee_payment_intent(quote.recommended_intent);
        }
        builder.sign(key.private_key())
    }

    /// Sign actual nonempty fixture work using the account seeded by this chain's genesis.
    pub(super) fn tick(&self, created_ms: u64) -> SignedTransaction {
        self.sign(
            &self.clock,
            [InstructionBox::from(Log::new(
                Level::DEBUG,
                format!("certified test chain clock {created_ms}"),
            ))],
            created_ms,
        )
    }
}

/// Exclusive test owner of one original native Worker execution.
///
/// The Worker keeps the original overlay and witness; this owner retains only the exact
/// source header, source payload and R returned by that Worker. Certification and publication
/// use the production path. Dropping an unpublished owner discards only that speculative work.
pub struct PendingTestExecution<'chain> {
    chain: &'chain mut CertifiedTestChain,
    block: AvailableBody,
    block_hash: Hash32,
    result: Hash32,
    certificate: Option<(Signers, Qc)>,
    published: Option<CommittedBlock>,
}

impl PendingTestExecution<'_> {
    /// Read the actual native authority and move the original complete-effect source
    /// after publication. This is the production executor handoff, not reconstructed wire.
    #[cfg(test)]
    pub(crate) fn take_finalized_fastpq_source(
        &self,
    ) -> Result<crate::fastpq::finalized_source::FinalizedFastpqSource, String> {
        let view = self.chain.state.view();
        let native = super::certified_chain::CertifiedChain::new(&view)
            .and_then(|chain| chain.authenticated_execution(self.block.header().height))
            .map_err(|error| error.to_string())?;
        self.chain.executor.take_finalized_fastpq_source(native)
    }

    /// Durably append the original certificate and finalize its actual State metadata while
    /// a held physical history writer defers visibility. This retains the original overlay
    /// for immutable checkpoint inspection; [`Self::publish`] retries its ordinary publisher.
    ///
    /// # Errors
    /// The original certificate, durable append or actual publication preparation refuses.
    #[cfg(test)]
    pub fn prepare_publication_for_inspection(&mut self, signers: Signers) -> Result<(), String> {
        if self.published.is_some() {
            return Err("published source cannot prepare another inspection".into());
        }
        self.prepare(signers)?;
        let (_, qc) = self
            .certificate
            .as_ref()
            .expect("original certificate retained");
        self.chain
            .blocks
            .append(&self.block, qc)
            .map_err(|error| error.to_string())?;
        self.chain
            .executor
            .prepare_publication_for_inspection(&self.block, qc)
    }

    /// Hash of R returned by the original execution.
    #[must_use]
    pub fn result(&self) -> Hash32 {
        self.result
    }

    /// Observe or alter the original unprepared execution on its owning Worker thread.
    /// A changed sealed source must fail production preparation. Borrowed source values
    /// cannot escape this callback, and certified publication cannot be inspected mutably.
    ///
    /// # Errors
    /// The original owner is absent, already certified, or the callback panics.
    pub fn inspect<R: Send + 'static>(
        &mut self,
        inspect: impl for<'borrow, 'state> FnOnce(
            super::executor::PendingExecutionView<'borrow, 'state>,
        ) -> R
        + Send
        + 'static,
    ) -> Result<R, String> {
        self.chain
            .executor
            .inspect_pending(self.block_hash, inspect)
    }

    /// Inspect the immutable original certified overlay retained for publication.
    /// No mutable source or publication capability escapes this callback.
    ///
    /// # Errors
    /// The original source is absent, unprepared, already consumed, or the callback panics.
    pub fn inspect_prepared<R: Send + 'static>(
        &self,
        inspect: impl for<'borrow, 'state> FnOnce(
            super::executor::PreparedExecutionView<'borrow, 'state>,
        ) -> R
        + Send
        + 'static,
    ) -> Result<R, String> {
        self.chain
            .executor
            .inspect_prepared(self.block_hash, inspect)
    }

    /// Certify this retained R and prepare the same original Worker execution.
    /// A failed attempt retains its exact certificate and source for a retry.
    ///
    /// # Errors
    /// Refuses changed signing choices, source mutation, invalid quorum, or production refusal.
    pub fn prepare(&mut self, signers: Signers) -> Result<(), String> {
        if let Some((original, _)) = &self.certificate {
            if *original != signers {
                return Err("original pending certificate cannot be replaced".into());
            }
        } else {
            let mut qc = self.chain.commit_qc(
                self.block.header().height,
                self.block_hash,
                self.result,
                self.block.header().attest,
                signers,
            );
            qc.admit_attestation_witness(&self.chain.state.ivm_execution_budget())
                .map_err(|error| error.to_string())?;
            self.certificate = Some((signers, qc));
        }
        let (_, qc) = self
            .certificate
            .as_ref()
            .expect("original certificate retained");
        match self
            .chain
            .executor
            .prepare(&self.block, qc)
            .map_err(|error| error.to_string())?
        {
            Some(result) if result == self.result => Ok(()),
            other => Err(format!("original execution preparation refused: {other:?}")),
        }
    }

    /// Persist and publish this exact original execution. Repeated completion returns the
    /// original committed block without repeating State changes or event delivery.
    ///
    /// # Errors
    /// Returns preparation, durable storage or publication refusal with this owner retained.
    pub fn publish(&mut self, signers: Signers) -> Result<CommittedBlock, String> {
        if let Some(published) = &self.published {
            if self
                .certificate
                .as_ref()
                .is_some_and(|(original, _)| *original != signers)
            {
                return Err("original published certificate cannot be replaced".into());
            }
            return Ok(published.clone());
        }
        self.prepare(signers)?;
        let (_, qc) = self
            .certificate
            .as_ref()
            .expect("prepared original certificate");
        self.chain
            .blocks
            .append(&self.block, qc)
            .map_err(|error| error.to_string())?;
        self.chain
            .executor
            .commit(&self.block, qc)
            .map_err(|error| error.to_string())?;
        self.chain.tip = (self.block.header().height, self.block_hash, self.result);
        let published = self.chain.committed(self.block.header().height);
        self.published = Some(published.clone());
        Ok(published)
    }
}

impl Drop for PendingTestExecution<'_> {
    fn drop(&mut self) {
        if self.published.is_none() {
            self.chain.executor.discard(self.block.header().height, &[]);
        }
    }
}

/// Derive the signed policies through the same refusing native execution boundary used by
/// production. A provisional mismatch supplies only the two typed policy digests. Its overlay
/// is discarded, its pristine World is moved into a new State bound to the final signed network,
/// and the corrected original is executed again before this function returns.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_configured_genesis(
    mut world: World,
    chain_id: &ChainId,
    key: &KeyPair,
    validators: &[(PeerId, Vec<u8>)],
    mut genesis: SignedBlock,
    mut manifest: iroha_genesis::RawGenesisTransaction,
    mode: SumeragiConsensusMode,
    time_ms: u64,
    pipeline: &iroha_config::parameters::actual::Pipeline,
    fraud_monitoring: &iroha_config::parameters::actual::FraudMonitoring,
    nexus_config: Option<&iroha_config::parameters::actual::Nexus>,
    zk: Option<&iroha_config::parameters::actual::Zk>,
    governance: Option<&iroha_config::parameters::actual::Governance>,
    crypto: Option<&iroha_config::parameters::actual::Crypto>,
    lane_manifests: Option<&Arc<LaneManifestRegistry>>,
) -> Result<
    (
        SignedBlock,
        iroha_genesis::RawGenesisTransaction,
        Arc<State>,
        Arc<Kura>,
    ),
    StartFailure,
> {
    // LaneConfig is derived runtime geometry. Rebuild it from the authoritative catalog
    // before signing, exactly as the pre-genesis State constructor does, so both owners
    // authenticate the same height-one DA policies even when a caller changes the catalog.
    let normalized_nexus = nexus_config.map(|nexus| {
        let mut nexus = nexus.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus
    });
    let nexus_config = normalized_nexus.as_ref();
    let da_policies =
        nexus_config.map(|nexus| crate::da::active_proof_policy_bundle_at_height(nexus, 1));
    let confidential = zk.map_or_else(
        crate::state::default_genesis_confidential_policy_hash,
        crate::state::compute_genesis_confidential_policy_hash,
    );
    if nexus_config.is_some() || zk.is_some() {
        genesis = manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                key,
                da_policies.clone(),
                Some(confidential),
                time_ms,
            )
            .expect("sign configured fixture genesis with its actual DA/ZK policies")
            .0;
    }
    let topology =
        super::network_topology::Topology::new(validators.iter().map(|(peer, _)| peer.clone()));
    let account = AccountId::new(key.public_key().clone());
    for attempt in 0..2 {
        let network = NetworkId::from_genesis_hash(genesis.hash());
        let default_catalog = iroha_data_model::nexus::DataSpaceCatalog::default();
        let catalog = nexus_config.map_or(&default_catalog, |nexus| &nexus.dataspace_catalog);
        // Match the production fresh-start owner before State can install namespace defaults.
        // These authenticated leases/permissions depend only on unchanged instructions,
        // authorities, catalog, root scope and signed private fee policy, so the same rows
        // survive policy re-signing below without retaining a provisional network identity.
        if let Err(error) = crate::sns::seed_genesis_alias_bootstrap(&mut world, &genesis, catalog)
        {
            return Err(StartFailure {
                error: TestChainError::Genesis(format!(
                    "initialize authenticated genesis SNS bootstrap: {error}"
                )),
                state: Arc::new(State::new_with_chain_and_network_id_for_testing(
                    world,
                    Kura::blank_kura_for_testing(),
                    LiveQueryStore::start_test(),
                    chain_id.clone(),
                    network,
                )),
            });
        }
        let (mut state, kura) = fixture_bootstrap_state(world, chain_id, network, nexus_config);
        if let Some(zk) = zk {
            if let Err(error) = state.set_zk(zk.clone()) {
                return Err(StartFailure {
                    error: TestChainError::Genesis(format!("configured fixture ZK: {error}")),
                    state: Arc::new(state),
                });
            }
        }
        if let Some(governance) = governance {
            state.set_gov(governance.clone());
        }
        if let Some(crypto) = crypto {
            state.set_crypto(crypto.clone());
        }
        state.set_pipeline(pipeline.clone());
        state.set_fraud_monitoring(fraud_monitoring.clone());
        let nexus = state.nexus_snapshot();
        let manifests = lane_manifests.cloned().unwrap_or_else(|| {
            Arc::new(LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance))
        });
        state.install_lane_manifests_for_testing(&manifests);
        let policies = validate_fixture_genesis_policy(
            genesis.clone(),
            &topology,
            &account,
            &state,
            mode.into(),
            attempt,
        );
        let policies = match policies {
            Ok(policies) => policies,
            Err(error) => {
                return Err(StartFailure {
                    error: TestChainError::OriginalGenesisExecution(error),
                    state: Arc::new(state),
                });
            }
        };
        let Some((execution, nexus)) = policies else {
            return Ok((genesis, manifest, Arc::new(state), kura));
        };
        let mut parameters = manifest.sumeragi_context_parameters();
        parameters.execution_policy_hash = execution.into();
        parameters.nexus_amx_context_hash = nexus.into();
        manifest = match manifest
            .with_sumeragi_context_parameters(parameters)
            .with_consensus_meta()
        {
            Ok(manifest) => manifest,
            Err(error) => {
                return Err(StartFailure {
                    error: TestChainError::Genesis(format!(
                        "derive native genesis metadata: {error:#}"
                    )),
                    state: Arc::new(state),
                });
            }
        };
        genesis = match manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                key,
                da_policies.clone(),
                Some(confidential),
                time_ms,
            ) {
            Ok(signed) => signed.0,
            Err(error) => {
                return Err(StartFailure {
                    error: TestChainError::Genesis(format!(
                        "sign derived native genesis policies: {error:#}"
                    )),
                    state: Arc::new(state),
                });
            }
        };
        // The provisional execution never publishes. Its pristine bootstrap World survives;
        // no result, schedule, context values, or provisional network identity crosses this move.
        world = state.world;
    }
    unreachable!("second native validation either succeeds or returns its typed failure")
}

// Constructor temporaries retire before the original signed genesis executes. This helper
// preserves the exact fresh State's network, Nexus geometry, fee policy and original owners.
fn fixture_bootstrap_state(
    world: World,
    chain_id: &ChainId,
    network: NetworkId,
    nexus_config: Option<&iroha_config::parameters::actual::Nexus>,
) -> (State, Arc<Kura>) {
    if let Some(nexus) = nexus_config {
        let (mut state, kura) =
            State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
                world,
                nexus.clone(),
                LiveQueryStore::start_test(),
                chain_id.clone(),
                network,
            );
        // The generic State fixture disables fees. Reinstall the explicit caller policy
        // before the first staged genesis execution, preserving its authenticated geometry.
        state
            .set_nexus_from_config(nexus.clone())
            .expect("configured fixture Nexus");
        (state, kura)
    } else {
        let kura = Kura::blank_kura_for_testing();
        let state = State::new_with_chain_and_network_id_for_testing(
            world,
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
            chain_id.clone(),
            network,
        );
        (state, kura)
    }
}

// Complete original validation owners are destroyed before the caller adjusts signed policy.
// This retains genuine genesis execution and its original rejection/refusal classification.
fn validate_fixture_genesis_policy(
    genesis: SignedBlock,
    topology: &super::network_topology::Topology,
    account: &AccountId,
    state: &State,
    mode: iroha_data_model::parameter::system::ConsensusMode,
    attempt: u8,
) -> Result<Option<(iroha_crypto::Hash, iroha_crypto::Hash)>, Box<crate::block::BlockValidationError>>
{
    let validation = crate::block::ValidBlock::validate_signed_genesis(
        genesis,
        topology,
        account,
        &TimeSource::new_system(),
        state,
        mode,
    )
    .unpack(|_| {});
    match validation {
        Ok((valid, overlay)) => {
            drop((valid, overlay));
            Ok(None)
        }
        Err((_, error)) => match *error {
            crate::block::BlockValidationError::GenesisPolicyMismatch {
                actual_execution,
                actual_nexus,
                ..
            } if attempt == 0 => Ok(Some((actual_execution, actual_nexus))),
            error => Err(Box::new(error)),
        },
    }
}

/// Build a signed genesis with an explicit NPoS policy for authority-reader tests.
#[cfg(test)]
pub(crate) fn signed_genesis_fixture(
    chain_id: &ChainId,
    genesis_key: &KeyPair,
    validators: &[(PeerId, Vec<u8>)],
    instructions: Vec<InstructionBox>,
    genesis_time_ms: u64,
    mode: ConsensusMode,
    npos: Option<SumeragiNposParameters>,
) -> Result<SignedBlock, String> {
    if (mode == ConsensusMode::Npos) != npos.is_some() {
        return Err("fixture NPoS policy must exactly match signed mode".into());
    }
    build_genesis(
        chain_id,
        genesis_key,
        validators,
        instructions,
        genesis_policy::npos_genesis_parameters(npos),
        mode.into(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        genesis_time_ms,
        NonZeroU64::new(1).expect("nonzero fixture cadence"),
    )
    .map(|(block, _)| block)
}

/// The signed genesis of the fixed committee with `instructions` in its ordinary transaction.
fn build_genesis(
    chain_id: &ChainId,
    genesis_key: &KeyPair,
    validators: &[(PeerId, Vec<u8>)],
    instructions: Vec<InstructionBox>,
    parameters: Vec<Parameter>,
    consensus_mode: SumeragiConsensusMode,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    genesis_time_ms: u64,
    genesis_block_cadence_ms: NonZeroU64,
) -> Result<(SignedBlock, iroha_genesis::RawGenesisTransaction), String> {
    let entries = validators
        .iter()
        .map(|(peer, pop)| GenesisTopologyEntry::new(peer.clone(), pop.clone()))
        .collect::<Vec<_>>();
    let roster = validators
        .iter()
        .map(|(peer, _)| ValidatorPower {
            validator: peer.clone(),
            power: 1,
        })
        .collect::<Vec<_>>();
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = root_scope;
    let builder = GenesisBuilder::new_without_executor(chain_id.clone(), ".")
        .with_block_cadence_ms(genesis_block_cadence_ms)
        .set_topology(entries)
        .with_sumeragi_context_parameters(context)
        .with_kagemusha_mint_finality_genesis_parameters(
            crate::kagemusha_v1_test_fixtures::mint_finality_genesis_parameters(&roster),
        );
    let builder = parameters
        .into_iter()
        .fold(builder, GenesisBuilder::append_parameter);
    // A raw genesis transaction emits its custom instructions before topology.
    // Put peer-dependent fixture instructions after the original topology batch,
    // so staking and other consumers see the authenticated registered peers.
    let builder = if instructions.is_empty() {
        builder
    } else {
        builder.next_transaction()
    };
    let builder = instructions
        .into_iter()
        .fold(builder, GenesisBuilder::append_instruction);
    let raw = builder
        .build_raw()
        .map_err(|error| format!("{error:#}"))?
        .with_consensus_mode(consensus_mode)
        .with_consensus_meta()
        .map_err(|error| format!("{error:#}"))?;
    let genesis = raw
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            genesis_key,
            None,
            Some(crate::state::default_genesis_confidential_policy_hash()),
            genesis_time_ms,
        )
        .map_err(|error| format!("{error:#}"))?;
    Ok((genesis.0, raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_genesis_bootstrap_matches_final_original_without_provisional_effects() {
        use iroha_data_model::{
            account::rekey::{AccountAlias, AccountAliasDomain},
            isi::Register,
            permission::Permission,
        };
        use iroha_executor_data_model::permission::account::{
            AccountAliasPermissionScope, CanManageAccountAlias,
        };
        use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

        let key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let clock = AccountId::new(
            KeyPair::from_seed(vec![CLOCK_SEED; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let recipient = AccountId::new(
            KeyPair::from_seed(vec![0xCF; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let domain = DomainId::try_new("bootstrap", "universal").unwrap();
        let alias = AccountAlias::new(
            "merchant".parse().unwrap(),
            Some(AccountAliasDomain::new(domain.name().clone())),
            DataSpaceId::UNIVERSAL,
        );
        let original_world = || {
            World::with(
                [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&authority)],
                [
                    Account::new(authority.clone()).build(&authority),
                    Account::new(clock.clone()).build(&clock),
                ],
                [],
            )
        };
        let mut config = TestChainConfig::new(original_world(), 1_000);
        config.genesis_instructions = vec![
            Register::domain(Domain::new(domain.clone())).into(),
            Register::account(Account::new(recipient.clone()).with_label(Some(alias.clone())))
                .into(),
        ];
        // A distinct actual process policy forces the provisional-policy re-signing pass.
        let mut zk = crate::state::default_zk_config();
        zk.max_verify_calls_per_tx = 3;
        config.zk = Some(zk);
        let prepared = CertifiedTestChain::prepare(config).expect("authenticated alias bootstrap");
        assert_ne!(
            prepared
                .manifest
                .sumeragi_context_parameters()
                .execution_policy_hash,
            SumeragiGenesisContextParameters::recommended().execution_policy_hash,
        );
        let original_wire = prepared.genesis.canonical_wire().to_vec();
        let catalog = prepared.state.nexus_snapshot().dataspace_catalog;
        let mut expected = original_world();
        crate::sns::seed_genesis_alias_bootstrap(&mut expected, prepared.genesis.block(), &catalog)
            .expect("fresh seeding from the final original genesis");
        // State also seeds the reserved universal dataspace and existing domain leases.
        // Reproduce that exact initialization over the freshly seeded final original.
        let expected = State::new_with_chain_and_network_id_for_testing(
            expected,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            prepared.state.chain_id_ref().clone(),
            NetworkId::from_genesis_hash(prepared.genesis.block().hash()),
        );
        {
            let view = prepared.state.view();
            let expected_view = expected.view();
            assert_eq!(view.height(), 0);
            assert_eq!(prepared.kura.blocks_count(), 0);
            assert!(view.world().domains().get(&domain).is_none());
            assert!(view.world().accounts().get(&recipient).is_none());
            assert_eq!(
                view.world()
                    .smart_contract_state()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
                expected_view
                    .world()
                    .smart_contract_state()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
                "only the same final-original bootstrap rows survive provisional execution",
            );
            assert_eq!(
                view.world()
                    .account_permissions()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
                expected_view
                    .world()
                    .account_permissions()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
            );
            let permissions = view.world().account_permissions().get(&authority).unwrap();
            for scope in [
                AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
                AccountAliasPermissionScope::Domain(domain.clone()),
            ] {
                assert!(permissions.contains(&Permission::from(CanManageAccountAlias { scope })));
            }
            assert_eq!(
                crate::sns::get_name_record(
                    view.world(),
                    crate::sns::SnsNamespace::AccountAlias,
                    "merchant@bootstrap.universal",
                    1_000,
                )
                .unwrap()
                .owner,
                recipient,
            );
        }
        let chain = CertifiedTestChain::from_prepared(prepared)
            .expect("the original signed genesis consumes its authenticated bootstrap");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.genesis().encode_wire().unwrap(), original_wire);
        let view = chain.state().view();
        assert!(view.world().domains().get(&domain).is_some());
        assert!(view.world().accounts().get(&recipient).is_some());
        assert_eq!(view.world().account_aliases().get(&alias), Some(&recipient));
    }

    #[test]
    fn configured_genesis_cadence_is_signed_and_used_for_original_sealed_work() {
        use iroha_data_model::transaction::signed::{
            SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
        };
        let mut config = TestChainConfig::new(World::default(), 0);
        config.genesis_block_cadence_ms = NonZeroU64::new(1001).unwrap();
        let key = config.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(config).expect("original signed cadence");
        let parent = chain.genesis().clone();
        let view = chain.state().view();
        assert_eq!(
            view.world()
                .parameters()
                .sumeragi()
                .block_cadence_ms()
                .get(),
            1001
        );
        assert_eq!(
            view.world()
                .consensus_schedule()
                .ready(2)
                .unwrap()
                .params
                .block_time_ms,
            1001
        );
        drop(view);
        let entry = iroha_data_model::transaction::TransactionEntrypoint::SealedCommitment(
            SignedSealedTransactionCommitment::sign(
                SealedTransactionCommitmentPayload::new(
                    chain.network_id(),
                    AccountId::new(key.public_key().clone()),
                    iroha_crypto::Hash::new(b"original sealed cadence fixture"),
                    3,
                    5,
                    None,
                ),
                key.private_key(),
            ),
        );
        let entry_hash = entry.hash();
        let committed = chain.commit_entrypoints(vec![entry]);
        assert_eq!(
            committed.block().header().prev_block_hash(),
            Some(parent.hash())
        );
        assert_eq!(
            committed.block().header().creation_time(),
            parent.header().creation_time() + Duration::from_millis(1001)
        );
        assert_eq!(
            committed.block().network_input_hashes().collect::<Vec<_>>(),
            vec![entry_hash]
        );
        assert!(
            committed
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok()
        );
    }

    #[test]
    fn boundary_currency_fixture_retains_native_authority_with_signed_genesis() {
        use iroha_data_model::{
            asset::AssetBalancePolicy, sumeragi::epoch::ValidatorEpochDecisionV1,
        };

        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        let current = {
            let view = chain.state().view();
            let policy = view
                .world()
                .sumeragi_npos_parameters()
                .expect("original policy decoder completes")
                .unwrap();
            let currency = view
                .world()
                .asset_definitions()
                .get(&policy.xor_asset_definition_id)
                .expect("original signed genesis currency");
            assert_eq!(currency.spec().scale(), Some(9));
            assert_eq!(currency.balance_scope_policy(), AssetBalancePolicy::Global);
            view.world()
                .consensus_schedule()
                .ready(10)
                .unwrap()
                .epoch
                .clone()
        };
        chain.commit(Vec::new());
        let boundary = chain.committed(10);
        assert!(boundary.header().unwrap().attest);
        assert_eq!(boundary.commitment().execution.kagemusha_top_up_count, 0);
        let next = &boundary
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .unwrap()
            .next;
        assert_eq!(
            next.authorization.decision,
            ValidatorEpochDecisionV1::Retain
        );
        assert_eq!(next.authority, current.authority);
        assert_eq!(next.committee, current.committee);
        chain.commit(Vec::new());
        assert_eq!(chain.height(), 11);
    }

    #[test]
    fn absent_boundary_currency_rejects_execution_without_draining_original_events() {
        use iroha_data_model::events::{
            EventBox,
            pipeline::{BlockStatus, PipelineEventBox},
        };

        // Omit the currency in the original signed genesis. Removing an authenticated
        // live definition would violate AXT incarnation custody before boundary execution.
        let mut chain = CertifiedTestChain::npos_boundary_fixture_with_currency(false);
        let currency = chain
            .state()
            .view()
            .world()
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .unwrap()
            .xor_asset_definition_id;
        assert!(
            chain
                .state()
                .view()
                .world()
                .asset_definitions()
                .get(&currency)
                .is_none(),
            "negative fixture omits currency from its original signed genesis"
        );
        let original = chain.committed(9);
        let proposal = chain.proposal(None, Vec::new());
        let error = match chain.begin_proposal(proposal, Default::default()) {
            Ok(_) => panic!("absent currency cannot authorize the native boundary"),
            Err(error) => error,
        };
        assert!(error.contains("Some(Invalid)"), "{error}");
        assert!(error.contains("native rejection: Some("), "{error}");
        assert_eq!(chain.height(), 9);
        assert_eq!(chain.committed(9).result(), original.result());
        assert!(chain.take_events().unwrap().iter().any(|event| matches!(
            event,
            EventBox::Pipeline(PipelineEventBox::Block(event))
                if event.header.height().get() == 10 && matches!(event.status, BlockStatus::Rejected(_))
        )));
    }

    #[test]
    fn custom_genesis_staking_observes_the_original_topology_before_moving_funds() {
        use iroha_data_model::{
            asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
            isi::{RegisterBox, RegisterPublicLaneValidator},
            nexus::PublicLaneMonetaryPlanV1,
            transaction::Executable,
        };
        use iroha_model_base::{domain::DomainId, topology::LaneId};
        use iroha_primitives::numeric::{NumericSpec, Quantity};

        let mut config = TestChainConfig::new(World::new(), 1_000);
        let owner = AccountId::new(config.genesis_key.public_key().clone());
        let (peer, _) = fixture_validators().remove(0);
        let validator = AccountId::new(peer.public_key().clone());
        let staking = iroha_config::parameters::actual::NexusStaking::default();
        let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
        let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
        let source_asset = AssetId::new(definition.clone(), validator.clone());
        let escrow_asset = AssetId::new(definition.clone(), escrow.clone());
        let amount = Quantity::from(1_000_u32);
        config.world = World::with_assets(
            [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&owner)],
            [
                Account::new(validator.clone()).build(&owner),
                Account::new(escrow.clone()).build(&owner),
            ],
            [AssetDefinition::new(
                definition,
                "Network XOR",
                NumericSpec::fractional(9),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&owner)],
            [Asset::new(source_asset.clone(), amount.clone())],
            [],
        );
        // This permissioned-chain fixture supplies the same initial staking policy
        // as its application consumers; it does not declare an NPoS consensus mode.
        let mut initial = config.world.block();
        initial
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                SumeragiNposParameters::default().into_custom_parameter(),
            ));
        initial.commit();
        config.genesis_instructions.push(
            RegisterPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: peer.clone(),
                stake_account: validator.clone(),
                initial_stake: amount.clone(),
                metadata: Default::default(),
                monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                    source_asset.clone(),
                    escrow_asset.clone(),
                    amount.clone(),
                ),
            }
            .into(),
        );
        let chain = CertifiedTestChain::start(config)
            .expect("original topology must precede peer-dependent genesis instructions");
        assert_eq!(chain.height(), 1);
        assert!(
            chain
                .genesis()
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        let mut topology_positions = Vec::new();
        let mut registration_position = None;
        for (index, transaction) in chain.genesis().external_transactions().enumerate() {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                panic!("genesis contains only original instruction batches")
            };
            for instruction in instructions {
                if matches!(
                    instruction.as_any().downcast_ref::<RegisterBox>(),
                    Some(RegisterBox::Peer(_))
                ) {
                    topology_positions.push(index);
                }
                if instruction.as_any().is::<RegisterPublicLaneValidator>() {
                    assert!(registration_position.replace(index).is_none());
                }
            }
        }
        assert_eq!(
            topology_positions.len(),
            4,
            "no duplicate peer registration workaround"
        );
        let registration_position = registration_position.expect("original custom registration");
        assert!(
            topology_positions
                .into_iter()
                .all(|index| index < registration_position)
        );
        let view = chain.state().view();
        let record = view
            .world()
            .public_lane_validators()
            .get(&(LaneId::SINGLE, validator))
            .expect("actual registered staking record");
        assert_eq!(record.peer_id, peer);
        assert_eq!(record.total_stake, amount);
        assert_eq!(record.self_stake, amount);
        assert_eq!(
            view.world()
                .assets()
                .get(&source_asset)
                .map_or_else(Quantity::zero, |asset| asset.as_ref().clone()),
            Quantity::zero(),
        );
        assert_eq!(
            view.world().assets().get(&escrow_asset).unwrap().as_ref(),
            &amount
        );
    }

    #[test]
    fn configured_genesis_and_exact_certified_replay_preserve_native_ownership() {
        let config = || {
            let mut config = TestChainConfig::new(World::new(), 1_000);
            let mut nexus = iroha_config::parameters::actual::Nexus::default();
            nexus.fees.base_fee = 0_u32.into();
            nexus.fees.per_byte_fee = 0_u32.into();
            nexus.fees.per_instruction_fee = 0_u32.into();
            nexus.fees.per_gas_unit_fee = 0_u32.into();
            config.nexus = Some(nexus);
            let mut zk = crate::state::default_zk_config();
            zk.max_verify_calls_per_tx = 3;
            config.zk = Some(zk);
            config.validator_keys = Some(
                (0xD1..=0xD4)
                    .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
                    .collect(),
            );
            config.crypto = Some(iroha_config::parameters::actual::Crypto::default());
            config
        };
        let mut source = CertifiedTestChain::start(config()).unwrap();
        assert_ne!(
            source.validators(),
            fixture_validators().as_slice(),
            "caller custody is the signed original committee"
        );
        source.commit(Vec::new());
        source.commit(Vec::new());
        let mut replay = CertifiedTestChain::start(config()).unwrap();
        replay.replay_from(&source).unwrap();
        assert_eq!(replay.tip, source.tip);
        assert_eq!(replay.state.zk_snapshot().max_verify_calls_per_tx, 3);
        for height in 1..=source.height() {
            assert_eq!(
                replay.committed(height).block().encode_wire().unwrap(),
                source.committed(height).block().encode_wire().unwrap()
            );
        }
        let mut foreign_config = config();
        foreign_config.genesis_time_ms += 1;
        let mut foreign = CertifiedTestChain::start(foreign_config).unwrap();
        assert!(foreign.replay_from(&source).is_err());
        assert_eq!(foreign.height(), 1);
    }

    #[test]
    fn configured_genesis_derives_da_geometry_before_signing_and_rejects_wrong_policy() {
        use iroha_crypto::HashOf;
        use iroha_data_model::{da::commitment::DaProofPolicyBundle, nexus::LaneCatalog};

        let mut config = TestChainConfig::new(World::new(), 1_000);
        let key = config.genesis_key.clone();
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.fees.base_fee = 0_u32.into();
        nexus.fees.per_byte_fee = 0_u32.into();
        nexus.fees.per_instruction_fee = 0_u32.into();
        nexus.fees.per_gas_unit_fee = 0_u32.into();
        nexus.lane_catalog = LaneCatalog::new(
            std::num::NonZeroU32::new(1).unwrap(),
            vec![iroha_data_model::nexus::LaneConfig {
                alias: "configured-primary".to_owned(),
                ..Default::default()
            }],
        )
        .unwrap();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        // Deliberately retain the prior derived table: the configured catalog is the source.
        let stale_policies = crate::da::active_proof_policy_bundle_at_height(&nexus, 1);
        assert!(stale_policies.policies().is_empty());
        config.nexus = Some(nexus);
        let prepared = CertifiedTestChain::prepare(config)
            .expect("custom catalog policies are signed before original genesis execution");
        let original = prepared.genesis.block();
        let actual_nexus = prepared.state.nexus_snapshot();
        let expected = crate::da::active_proof_policy_bundle_at_height(&actual_nexus, 1);
        assert_eq!(expected.policies().len(), 1);
        assert_eq!(expected.policies()[0].alias, "configured-primary");
        assert_eq!(original.da_proof_policies(), Some(&expected));
        assert_eq!(
            original.header().da_proof_policies_hash(),
            Some(HashOf::new(&expected))
        );
        assert_ne!(expected, stale_policies);
        let original_wire = prepared.genesis.canonical_wire().to_vec();

        // Independently sign the wrong policy; do not mutate a signed header or bypass
        // signature validation. The production policy check must reject it without output.
        let wrong_policy = DaProofPolicyBundle::new(Vec::new());
        let wrong = prepared
            .manifest
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &key,
                Some(wrong_policy.clone()),
                Some(crate::state::default_genesis_confidential_policy_hash()),
                1_000,
            )
            .unwrap()
            .0;
        let topology = super::super::network_topology::Topology::new(
            prepared
                .validator_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        assert!(
            validate_fixture_genesis_policy(
                prepared.genesis.block().clone(),
                &topology,
                &AccountId::new(key.public_key().clone()),
                &prepared.state,
                ConsensusMode::Permissioned,
                1,
            )
            .unwrap()
            .is_none(),
            "the helper preserves genuine completed genesis validation"
        );
        assert!(matches!(
            *validate_fixture_genesis_policy(
                wrong.clone(),
                &topology,
                &AccountId::new(key.public_key().clone()),
                &prepared.state,
                ConsensusMode::Permissioned,
                0,
            )
            .unwrap_err(),
            crate::block::BlockValidationError::ProofPolicyHashMismatch { expected: hash, actual }
                if hash == HashOf::new(&expected) && actual == Some(HashOf::new(&wrong_policy))
        ));
        {
            let validation = crate::block::ValidBlock::validate_signed_genesis(
                wrong,
                &topology,
                &AccountId::new(key.public_key().clone()),
                &TimeSource::new_system(),
                &prepared.state,
                ConsensusMode::Permissioned,
            )
            .unpack(|_| {});
            let (rejected, error) = match validation {
                Ok(_) => panic!("signed policy outside the configured catalog must be rejected"),
                Err(rejected) => rejected,
            };
            assert!(matches!(
                *error,
                crate::block::BlockValidationError::ProofPolicyHashMismatch { expected: hash, actual }
                    if hash == HashOf::new(&expected) && actual == Some(HashOf::new(&wrong_policy))
            ));
            assert!(rejected.execution_outputs().is_empty());
        }
        assert_eq!(prepared.state.view().height(), 0);
        assert_eq!(prepared.kura.blocks_count(), 0);

        let chain = CertifiedTestChain::from_prepared(prepared)
            .expect("the original custom-catalog genesis applies unchanged");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.genesis().encode_wire().unwrap(), original_wire);
    }

    fn prepared_config() -> PreparedTestChainConfig {
        iroha_genesis::init_instruction_registry();
        let chain_id = ChainId::from("original-prepared-native-fixture");
        let genesis_key = KeyPair::from_seed(vec![0xD0; 32], Algorithm::Ed25519);
        let clock = KeyPair::from_seed(vec![0xD5; 32], Algorithm::Ed25519);
        let mut keys = (0xD1..=0xD4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let validators = keys
            .iter()
            .map(|key| {
                (
                    PeerId::new(key.public_key().clone()),
                    bls_normal_pop_prove(key.private_key()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let (genesis, manifest) = build_genesis(
            &chain_id,
            &genesis_key,
            &validators,
            Vec::new(),
            Vec::new(),
            SumeragiConsensusMode::Permissioned,
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            10_000,
            NonZeroU64::new(1).expect("nonzero fixture cadence"),
        )
        .unwrap();
        let owner = AccountId::new(genesis_key.public_key().clone());
        let world = World::with(
            [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&owner)],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(AccountId::new(clock.public_key().clone())).build(&owner),
            ],
            [],
        );
        let (genesis, manifest, state, kura) = prepare_configured_genesis(
            world,
            &chain_id,
            &genesis_key,
            &validators,
            genesis,
            manifest,
            SumeragiConsensusMode::Permissioned,
            10_000,
            &iroha_config::parameters::actual::Pipeline::default(),
            &iroha_config::parameters::actual::FraudMonitoring::default(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let genesis = iroha_genesis::validate_prepared_genesis_bundle(
            &genesis.encode_wire().unwrap(),
            &manifest,
            genesis_key.public_key(),
            genesis.hash(),
        )
        .unwrap();
        PreparedTestChainConfig {
            genesis,
            manifest,
            state,
            kura,
            validator_keys: keys,
            pasta_seeds: (0..4)
                .map(|index| zeroize::Zeroizing::new([0xA0 + index; 32]))
                .collect(),
            clock,
            lane_blocks: Arc::new(crate::sumeragi::lanes::merge::NoLanes),
        }
    }

    mod pending_execution_tests {
        use super::*;
        include!("test_chain/pending_execution_tests.rs");
    }

    mod native_publication_tests {
        use super::*;
        include!("test_chain/native_publication_tests.rs");
    }

    mod world_state_tests {
        use super::*;
        include!("test_chain/world_state_tests.rs");
    }

    #[test]
    fn prepared_chain_executes_original_genesis_and_authenticates_its_result_at_h2() {
        let config = prepared_config();
        let original = config.genesis.canonical_wire().to_vec();
        let chain_id = config.manifest.chain_id().clone();
        let network = NetworkId::from_genesis_hash(config.genesis.expected_hash());
        let exact_state = Arc::clone(&config.state);
        let exact_kura = Arc::clone(&config.kura);
        let mut chain = CertifiedTestChain::from_prepared(config).unwrap();
        assert!(Arc::ptr_eq(chain.state(), &exact_state));
        assert!(Arc::ptr_eq(chain.kura(), &exact_kura));
        assert_eq!(chain.genesis().encode_wire().unwrap(), original);
        assert_ne!(chain.validators(), fixture_validators());
        let genesis = chain.committed(1);
        assert_eq!(
            genesis
                .block()
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection")
                .encode_wire()
                .unwrap(),
            original,
        );
        let mut prefix = super::super::certified_chain::CertifiedPrefix::new(
            &chain_id,
            network,
            genesis.block().clone(),
        )
        .unwrap();
        chain.commit_at(20_000, Vec::new());
        let successor = chain.committed(2);
        let (certified, anchor) = prefix.push(successor.block().clone()).unwrap().into_parts();
        assert_eq!(certified.core_hash(), successor.core_hash());
        let anchor = anchor.expect("actual H2 certificate authenticates original H1 result");
        assert_eq!(anchor.into_committed().result(), genesis.result());
        assert!(
            successor
                .block()
                .network_output_at(0)
                .unwrap()
                .1
                .result
                .is_ok()
        );
        assert!(successor.commitment().native_lanes.verify(
            network,
            2,
            successor.commitment().execution.ordinary_writes_root,
        ));
    }

    #[test]
    fn prepared_chain_rejects_foreign_or_incomplete_custody_before_execution() {
        for control in 0..5 {
            let mut config = prepared_config();
            match control {
                0 => config.validator_keys.swap(0, 1),
                1 => {
                    config.validator_keys.pop();
                }
                2 => config.pasta_seeds[2] = zeroize::Zeroizing::new([0xFF; 32]),
                3 => {
                    config.pasta_seeds.pop();
                }
                4 => config.kura = Kura::blank_kura_for_testing(),
                _ => unreachable!(),
            }
            let state = Arc::clone(&config.state);
            let error = CertifiedTestChain::from_prepared(config).unwrap_err();
            assert!(matches!(error.error, TestChainError::Genesis(_)));
            assert!(Arc::ptr_eq(&state, &error.state));
            assert_eq!(state.view().height(), 0);
            assert_eq!(state.kura().blocks_count(), 0);
        }
    }

    #[test]
    fn malformed_original_lane_merge_is_rejected_without_publication() {
        let mut chain = CertifiedTestChain::from_prepared(prepared_config()).unwrap();
        let before = chain.committed(1);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            chain.commit_with_proposal(
                Some(20_000),
                Vec::new(),
                Signers::Quorum,
                Default::default(),
                |proposal| {
                    let mut context = proposal.execution_context().cloned().unwrap_or_default();
                    context.lane_merge = Some(Default::default());
                    proposal.set_execution_context(Some(context));
                },
            );
        }));
        assert!(
            rejected.is_err(),
            "empty lane merge must fail actual execution"
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state().view().height(), 1);
        assert_eq!(chain.kura().blocks_count(), 1);
        assert_eq!(chain.committed(1).result(), before.result());
    }

    #[test]
    fn blocks_commit_certified_at_exact_times() {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000))
            .expect("chain starts");
        assert_eq!(chain.height(), 1);
        let genesis = chain.committed(1);
        assert!(genesis.header().is_none());
        assert_eq!(chain.commit_at(20_000, Vec::new()), Vec::<bool>::new());
        assert_eq!(chain.height(), 2);
        let block = chain.committed(2);
        assert_eq!(block.block_time_ms(), 20_000);
        assert!(block.extends(&genesis));
        // Without a target time the block follows its parent by the one-millisecond cadence.
        chain.commit(Vec::new());
        assert_eq!(chain.committed(3).block_time_ms(), 20_001);
        assert!(chain.committed(3).extends(&block));
        // A transaction of an unknown account executes and fails; its outcome is reported.
        let stranger = KeyPair::from_seed(vec![9; 32], Algorithm::Ed25519);
        let failing = chain.sign(
            &stranger,
            [InstructionBox::from(Log::new(Level::INFO, "who".into()))],
            29_999,
        );
        assert_eq!(chain.commit_at(30_000, vec![failing]), [false]);
        assert_eq!(chain.committed(4).block_time_ms(), 30_000);
    }
}
