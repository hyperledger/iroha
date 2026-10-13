//! Supervised native AMX delivery from authenticated local history through durable workflows.
//!
//! Source files never supply authority. Core's opaque intent binds the original certified
//! carrier, record and destination; explicit route configuration owns signing and fee custody.
//! Restart selects that source again and resumes the existing exact-byte workflow journal.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read as _,
    sync::{Arc, Mutex},
    time::Duration,
};

use eyre::{Result, eyre};
use iroha::{
    client::{AccountClient, AccountTransactionDraft, AccountWorkflowContext, Client},
    workflow::{
        BuiltStepPayload, CommittedOutcome, DriverIdentityV1, FileWorkflowStorage, StepContext,
        StepDescriptorV1, StepFailure, SystemWorkflowClock, WorkflowClock, WorkflowDriver,
        WorkflowEngine, WorkflowErrorCode, WorkflowFuture, WorkflowKindV1, WorkflowLedger,
        WorkflowPlanV1, WorkflowRunOptions, WorkflowStorage, domain_digest,
    },
};
use iroha_config::parameters::actual::{AmxRelay, AmxRelayRoute};
use iroha_core::{
    query::native_receipts::{
        NativeAmxRelayDescriptorV1, NativeAmxRelayIntentV1, NativeAmxRelaySourceV1, amx_relays_to,
    },
    state::State,
};
use iroha_data_model::{
    NetworkId,
    isi::InstructionBox,
    sumeragi_finality::{
        MAX_SIGNED_GENESIS_BYTES_V1, SignedGenesisPinsV1, SumeragiFinalityVerifier,
        authenticate_signed_genesis_v1, authenticated_genesis,
    },
    transaction::FeePaymentIntent,
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_model_base::metadata::Metadata;
use sha2::{Digest as _, Sha256};

mod expiry;
mod ledger;
use expiry::{ExpiryProgress, ExpiryRecovery};
use ledger::{RelayAccount, RelayLedger};

const ID_DOMAIN: &[u8] = b"iroha:native-amx-relay:v1\0";
// Service policy: authenticated rejections permit bounded fee-funded replacement.
const MAX_CARRIER_IDENTITIES: u8 = 3;

// At most one cursor per configured route, scoped to the immutable source and
// destination roots. This is in-memory scheduling, never durable delivery evidence.
#[derive(Clone, Copy)]
struct ScanPosition {
    target: NetworkId,
    context: [u8; 32],
    identity: [u8; 32],
    height: u64,
    boundary: bool,
}
impl ScanPosition {
    fn from_descriptor(
        value: &NativeAmxRelayDescriptorV1,
        instruction: iroha_crypto::Hash,
    ) -> Result<Self> {
        let context = norito::encode_canonical(&(
            value.source_network(),
            value.source_scope(),
            value.target_network(),
            value.target_scope(),
            value.target_instance(),
        ))?;
        Ok(Self {
            target: value.target_network(),
            context: domain_digest(ID_DOMAIN, &[b"scan-context", &context]),
            identity: plan(value, instruction)?.request_context_digest,
            height: value.source_height(),
            boundary: matches!(value.source(), NativeAmxRelaySourceV1::EpochBoundary { .. }),
        })
    }
}
#[derive(Default)]
struct HandoffOrder {
    pending: BTreeMap<NetworkId, ScanPosition>,
    blocked: BTreeSet<NetworkId>,
}
impl HandoffOrder {
    fn permits(&mut self, position: ScanPosition) -> bool {
        if self.pending.get(&position.target).is_some_and(|pending| {
            pending.context != position.context
                || (pending.height == position.height
                    && position.boundary
                    && pending.identity != position.identity)
        }) {
            // A changed original history or root binding cannot inherit a cursor.
            self.pending.remove(&position.target);
            self.blocked.remove(&position.target);
        }
        if self.blocked.contains(&position.target) {
            return false;
        }
        // Earlier handoffs already authenticated in this process must not replace
        // a later unfinished recovery cursor on each source rescan. A process
        // restart discards this scheduling cursor and reauthenticates from H2.
        !position.boundary
            || !self
                .pending
                .get(&position.target)
                .is_some_and(|pending| position.height < pending.height)
    }
    fn observed(&mut self, position: ScanPosition, applied: bool) {
        if !position.boundary {
            return;
        }
        if applied {
            self.pending.remove(&position.target);
        } else {
            self.pending.insert(position.target, position);
            self.blocked.insert(position.target);
        }
    }
    fn restart_scan(&mut self) {
        self.blocked.clear();
    }
}

// Fix one finite authenticated source frontier per sweep. Continuous new traffic
// must not postpone a blocked historical handoff's next recovery observation.
#[derive(Default)]
struct ScanEnd(Option<u64>);
impl ScanEnd {
    fn for_pass(&mut self, observed_tip: u64) -> u64 {
        if cfg!(all(test, sumeragi_daemon_mutation = "HC332")) {
            return observed_tip;
        }
        *self.0.get_or_insert(observed_tip)
    }
    fn restart(&mut self) {
        self.0 = None;
    }
}

struct Route {
    config: AmxRelayRoute,
    account: AccountClient,
    ledger: Arc<RelayLedger>,
    engine: WorkflowEngine,
    instance: [u8; 32],
}

fn driver_identity() -> DriverIdentityV1 {
    DriverIdentityV1 {
        id: "native_amx_relay".into(),
        schema_version: 1,
    }
}

fn plan(
    descriptor: &NativeAmxRelayDescriptorV1,
    instruction: iroha_crypto::Hash,
) -> Result<WorkflowPlanV1> {
    // Local cadence, fee caps and endpoint addresses do not mint a replacement journal.
    // Both source scopes and original destination instance are authenticated coordinates.
    let bytes = norito::encode_canonical(&(
        descriptor.source_network(),
        descriptor.source_scope(),
        descriptor.source_height(),
        descriptor.source_carrier(),
        descriptor.source(),
        descriptor.target_network(),
        descriptor.target_scope(),
        descriptor.target_instance(),
        descriptor.ready_at_ms(),
        instruction,
    ))?;
    let digest = domain_digest(ID_DOMAIN, &[&bytes]);
    Ok(WorkflowPlanV1 {
        kind: WorkflowKindV1::AmxRelay,
        instance: hex::encode(digest),
        driver: driver_identity(),
        request_context_digest: digest,
        steps: vec![
            StepDescriptorV1::transaction("relay", digest)
                .with_max_transaction_identities(MAX_CARRIER_IDENTITIES),
        ],
    })
}

struct RelayDriver {
    account: AccountClient,
    instruction: Mutex<Option<InstructionBox>>,
    fee_payment: FeePaymentIntent,
    digest: [u8; 32],
}
impl WorkflowDriver for RelayDriver {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            if context.descriptor.intent_digest != self.digest
                || !(1..=MAX_CARRIER_IDENTITIES).contains(&context.identity_ordinal)
            {
                return Err(StepFailure::new(
                    WorkflowErrorCode::BindingMismatch,
                    "AMX original source or identity ordinal changed",
                ));
            }
            let instruction = self
                .instruction
                .lock()
                .map_err(|_| {
                    StepFailure::new(
                        WorkflowErrorCode::LocalResourceUnavailable,
                        "AMX original instruction owner poisoned",
                    )
                })?
                .take()
                .ok_or_else(|| {
                    StepFailure::new(
                        WorkflowErrorCode::LocalResourceUnavailable,
                        "AMX original instruction already moved into its payload",
                    )
                })?;
            let payload = self
                .account
                .prepare_transaction(AccountTransactionDraft::new(
                    vec![instruction],
                    self.fee_payment.clone(),
                    Metadata::default(),
                ))
                .map_err(|error| {
                    StepFailure::new(WorkflowErrorCode::InvalidInput, error.to_string())
                })?;
            let unsigned_payload = norito::encode_canonical(&payload).map_err(|error| {
                StepFailure::new(
                    WorkflowErrorCode::LocalResourceUnavailable,
                    error.to_string(),
                )
            })?;
            Ok(BuiltStepPayload {
                intent_digest: self.digest,
                unsigned_payload,
            })
        })
    }
}

fn trust(config: &AmxRelayRoute) -> Result<SumeragiFinalityVerifier> {
    let file = File::open(&config.signed_genesis)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_SIGNED_GENESIS_BYTES_V1 as u64 {
        return Err(eyre!(
            "AMX trust file is not a bounded regular signed genesis"
        ));
    }
    let mut wire = Vec::new();
    file.take(MAX_SIGNED_GENESIS_BYTES_V1 as u64 + 1)
        .read_to_end(&mut wire)?;
    if wire.len() > MAX_SIGNED_GENESIS_BYTES_V1
        || <[u8; 32]>::from(Sha256::digest(&wire)) != config.signed_genesis_sha256
    {
        return Err(eyre!(
            "AMX signed genesis differs from its independently configured digest"
        ));
    }
    let block = iroha_data_model::block::decode_framed_signed_block(&wire)?;
    // Roster and mode are obtained only after the independently pinned exact file digest.
    let (epoch, scope) = authenticated_genesis(&block)?.into_parts();
    if scope != config.scope {
        return Err(eyre!(
            "AMX destination root scope differs from configured trust"
        ));
    }
    let pins = SignedGenesisPinsV1 {
        chain_id: config.chain_id.to_string(),
        network_id: config.network_id,
        genesis_hash: block.hash(),
        signed_genesis_sha256: config.signed_genesis_sha256,
        genesis_public_key: config.genesis_public_key.clone(),
        mode: epoch.mode,
        roster: epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect(),
    };
    let authenticated = authenticate_signed_genesis_v1(&wire, &pins)?;
    Ok(SumeragiFinalityVerifier::new(
        authenticated.block(),
        &pins.chain_id,
        authenticated.validators().to_vec(),
    )?)
}

fn build_route(
    config: AmxRelayRoute,
    storage: Arc<dyn WorkflowStorage>,
    reads: usize,
) -> Result<Route> {
    let verifier = trust(&config)?;
    let account_config = iroha::config::Config::load_file(&config.account_config)?;
    let authority_matches = account_config.account == config.authority;
    if !authority_matches
        || account_config.network_id != config.network_id
        || account_config.chain != config.chain_id
    {
        return Err(eyre!(
            "AMX account file differs from explicit authority, network or chain pins"
        ));
    }
    let client = Arc::new(Client::builder(account_config).build()?);
    let account = client.account_client()?;
    let context = Arc::new(AccountWorkflowContext::new(account.clone())?);
    let instance = verifier.instance().0;
    let ledger = Arc::new(RelayLedger::new(
        client,
        &account,
        context.clone(),
        verifier,
        config.scope,
        config.fee_payment.clone(),
        reads,
    ));
    let engine = WorkflowEngine::new(
        storage,
        Arc::new(RelayAccount {
            account: context,
            ledger: ledger.clone(),
        }),
        ledger.clone(),
        Arc::new(SystemWorkflowClock::new()),
    );
    Ok(Route {
        config,
        account,
        ledger,
        engine,
        instance,
    })
}

// The opaque source authenticates the original X; its registered target and exact local
// leg select the independently owner-issued permission. Source proof is never that permission.
fn debit_approval(
    descriptor: &NativeAmxRelayDescriptorV1,
    instruction: &InstructionBox,
) -> Result<Option<iroha_data_model::sumeragi_amx::AmxDebitApprovalV1>> {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        isi::sumeragi_amx::PrepareAmxV1,
        sumeragi_amx::{AmxDebitApprovalV1, AmxTransferLegV1},
    };
    let Some(prepare) = instruction.as_any().downcast_ref::<PrepareAmxV1>() else {
        return Ok(None);
    };
    let SumeragiRootScope::Dataspace {
        parent_network_id,
        dataspace_id,
    } = descriptor.target_scope()
    else {
        return Err(eyre!("AMX Prepare cannot target a Global root"));
    };
    if parent_network_id != descriptor.source_network()
        || descriptor.source_scope() != SumeragiRootScope::Global
        || dataspace_id != prepare.dataspace
    {
        return Err(eyre!(
            "AMX Prepare approval differs from its original registered roots"
        ));
    }
    let leg = prepare
        .transaction
        .leg(dataspace_id)
        .ok_or_else(|| eyre!("AMX Prepare lacks exact local terms"))?;
    let transfer: AmxTransferLegV1 = norito::decode_canonical_with_limits(
        &leg.payload,
        norito::canonical_decode_limits(leg.payload.len()),
    )?;
    let approval = AmxDebitApprovalV1 {
        global_network: parent_network_id,
        participant_network: descriptor.target_network(),
        participant_instance: descriptor.target_instance(),
        dataspace: dataspace_id,
        transaction_id: prepare.transaction.id()?,
        debited_asset: transfer.source,
    };
    approval.validate_root(
        descriptor.target_network(),
        descriptor.target_scope(),
        descriptor.target_instance(),
    )?;
    Ok(Some(approval))
}

impl Route {
    // A business Decision ends new expiry work, while an existing exact carrier
    // still needs read-only outcome recovery. This path cannot sign or dispatch.
    async fn recover_decided_expiry(
        &self,
        intent: &NativeAmxRelayIntentV1,
        cadence: Duration,
    ) -> Result<()> {
        let descriptor = intent.descriptor();
        if descriptor.target_network() != self.config.network_id
            || descriptor.target_scope() != self.config.scope
            || descriptor.target_instance() != self.instance
        {
            return Err(eyre!(
                "AMX expiry recovery differs from independently pinned route"
            ));
        }
        let instruction = ledger::instruction_digest(intent.instruction())?;
        self.ledger.begin_observation(instruction, None)?;
        expiry::recover_carrier(
            &self.engine,
            self.ledger.as_ref(),
            plan(descriptor, instruction)?,
            cadence,
        )
        .await
    }

    async fn deliver(&self, intent: NativeAmxRelayIntentV1, cadence: Duration) -> Result<()> {
        let descriptor = intent.descriptor();
        let instruction_digest = ledger::instruction_digest(intent.instruction())?;
        if descriptor.target_network() != self.config.network_id
            || descriptor.target_scope() != self.config.scope
            || descriptor.target_instance() != self.instance
        {
            return Err(eyre!(
                "AMX source selects a destination different from independently pinned route"
            ));
        }
        let approval = debit_approval(intent.descriptor(), intent.instruction())?;
        self.ledger
            .begin_observation(instruction_digest, approval)?;
        if matches!(
            descriptor.source(),
            NativeAmxRelaySourceV1::EpochBoundary { .. }
        ) && self.ledger.recover_handoff(intent.instruction()).await?
        {
            // Independently authenticated effect, possibly another relayer's carrier.
            // This neither decodes terminal journal state nor closes an unknown carrier.
            return Ok(());
        }
        let plan = plan(descriptor, instruction_digest)?;
        let digest = plan.request_context_digest;
        let handle = self.engine.workflow(plan)?;
        let (_, instruction) = intent.into_parts();
        let driver = RelayDriver {
            account: self.account.clone(),
            instruction: Mutex::new(Some(instruction)),
            fee_payment: self.config.fee_payment.clone(),
            digest,
        };
        let progress = handle
            .run(
                &driver,
                &WorkflowRunOptions {
                    observation_timeout: cadence,
                    poll_interval: cadence,
                    retransmit_identical_bytes: true,
                    retry_rejected_step: true,
                },
            )
            .await?;
        // A decoded completed journal never substitutes for fresh destination authentication.
        let identity = progress
            .steps
            .first()
            .and_then(|step| step.identities.last())
            .and_then(|attempt| attempt.identity.as_ref())
            .ok_or_else(|| eyre!("completed AMX workflow has no exact carrier identity"))?;
        match self.ledger.committed_outcome(identity).await {
            CommittedOutcome::Applied { .. } => Ok(()),
            _ => Err(eyre!(
                "AMX delivery awaits freshly authenticated successful execution"
            )),
        }
    }
}

/// Validate all explicit routes, then start one supervised original-source worker per route.
/// No routes means no signing, journal creation or background worker.
pub fn start(
    state: Arc<State>,
    config: AmxRelay,
    shutdown: ShutdownSignal,
) -> Result<Vec<Child>> {
    if config.routes.is_empty() {
        return Ok(Vec::new());
    }
    validate_route_set(&config.routes)?;
    let storage: Arc<dyn WorkflowStorage> =
        Arc::new(FileWorkflowStorage::open_or_create(&config.journal_dir)?);
    let routes = config
        .routes
        .into_iter()
        .map(|route| {
            let key = route.network_id;
            build_route(route, storage.clone(), config.max_finality_proof_reads)
                .map(|route| (key, route))
        })
        .collect::<Result<BTreeMap<NetworkId, Route>>>()?;
    let runtime = tokio::runtime::Handle::current();
    Ok(routes
        .into_values()
        .map(|route| {
            start_route(
                Arc::clone(&state),
                route,
                config.max_source_heights_per_pass,
                config.max_finality_proof_reads,
                config.poll_interval,
                runtime.clone(),
                shutdown.clone(),
            )
        })
        .collect())
}

fn validate_route_set(routes: &[AmxRelayRoute]) -> Result<()> {
    if routes.len() > iroha_config::parameters::defaults::amx_relay::MAX_ROUTES {
        return Err(eyre!("AMX route count exceeds the supervised worker bound"));
    }
    let mut networks = BTreeSet::new();
    if routes
        .iter()
        .any(|route| !networks.insert(route.network_id))
    {
        return Err(eyre!(
            "AMX destinations must have one original-source worker each"
        ));
    }
    Ok(())
}

fn start_route(
    state: Arc<State>,
    route: Route,
    max_source_heights_per_pass: usize,
    max_finality_proof_reads: usize,
    cadence: Duration,
    runtime: tokio::runtime::Handle,
    shutdown: ShutdownSignal,
) -> Child {
    let task = tokio::task::spawn_blocking(move || {
        let mut height = 2u64;
        let mut scan_end = ScanEnd::default();
        let mut handoff_order = HandoffOrder::default();
        let clock = SystemWorkflowClock::new();
        let target = route.config.network_id;
        let mut expiry_recovery = ExpiryRecovery::default();
        while !shutdown.is_sent() {
            let view = state.view();
            let tip = scan_end.for_pass(view.block_hashes().len() as u64);
            for _ in 0..max_source_heights_per_pass {
                if shutdown.is_sent() || height > tip {
                    break;
                }
                let mut original = match amx_relays_to(&view, height, target) {
                    Ok(original) => original,
                    Err(error) => {
                        iroha_logger::warn!(height, %error, "AMX original source unavailable");
                        break;
                    }
                };
                loop {
                    if shutdown.is_sent() {
                        return;
                    }
                    match original.complete_next() {
                        Ok(Some(intent)) => {
                            let position = match ledger::instruction_digest(intent.instruction())
                                .and_then(|digest| {
                                    ScanPosition::from_descriptor(intent.descriptor(), digest)
                                }) {
                                Ok(position) => position,
                                Err(error) => {
                                    iroha_logger::warn!(height, %error, "AMX source scan identity unavailable");
                                    break;
                                }
                            };
                            if !handoff_order.permits(position) {
                                // An earlier handoff has no authenticated successful outcome.
                                // Do not spend fresh identities on a later epoch/record yet.
                                continue;
                            }
                            let decided = match expiry_recovery.observe(
                                &view,
                                &intent,
                                clock.now_unix_ms(),
                                max_finality_proof_reads,
                                &runtime,
                                &shutdown,
                                cadence,
                            ) {
                                Ok(ExpiryProgress::Ordinary | ExpiryProgress::Ready) => false,
                                Ok(ExpiryProgress::Decided) => true,
                                Ok(ExpiryProgress::Waiting) => {
                                    continue;
                                }
                                Err(error) => {
                                    iroha_logger::warn!(height, %error, "AMX expiry recovery remains resumable");
                                    continue;
                                }
                            };
                            // The same original State view/job stays alive until the move-only
                            // instruction is consumed or explicitly retired after this attempt.
                            let result = runtime.block_on(async {
                                tokio::select! {
                                    () = shutdown.receive() => Ok(()),
                                    result = async {
                                        if decided {
                                            route.recover_decided_expiry(&intent, cadence).await
                                        } else {
                                            route.deliver(intent, cadence).await
                                        }
                                    } => result,
                                }
                            });
                            handoff_order.observed(position, result.is_ok());
                            if let Err(error) = result {
                                iroha_logger::warn!(height, %error, "AMX workflow remains resumable");
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            iroha_logger::warn!(height, %error, "AMX original proof retained for retry");
                            if wait(&runtime, &shutdown, cadence) {
                                return;
                            }
                        }
                    }
                }
                height += 1;
            }
            drop(view);
            if height > tip {
                height = 2;
                scan_end.restart();
                handoff_order.restart_scan();
            }
            if wait(&runtime, &shutdown, cadence) {
                break;
            }
        }
    });
    Child::new(task, OnShutdown::Drain)
}

fn wait(runtime: &tokio::runtime::Handle, shutdown: &ShutdownSignal, duration: Duration) -> bool {
    runtime.block_on(async { tokio::select! { () = shutdown.receive() => true, () = tokio::time::sleep(duration) => false } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId, block::consensus::SumeragiRootScope,
        sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };

    #[test]
    fn relay_source_schema_roundtrips_and_binds_both_source_variants() {
        use iroha_data_model::sumeragi_amx::{AmxRecordKind, amx_record_witness_key};
        use norito::core::{DecodeFlagsGuard, default_encode_flags};

        assert_eq!(
            <NativeAmxRelaySourceV1 as norito::NoritoSchema>::nominal_name(),
            "iroha_core::query::native_receipts::NativeAmxRelaySourceV1"
        );
        let sources = [
            NativeAmxRelaySourceV1::Record {
                key: amx_record_witness_key(AmxRecordKind::Begin, [7; 32]),
            },
            NativeAmxRelaySourceV1::Record {
                key: amx_record_witness_key(AmxRecordKind::Prepared, [7; 32]),
            },
            NativeAmxRelaySourceV1::Record {
                key: amx_record_witness_key(AmxRecordKind::Begin, [8; 32]),
            },
            NativeAmxRelaySourceV1::EpochBoundary {
                epoch: 7,
                next_epoch: 8,
            },
            NativeAmxRelaySourceV1::EpochBoundary {
                epoch: 6,
                next_epoch: 8,
            },
            NativeAmxRelaySourceV1::EpochBoundary {
                epoch: 7,
                next_epoch: 9,
            },
        ];
        let mut identities = BTreeSet::new();
        for source in sources {
            let canonical = norito::encode_canonical(&source).unwrap();
            assert!(identities.insert(domain_digest(ID_DOMAIN, &[&canonical])));
            for flags in [
                0,
                default_encode_flags(),
                default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN,
            ] {
                let _ambient = DecodeFlagsGuard::enter(flags);
                assert_eq!(norito::encode_canonical(&source).unwrap(), canonical);
                assert_eq!(
                    norito::decode_canonical::<NativeAmxRelaySourceV1>(&canonical).unwrap(),
                    source
                );
                assert_eq!(norito::core::get_decode_flags(), flags);
            }
        }
        // These public identity coordinates, including a successful decode, grant no
        // authority to construct the opaque relay intent, sign, fund or deliver work.
    }

    #[test]
    fn growing_source_tip_cannot_starve_pending_original_handoff_retry() {
        let mut scan_end = ScanEnd::default();
        let mut height = 2;
        let mut retries = Vec::new();
        let mut independent_heights = Vec::new();
        // One selected source height per pass and one additional certified height
        // per observation reproduce the starvation of an ever-moving frontier.
        for pass in 0..8 {
            let tip = scan_end.for_pass(3 + pass);
            if height <= tip {
                if height == 2 {
                    retries.push(pass);
                } else {
                    independent_heights.push(height);
                }
                height += 1;
            }
            if height > tip {
                height = 2;
                scan_end.restart();
            }
        }
        assert_eq!(
            retries,
            [0, 2, 6],
            "continuous source growth must not starve bounded retry of the original handoff"
        );
        assert!(
            independent_heights.contains(&5),
            "independent source work also progresses"
        );
    }

    #[test]
    fn unresolved_handoff_defers_later_route_work_until_an_authenticated_rescan() {
        let first = NativeFinalityFixture::start("amx-handoff-order-first").network_id();
        let second =
            NativeFinalityFixture::start_with_explicit_parameters("amx-handoff-order-second")
                .network_id();
        assert_ne!(
            first, second,
            "independent routes require distinct signed genesis, not just chain labels"
        );
        let early = ScanPosition {
            target: first,
            context: [1; 32],
            identity: [10; 32],
            height: 10,
            boundary: true,
        };
        let pending = ScanPosition {
            identity: [20; 32],
            height: 20,
            ..early
        };
        let record = ScanPosition {
            boundary: false,
            ..pending
        };
        let mut order = HandoffOrder::default();
        order.observed(record, false);
        assert!(
            order.permits(record),
            "ordinary pending work does not serialize independent obligations"
        );
        order.observed(early, true);
        order.observed(pending, false);
        assert!(
            !order.permits(record),
            "unresolved authority handoff must defer all later work for its route"
        );
        assert!(
            order.permits(ScanPosition {
                target: second,
                ..pending
            }),
            "a different independent root keeps progressing"
        );
        order.restart_scan();
        assert!(
            !order.permits(early),
            "an earlier authenticated handoff must not reset the pending recovery cursor"
        );
        assert!(
            order.permits(pending),
            "a new original-history pass must retry its earliest unresolved handoff"
        );
        order.observed(pending, true);
        assert!(
            order.permits(record),
            "authenticated delivery permits later sequential authority work"
        );
        order.observed(pending, false);
        order.restart_scan();
        assert!(
            order.permits(ScanPosition {
                context: [2; 32],
                ..early
            }),
            "changed source or destination roots discard the old scheduling cursor"
        );
        order.observed(pending, false);
        order.restart_scan();
        assert!(
            order.permits(ScanPosition {
                identity: [21; 32],
                ..pending
            }),
            "changed original carrier discards the old scheduling cursor"
        );
        assert!(order.pending.is_empty());
        assert!(
            HandoffOrder::default().permits(early),
            "restart authenticates original history again"
        );
    }

    #[test]
    fn relay_trust_requires_exact_original_and_independent_signer() {
        let fixture = NativeFinalityFixture::start("amx-route-trust");
        let root = tempfile::tempdir().unwrap();
        let genesis = root.path().join("genesis.nrt");
        let wire = fixture.genesis().encode_wire().unwrap();
        std::fs::write(&genesis, &wire).unwrap();
        let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let route = AmxRelayRoute {
            network_id: fixture.network_id(),
            chain_id: fixture.chain_id().parse().unwrap(),
            scope: SumeragiRootScope::Global,
            authority: AccountId::new(key.public_key().clone()),
            account_config: root.path().join("account.toml"),
            signed_genesis: genesis,
            signed_genesis_sha256: Sha256::digest(&wire).into(),
            genesis_public_key: key.public_key().clone(),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        };
        assert!(validate_route_set(&[]).is_ok());
        assert!(validate_route_set(std::slice::from_ref(&route)).is_ok());
        assert!(
            validate_route_set(&[route.clone(), route.clone()])
                .unwrap_err()
                .to_string()
                .contains("one original-source worker")
        );
        let mut bounded = (0..iroha_config::parameters::defaults::amx_relay::MAX_ROUTES)
            .map(|index| {
                let mut selected = route.clone();
                selected.network_id =
                    NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::new(index.to_le_bytes()),
                    ));
                selected
            })
            .collect::<Vec<_>>();
        assert!(validate_route_set(&bounded).is_ok());
        bounded.push(route.clone());
        assert!(
            validate_route_set(&bounded)
                .unwrap_err()
                .to_string()
                .contains("worker bound")
        );
        assert_eq!(
            trust(&route).unwrap().instance(),
            fixture.verifier().instance()
        );
        let mut wrong = route.clone();
        wrong.signed_genesis_sha256[0] ^= 1;
        assert!(trust(&wrong).is_err());
        wrong = route.clone();
        wrong.genesis_public_key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
            .public_key()
            .clone();
        assert!(trust(&wrong).is_err());
        wrong = route.clone();
        wrong.network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"foreign genesis identity"),
            ));
        assert!(trust(&wrong).is_err());
        std::fs::write(&route.signed_genesis, &wire[..wire.len() - 1]).unwrap();
        assert!(trust(&route).is_err());
    }
}
