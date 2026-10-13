//! Supervised native AMX delivery from authenticated local history through durable workflows.
//!
//! Source files never supply authority. Core's opaque intent binds the original certified
//! carrier, record and destination; explicit route configuration owns signing and fee custody.
//! Restart selects that source again and resumes the existing exact-byte workflow journal.

use std::{
    collections::BTreeMap,
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
        StepDescriptorV1, StepFailure, SystemWorkflowClock, WorkflowDriver, WorkflowEngine,
        WorkflowErrorCode, WorkflowFuture, WorkflowKindV1, WorkflowLedger, WorkflowPlanV1,
        WorkflowRunOptions, WorkflowStorage, domain_digest,
    },
};
use iroha_config::parameters::actual::{AmxRelay, AmxRelayRoute};
use iroha_core::{
    query::native_receipts::{NativeAmxRelayDescriptorV1, NativeAmxRelayIntentV1, amx_relays},
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

mod ledger;
use ledger::{RelayAccount, RelayLedger};

const ID_DOMAIN: &[u8] = b"iroha:native-amx-relay:v1\0";
// Service policy: authenticated rejections permit bounded fee-funded replacement.
const MAX_CARRIER_IDENTITIES: u8 = 3;

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

fn plan(descriptor: &NativeAmxRelayDescriptorV1) -> Result<WorkflowPlanV1> {
    // Local cadence, fee caps and endpoint addresses do not mint a replacement journal.
    // Both source scopes and original destination instance are authenticated coordinates.
    let bytes = norito::encode_canonical(&(
        descriptor.source_network(),
        descriptor.source_scope(),
        descriptor.source_height(),
        descriptor.source_carrier(),
        descriptor.source_record_key().to_vec(),
        descriptor.target_network(),
        descriptor.target_scope(),
        descriptor.target_instance(),
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
    if account_config.account != config.authority
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
        account.clone(),
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

impl Route {
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
        let plan = plan(descriptor)?;
        let digest = plan.request_context_digest;
        let handle = self.engine.workflow(plan)?;
        let (_, instruction) = intent.into_parts();
        let driver = RelayDriver {
            account: self.account.clone(),
            instruction: Mutex::new(Some(instruction)),
            fee_payment: self.config.fee_payment.clone(),
            digest,
        };
        self.ledger.begin_observation(instruction_digest)?;
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

/// Validate explicit routes and start one supervised original-source worker.
/// No routes means no signing, journal creation or background worker.
pub(crate) fn start(
    state: Arc<State>,
    config: AmxRelay,
    shutdown: ShutdownSignal,
) -> Result<Option<Child>> {
    if config.routes.is_empty() {
        return Ok(None);
    }
    let storage: Arc<dyn WorkflowStorage> =
        Arc::new(FileWorkflowStorage::open_or_create(&config.journal_dir)?);
    let routes = config
        .routes
        .iter()
        .cloned()
        .map(|route| {
            let key = route.network_id;
            build_route(route, storage.clone(), config.max_finality_proof_reads)
                .map(|route| (key, route))
        })
        .collect::<Result<BTreeMap<NetworkId, Route>>>()?;
    let runtime = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let mut height = 2u64;
        while !shutdown.is_sent() {
            let view = state.view();
            let tip = view.block_hashes().len() as u64;
            for _ in 0..config.max_source_heights_per_pass {
                if shutdown.is_sent() || height > tip {
                    break;
                }
                let mut original = match amx_relays(&view, height) {
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
                            if let Some(route) = routes.get(&intent.descriptor().target_network()) {
                                // The same original State view/job stays alive until the move-only
                                // instruction is consumed or explicitly retired after this attempt.
                                let result = runtime.block_on(async {
                                    tokio::select! {
                                        () = shutdown.receive() => Ok(()),
                                        result = route.deliver(intent, config.poll_interval) => result,
                                    }
                                });
                                if let Err(error) = result {
                                    iroha_logger::warn!(height, %error, "AMX workflow remains resumable");
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            iroha_logger::warn!(height, %error, "AMX original proof retained for retry");
                            if wait(&runtime, &shutdown, config.poll_interval) {
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
            }
            if wait(&runtime, &shutdown, config.poll_interval) {
                break;
            }
        }
    });
    Ok(Some(Child::new(
        task,
        OnShutdown::Wait(Duration::from_secs(5)),
    )))
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
