//! Best-effort Torii push notification bridge.
//!
//! Local device, delivery, and provider-credential files are consumed through bounded direct-file
//! reads. Each device is one flat, token-fingerprint-keyed record, so an account reassignment is a
//! single atomic replacement. Startup enumeration and dispatch are likewise count-bounded so
//! corrupted local persistence cannot determine peak memory. Remote provider bodies are streamed
//! under one source-coupled ceiling, and successful delivery responses are not buffered.
use crate::{account_activity::AccountActivityRole, secure_file_metadata};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use dashmap::DashMap;
use iroha_allocation::{AllocationRefusal, PrepaidSharedError, release::ReleaseRegistration};
use iroha_config::parameters::actual;
#[cfg(test)]
use iroha_core::kura::Kura;
use iroha_core::{
    EventsSender,
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred},
    state::State,
};
use iroha_crypto::HashOf;
#[cfg(test)]
use iroha_data_model::transaction::SignedTransaction;
use iroha_data_model::{
    account::AccountId,
    block::{BlockHeader, SharedSignedBlock, SignedBlock},
    events::{
        EventBox,
        pipeline::{BlockStatus, PipelineEventBox},
    },
};
use iroha_futures::supervisor::ShutdownSignal;
use jsonwebtoken::{Algorithm, EncodingKey};
#[cfg(test)]
use nonzero_ext::nonzero;
use parking_lot::Mutex as StorageMutex;
use reqwest::StatusCode as HttpStatusCode;
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read as _, Write as _},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
const PUSH_DIR: &str = "push";
const PUSH_INITIALIZATION_DIR: &str = ".push-initialize-v1";
const DEVICES_DIR: &str = "devices";
const QUEUE_DIR: &str = "queue";
const APPLIED_BLOCK_CURSOR_FILE: &str = "applied-block-cursor.json";
const APPLIED_BLOCK_CURSOR_VERSION: u32 = 1;
const FCM_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const APNS_SANDBOX_ENDPOINT: &str = "https://api.sandbox.push.apple.com";
const APNS_PRODUCTION_ENDPOINT: &str = "https://api.push.apple.com";
const INITIAL_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);
const DISPATCH_TICK: Duration = Duration::from_secs(5);
// Push persistence is local best-effort state, but every record remains resident
// after startup. These source-local ceilings bound both directory work and the
// retained maps; field validation keeps a maximum-count set from amplifying its
// bounded on-disk representation into unbounded strings or collections.
const MAX_PUSH_DEVICES: usize = 4 * 1024;
const MAX_PUSH_QUEUE_JOBS: usize = 4 * MAX_PUSH_DEVICES;
const MAX_PUSH_DEVICE_RECORD_BYTES: usize = 64 * 1024;
const MAX_PUSH_QUEUE_JOB_BYTES: usize = 16 * 1024;
const MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES: usize = 1024;
const MAX_PUSH_RECOVERABLE_TEMP_FILES: usize = 1;
const MAX_PUSH_TOKEN_BYTES: usize = 8 * 1024;
// `torii.push.max_topics_per_device` may lower, but never raise, this invariant.
const MAX_PUSH_TOPICS: usize = 256;
const MAX_PUSH_TOPIC_BYTES: usize = 256;
const MAX_PUSH_TOPIC_BYTES_PER_DEVICE: usize = 8 * 1024;
const MAX_PUSH_ACTIVITY_KIND_BYTES: usize = 256;
const MAX_PUSH_TX_HASH_BYTES: usize = 256;
const MAX_PUSH_DIRECTION_BYTES: usize = 64;
const MAX_FCM_SERVICE_ACCOUNT_BYTES: usize = 64 * 1024;
const MAX_APNS_PRIVATE_KEY_BYTES: usize = 16 * 1024;
// FCM OAuth/send and APNs responses are small, fixed-schema JSON envelopes.
// Keep one local ceiling for every provider-controlled response body so a
// proxy, chunked sender, or future transparent decompressor cannot grow a
// dispatch task's retained buffer without bound.
const MAX_PUSH_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;
const PUSH_DISPATCH_BATCH_SIZE: usize = 256;
static PUSH_INITIALIZATION_GUARD: StorageMutex<()> = StorageMutex::new(());
#[derive(Clone, Copy, Debug)]
struct PushStorageLimits {
    max_devices: usize,
    max_queue_jobs: usize,
    max_device_record_bytes: usize,
    max_queue_job_bytes: usize,
    dispatch_batch_size: usize,
}
const PUSH_STORAGE_LIMITS: PushStorageLimits = PushStorageLimits {
    max_devices: MAX_PUSH_DEVICES,
    max_queue_jobs: MAX_PUSH_QUEUE_JOBS,
    max_device_record_bytes: MAX_PUSH_DEVICE_RECORD_BYTES,
    max_queue_job_bytes: MAX_PUSH_QUEUE_JOB_BYTES,
    dispatch_batch_size: PUSH_DISPATCH_BATCH_SIZE,
};
/// Logical push notification target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Fcm,
    Apns,
}
impl Platform {
    fn from_label(label: &str) -> Result<Self, PushError> {
        match label {
            "FCM" => Ok(Self::Fcm),
            "APNS" => Ok(Self::Apns),
            _ => Err(PushError::InvalidPlatform(label.to_owned())),
        }
    }
    fn from_stored(label: &str) -> Option<Self> {
        match label {
            "FCM" => Some(Self::Fcm),
            "APNS" => Some(Self::Apns),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Fcm => "FCM",
            Self::Apns => "APNS",
        }
    }
}
/// Request payload for `POST /v1/notify/devices` and `DELETE /v1/notify/devices`.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::push::RegisterDeviceRequest")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]

pub struct RegisterDeviceRequest {
    pub account_id: String,
    pub platform: String,
    pub token: String,
    pub topics: Option<Vec<String>>,
}
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct RegisteredDevice {
    pub account_id: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::push::PushActivityPayload")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
pub struct PushActivityPayload {
    pub account_id: String,
    pub activity_kind: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub instruction_index: u64,
    pub direction: String,
}
#[derive(Debug, Clone)]
pub enum PushError {
    Disabled,
    InvalidAccount(String),
    InvalidPlatform(String),
    InvalidEnvironment(String),
    MissingCredentials { platform: Platform },
    TooManyTopics { max: usize },
    EmptyToken,
    InvalidToken,
    InvalidTopic { index: usize },
    DuplicateTopic { index: usize },
    TopicsTooLarge { max_bytes: usize },
    Storage(String),
}
/// Original-pool refusal before a push worker acquires any startup effects.
#[derive(Debug, thiserror::Error)]
pub enum PushWorkerStartError {
    /// The original State pool could not admit the exact retry control.
    #[error("push retry control admission: {0}")]
    Admission(#[source] AllocationRefusal),
    /// Construction failed after the control's exact layout was prepaid.
    #[error("push retry control construction: {0}")]
    Registration(#[source] PrepaidSharedError),
}

/// Dispatch settings derived from configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchSettings {
    /// HTTP connect timeout.
    pub connect_timeout: Duration,
    /// HTTP request timeout.
    pub request_timeout: Duration,
}
/// Provider-specific credentials derived from configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderCredentials {
    Fcm {
        project_id: String,
        service_account_path: PathBuf,
    },
    Apns {
        endpoint: String,
        topic: String,
        team_id: String,
        key_id: String,
        private_key_path: PathBuf,
    },
}
/// Single provider delivery attempt.
#[derive(Clone, Debug)]
pub struct PushDelivery {
    #[cfg(test)]
    pub platform: Platform,
    pub token: String,
    pub payload: PushActivityPayload,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    Sent,
    Retry(String),
    InvalidToken(String),
    PermanentFailure(String),
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::push::AppliedBlockCursor")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
struct AppliedBlockCursor {
    version: u32,
    height: u64,
    block_hash: Option<HashOf<BlockHeader>>,
}
impl AppliedBlockCursor {
    const fn origin() -> Self {
        Self {
            version: APPLIED_BLOCK_CURSOR_VERSION,
            height: 0,
            block_hash: None,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.version != APPLIED_BLOCK_CURSOR_VERSION {
            return Err(invalid_data(format!(
                "unsupported push applied-block cursor version {}; expected {}",
                self.version, APPLIED_BLOCK_CURSOR_VERSION
            )));
        }
        match (self.height, self.block_hash.as_ref()) {
            (0, None) | (1.., Some(_)) => Ok(()),
            (0, Some(_)) => Err(invalid_data(
                "push applied-block cursor at origin must not carry a block hash",
            )),
            (_, None) => Err(invalid_data(
                "nonzero push applied-block cursor must carry its block hash",
            )),
        }
    }
}
#[derive(Debug)]
enum PushReplayError {
    AwaitingGenesisSuccessor,
    Deferred(ExecutionDeferred),
    Backpressure {
        height: u64,
        queued: usize,
        required: usize,
        maximum: usize,
    },
    Fatal(PushError),
}
impl From<PushError> for PushReplayError {
    fn from(error: PushError) -> Self {
        Self::Fatal(error)
    }
}
impl From<ExecutionAttemptError<PushError>> for PushReplayError {
    fn from(error: ExecutionAttemptError<PushError>) -> Self {
        match error {
            ExecutionAttemptError::Deferred(reason) => Self::Deferred(reason),
            ExecutionAttemptError::Rejected(error) => Self::Fatal(error),
        }
    }
}
#[derive(Clone, Copy)]
enum PushReplayTarget {
    Authoritative,
    Height(u64),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PushReplayOutcome {
    Complete,
    StoppedByShutdown,
}
/// Dispatcher trait so provider delivery can be mocked in tests.
#[async_trait]
pub trait PushDispatcher: Send + Sync {
    /// Dispatch a payload to the configured push provider.
    async fn send(
        &self,
        delivery: &PushDelivery,
        settings: &DispatchSettings,
        credentials: &ProviderCredentials,
    ) -> DispatchOutcome;
}
#[derive(Clone, Default)]
struct RealPushDispatcher;
#[async_trait]
impl PushDispatcher for RealPushDispatcher {
    async fn send(
        &self,
        delivery: &PushDelivery,
        settings: &DispatchSettings,
        credentials: &ProviderCredentials,
    ) -> DispatchOutcome {
        match credentials {
            ProviderCredentials::Fcm {
                project_id,
                service_account_path,
            } => send_fcm_http_v1(project_id, service_account_path, delivery, settings).await,
            ProviderCredentials::Apns {
                endpoint,
                topic,
                team_id,
                key_id,
                private_key_path,
            } => {
                send_apns_http2(
                    endpoint,
                    topic,
                    team_id,
                    key_id,
                    private_key_path,
                    delivery,
                    settings,
                )
                .await
            }
        }
    }
}
#[derive(Clone)]
pub struct PushBridge {
    config: actual::Push,
    settings: DispatchSettings,
    dispatcher: Arc<dyn PushDispatcher>,
    devices: Arc<DashMap<String, DeviceRecord>>,
    queue: Arc<DashMap<String, DeliveryJob>>,
    data_dir: Arc<PathBuf>,
    storage_limits: PushStorageLimits,
    mutation_guard: Arc<StorageMutex<()>>,
    applied_block_cursor: Arc<StorageMutex<AppliedBlockCursor>>,
}
impl PushBridge {
    #[cfg(test)]
    pub fn new(config: actual::Push) -> Self {
        Self::new_in(config, crate::data_dir::base_dir())
            .expect("test push persistence must be valid")
    }
    /// Construct a push bridge rooted at the explicitly configured Torii data directory.
    ///
    /// # Errors
    ///
    /// Returns an error when any existing device or delivery record is unsafe,
    /// malformed, conflicting, or exceeds the bounded storage geometry.
    pub fn new_in(config: actual::Push, data_dir: PathBuf) -> Result<Self, PushError> {
        Self::with_dispatcher_and_limits_in(
            config,
            Arc::new(RealPushDispatcher),
            PUSH_STORAGE_LIMITS,
            data_dir,
        )
    }
    #[cfg(test)]
    pub fn with_dispatcher(config: actual::Push, dispatcher: Arc<dyn PushDispatcher>) -> Self {
        Self::with_dispatcher_and_limits_in(
            config,
            dispatcher,
            PUSH_STORAGE_LIMITS,
            crate::data_dir::base_dir(),
        )
        .expect("test push persistence must be valid")
    }
    #[cfg(test)]
    fn with_dispatcher_and_limits(
        config: actual::Push,
        dispatcher: Arc<dyn PushDispatcher>,
        storage_limits: PushStorageLimits,
    ) -> Self {
        Self::with_dispatcher_and_limits_in(
            config,
            dispatcher,
            storage_limits,
            crate::data_dir::base_dir(),
        )
        .expect("test push persistence must be valid")
    }
    fn with_dispatcher_and_limits_in(
        config: actual::Push,
        dispatcher: Arc<dyn PushDispatcher>,
        storage_limits: PushStorageLimits,
        data_dir: PathBuf,
    ) -> Result<Self, PushError> {
        let settings = DispatchSettings {
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
        };
        let data_dir = Arc::new(data_dir.join(PUSH_DIR));
        let applied_block_cursor =
            load_or_initialize_applied_block_cursor(&data_dir).map_err(storage_error)?;
        let bridge = Self {
            config,
            settings,
            dispatcher,
            devices: Arc::new(DashMap::new()),
            queue: Arc::new(DashMap::new()),
            data_dir,
            storage_limits,
            mutation_guard: Arc::new(StorageMutex::new(())),
            applied_block_cursor: Arc::new(StorageMutex::new(applied_block_cursor)),
        };
        bridge.load_from_disk().map_err(storage_error)?;
        Ok(bridge)
    }
    pub fn register_device(&self, request: RegisterDeviceRequest) -> Result<(), PushError> {
        self.register_device_with(request, |record| self.persist_device(record))
    }
    fn register_device_with(
        &self,
        request: RegisterDeviceRequest,
        persist: impl FnOnce(&DeviceRecord) -> Result<(), AtomicWriteError>,
    ) -> Result<(), PushError> {
        if !self.config.enabled {
            return Err(PushError::Disabled);
        }
        let account_id = canonical_account(&request.account_id)?;
        let platform = Platform::from_label(&request.platform)?;
        if !self.has_credentials(platform) {
            return Err(PushError::MissingCredentials { platform });
        }
        let token = validate_device_token(platform, &request.token)?;
        let max_topics = self.config.max_topics_per_device.get().min(MAX_PUSH_TOPICS);
        let topics = validate_topics(request.topics, max_topics)?;
        let token = token.to_owned();
        let token_fingerprint = fingerprint(token.as_bytes());
        let record = DeviceRecord {
            account_id: account_id.to_string(),
            platform: platform.label().to_string(),
            token,
            token_fingerprint: token_fingerprint.clone(),
            topics,
            updated_at_ms: now_ms(),
        };
        let _mutation = self.mutation_guard.lock();
        let old = self
            .devices
            .get(&token_fingerprint)
            .map(|entry| entry.clone());
        if old.is_none() && self.devices.len() >= self.storage_limits.max_devices {
            return Err(storage_limit_error(
                "registered device count",
                self.devices.len().saturating_add(1),
                self.storage_limits.max_devices,
            ));
        }
        if let Err(error) = persist(&record) {
            if error.published {
                // The rename already replaced the sole token-keyed record. Keep the live view
                // aligned even though the caller must retry because directory durability is
                // uncertain.
                self.devices.insert(token_fingerprint, record);
            }
            return Err(storage_error(error.source));
        }
        self.devices.insert(token_fingerprint, record);
        Ok(())
    }
    pub fn unregister_device(&self, request: RegisterDeviceRequest) -> Result<(), PushError> {
        if !self.config.enabled {
            return Err(PushError::Disabled);
        }
        let account_id = canonical_account(&request.account_id)?;
        let platform = Platform::from_label(&request.platform)?;
        let token = validate_device_token(platform, &request.token)?;
        let token_fingerprint = fingerprint(token.as_bytes());
        let _mutation = self.mutation_guard.lock();
        let Some(record) = self
            .devices
            .get(&token_fingerprint)
            .map(|entry| entry.clone())
        else {
            return Ok(());
        };
        if record.account_id != account_id.to_string() || record.platform != platform.label() {
            return Ok(());
        }
        self.remove_device_file_and_reconcile_memory(
            &token_fingerprint,
            remove_file_if_exists_with_state,
        )
    }
    #[cfg(test)]
    pub(crate) fn enqueue_activity(
        &self,
        account: &AccountId,
        tx_hash: &str,
        block_height: u64,
        instruction_index: u64,
        activity_kind: &str,
        role: AccountActivityRole,
    ) -> Result<usize, PushError> {
        if !self.config.enabled {
            return Err(PushError::Disabled);
        }
        let _mutation = self.mutation_guard.lock();
        self.enqueue_activity_locked(
            account,
            tx_hash,
            block_height,
            instruction_index,
            activity_kind,
            role,
        )
    }
    #[cfg(test)]
    fn enqueue_activity_locked(
        &self,
        account: &AccountId,
        tx_hash: &str,
        block_height: u64,
        instruction_index: u64,
        activity_kind: &str,
        role: AccountActivityRole,
    ) -> Result<usize, PushError> {
        let mut queued = 0usize;
        for job in self.activity_jobs(
            account,
            tx_hash,
            block_height,
            instruction_index,
            activity_kind,
            role,
        ) {
            let dedupe_key = job.dedupe_key.clone();
            if self.queue.contains_key(&dedupe_key) {
                continue;
            }
            if self.queue.len() >= self.storage_limits.max_queue_jobs {
                return Err(storage_limit_error(
                    "push queue job count",
                    self.queue.len().saturating_add(1),
                    self.storage_limits.max_queue_jobs,
                ));
            }
            self.persist_job(&job)?;
            self.queue.insert(dedupe_key, job);
            queued += 1;
        }
        Ok(queued)
    }
    fn activity_jobs(
        &self,
        account: &AccountId,
        tx_hash: &str,
        block_height: u64,
        instruction_index: u64,
        activity_kind: &str,
        role: AccountActivityRole,
    ) -> Vec<DeliveryJob> {
        let account_id = account.to_string();
        self.devices_for_account(&account_id)
            .into_iter()
            .map(|device| {
                let payload = PushActivityPayload {
                    account_id: account_id.clone(),
                    activity_kind: activity_kind.to_string(),
                    tx_hash: tx_hash.to_string(),
                    block_height,
                    instruction_index,
                    direction: role.as_str().to_string(),
                };
                let dedupe_key = delivery_dedupe_key(&payload, &device.token_fingerprint);
                let now = now_ms();
                DeliveryJob {
                    dedupe_key,
                    account_id: account_id.clone(),
                    token_fingerprint: device.token_fingerprint,
                    target_platform: device.platform,
                    payload,
                    attempts: 0,
                    next_attempt_ms: now,
                    created_at_ms: now,
                    updated_at_ms: now,
                }
            })
            .collect()
    }
    pub async fn dispatch_due_once(&self) {
        if !self.config.enabled {
            return;
        }
        let now = now_ms();
        let keys: Vec<String> = self
            .queue
            .iter()
            .filter(|entry| entry.next_attempt_ms <= now)
            .map(|entry| entry.key().clone())
            .take(self.storage_limits.dispatch_batch_size)
            .collect();
        for key in keys {
            let Some(job) = self.queue.get(&key).map(|entry| entry.clone()) else {
                continue;
            };
            self.dispatch_job(job).await;
        }
    }
    pub(crate) fn start_event_worker(
        &self,
        state: Arc<State>,
        events: EventsSender,
        shutdown_signal: ShutdownSignal,
    ) -> Result<Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>>, PushWorkerStartError>
    {
        if !self.config.enabled {
            return Ok(None);
        }
        let pool = state.ivm_execution_budget();
        let mut prepaid = pool
            .try_reserve(ReleaseRegistration::allocation_layout())
            .map_err(PushWorkerStartError::Admission)?;
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid)
            .map_err(PushWorkerStartError::Registration)?;
        debug_assert!(registration.belongs_to(&pool));
        drop(prepaid);
        // Subscribe before spawning so the caller cannot observe a startup
        // window in which committed events have no receiver.
        let mut receiver = events.subscribe();
        let bridge = self.clone();
        Ok(Some(tokio::spawn(async move {
            if shutdown_signal.is_sent() {
                return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
            }
            match replay_with_queue_drain(
                &bridge,
                &state,
                PushReplayTarget::Authoritative,
                &shutdown_signal,
                &mut registration,
            )
            .await
            {
                Ok(PushReplayOutcome::Complete) => {}
                Ok(PushReplayOutcome::StoppedByShutdown) => {
                    return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                }
                Err(error) => {
                    iroha_logger::error!(
                        ?error,
                        "push bridge could not replay its applied State backlog"
                    );
                    return crate::ToriiCriticalWorkerExit::UnexpectedExit;
                }
            }
            if shutdown_signal.is_sent() {
                return crate::ToriiCriticalWorkerExit::StoppedByShutdown;
            }
            let mut tick = tokio::time::interval(DISPATCH_TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            'worker: loop {
                tokio::select! {
                    () = shutdown_signal.receive() => {
                        break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                    },
                    event = receiver.recv() => match event {
                        Ok(event) => {
                            if let Some(height) = applied_block_heights(&event).last().copied() {
                                match replay_with_queue_drain(
                                    &bridge,
                                    &state,
                                    PushReplayTarget::Height(height),
                                    &shutdown_signal,
                                    &mut registration,
                                )
                                .await
                                {
                                    Ok(PushReplayOutcome::Complete) => {}
                                    Ok(PushReplayOutcome::StoppedByShutdown) => {
                                        break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                                    }
                                    Err(error) => {
                                        iroha_logger::error!(
                                            ?error,
                                            height,
                                            "push bridge could not durably reconcile an applied block"
                                        );
                                        break 'worker crate::ToriiCriticalWorkerExit::UnexpectedExit;
                                    }
                                }
                                tokio::select! {
                                    () = shutdown_signal.receive() => {
                                        break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                                    },
                                    () = bridge.dispatch_due_once() => {}
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            iroha_logger::warn!(
                                skipped,
                                "push bridge event subscription lagged; reconciling from applied State"
                            );
                            match replay_with_queue_drain(
                                &bridge,
                                &state,
                                PushReplayTarget::Authoritative,
                                &shutdown_signal,
                                &mut registration,
                            )
                            .await
                            {
                                Ok(PushReplayOutcome::Complete) => {}
                                Ok(PushReplayOutcome::StoppedByShutdown) => {
                                    break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                                }
                                Err(error) => {
                                    iroha_logger::error!(
                                        ?error,
                                        "push bridge could not reconcile a lagged event subscription"
                                    );
                                    break 'worker crate::ToriiCriticalWorkerExit::UnexpectedExit;
                                }
                            }
                            tokio::select! {
                                () = shutdown_signal.receive() => {
                                    break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                                },
                                () = bridge.dispatch_due_once() => {}
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break 'worker if shutdown_signal.is_sent() {
                                crate::ToriiCriticalWorkerExit::StoppedByShutdown
                            } else {
                                crate::ToriiCriticalWorkerExit::UnexpectedExit
                            };
                        },
                    },
                    _ = tick.tick() => {
                        tokio::select! {
                            () = shutdown_signal.receive() => {
                                break 'worker crate::ToriiCriticalWorkerExit::StoppedByShutdown;
                            },
                            () = bridge.dispatch_due_once() => {}
                        }
                    }
                }
            }
        })))
    }
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }
    #[cfg(test)]
    pub(crate) fn registered_device_by_token(&self, token: &str) -> Option<RegisteredDevice> {
        self.devices
            .get(&fingerprint(token.as_bytes()))
            .map(|entry| registered_device_from_record(&entry))
    }
    #[cfg(test)]
    pub(crate) fn registered_device(&self, token: &str) -> Option<RegisteredDevice> {
        self.registered_device_by_token(token)
    }
    #[cfg(test)]
    fn reconcile_to_authoritative_height(&self, state: &State) -> Result<(), PushReplayError> {
        PushReplayRead::new(state).reconcile(self, PushReplayTarget::Authoritative)
    }
    #[cfg(test)]
    fn reconcile_through_height(&self, state: &State, height: u64) -> Result<(), PushReplayError> {
        PushReplayRead::new(state).reconcile(self, PushReplayTarget::Height(height))
    }
    fn reconcile_with_reader(
        &self,
        target_height: u64,
        authoritative_height: u64,
        read: &mut PushReplayRead<'_>,
    ) -> Result<(), PushReplayError> {
        self.validate_applied_block_cursor_against_state(authoritative_height, read)?;
        let current_height = self.applied_block_cursor.lock().height;
        if current_height >= target_height {
            return Ok(());
        }
        // Native genesis execution needs the real H2 anchor. A height observation
        // grants no authority: defer source verification until that successor is
        // stably published, then authenticate the unchanged complete native prefix.
        // Idle chains produce no blocks, so bootstrap must remain cancellable.
        if !cfg!(all(test, sumeragi_torii_mutation = "TOR5"))
            && authoritative_height == 1
            && target_height == 1
        {
            return Err(PushReplayError::AwaitingGenesisSuccessor);
        }
        let first_height = current_height.checked_add(1).ok_or_else(|| {
            PushReplayError::Fatal(PushError::Storage(
                "push applied-block cursor height overflowed".to_owned(),
            ))
        })?;
        for next_height in first_height..=target_height {
            self.enqueue_committed_block(next_height, read)?;
        }
        Ok(())
    }
    fn validate_applied_block_cursor_against_state(
        &self,
        authoritative_height: u64,
        read: &mut PushReplayRead<'_>,
    ) -> Result<(), ExecutionAttemptError<PushError>> {
        let cursor = self.applied_block_cursor.lock().clone();
        cursor.validate().map_err(storage_error)?;
        if cursor.height > authoritative_height {
            return Err(PushError::Storage(format!(
                "push applied-block cursor height {} exceeds State's applied height {authoritative_height}",
                cursor.height
            )).into());
        }
        if cursor.height == 0 {
            return Ok(());
        }
        if authoritative_height == 1 {
            return Err(PushError::Storage(
                "push applied-block cursor cannot be published before genesis has a committed successor".into(),
            ).into());
        }
        if read.cursor_is_verified(&cursor)? {
            return Ok(());
        }
        let block = read.block(cursor.height)?;
        if block.header().height().get() != cursor.height {
            return Err(PushError::Storage(format!(
                "State returned block height {} for push cursor height {}",
                block.header().height(),
                cursor.height
            ))
            .into());
        }
        if Some(block.hash()) != cursor.block_hash {
            return Err(PushError::Storage(format!(
                "push applied-block cursor hash does not match State at height {}",
                cursor.height
            ))
            .into());
        }
        read.retain_verified_cursor(&cursor, &block);
        Ok(())
    }
    fn enqueue_committed_block(
        &self,
        height: u64,
        read: &mut PushReplayRead<'_>,
    ) -> Result<(), PushReplayError> {
        let block = read.block(height)?;
        if block.header().height().get() != height {
            return Err(PushError::Storage(format!(
                "State returned block height {} while push reconciliation requested {height}",
                block.header().height()
            ))
            .into());
        }
        if !block.has_results() {
            return Err(PushError::Storage(format!(
                "applied native block {height} has no execution results"
            ))
            .into());
        }
        let _mutation = self.mutation_guard.lock();
        let mut cursor = self.applied_block_cursor.lock();
        let expected_height = cursor.height.checked_add(1).ok_or_else(|| {
            PushReplayError::Fatal(PushError::Storage(
                "push applied-block cursor height overflowed".to_owned(),
            ))
        })?;
        if height != expected_height {
            return Err(PushError::Storage(format!(
                "push block reconciliation expected height {expected_height}, received {height}"
            ))
            .into());
        }
        if block.header().prev_block_hash().as_ref() != cursor.block_hash.as_ref() {
            return Err(PushError::Storage(format!(
                "push block at height {height} does not extend the durable applied-block cursor"
            ))
            .into());
        }
        self.enqueue_block_activities_locked(&block)?;
        let next_cursor = AppliedBlockCursor {
            version: APPLIED_BLOCK_CURSOR_VERSION,
            height,
            block_hash: Some(block.hash()),
        };
        self.persist_applied_block_cursor(&next_cursor)?;
        read.retain_verified_cursor(&next_cursor, &block);
        *cursor = next_cursor;
        Ok(())
    }
    fn enqueue_block_activities_locked(&self, block: &SignedBlock) -> Result<(), PushReplayError> {
        let block_height = block.header().height().get();
        let mut jobs = BTreeMap::<String, DeliveryJob>::new();
        for (entrypoint_hash, tx, result) in crate::canonical_history::signed_calls(block)
            .map_err(|error| PushError::Storage(error.to_string()))?
        {
            if result.is_err() {
                continue;
            }
            let tx_hash = entrypoint_hash.to_string();
            for (instruction_index, instruction) in
                tx.instructions().explicit_instructions().enumerate()
            {
                let instruction_index = u64::try_from(instruction_index).map_err(|_| {
                    PushReplayError::Fatal(PushError::Storage(
                        "block instruction index exceeds the push payload range".to_owned(),
                    ))
                })?;
                let activity_kind = crate::explorer::instruction_kind(instruction).as_str();
                for activity in crate::account_activity::instruction_account_activities(instruction)
                {
                    for job in self.activity_jobs(
                        &activity.account,
                        &tx_hash,
                        block_height,
                        instruction_index,
                        activity_kind,
                        activity.role,
                    ) {
                        if !self.queue.contains_key(&job.dedupe_key) {
                            jobs.entry(job.dedupe_key.clone()).or_insert(job);
                        }
                    }
                }
            }
        }
        let queued = self.queue.len();
        let required = jobs.len();
        if required > self.storage_limits.max_queue_jobs {
            return Err(PushReplayError::Fatal(PushError::Storage(format!(
                "push block {block_height} requires {required} delivery jobs, exceeding the configured durable queue capacity {}",
                self.storage_limits.max_queue_jobs
            ))));
        }
        if required > self.storage_limits.max_queue_jobs.saturating_sub(queued) {
            return Err(PushReplayError::Backpressure {
                height: block_height,
                queued,
                required,
                maximum: self.storage_limits.max_queue_jobs,
            });
        }
        for (dedupe_key, job) in jobs {
            self.persist_job(&job)?;
            self.queue.insert(dedupe_key, job);
        }
        Ok(())
    }
    async fn dispatch_job(&self, job: DeliveryJob) {
        let Some(device) = self
            .devices
            .get(&job.token_fingerprint)
            .map(|entry| entry.clone())
        else {
            self.remove_job(&job.dedupe_key);
            return;
        };
        if (
            &device.account_id,
            &device.token_fingerprint,
            &device.platform,
        ) != (
            &job.account_id,
            &job.token_fingerprint,
            &job.target_platform,
        ) {
            // A token can be re-registered between enqueue and dispatch. Never deliver an old
            // account's activity through the replacement registration.
            self.remove_job(&job.dedupe_key);
            return;
        }
        let Some(platform) = Platform::from_stored(&device.platform) else {
            self.remove_job(&job.dedupe_key);
            return;
        };
        let credentials = match self.credentials_for(platform) {
            Ok(credentials) => credentials,
            Err(error) => {
                iroha_logger::warn!(?error, "push provider credentials unavailable");
                self.reschedule_job(job);
                return;
            }
        };
        let delivery = PushDelivery {
            #[cfg(test)]
            platform,
            token: device.token,
            payload: job.payload.clone(),
        };
        match self
            .dispatcher
            .send(&delivery, &self.settings, &credentials)
            .await
        {
            DispatchOutcome::Sent | DispatchOutcome::PermanentFailure(_) => {
                self.remove_job(&job.dedupe_key);
            }
            DispatchOutcome::InvalidToken(reason) => {
                iroha_logger::info!(
                    token_fingerprint = job.token_fingerprint.as_str(),
                    reason = reason.as_str(),
                    "removing invalid push token"
                );
                self.remove_job(&job.dedupe_key);
                if let Err(error) = self.remove_device_by_fingerprint(&job.token_fingerprint) {
                    iroha_logger::warn!(?error, "failed to remove invalid push device");
                }
            }
            DispatchOutcome::Retry(reason) => {
                iroha_logger::debug!(
                    reason = reason.as_str(),
                    "push delivery scheduled for retry"
                );
                self.reschedule_job(job);
            }
        }
    }
    fn reschedule_job(&self, mut job: DeliveryJob) {
        job.attempts = job.attempts.saturating_add(1);
        let backoff = retry_backoff(job.attempts);
        job.next_attempt_ms = now_ms().saturating_add(duration_ms(backoff));
        job.updated_at_ms = now_ms();
        let _mutation = self.mutation_guard.lock();
        if !self.queue.contains_key(&job.dedupe_key)
            && self.queue.len() >= self.storage_limits.max_queue_jobs
        {
            iroha_logger::warn!(
                maximum = self.storage_limits.max_queue_jobs,
                "dropping push retry because the hard queue capacity is full"
            );
            return;
        }
        if let Err(error) = self.persist_job_with_state(&job) {
            iroha_logger::warn!(error = ?error.source, "failed to persist push retry");
            if !error.published {
                return;
            }
        }
        self.queue.insert(job.dedupe_key.clone(), job);
    }
    fn has_credentials(&self, platform: Platform) -> bool {
        self.credentials_for(platform).is_ok()
    }
    fn credentials_for(&self, platform: Platform) -> Result<ProviderCredentials, PushError> {
        match platform {
            Platform::Fcm => match (
                exact_nonempty_ref(self.config.fcm_project_id.as_deref()),
                self.config.fcm_service_account_path.as_ref(),
            ) {
                (Some(project_id), Some(path)) => Ok(ProviderCredentials::Fcm {
                    project_id: project_id.to_owned(),
                    service_account_path: path.clone(),
                }),
                _ => Err(PushError::MissingCredentials { platform }),
            },
            Platform::Apns => {
                let endpoint = match self
                    .config
                    .apns_endpoint
                    .as_ref()
                    .and_then(|url| exact_nonempty_ref(Some(url.as_str())))
                {
                    Some(endpoint) => endpoint.to_owned(),
                    None => match self.config.apns_environment.as_str() {
                        "sandbox" => APNS_SANDBOX_ENDPOINT.to_string(),
                        "production" => APNS_PRODUCTION_ENDPOINT.to_string(),
                        other => return Err(PushError::InvalidEnvironment(other.to_string())),
                    },
                };
                match (
                    exact_nonempty_ref(self.config.apns_topic.as_deref()),
                    exact_nonempty_ref(self.config.apns_team_id.as_deref()),
                    exact_nonempty_ref(self.config.apns_key_id.as_deref()),
                    self.config.apns_private_key_path.as_ref(),
                ) {
                    (Some(topic), Some(team_id), Some(key_id), Some(path)) => {
                        Ok(ProviderCredentials::Apns {
                            endpoint,
                            topic: topic.to_owned(),
                            team_id: team_id.to_owned(),
                            key_id: key_id.to_owned(),
                            private_key_path: path.clone(),
                        })
                    }
                    _ => Err(PushError::MissingCredentials { platform }),
                }
            }
        }
    }
    fn devices_for_account(&self, account_id: &str) -> Vec<DeviceRecord> {
        self.devices
            .iter()
            .filter(|entry| entry.account_id == account_id)
            .map(|entry| entry.clone())
            .take(self.storage_limits.max_devices)
            .collect()
    }
    fn remove_device_by_fingerprint(&self, token_fingerprint: &str) -> Result<(), PushError> {
        self.remove_device_by_fingerprint_with(token_fingerprint, remove_file_if_exists_with_state)
    }
    fn remove_device_by_fingerprint_with(
        &self,
        token_fingerprint: &str,
        remove: impl FnOnce(&Path) -> Result<(), AtomicRemovalError>,
    ) -> Result<(), PushError> {
        let _mutation = self.mutation_guard.lock();
        let Some(record) = self
            .devices
            .get(token_fingerprint)
            .map(|entry| entry.clone())
        else {
            return Ok(());
        };
        drop(record);
        self.remove_device_file_and_reconcile_memory(token_fingerprint, remove)
    }
    fn remove_device_file_and_reconcile_memory(
        &self,
        token_fingerprint: &str,
        remove: impl FnOnce(&Path) -> Result<(), AtomicRemovalError>,
    ) -> Result<(), PushError> {
        let path = self.device_path(token_fingerprint);
        match remove(&path) {
            Ok(()) => {
                self.devices.remove(token_fingerprint);
                Ok(())
            }
            Err(error) => {
                if error.target_absent {
                    // Unlink committed before directory synchronization failed. Never keep
                    // dispatching through a token whose sole durable record is already gone.
                    self.devices.remove(token_fingerprint);
                }
                Err(storage_error(error.source))
            }
        }
    }
    fn remove_job(&self, dedupe_key: &str) {
        let _mutation = self.mutation_guard.lock();
        if let Err(error) = remove_file_if_exists_with_state(&self.job_path(dedupe_key)) {
            iroha_logger::warn!(error = ?error.source, "failed to remove push queue file");
            if !error.target_absent {
                return;
            }
        }
        self.queue.remove(dedupe_key);
    }
    fn persist_device(&self, record: &DeviceRecord) -> Result<(), AtomicWriteError> {
        validate_device_record(record, self.effective_max_topics())
            .map_err(AtomicWriteError::before_publish)?;
        write_json_atomic_with_publish_state(
            &self.device_path(&record.token_fingerprint),
            record,
            self.storage_limits.max_device_record_bytes,
        )
    }
    fn persist_job(&self, job: &DeliveryJob) -> Result<(), PushError> {
        self.persist_job_with_state(job)
            .map_err(|error| storage_error(error.source))
    }
    fn persist_job_with_state(&self, job: &DeliveryJob) -> Result<(), AtomicWriteError> {
        validate_delivery_job(job).map_err(AtomicWriteError::before_publish)?;
        write_json_atomic_with_publish_state(
            &self.job_path(&job.dedupe_key),
            job,
            self.storage_limits.max_queue_job_bytes,
        )
    }
    fn persist_applied_block_cursor(&self, cursor: &AppliedBlockCursor) -> Result<(), PushError> {
        cursor.validate().map_err(storage_error)?;
        write_json_atomic(
            &self.applied_block_cursor_path(),
            cursor,
            MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES,
        )
        .map_err(storage_error)
    }
    fn load_from_disk(&self) -> io::Result<()> {
        self.load_devices()?;
        self.load_queue()
    }
    fn load_devices(&self) -> io::Result<()> {
        let root = self.data_dir.join(DEVICES_DIR);
        let files = match read_direct_directory(&root) {
            Ok(files) => files,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut device_entries = 0_usize;
        let mut temp_entries = 0_usize;
        let mut recoverable_temps = Vec::new();
        let mut loaded = BTreeMap::<String, DeviceRecord>::new();
        for file in files {
            let file = file?;
            let path = file.path();
            let file_type = file.file_type()?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(invalid_data(format!(
                    "push device record is not a direct regular file: {}",
                    path.display()
                )));
            }
            if is_canonical_record_temp_path(&path) {
                temp_entries = temp_entries.saturating_add(1);
                if temp_entries > MAX_PUSH_RECOVERABLE_TEMP_FILES {
                    return Err(invalid_data(format!(
                        "push device temporary record count exceeds {MAX_PUSH_RECOVERABLE_TEMP_FILES}"
                    )));
                }
                read_bounded_stable_file(&path, self.storage_limits.max_device_record_bytes)?;
                recoverable_temps.push(path);
                continue;
            }
            device_entries = device_entries.saturating_add(1);
            if device_entries > self.storage_limits.max_devices {
                return Err(invalid_data(format!(
                    "push device record count exceeds {}",
                    self.storage_limits.max_devices
                )));
            }
            let record =
                read_json::<DeviceRecord>(&path, self.storage_limits.max_device_record_bytes)?;
            validate_device_record(&record, self.effective_max_topics())?;
            let token_fingerprint = record.token_fingerprint.clone();
            let expected_name = format!("{token_fingerprint}.json");
            if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
                return Err(invalid_data(format!(
                    "push device record filename is not canonical: {}",
                    path.display()
                )));
            }
            if loaded.insert(token_fingerprint.clone(), record).is_some() {
                return Err(invalid_data(format!(
                    "duplicate persisted push token fingerprint: {token_fingerprint}"
                )));
            }
        }
        for path in recoverable_temps {
            remove_recoverable_record_temp(&path, self.storage_limits.max_device_record_bytes)?;
        }
        for (token_fingerprint, record) in loaded {
            self.devices.insert(token_fingerprint, record);
        }
        Ok(())
    }
    fn load_queue(&self) -> io::Result<()> {
        let root = self.data_dir.join(QUEUE_DIR);
        let files = match read_direct_directory(&root) {
            Ok(files) => files,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut queue_entries = 0_usize;
        let mut temp_entries = 0_usize;
        let mut recoverable_temps = Vec::new();
        let mut loaded = BTreeMap::<String, DeliveryJob>::new();
        for file in files {
            let file = file?;
            let path = file.path();
            let file_type = file.file_type()?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(invalid_data(format!(
                    "push queue record is not a direct regular file: {}",
                    path.display()
                )));
            }
            if is_canonical_record_temp_path(&path) {
                temp_entries = temp_entries.saturating_add(1);
                if temp_entries > MAX_PUSH_RECOVERABLE_TEMP_FILES {
                    return Err(invalid_data(format!(
                        "push queue temporary record count exceeds {MAX_PUSH_RECOVERABLE_TEMP_FILES}"
                    )));
                }
                read_bounded_stable_file(&path, self.storage_limits.max_queue_job_bytes)?;
                recoverable_temps.push(path);
                continue;
            }
            queue_entries = queue_entries.saturating_add(1);
            if queue_entries > self.storage_limits.max_queue_jobs {
                return Err(invalid_data(format!(
                    "push queue record count exceeds {}",
                    self.storage_limits.max_queue_jobs
                )));
            }
            let job = read_json::<DeliveryJob>(&path, self.storage_limits.max_queue_job_bytes)?;
            validate_delivery_job(&job)?;
            let expected_name = format!("{}.json", job.dedupe_key);
            if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
                return Err(invalid_data(format!(
                    "push queue record filename is not canonical: {}",
                    path.display()
                )));
            }
            let dedupe_key = job.dedupe_key.clone();
            if loaded.insert(dedupe_key.clone(), job).is_some() {
                return Err(invalid_data(format!(
                    "duplicate persisted push queue key: {dedupe_key}"
                )));
            }
        }
        for path in recoverable_temps {
            remove_recoverable_record_temp(&path, self.storage_limits.max_queue_job_bytes)?;
        }
        for (dedupe_key, job) in loaded {
            self.queue.insert(dedupe_key, job);
        }
        Ok(())
    }
    fn effective_max_topics(&self) -> usize {
        self.config.max_topics_per_device.get().min(MAX_PUSH_TOPICS)
    }
    fn device_path(&self, token_fingerprint: &str) -> PathBuf {
        self.data_dir
            .join(DEVICES_DIR)
            .join(format!("{token_fingerprint}.json"))
    }
    fn job_path(&self, dedupe_key: &str) -> PathBuf {
        self.data_dir
            .join(QUEUE_DIR)
            .join(format!("{dedupe_key}.json"))
    }
    fn applied_block_cursor_path(&self) -> PathBuf {
        self.data_dir.join(APPLIED_BLOCK_CURSOR_FILE)
    }
}
// Only the original refused pool supplies a release wake. Demands without a
// release source retry on the existing bounded dispatch cadence, never a spin.
async fn wait_for_push_history_retry(
    reason: &ExecutionDeferred,
    shutdown: &ShutdownSignal,
    registration: &mut ReleaseRegistration,
) -> bool {
    match reason.allocation_refusal() {
        Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
            tokio::select! {
                () = shutdown.receive() => false,
                () = release.clone().wait_for_release(registration) => true,
            }
        }
        _ => {
            tokio::select! {
                () = shutdown.receive() => false,
                () = tokio::time::sleep(DISPATCH_TICK) => true,
            }
        }
    }
}
// Durable replay owns its current read across waiting. This private cursor receipt
// is obtained only from a carrier authenticated during this operation and checked
// against the exact durable cursor plus current State binding on every reuse. It
// retains no completed block graph and grants no authority outside this operation.
struct VerifiedPushCursor {
    height: u64,
    block_hash: HashOf<BlockHeader>,
}
struct PushReplayRead<'state> {
    state: &'state State,
    pending:
        Option<iroha_core::smartcontracts::isi::tx::FinalizedExecutionCarrierReadAttempt<'state>>,
    verified_cursor: Option<VerifiedPushCursor>,
}
impl<'state> PushReplayRead<'state> {
    fn new(state: &'state State) -> Self {
        Self {
            state,
            pending: None,
            verified_cursor: None,
        }
    }

    fn cursor_is_verified(
        &self,
        cursor: &AppliedBlockCursor,
    ) -> Result<bool, ExecutionAttemptError<PushError>> {
        let Some(original) = &self.verified_cursor else {
            return Ok(false);
        };
        if original.height != cursor.height || Some(original.block_hash) != cursor.block_hash {
            return Ok(false);
        }
        let index = usize::try_from(cursor.height).map_err(|_| {
            PushError::Storage(format!(
                "native block height {} exceeds usize",
                cursor.height
            ))
        })?;
        if self.state.block_hashes.view().get(index - 1).copied() != Some(original.block_hash) {
            return Err(
                PushError::Storage("push replay's original cursor binding changed".into()).into(),
            );
        }
        Ok(true)
    }

    fn retain_verified_cursor(&mut self, cursor: &AppliedBlockCursor, block: &SignedBlock) {
        // Both callers first authenticate this actual native carrier and require
        // exact height/hash agreement. Queue publication records it only after
        // durable cursor persistence succeeds.
        debug_assert_eq!(cursor.height, block.header().height().get());
        debug_assert_eq!(cursor.block_hash, Some(block.hash()));
        self.verified_cursor = Some(VerifiedPushCursor {
            height: block.header().height().get(),
            block_hash: block.hash(),
        });
    }

    fn block(
        &mut self,
        height: u64,
    ) -> Result<SharedSignedBlock, ExecutionAttemptError<PushError>> {
        let index = usize::try_from(height).map_err(|_| {
            PushError::Storage(format!("native block height {height} exceeds usize"))
        })?;
        let height_nonzero = NonZeroUsize::new(index)
            .ok_or_else(|| PushError::Storage("native block height must be nonzero".into()))?;
        if let Some(original) = &self.pending {
            if original.height() != height_nonzero {
                return Err(
                    PushError::Storage("push replay's pending target changed".into()).into(),
                );
            }
        } else {
            let work = crate::routing::app_query_limits().max_fetch_size;
            self.pending = Some(
                self.state
                    .begin_finalized_execution_carrier_read(
                        height_nonzero,
                        work,
                        iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
                    )
                    .map_err(|error| {
                        error.map_rejection(|error| PushError::Storage(error.to_string()))
                    })?,
            );
        }
        let block = self
            .pending
            .as_mut()
            .expect("same original pending target")
            .advance()
            .map_err(|error| error.map_rejection(|error| PushError::Storage(error.to_string())))?
            .into_block();
        self.pending = None;
        Ok(block)
    }

    fn reconcile(
        &mut self,
        bridge: &PushBridge,
        target: PushReplayTarget,
    ) -> Result<(), PushReplayError> {
        let authoritative_height = exact_applied_state_height(self.state)?;
        let target_height = match target {
            PushReplayTarget::Authoritative => authoritative_height,
            PushReplayTarget::Height(height) => {
                if height > authoritative_height {
                    return Err(PushError::Storage(format!(
                        "observed applied block height {height} exceeds State's applied height {authoritative_height}"
                    )).into());
                }
                height
            }
        };
        bridge.reconcile_with_reader(target_height, authoritative_height, self)
    }
}

async fn replay_with_queue_drain(
    bridge: &PushBridge,
    state: &State,
    target: PushReplayTarget,
    shutdown_signal: &ShutdownSignal,
    registration: &mut ReleaseRegistration,
) -> Result<PushReplayOutcome, PushError> {
    replay_with_queue_drain_observed(
        bridge,
        state,
        target,
        shutdown_signal,
        registration,
        #[cfg(test)]
        None,
    )
    .await
}
async fn replay_with_queue_drain_observed(
    bridge: &PushBridge,
    state: &State,
    target: PushReplayTarget,
    shutdown_signal: &ShutdownSignal,
    registration: &mut ReleaseRegistration,
    #[cfg(test)] mut observe: Option<&mut (dyn FnMut(&ExecutionDeferred) + Send)>,
) -> Result<PushReplayOutcome, PushError> {
    let mut original = PushReplayRead::new(state);
    loop {
        let result = original.reconcile(bridge, target);
        match result {
            Ok(()) => return Ok(PushReplayOutcome::Complete),
            Err(PushReplayError::Fatal(error)) => return Err(error),
            Err(PushReplayError::AwaitingGenesisSuccessor) => {
                tokio::select! {
                    () = shutdown_signal.receive() => {
                        return Ok(PushReplayOutcome::StoppedByShutdown);
                    },
                    () = state.wait_for_committed_height(2) => {}
                }
            }
            Err(PushReplayError::Deferred(reason)) => {
                // Mutation restores only the old current-read abandonment. The
                // original typed refusal and its exact release cut remain unchanged.
                #[cfg(all(test, sumeragi_torii_mutation = "TOR4"))]
                {
                    original.pending = None;
                }
                #[cfg(test)]
                if let Some(probe) = observe.as_mut() {
                    probe(&reason);
                }
                iroha_logger::debug!(%reason, "push native history is waiting for original allocation capacity");
                if !wait_for_push_history_retry(&reason, shutdown_signal, registration).await {
                    return Ok(PushReplayOutcome::StoppedByShutdown);
                }
            }
            Err(PushReplayError::Backpressure {
                height,
                queued,
                required,
                maximum,
            }) => {
                iroha_logger::warn!(
                    height,
                    queued,
                    required,
                    maximum,
                    "push Kura replay is waiting for durable queue capacity"
                );
                let queued_before_dispatch = bridge.queued_count();
                tokio::select! {
                    () = shutdown_signal.receive() => {
                        return Ok(PushReplayOutcome::StoppedByShutdown);
                    },
                    () = bridge.dispatch_due_once() => {}
                }
                if bridge.queued_count() >= queued_before_dispatch {
                    tokio::select! {
                        () = shutdown_signal.receive() => {
                            return Ok(PushReplayOutcome::StoppedByShutdown);
                        },
                        () = tokio::time::sleep(DISPATCH_TICK) => {}
                    }
                }
            }
        }
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::push::DeviceRecord")]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
struct DeviceRecord {
    account_id: String,
    platform: String,
    token: String,
    token_fingerprint: String,
    topics: Vec<String>,
    updated_at_ms: u64,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::push::DeliveryJob")]
#[derive(
    Clone,
    Debug,
    crate::json_macros::JsonDeserialize,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoDeserialize,
    norito::derive::NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
struct DeliveryJob {
    dedupe_key: String,
    account_id: String,
    token_fingerprint: String,
    target_platform: String,
    payload: PushActivityPayload,
    attempts: u32,
    next_attempt_ms: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
}
#[cfg(test)]
fn registered_device_from_record(record: &DeviceRecord) -> RegisteredDevice {
    RegisteredDevice {
        account_id: record.account_id.clone(),
    }
}
fn canonical_account(account_id: &str) -> Result<AccountId, PushError> {
    let account = AccountId::parse_encoded(account_id)
        .map_err(|_| PushError::InvalidAccount(account_id.to_owned()))?;
    if account.to_string() != account_id {
        return Err(PushError::InvalidAccount(account_id.to_owned()));
    }
    Ok(account)
}
fn validate_device_record(record: &DeviceRecord, max_topics: usize) -> io::Result<()> {
    let account = canonical_account(&record.account_id)
        .map_err(|_| invalid_data("persisted push device has an invalid account id"))?;
    if account.to_string() != record.account_id {
        return Err(invalid_data(
            "persisted push device account id is not canonical",
        ));
    }
    let platform = Platform::from_stored(&record.platform)
        .ok_or_else(|| invalid_data("persisted push device has an invalid platform"))?;
    if validate_device_token(platform, &record.token).is_err() {
        return Err(invalid_data(
            "persisted push device token is not canonical for its platform",
        ));
    }
    if record.token_fingerprint != fingerprint(record.token.as_bytes()) {
        return Err(invalid_data(
            "persisted push device token fingerprint does not match its token",
        ));
    }
    if record.topics.len() > max_topics.min(MAX_PUSH_TOPICS) {
        return Err(invalid_data(
            "persisted push device topic count exceeds the configured hard bound",
        ));
    }
    let mut topic_bytes = 0_usize;
    for (index, topic) in record.topics.iter().enumerate() {
        if topic.is_empty()
            || topic.len() > MAX_PUSH_TOPIC_BYTES
            || !topic.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(invalid_data(
                "persisted push device topic is not canonical visible ASCII",
            ));
        }
        if record.topics[..index].contains(topic) {
            return Err(invalid_data(
                "persisted push device contains duplicate topics",
            ));
        }
        topic_bytes = topic_bytes
            .checked_add(topic.len())
            .ok_or_else(|| invalid_data("persisted push device topic bytes overflow"))?;
        if topic_bytes > MAX_PUSH_TOPIC_BYTES_PER_DEVICE {
            return Err(invalid_data(
                "persisted push device aggregate topic bytes exceed the hard bound",
            ));
        }
    }
    Ok(())
}
fn validate_delivery_job(job: &DeliveryJob) -> io::Result<()> {
    let account = canonical_account(&job.account_id)
        .map_err(|_| invalid_data("persisted push job has an invalid account id"))?;
    if account.to_string() != job.account_id || job.payload.account_id != job.account_id {
        return Err(invalid_data(
            "persisted push job account id is non-canonical or inconsistent",
        ));
    }
    if !is_lower_hex_fingerprint(&job.token_fingerprint) {
        return Err(invalid_data(
            "persisted push job has an invalid token fingerprint",
        ));
    }
    if Platform::from_stored(&job.target_platform).is_none() {
        return Err(invalid_data(
            "persisted push job has an invalid target platform",
        ));
    }
    if job.payload.activity_kind.len() > MAX_PUSH_ACTIVITY_KIND_BYTES
        || job.payload.tx_hash.len() > MAX_PUSH_TX_HASH_BYTES
        || job.payload.direction.len() > MAX_PUSH_DIRECTION_BYTES
    {
        return Err(invalid_data(
            "persisted push job payload field exceeds its hard byte bound",
        ));
    }
    if job.dedupe_key != delivery_dedupe_key(&job.payload, &job.token_fingerprint) {
        return Err(invalid_data(
            "persisted push job dedupe key does not match its payload",
        ));
    }
    Ok(())
}
fn is_lower_hex_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn is_canonical_record_temp_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".json.tmp"))
        .is_some_and(is_lower_hex_fingerprint)
}
fn remove_recoverable_record_temp(path: &Path, maximum: usize) -> io::Result<()> {
    let _bytes = read_bounded_stable_file(path, maximum)?;
    remove_file_if_exists(path)
}
fn validate_device_token(platform: Platform, token: &str) -> Result<&str, PushError> {
    if token.is_empty() {
        return Err(PushError::EmptyToken);
    }
    if token.len() > MAX_PUSH_TOKEN_BYTES || !token.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
    {
        return Err(PushError::InvalidToken);
    }
    if platform == Platform::Apns
        && (token.len() != 64
            || !token
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(PushError::InvalidToken);
    }
    Ok(token)
}

fn validate_topics(
    topics: Option<Vec<String>>,
    max_topics: usize,
) -> Result<Vec<String>, PushError> {
    let topics = topics.unwrap_or_default();
    if topics.len() > max_topics {
        return Err(PushError::TooManyTopics { max: max_topics });
    }
    let mut out = Vec::with_capacity(topics.len());
    let mut topic_bytes = 0_usize;
    for (index, topic) in topics.into_iter().enumerate() {
        if topic.is_empty()
            || topic.len() > MAX_PUSH_TOPIC_BYTES
            || !topic.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        {
            return Err(PushError::InvalidTopic { index });
        }
        if out.contains(&topic) {
            return Err(PushError::DuplicateTopic { index });
        }
        topic_bytes = topic_bytes
            .checked_add(topic.len())
            .ok_or(PushError::TopicsTooLarge {
                max_bytes: MAX_PUSH_TOPIC_BYTES_PER_DEVICE,
            })?;
        if topic_bytes > MAX_PUSH_TOPIC_BYTES_PER_DEVICE {
            return Err(PushError::TopicsTooLarge {
                max_bytes: MAX_PUSH_TOPIC_BYTES_PER_DEVICE,
            });
        }
        out.push(topic);
    }
    Ok(out)
}
fn exact_nonempty_ref(value: Option<&str>) -> Option<&str> {
    value.filter(|raw| !raw.is_empty() && raw.bytes().all(|byte| matches!(byte, 0x21..=0x7e)))
}
fn delivery_dedupe_key(payload: &PushActivityPayload, token_fingerprint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"iroha.torii.push.delivery.v1");
    let mut append = |component: &[u8]| {
        let length = u64::try_from(component.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_be_bytes());
        hasher.update(component);
    };
    append(payload.account_id.as_bytes());
    append(payload.activity_kind.as_bytes());
    append(payload.tx_hash.as_bytes());
    append(&payload.block_height.to_be_bytes());
    append(&payload.instruction_index.to_be_bytes());
    append(payload.direction.as_bytes());
    append(token_fingerprint.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
fn retry_backoff(attempts: u32) -> Duration {
    let multiplier = 1u32.checked_shl(attempts.min(10)).unwrap_or(1 << 10);
    INITIAL_BACKOFF.saturating_mul(multiplier).min(MAX_BACKOFF)
}
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
use crate::utils::unix_now_ms as now_ms;
fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
fn storage_error(error: io::Error) -> PushError {
    PushError::Storage(error.to_string())
}
fn storage_limit_error(label: &str, actual: usize, maximum: usize) -> PushError {
    PushError::Storage(format!(
        "{label} {actual} exceeds the push storage maximum {maximum}"
    ))
}
fn exact_applied_state_height(state: &State) -> Result<u64, PushError> {
    u64::try_from(state.committed_height())
        .map_err(|_| PushError::Storage("State's applied height exceeds u64".to_owned()))
}
#[cfg(test)]
fn state_block_at_height(
    state: &State,
    height: u64,
) -> Result<SharedSignedBlock, ExecutionAttemptError<PushError>> {
    let height_usize = usize::try_from(height)
        .map_err(|_| PushError::Storage(format!("native block height {height} exceeds usize")))?;
    let height = NonZeroUsize::new(height_usize)
        .ok_or_else(|| PushError::Storage("native block height must be nonzero".to_owned()))?;
    let work = crate::routing::app_query_limits().max_fetch_size;
    state
        .read_finalized_execution_carrier(
            height,
            work,
            iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
        )
        .map(iroha_core::smartcontracts::tx::FinalizedExecutionCarrier::into_block)
        .map_err(|error| error.map_rejection(|error| PushError::Storage(error.to_string())))
}
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn sync_directory(path: &Path) -> io::Result<()> {
    crate::durable_fs::sync_direct_directory(path)
}
fn sync_directory_if_present(path: &Path) -> io::Result<()> {
    match sync_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("push persistence path has no parent directory"))?;
    sync_directory(parent)
}
#[derive(Debug)]
struct AtomicWriteError {
    source: io::Error,
    published: bool,
}
impl AtomicWriteError {
    fn before_publish(source: io::Error) -> Self {
        Self {
            source,
            published: false,
        }
    }
    fn after_publish(source: io::Error) -> Self {
        Self {
            source,
            published: true,
        }
    }
}
#[derive(Debug)]
struct AtomicRemovalError {
    source: io::Error,
    target_absent: bool,
}
fn sync_json_publication(path: &Path) -> io::Result<()> {
    sync_parent_directory(path)?;
    if let Some(grandparent) = path.parent().and_then(Path::parent) {
        sync_directory_if_present(grandparent)?;
    }
    Ok(())
}
fn write_json_atomic_with_publish_sync<T>(
    path: &Path,
    value: &T,
    maximum: usize,
    sync_publication: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), AtomicWriteError>
where
    T: norito::json::JsonSerialize + ?Sized,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AtomicWriteError::before_publish)?;
        let metadata = fs::symlink_metadata(parent).map_err(AtomicWriteError::before_publish)?;
        if push_metadata_is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(AtomicWriteError::before_publish(invalid_data(
                "push output parent is not a direct directory",
            )));
        }
    }
    let bytes = norito::json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        .map_err(AtomicWriteError::before_publish)?;
    if bytes.len() > maximum {
        return Err(AtomicWriteError::before_publish(invalid_data(format!(
            "push JSON has {} bytes, exceeding the maximum {maximum}",
            bytes.len()
        ))));
    }
    let tmp = path.with_extension("json.tmp");
    write_direct_regular_file(&tmp, &bytes).map_err(AtomicWriteError::before_publish)?;
    fs::rename(tmp, path).map_err(AtomicWriteError::before_publish)?;
    sync_publication(path).map_err(AtomicWriteError::after_publish)
}
fn write_json_atomic_with_publish_state<T>(
    path: &Path,
    value: &T,
    maximum: usize,
) -> Result<(), AtomicWriteError>
where
    T: norito::json::JsonSerialize + ?Sized,
{
    write_json_atomic_with_publish_sync(path, value, maximum, sync_json_publication)
}
fn write_json_atomic<T>(path: &Path, value: &T, maximum: usize) -> io::Result<()>
where
    T: norito::json::JsonSerialize + ?Sized,
{
    write_json_atomic_with_publish_state(path, value, maximum).map_err(|error| error.source)
}
fn read_json<T>(path: &Path, maximum: usize) -> io::Result<T>
where
    T: norito::json::JsonDeserialize,
{
    let bytes = read_bounded_stable_file(path, maximum)?;
    norito::json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}
fn load_or_initialize_applied_block_cursor(data_dir: &Path) -> io::Result<AppliedBlockCursor> {
    let _initialization = PUSH_INITIALIZATION_GUARD.lock();
    let parent = data_dir
        .parent()
        .ok_or_else(|| invalid_data("push persistence root has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if push_metadata_is_symlink_or_reparse(&parent_metadata) || !parent_metadata.is_dir() {
        return Err(invalid_data(
            "push persistence parent is not a direct directory",
        ));
    }
    let prepared_dir = parent.join(PUSH_INITIALIZATION_DIR);
    match fs::symlink_metadata(data_dir) {
        Ok(metadata) => {
            if push_metadata_is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(invalid_data(
                    "push persistence root is not a direct directory",
                ));
            }
            match fs::symlink_metadata(&prepared_dir) {
                Ok(_) => {
                    return Err(invalid_data(
                        "push persistence root conflicts with an unfinished initialization directory",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let cursor_path = data_dir.join(APPLIED_BLOCK_CURSOR_FILE);
            let cursor =
                read_json::<AppliedBlockCursor>(&cursor_path, MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES)?;
            cursor.validate()?;
            let cursor_tmp_path = cursor_path.with_extension("json.tmp");
            match fs::symlink_metadata(&cursor_tmp_path) {
                Ok(_) => remove_recoverable_record_temp(
                    &cursor_tmp_path,
                    MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES,
                )?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            return Ok(cursor);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    match fs::symlink_metadata(&prepared_dir) {
        Ok(metadata) => {
            if push_metadata_is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(invalid_data(
                    "push initialization path is not a direct directory",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&prepared_dir)?;
            sync_directory(parent)?;
        }
        Err(error) => return Err(error),
    }

    let cursor_path = prepared_dir.join(APPLIED_BLOCK_CURSOR_FILE);
    let cursor_tmp_path = cursor_path.with_extension("json.tmp");
    let mut cursor_present = false;
    let mut tmp_present = false;
    for entry in read_direct_directory(&prepared_dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if push_metadata_is_symlink_or_reparse(&metadata) || !metadata.is_file() {
            return Err(invalid_data(format!(
                "push initialization contains a non-regular entry: {}",
                path.display()
            )));
        }
        if path == cursor_path {
            if cursor_present {
                return Err(invalid_data(
                    "push initialization contains duplicate cursor entries",
                ));
            }
            cursor_present = true;
        } else if path == cursor_tmp_path {
            if tmp_present {
                return Err(invalid_data(
                    "push initialization contains duplicate temporary cursor entries",
                ));
            }
            tmp_present = true;
        } else {
            return Err(invalid_data(format!(
                "push initialization contains an unexpected entry: {}",
                path.display()
            )));
        }
    }

    let cursor = if cursor_present {
        let cursor =
            read_json::<AppliedBlockCursor>(&cursor_path, MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES)?;
        cursor.validate()?;
        if tmp_present {
            remove_file_if_exists(&cursor_tmp_path)?;
        }
        cursor
    } else {
        let cursor = AppliedBlockCursor::origin();
        write_json_atomic(&cursor_path, &cursor, MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES)?;
        cursor
    };
    sync_directory(&prepared_dir)?;
    fs::rename(&prepared_dir, data_dir)?;
    sync_directory(parent)?;
    Ok(cursor)
}
fn read_direct_directory(path: &Path) -> io::Result<fs::ReadDir> {
    let metadata = fs::symlink_metadata(path)?;
    if push_metadata_is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(invalid_data(
            "push persistence path is not a direct directory",
        ));
    }
    fs::read_dir(path)
}
fn read_bounded_stable_file(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    read_bounded_stable_file_with(path, maximum, || Ok(()))
}
fn read_bounded_stable_file_with(
    path: &Path,
    maximum: usize,
    after_open: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let named_before = secure_file_metadata::from_path(path)?;
    if !secure_file_metadata::is_direct_file(&named_before)
        || secure_file_metadata::number_of_links(&named_before) != Some(1)
    {
        return Err(invalid_data(
            "push input must be a direct single-link regular file",
        ));
    }
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if named_before.len() > maximum_u64 {
        return Err(invalid_data(format!(
            "push input has {} bytes, exceeding the maximum {maximum}",
            named_before.len()
        )));
    }
    #[cfg(windows)]
    let mut file = secure_file_metadata::open_direct_file(path)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        set_no_follow_open_options(&mut options);
        options.open(path)?
    };
    let opened_before = secure_file_metadata::from_file(&file)?;
    if !secure_file_metadata::is_direct_file(&opened_before)
        || secure_file_metadata::number_of_links(&opened_before) != Some(1)
    {
        return Err(invalid_data(
            "opened push input is not a direct single-link regular file",
        ));
    }
    if opened_before.len() > maximum_u64 {
        return Err(invalid_data(format!(
            "opened push input has {} bytes, exceeding the maximum {maximum}",
            opened_before.len()
        )));
    }
    if !secure_file_metadata::unchanged(&named_before, &opened_before) {
        return Err(invalid_data("push input changed identity while opening"));
    }
    after_open()?;
    let capacity = usize::try_from(opened_before.len())
        .unwrap_or(maximum)
        .min(maximum);
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid_data(format!(
            "push input exceeds the maximum {maximum} bytes"
        )));
    }
    let opened_after = secure_file_metadata::from_file(&file)?;
    let named_after = secure_file_metadata::from_path(path)?;
    if !secure_file_metadata::is_direct_file(&opened_after)
        || !secure_file_metadata::is_direct_file(&named_after)
        || secure_file_metadata::number_of_links(&opened_after) != Some(1)
        || secure_file_metadata::number_of_links(&named_after) != Some(1)
        || !secure_file_metadata::unchanged(&opened_before, &opened_after)
        || !secure_file_metadata::unchanged(&opened_after, &named_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(invalid_data("push input changed while reading"));
    }
    Ok(bytes)
}
fn write_direct_regular_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Keep the newly-created inode private until it has been fully written and closed.
        options.share_mode(0);
    }
    set_no_follow_open_options(&mut options);
    let mut file = options.open(path)?;
    let opened_before = secure_file_metadata::from_file(&file)?;
    let named_before = secure_file_metadata::from_path(path)?;
    if !secure_file_metadata::is_direct_file(&opened_before)
        || !secure_file_metadata::is_direct_file(&named_before)
        || secure_file_metadata::number_of_links(&opened_before) != Some(1)
        || secure_file_metadata::number_of_links(&named_before) != Some(1)
        || !secure_file_metadata::same_file(&opened_before, &named_before)
    {
        return Err(invalid_data(
            "push temporary output is not a newly-created single-link regular file",
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    let opened_after = secure_file_metadata::from_file(&file)?;
    let named_after = secure_file_metadata::from_path(path)?;
    let expected = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if !secure_file_metadata::is_direct_file(&opened_after)
        || !secure_file_metadata::is_direct_file(&named_after)
        || secure_file_metadata::number_of_links(&opened_after) != Some(1)
        || secure_file_metadata::number_of_links(&named_after) != Some(1)
        || !secure_file_metadata::same_file(&opened_before, &opened_after)
        || !secure_file_metadata::same_file(&opened_after, &named_after)
        || opened_after.len() != expected
        || named_after.len() != expected
    {
        return Err(invalid_data("push temporary output changed while writing"));
    }
    Ok(())
}
fn set_no_follow_open_options(options: &mut fs::OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOCTTY)
                .bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}
fn push_metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}
fn remove_file_if_exists_with_state(path: &Path) -> Result<(), AtomicRemovalError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AtomicRemovalError {
                source,
                target_absent: false,
            });
        }
    }
    let parent = path.parent().ok_or_else(|| AtomicRemovalError {
        source: invalid_data("push persistence path has no parent directory"),
        target_absent: true,
    })?;
    sync_directory_if_present(parent).map_err(|source| AtomicRemovalError {
        source,
        target_absent: true,
    })
}
fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    remove_file_if_exists_with_state(path).map_err(|error| error.source)
}
fn applied_block_heights(event: &EventBox) -> BTreeSet<u64> {
    let mut heights = BTreeSet::new();
    match event {
        EventBox::Pipeline(PipelineEventBox::Block(block_event)) => {
            if matches!(block_event.status(), BlockStatus::Applied) {
                heights.insert(block_event.header().height().get());
            }
        }
        EventBox::PipelineBatch(events) => {
            for event in events {
                let PipelineEventBox::Block(block_event) = event else {
                    continue;
                };
                if matches!(block_event.status(), BlockStatus::Applied) {
                    heights.insert(block_event.header().height().get());
                }
            }
        }
        _ => {}
    }
    heights
}
async fn send_fcm_http_v1(
    project_id: &str,
    service_account_path: &Path,
    delivery: &PushDelivery,
    settings: &DispatchSettings,
) -> DispatchOutcome {
    let client = match http_client(settings) {
        Ok(client) => client,
        Err(error) => return DispatchOutcome::Retry(error),
    };
    let token = match mint_fcm_access_token(&client, service_account_path, settings).await {
        Ok(token) => token,
        Err(error) => return DispatchOutcome::Retry(error),
    };
    let url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        project_id
    );
    let body = fcm_body(&delivery.token, &delivery.payload);
    let body = match norito::json::to_vec(&body) {
        Ok(body) => body,
        Err(error) => return DispatchOutcome::PermanentFailure(error.to_string()),
    };
    match client
        .post(url)
        .bearer_auth(token)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body(body)
        .send()
        .await
    {
        Ok(response) => classify_fcm_response(response).await,
        Err(error) if error.is_timeout() => DispatchOutcome::Retry(error.to_string()),
        Err(error) => DispatchOutcome::Retry(error.to_string()),
    }
}
async fn send_apns_http2(
    endpoint: &str,
    topic: &str,
    team_id: &str,
    key_id: &str,
    private_key_path: &Path,
    delivery: &PushDelivery,
    settings: &DispatchSettings,
) -> DispatchOutcome {
    let client = match http_client(settings) {
        Ok(client) => client,
        Err(error) => return DispatchOutcome::Retry(error),
    };
    let token = match mint_apns_provider_token(team_id, key_id, private_key_path) {
        Ok(token) => token,
        Err(error) => return DispatchOutcome::Retry(error),
    };
    let url = format!(
        "{}/3/device/{}",
        endpoint.trim_end_matches('/'),
        delivery.token
    );
    let body = apns_body(&delivery.payload);
    let body = match norito::json::to_vec(&body) {
        Ok(body) => body,
        Err(error) => return DispatchOutcome::PermanentFailure(error.to_string()),
    };
    match client
        .post(url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("apns-topic", topic)
        .header("apns-push-type", "background")
        .header("apns-priority", "5")
        .body(body)
        .send()
        .await
    {
        Ok(response) => classify_apns_response(response).await,
        Err(error) if error.is_timeout() => DispatchOutcome::Retry(error.to_string()),
        Err(error) => DispatchOutcome::Retry(error.to_string()),
    }
}
fn http_client(settings: &DispatchSettings) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(settings.connect_timeout)
        .timeout(settings.request_timeout)
        .http2_adaptive_window(true)
        .build()
        .map_err(|error| error.to_string())
}
fn jwt_algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
    }
}
fn encode_jwt_claims(
    algorithm: Algorithm,
    key_id: Option<&str>,
    claims: norito::json::Value,
    key: &EncodingKey,
) -> Result<String, String> {
    let mut header = norito::json::Map::new();
    header.insert("typ".to_string(), norito::json::Value::from("JWT"));
    header.insert(
        "alg".to_string(),
        norito::json::Value::from(jwt_algorithm_name(algorithm)),
    );
    if let Some(key_id) = key_id {
        header.insert("kid".to_string(), norito::json::Value::from(key_id));
    }
    let encoded_header = BASE64_URL_SAFE_NO_PAD.encode(
        norito::json::to_vec(&norito::json::Value::Object(header))
            .map_err(|error| error.to_string())?,
    );
    let encoded_claims = BASE64_URL_SAFE_NO_PAD
        .encode(norito::json::to_vec(&claims).map_err(|error| error.to_string())?);
    let message = format!("{encoded_header}.{encoded_claims}");
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), key, algorithm)
        .map_err(|error| error.to_string())?;
    Ok(format!("{message}.{signature}"))
}
async fn read_push_provider_response_bounded(
    mut response: reqwest::Response,
    source: &'static str,
) -> Result<Vec<u8>, String> {
    let maximum = u64::try_from(MAX_PUSH_PROVIDER_RESPONSE_BYTES)
        .map_err(|_| "push provider response ceiling does not fit u64".to_string())?;
    let declared = response.content_length();
    if let Some(length) = declared
        && length > maximum
    {
        return Err(format!(
            "{source} declared a {length}-byte response, exceeding the {MAX_PUSH_PROVIDER_RESPONSE_BYTES}-byte ceiling"
        ));
    }
    let initial_capacity = declared
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(MAX_PUSH_PROVIDER_RESPONSE_BYTES);
    let mut body = Vec::new();
    body.try_reserve_exact(initial_capacity)
        .map_err(|error| format!("failed to reserve {source} response buffer: {error}"))?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to stream {source} response: {error}"))?
    {
        // The streamed count is authoritative for chunked responses and for
        // bodies that grow after transparent decompression. Stop at max + 1
        // before copying an oversized chunk into the retained buffer.
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| format!("{source} response length overflowed"))?;
        if next_len > MAX_PUSH_PROVIDER_RESPONSE_BYTES {
            return Err(format!(
                "{source} response exceeded the {MAX_PUSH_PROVIDER_RESPONSE_BYTES}-byte ceiling while streaming"
            ));
        }
        body.try_reserve_exact(chunk.len())
            .map_err(|error| format!("failed to grow {source} response buffer: {error}"))?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
async fn mint_fcm_access_token(
    client: &reqwest::Client,
    service_account_path: &Path,
    settings: &DispatchSettings,
) -> Result<String, String> {
    let bytes = read_bounded_stable_file(service_account_path, MAX_FCM_SERVICE_ACCOUNT_BYTES)
        .map_err(|error| error.to_string())?;
    let value: norito::json::Value =
        norito::json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let client_email = json_string_field(&value, "client_email")?;
    let private_key = json_string_field(&value, "private_key")?;
    let issued_at = now_ms() / 1000;
    let mut claims = norito::json::Map::new();
    claims.insert("iss".to_string(), norito::json::Value::from(client_email));
    claims.insert("scope".to_string(), norito::json::Value::from(FCM_SCOPE));
    claims.insert(
        "aud".to_string(),
        norito::json::Value::from(FCM_TOKEN_ENDPOINT),
    );
    claims.insert("iat".to_string(), norito::json::Value::from(issued_at));
    claims.insert(
        "exp".to_string(),
        norito::json::Value::from(issued_at.saturating_add(3600)),
    );
    let jwt = encode_jwt_claims(
        Algorithm::RS256,
        None,
        norito::json::Value::Object(claims),
        &EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|error| error.to_string())?,
    )?;
    let response = client
        .post(FCM_TOKEN_ENDPOINT)
        .timeout(settings.request_timeout)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt.as_str()),
        ])
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        // OAuth failure semantics depend only on the status. Avoid retaining
        // an attacker- or proxy-controlled diagnostic body.
        return Err(format!("FCM token endpoint returned {status}"));
    }
    let bytes = read_push_provider_response_bounded(response, "FCM token endpoint").await?;
    let value: norito::json::Value =
        norito::json::from_slice(&bytes).map_err(|error| error.to_string())?;
    json_string_field(&value, "access_token")
}
fn mint_apns_provider_token(
    team_id: &str,
    key_id: &str,
    private_key_path: &Path,
) -> Result<String, String> {
    let private_key = read_bounded_stable_file(private_key_path, MAX_APNS_PRIVATE_KEY_BYTES)
        .map_err(|error| error.to_string())?;
    let issued_at = now_ms() / 1000;
    let mut claims = norito::json::Map::new();
    claims.insert("iss".to_string(), norito::json::Value::from(team_id));
    claims.insert("iat".to_string(), norito::json::Value::from(issued_at));
    encode_jwt_claims(
        Algorithm::ES256,
        Some(key_id),
        norito::json::Value::Object(claims),
        &EncodingKey::from_ec_pem(&private_key).map_err(|error| error.to_string())?,
    )
}
fn json_string_field(value: &norito::json::Value, field: &str) -> Result<String, String> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(norito::json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing `{field}`"))
}
fn fcm_body(token: &str, payload: &PushActivityPayload) -> norito::json::Value {
    norito::json!({
        "message": {
            "token": token,
            "data": (push_data(payload)),
            "android": {
                "priority": "high"
            },
            "apns": {
                "headers": {
                    "apns-push-type": "background",
                    "apns-priority": "5"
                },
                "payload": {
                    "aps": {
                        "content-available": 1
                    }
                }
            }
        }
    })
}
fn apns_body(payload: &PushActivityPayload) -> norito::json::Value {
    norito::json!({
        "aps": {
            "content-available": 1
        },
        "iroha": (push_data(payload))
    })
}
fn push_data(payload: &PushActivityPayload) -> norito::json::Value {
    norito::json!({
        "account_id": (payload.account_id.clone()),
        "activity_kind": (payload.activity_kind.clone()),
        "tx_hash": (payload.tx_hash.clone()),
        "block_height": (payload.block_height.to_string()),
        "instruction_index": (payload.instruction_index.to_string()),
        "direction": (payload.direction.clone())
    })
}
async fn classify_fcm_response(response: reqwest::Response) -> DispatchOutcome {
    let status = response.status();
    if status.is_success() {
        return DispatchOutcome::Sent;
    }
    let body = read_push_provider_response_bounded(response, "FCM send endpoint")
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|error| format!("response body unavailable: {error}"));
    classify_fcm_status_body(status, &body)
}
async fn classify_apns_response(response: reqwest::Response) -> DispatchOutcome {
    let status = response.status();
    if status.is_success() {
        return DispatchOutcome::Sent;
    }
    let body = read_push_provider_response_bounded(response, "APNs send endpoint")
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|error| format!("response body unavailable: {error}"));
    classify_apns_status_body(status, &body)
}
fn classify_fcm_status_body(status: HttpStatusCode, body: &str) -> DispatchOutcome {
    if status.is_success() {
        return DispatchOutcome::Sent;
    }
    if status == HttpStatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return DispatchOutcome::Retry(format!("FCM returned {status}: {body}"));
    }
    if body.contains("UNREGISTERED")
        || body.contains("INVALID_ARGUMENT")
        || body.contains("registration token")
    {
        return DispatchOutcome::InvalidToken(format!("FCM returned {status}: {body}"));
    }
    DispatchOutcome::PermanentFailure(format!("FCM returned {status}: {body}"))
}
fn classify_apns_status_body(status: HttpStatusCode, body: &str) -> DispatchOutcome {
    if status.is_success() {
        return DispatchOutcome::Sent;
    }
    if status == HttpStatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return DispatchOutcome::Retry(format!("APNs returned {status}: {body}"));
    }
    if status == HttpStatusCode::GONE
        || body.contains("Unregistered")
        || body.contains("BadDeviceToken")
        || body.contains("DeviceTokenNotForTopic")
    {
        return DispatchOutcome::InvalidToken(format!("APNs returned {status}: {body}"));
    }
    DispatchOutcome::PermanentFailure(format!("APNs returned {status}: {body}"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_dir::OverrideGuard;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    const TEST_ACCOUNT_I105: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";
    fn fixture_account(seed: u8) -> String {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("push fixture key derivation should succeed");
        AccountId::new(key_pair.public_key().clone()).to_string()
    }
    async fn raw_provider_response(response: Vec<u8>) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind push provider response listener");
        let address = listener
            .local_addr()
            .expect("push provider response address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept provider request");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(&response)
                .await
                .expect("write provider response");
        });
        reqwest::Client::new()
            .get(format!("http://{address}/push-provider"))
            .send()
            .await
            .expect("receive provider response headers")
    }

    #[tokio::test]
    async fn push_provider_client_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test listener");
        let address = listener.local_addr().expect("redirect test address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept initial request");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{address}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write redirect response");
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok()
        });
        let client = http_client(&DispatchSettings {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
        })
        .expect("build push provider client");
        let response = client
            .post(format!("http://{address}/initial"))
            .body("credential-bearing-push-body")
            .send()
            .await
            .expect("receive redirect response");

        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        assert!(
            !server.await.expect("redirect test server"),
            "push provider client followed a redirect"
        );
    }
    fn chunked_provider_response(status: &str, body_len: usize) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body_len:X}\r\n"
        )
        .into_bytes();
        response.resize(response.len() + body_len, b'x');
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        response
    }
    fn test_bridge_config() -> actual::Push {
        actual::Push {
            enabled: true,
            fcm_project_id: Some("project".to_string()),
            fcm_service_account_path: Some(PathBuf::from("/tmp/service-account.json")),
            ..Default::default()
        }
    }
    fn test_storage_limits(max_devices: usize, max_queue_jobs: usize) -> PushStorageLimits {
        PushStorageLimits {
            max_devices,
            max_queue_jobs,
            dispatch_batch_size: max_queue_jobs,
            ..PUSH_STORAGE_LIMITS
        }
    }
    fn pipeline_block_event(height: u64, status: BlockStatus) -> PipelineEventBox {
        PipelineEventBox::Block(iroha_data_model::events::pipeline::BlockEvent {
            header: BlockHeader::new(
                std::num::NonZeroU64::new(height).expect("nonzero block event height"),
                None,
                None,
                0,
                0,
            ),
            status,
        })
    }
    fn applied_event(height: u64) -> EventBox {
        EventBox::Pipeline(pipeline_block_event(height, BlockStatus::Applied))
    }
    fn signed_push_block(
        height: u64,
        previous: Option<&SignedBlock>,
        transactions: Vec<SignedTransaction>,
    ) -> SignedBlock {
        let signer = iroha_crypto::KeyPair::try_from_seed(
            vec![u8::try_from(height).unwrap_or(0xE7); 32],
            iroha_crypto::Algorithm::Ed25519,
        )
        .expect("derive push block fixture key");
        let header = BlockHeader::new(
            std::num::NonZeroU64::new(height).expect("push block fixture height is nonzero"),
            previous.map(SignedBlock::hash),
            None,
            height,
            0,
        );
        let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
        let mut outputs = Vec::with_capacity(transactions.len());
        for (index, transaction) in transactions.into_iter().enumerate() {
            builder.push_transaction(transaction);
            outputs.push(
                iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                    iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                        input_index: u32::try_from(index).expect("fixture input count fits u32"),
                        result: iroha_data_model::transaction::TransactionResult::new(Ok(vec![])),
                        completions: vec![],
                    },
                ),
            );
        }
        let mut block = builder.build_with_signature(0, signer.private_key());
        crate::test_utils::attach_fixture_execution_outputs(&mut block, outputs);
        block
    }
    /// Apply the real signed genesis and H2 so genesis output has a native successor.
    fn native_push_chain(activity: bool) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
        use iroha_core::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::prelude::{Account, Register};
        let mut config = TestChainConfig::new(World::new(), 1_000);
        if activity {
            let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("fixture account");
            config
                .genesis_instructions
                .push(Register::account(Account::new(account)).into());
        }
        let mut chain = CertifiedTestChain::start(config).expect("apply original native genesis");
        chain.commit(Vec::new());
        for height in 1..=2 {
            let authenticated =
                state_block_at_height(chain.state(), height).expect("native push carrier");
            assert_eq!(
                authenticated.encode_wire().unwrap(),
                chain.committed(height).block().encode_wire().unwrap()
            );
        }
        chain
    }
    fn native_push_genesis_config() -> iroha_core::sumeragi::test_chain::TestChainConfig {
        use iroha_core::{state::World, sumeragi::test_chain::TestChainConfig};
        use iroha_data_model::prelude::{Account, Register};
        let mut config = TestChainConfig::new(World::new(), 1_000);
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("fixture account");
        config
            .genesis_instructions
            .push(Register::account(Account::new(account)).into());
        config
    }

    /// Only H2's schedule, captured from genuinely replayed G1 before H2 is supplied.
    struct RestartedPushGenesisSchedule {
        instance: iroha_sumeragi::types::Hash32,
        config: iroha_sumeragi::types::HeightConfig,
    }
    impl iroha_core::sumeragi::availability_schedule::AvailabilitySchedule
        for RestartedPushGenesisSchedule
    {
        fn instance(&self) -> iroha_sumeragi::types::Hash32 {
            self.instance
        }
        fn height_config(
            &self,
            height: u64,
        ) -> Result<Option<iroha_sumeragi::types::HeightConfig>, ExecutionAttemptError<io::Error>>
        {
            Ok((height == 2).then(|| self.config.clone()))
        }
    }

    /// Re-execute the original stored genesis into a new State/pool, then replay real H2.
    struct RestartedPushGenesis {
        state: Arc<State>,
        kura: Arc<Kura>,
        blocks: iroha_core::sumeragi::block_store::KuraBlockStore,
        executor: iroha_core::sumeragi::executor::StateExecutor,
    }
    impl RestartedPushGenesis {
        fn new(source: &iroha_core::sumeragi::test_chain::CertifiedTestChain) -> Self {
            use iroha_core::{
                state::WorldReadOnly as _,
                sumeragi::{
                    block_store::{KuraBlockStore, Staging},
                    crypto::BlsCrypto,
                    executor::{ExecutorContext, StateExecutor},
                    startup,
                    test_chain::CertifiedTestChain,
                },
            };
            let prepared = CertifiedTestChain::prepare(native_push_genesis_config()).unwrap();
            let state = prepared.state;
            let kura = prepared.kura;
            assert_eq!(state.committed_height(), 0);
            assert_eq!(kura.blocks_count(), 0);
            let original = source.committed(1);
            assert_eq!(
                prepared.genesis.expected_hash(),
                source.validated_genesis().expected_hash()
            );
            kura.store_block(original.block().clone()).unwrap();
            let (genesis, certificate, stored_tip) =
                startup::stored_genesis(&state).unwrap().unwrap();
            let instance =
                iroha_core::sumeragi::node::root_instance(&genesis, state.chain_id_ref().as_ref())
                    .unwrap();
            assert_eq!(instance, source.instance());
            let genesis_account = AccountId::new(prepared.genesis.public_key().clone());
            let consensus_mode = prepared.genesis.consensus_metadata().mode.into();
            let tip = startup::apply_genesis(
                &state,
                genesis,
                &genesis_account,
                consensus_mode,
                Some(&certificate),
            )
            .unwrap();
            assert_eq!(tip.block_hash, stored_tip.block_hash);
            assert_eq!(tip.result, stored_tip.result);
            assert_eq!(state.committed_height(), 1);

            // Authority comes only from the independently re-executed G1 State.
            // This fixture admits H2 only, not a caller-selected historical schedule.
            let scheduled = state
                .view()
                .world()
                .consensus_schedule()
                .ready(2)
                .unwrap()
                .clone();
            let crypto = Arc::new(BlsCrypto::new());
            crypto
                .admit_committee(scheduled.epoch.committee.iter().map(|member| {
                    (
                        member.validator.public_key(),
                        member.proof_of_possession.as_slice(),
                    )
                }))
                .unwrap();
            let schedule = Arc::new(RestartedPushGenesisSchedule {
                instance,
                config: scheduled.height_config().unwrap(),
            });
            let staging = Staging::new();
            let blocks = KuraBlockStore::new(
                Arc::clone(&kura),
                crypto.clone(),
                startup::GENESIS_HEIGHT,
                source.root_scope(),
                staging.clone(),
                state.ivm_execution_budget(),
                schedule,
            );
            let (events, _) = tokio::sync::broadcast::channel(16);
            let executor = StateExecutor::spawn(ExecutorContext {
                time_source: iroha_primitives::time::TimeSource::new_system(),
                state: Arc::clone(&state),
                root_scope: source.root_scope(),
                native_context_archive: Arc::new(
                    iroha_core::query::native_context_archive::NativeContextArchive::open(
                        &kura,
                        state.ivm_execution_budget(),
                        kura.native_context_archive_max_bytes(),
                    )
                    .unwrap(),
                ),
                queue: None,
                staging,
                events,
                genesis_account,
                consensus_mode,
                applied: (1, tip.block_hash),
                crypto: Some(crypto),
                applied_watch: Arc::new(iroha_core::sumeragi::lanes::global::AppliedWatch::new(
                    1,
                    state.view().latest_block_hash(),
                )),
                lane_blocks: prepared.lane_blocks,
            })
            .unwrap();
            Self {
                state,
                kura,
                blocks,
                executor,
            }
        }

        fn replay_successor(
            &mut self,
            source: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
        ) {
            assert_eq!(self.state.committed_height(), 1);
            assert_eq!(source.height(), 2);
            self.kura
                .store_block(source.committed(2).block().clone())
                .unwrap();
            let (body, certificate) = self.blocks.committed_body(2).unwrap().unwrap();
            assert!(body.admitted_to(&self.state.ivm_execution_budget()));
            self.executor.replay(&body, &certificate).unwrap();
            assert_eq!(self.state.committed_height(), 2);
        }
    }

    #[tokio::test]
    async fn push_worker_genesis_bootstrap_waits_for_authenticated_successor_and_shutdown() {
        use iroha_core::sumeragi::test_chain::CertifiedTestChain;
        for restarted in [false, true] {
            for publish_successor in [false, true] {
                let mut chain = CertifiedTestChain::start(native_push_genesis_config()).unwrap();
                let mut replayed = restarted.then(|| RestartedPushGenesis::new(&chain));
                let state = Arc::clone(
                    replayed
                        .as_ref()
                        .map_or_else(|| chain.state(), |owner| &owner.state),
                );
                assert_eq!(state.committed_height(), 1);
                assert_eq!(state.exact_durable_block_count().unwrap(), 1);
                let temp = tempfile::tempdir().unwrap();
                let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::Sent]));
                let bridge = PushBridge::with_dispatcher_and_limits_in(
                    test_bridge_config(),
                    dispatcher.clone(),
                    test_storage_limits(1, 1),
                    temp.path().to_path_buf(),
                )
                .unwrap();
                bridge
                    .register_device(register_request("genesis-bootstrap"))
                    .unwrap();
                let cursor_before = fs::read(bridge.applied_block_cursor_path()).unwrap();
                let pool = state.ivm_execution_budget();
                let before_worker = pool.reserved_bytes();
                // Deliberately send no Push events: State publication must wake bootstrap.
                let (events, _) = tokio::sync::broadcast::channel(4);
                let shutdown = ShutdownSignal::new();
                let mut worker = bridge
                    .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
                    .unwrap()
                    .unwrap();
                let parked = tokio::time::timeout(Duration::from_millis(20), &mut worker).await;
                assert!(
                    parked.is_err(),
                    "applied G1 worker must remain parked until its actual successor or shutdown; restarted={restarted}, got {parked:?}"
                );
                let waiting_cursor = bridge.applied_block_cursor.lock().clone();
                let waiting_disk = fs::read(bridge.applied_block_cursor_path()).unwrap();
                let waiting_queue = bridge.queued_count();
                let waiting_calls = dispatcher.calls.lock().unwrap().len();
                let progress = if publish_successor {
                    // The fixture supplies an actual signed clock Log transaction, not an empty block.
                    chain.commit(Vec::new());
                    if let Some(owner) = replayed.as_mut() {
                        owner.replay_successor(&chain);
                    }
                    tokio::time::timeout(Duration::from_secs(10), async {
                        while bridge.applied_block_cursor.lock().height != 2 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                } else {
                    Ok(())
                };
                shutdown.send();
                let exit = worker.await.unwrap();
                assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
                assert_eq!(waiting_cursor, AppliedBlockCursor::origin());
                assert_eq!(
                    waiting_disk, cursor_before,
                    "bootstrap wait must not publish a cursor"
                );
                assert_eq!(waiting_queue, 0);
                assert_eq!(waiting_calls, 0, "bootstrap wait must not dispatch");
                assert!(
                    progress.is_ok(),
                    "authentic successor must wake the original worker without a Push event"
                );
                let cursor = bridge.applied_block_cursor.lock().clone();
                if publish_successor {
                    assert_eq!(cursor.height, 2);
                    assert_eq!(cursor.block_hash, Some(chain.committed(2).block_hash()));
                    assert_eq!(
                        read_json::<AppliedBlockCursor>(
                            &bridge.applied_block_cursor_path(),
                            MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES
                        )
                        .unwrap(),
                        cursor
                    );
                    let native = state_block_at_height(&state, 1).unwrap();
                    assert_eq!(
                        native.encode_wire().unwrap(),
                        chain.committed(1).block().encode_wire().unwrap()
                    );
                    assert_eq!(
                        bridge.queued_count() + dispatcher.calls.lock().unwrap().len(),
                        1,
                        "the original genesis activity appears exactly once after full authentication"
                    );
                } else {
                    assert_eq!(cursor, AppliedBlockCursor::origin());
                    assert_eq!(
                        fs::read(bridge.applied_block_cursor_path()).unwrap(),
                        cursor_before
                    );
                    assert_eq!(bridge.queued_count(), 0);
                    assert_eq!(dispatcher.calls.lock().unwrap().len(), 0);
                    assert_eq!(
                        pool.reserved_bytes(),
                        before_worker,
                        "parked cancellation refunds original retry control"
                    );
                }
                drop(events);
            }
        }
    }

    #[tokio::test]
    async fn push_worker_genesis_bootstrap_rejects_corrupt_history_and_nonzero_cursor() {
        use iroha_core::sumeragi::test_chain::CertifiedTestChain;
        for missing in [false, true] {
            let mut chain = CertifiedTestChain::start(native_push_genesis_config()).unwrap();
            let state = Arc::clone(chain.state());
            let temp = tempfile::tempdir().unwrap();
            let dispatcher = Arc::new(MockDispatcher::new(Vec::new()));
            let bridge = PushBridge::with_dispatcher_and_limits_in(
                test_bridge_config(),
                dispatcher.clone(),
                test_storage_limits(1, 1),
                temp.path().to_path_buf(),
            )
            .unwrap();
            bridge
                .register_device(register_request("untrusted-genesis"))
                .unwrap();
            let cursor_before = fs::read(bridge.applied_block_cursor_path()).unwrap();
            let (events, _) = tokio::sync::broadcast::channel(4);
            let shutdown = ShutdownSignal::new();
            let mut worker = bridge
                .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
                .unwrap()
                .unwrap();
            let parked = tokio::time::timeout(Duration::from_millis(20), &mut worker).await;
            assert!(
                parked.is_err(),
                "applied G1 worker must remain parked before adversarial successor delivery; got {parked:?}"
            );
            // This test uses Tokio's current-thread runtime. Publish synchronously, then
            // corrupt the actual original journal before the woken Push worker can poll.
            chain.commit(Vec::new());
            let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
            let original = fs::read(&path).unwrap();
            let saved = path.with_extension("genesis-bootstrap-original");
            if missing {
                fs::rename(&path, &saved).unwrap();
            } else {
                let mut corrupt = original.clone();
                corrupt[0] ^= 0xff;
                fs::write(&path, corrupt).unwrap();
            }
            let terminal = tokio::time::timeout(Duration::from_secs(10), &mut worker).await;
            if missing {
                fs::rename(&saved, &path).unwrap();
            } else {
                fs::write(&path, &original).unwrap();
            }
            shutdown.send();
            let exit = match terminal {
                Ok(exit) => exit.unwrap(),
                Err(_) => worker.await.unwrap(),
            };
            assert_eq!(
                exit,
                crate::ToriiCriticalWorkerExit::UnexpectedExit,
                "successor notification supplies no authority for corrupt or missing history"
            );
            assert_eq!(
                *bridge.applied_block_cursor.lock(),
                AppliedBlockCursor::origin()
            );
            assert_eq!(
                fs::read(bridge.applied_block_cursor_path()).unwrap(),
                cursor_before
            );
            assert_eq!(bridge.queued_count(), 0);
            assert_eq!(dispatcher.calls.lock().unwrap().len(), 0);
            drop(events);
        }
        let chain = CertifiedTestChain::start(native_push_genesis_config()).unwrap();
        for cursor in [
            AppliedBlockCursor {
                version: APPLIED_BLOCK_CURSOR_VERSION,
                height: 1,
                block_hash: Some(chain.committed(1).block_hash()),
            },
            AppliedBlockCursor {
                version: APPLIED_BLOCK_CURSOR_VERSION,
                height: 2,
                block_hash: Some(chain.committed(1).block_hash()),
            },
            AppliedBlockCursor {
                version: APPLIED_BLOCK_CURSOR_VERSION,
                height: 0,
                block_hash: Some(chain.committed(1).block_hash()),
            },
            AppliedBlockCursor {
                version: APPLIED_BLOCK_CURSOR_VERSION + 1,
                height: 0,
                block_hash: None,
            },
        ] {
            let temp = tempfile::tempdir().unwrap();
            let bridge =
                PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
            *bridge.applied_block_cursor.lock() = cursor.clone();
            let (events, _) = tokio::sync::broadcast::channel(4);
            let shutdown = ShutdownSignal::new();
            let mut worker = bridge
                .start_event_worker(Arc::clone(chain.state()), events.clone(), shutdown.clone())
                .unwrap()
                .unwrap();
            let terminal = tokio::time::timeout(Duration::from_secs(10), &mut worker).await;
            shutdown.send();
            let exit = match terminal {
                Ok(exit) => exit.unwrap(),
                Err(_) => worker.await.unwrap(),
            };
            assert_eq!(
                exit,
                crate::ToriiCriticalWorkerExit::UnexpectedExit,
                "non-origin or corrupt cursor cannot wait on a genesis-only State"
            );
            assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
            assert_eq!(bridge.queued_count(), 0);
            drop(events);
        }
    }

    fn pristine_push_state(kura: Arc<Kura>) -> Arc<State> {
        Arc::new(State::new_for_testing(
            iroha_core::state::World::new(),
            kura,
            iroha_core::query::store::LiveQueryStore::start_test(),
        ))
    }
    fn write_origin_cursor(base: &Path) {
        write_json_atomic(
            &base.join(PUSH_DIR).join(APPLIED_BLOCK_CURSOR_FILE),
            &AppliedBlockCursor::origin(),
            MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES,
        )
        .expect("write origin push cursor fixture");
    }
    fn json_with_top_level_unknown<T>(value: &T) -> Vec<u8>
    where
        T: norito::json::JsonSerialize + ?Sized,
    {
        let mut bytes = norito::json::to_vec(value).expect("serialize strict push fixture");
        assert_eq!(bytes.pop(), Some(b'}'), "push fixture must be an object");
        bytes.extend_from_slice(b",\"unexpected\":true}");
        bytes
    }
    fn job_json_with_nested_payload_unknown(job: &DeliveryJob) -> Vec<u8> {
        let mut json = String::from_utf8(
            norito::json::to_vec(job).expect("serialize strict push job fixture"),
        )
        .expect("push job JSON is UTF-8");
        let marker = "\"direction\":\"incoming\"";
        let insertion = json
            .find(marker)
            .map(|offset| offset + marker.len())
            .expect("push job fixture contains its nested direction field");
        json.insert_str(insertion, ",\"unexpected\":true");
        json.into_bytes()
    }
    fn write_raw_push_fixture(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().expect("raw push fixture parent"))
            .expect("create raw push fixture parent");
        write_direct_regular_file(path, bytes).expect("write raw push fixture");
    }
    async fn wait_for_cursor(bridge: &PushBridge, expected_height: u64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if bridge.applied_block_cursor.lock().height == expected_height {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("push cursor must reach the expected height");
    }
    #[test]
    fn applied_block_heights_include_every_unique_applied_event() {
        let event = EventBox::PipelineBatch(vec![
            pipeline_block_event(1, BlockStatus::Committed),
            pipeline_block_event(2, BlockStatus::Applied),
            pipeline_block_event(3, BlockStatus::Applied),
            pipeline_block_event(2, BlockStatus::Applied),
        ]);
        assert_eq!(applied_block_heights(&event), BTreeSet::from([2, 3]));
    }
    #[tokio::test]
    async fn event_worker_reconciles_broadcast_lag_and_stays_supervised() {
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("valid empty push store");
        let (events, _) = tokio::sync::broadcast::channel(1);
        let shutdown = ShutdownSignal::new();
        let worker = bridge
            .start_event_worker(
                pristine_push_state(Kura::blank_kura_for_testing()),
                events.clone(),
                shutdown.clone(),
            )
            .expect("original State pool admits push retry control")
            .expect("enabled push worker");
        events
            .send(EventBox::PipelineBatch(Vec::new()))
            .expect("first event");
        events
            .send(EventBox::PipelineBatch(Vec::new()))
            .expect("second event");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !worker.is_finished(),
            "Kura reconciliation must keep a lagged worker alive"
        );
        shutdown.send();
        let exit = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("worker must stop after shutdown")
            .expect("worker join");
        assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
    }
    #[test]
    fn first_run_cursor_initialization_recovers_its_prepared_directory() {
        let temp = tempfile::tempdir().expect("push tempdir");
        fs::create_dir(temp.path().join(PUSH_INITIALIZATION_DIR))
            .expect("create interrupted push initialization fixture");

        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("prepared first-run initialization must be recoverable");

        assert_eq!(
            *bridge.applied_block_cursor.lock(),
            AppliedBlockCursor::origin()
        );
        assert!(bridge.applied_block_cursor_path().is_file());
        assert!(!temp.path().join(PUSH_INITIALIZATION_DIR).exists());
    }
    #[test]
    fn existing_push_store_without_cursor_is_a_hard_cut_error() {
        let temp = tempfile::tempdir().expect("push tempdir");
        fs::create_dir(temp.path().join(PUSH_DIR)).expect("create legacy push root");

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("legacy push root without cursor must fail closed");

        assert!(matches!(error, PushError::Storage(_)));
    }
    #[test]
    fn startup_removes_bounded_queue_writer_temp_after_crash() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let path = temp.path().join(PUSH_DIR).join(QUEUE_DIR).join(format!(
            "{}.json.tmp",
            fingerprint(b"interrupted-queue-job")
        ));
        fs::create_dir_all(path.parent().expect("queue temp parent"))
            .expect("create queue temp parent");
        write_direct_regular_file(&path, b"{\"partial\":")
            .expect("write interrupted queue publication");

        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("exact queue writer temp must be recoverable");

        assert_eq!(bridge.queued_count(), 0);
        assert!(!path.exists());
    }
    #[test]
    fn startup_removes_bounded_device_writer_temp_after_crash() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let path = temp
            .path()
            .join(PUSH_DIR)
            .join(DEVICES_DIR)
            .join(format!("{}.json.tmp", fingerprint(b"interrupted-device")));
        fs::create_dir_all(path.parent().expect("device temp parent"))
            .expect("create device temp parent");
        write_direct_regular_file(&path, b"{\"partial\":")
            .expect("write interrupted device publication");

        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("exact device writer temp must be recoverable");

        assert_eq!(bridge.device_count(), 0);
        assert!(!path.exists());
    }
    #[test]
    fn startup_recovers_device_temp_at_persisted_device_limit() {
        let temp = tempfile::tempdir().expect("push tempdir");
        let limits = test_storage_limits(1, 1);
        let bridge = PushBridge::with_dispatcher_and_limits_in(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            limits,
            temp.path().to_path_buf(),
        )
        .expect("initialize bounded push store");
        bridge
            .register_device(register_request("persisted-device"))
            .expect("persist one live device");
        drop(bridge);

        let path = temp
            .path()
            .join(PUSH_DIR)
            .join(DEVICES_DIR)
            .join(format!("{}.json.tmp", fingerprint(b"interrupted-device")));
        write_direct_regular_file(&path, b"{\"partial\":")
            .expect("write interrupted device publication");

        let reopened = PushBridge::with_dispatcher_and_limits_in(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            limits,
            temp.path().to_path_buf(),
        )
        .expect("recover temp outside the persisted device limit");

        assert_eq!(reopened.device_count(), 1);
        assert!(!path.exists());
    }
    #[test]
    fn startup_rejects_multiple_queue_temps_before_removing_either() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let queue_dir = temp.path().join(PUSH_DIR).join(QUEUE_DIR);
        fs::create_dir_all(&queue_dir).expect("create queue temp parent");
        let first = queue_dir.join(format!("{}.json.tmp", fingerprint(b"first-temp")));
        let second = queue_dir.join(format!("{}.json.tmp", fingerprint(b"second-temp")));
        write_direct_regular_file(&first, b"{\"partial\":").expect("write first queue temp");
        write_direct_regular_file(&second, b"{\"partial\":").expect("write second queue temp");

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("multiple queue temps must fail closed");

        assert!(matches!(error, PushError::Storage(_)));
        assert!(first.exists());
        assert!(second.exists());
    }
    #[test]
    fn startup_rejects_unknown_device_record_field() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let token = "strict-device-token";
        let token_fingerprint = fingerprint(token.as_bytes());
        let record = DeviceRecord {
            account_id: TEST_ACCOUNT_I105.to_owned(),
            platform: Platform::Fcm.label().to_owned(),
            token: token.to_owned(),
            token_fingerprint: token_fingerprint.clone(),
            topics: Vec::new(),
            updated_at_ms: 0,
        };
        let path = temp
            .path()
            .join(PUSH_DIR)
            .join(DEVICES_DIR)
            .join(format!("{token_fingerprint}.json"));
        write_raw_push_fixture(&path, &json_with_top_level_unknown(&record));

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("unknown device record fields must fail startup");

        assert!(matches!(error, PushError::Storage(_)));
    }
    #[test]
    fn startup_rejects_unknown_delivery_job_field() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let job = test_job(92);
        let path = temp
            .path()
            .join(PUSH_DIR)
            .join(QUEUE_DIR)
            .join(format!("{}.json", job.dedupe_key));
        write_raw_push_fixture(&path, &json_with_top_level_unknown(&job));

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("unknown delivery job fields must fail startup");

        assert!(matches!(error, PushError::Storage(_)));
    }
    #[test]
    fn startup_rejects_unknown_nested_push_payload_field() {
        let temp = tempfile::tempdir().expect("push tempdir");
        write_origin_cursor(temp.path());
        let job = test_job(93);
        let path = temp
            .path()
            .join(PUSH_DIR)
            .join(QUEUE_DIR)
            .join(format!("{}.json", job.dedupe_key));
        write_raw_push_fixture(&path, &job_json_with_nested_payload_unknown(&job));

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("unknown nested push payload fields must fail startup");

        assert!(matches!(error, PushError::Storage(_)));
    }
    #[test]
    fn replay_refuses_unfinalized_body_before_queue_side_effects() {
        let kura = Kura::blank_kura_for_testing();
        let block = signed_push_block(1, None, Vec::new());
        let state = pristine_push_state(kura.clone());
        let block = SharedSignedBlock::try_new(block, &state.ivm_execution_budget())
            .expect("fund unapplied body from its original State pool");
        kura.store_block(block)
            .expect("deliberately store an unapplied body");
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        bridge
            .register_device(register_request("unfinalized-activity-token"))
            .unwrap();
        bridge
            .reconcile_to_authoritative_height(&state)
            .expect("unapplied Kura body is outside State history");
        let error = bridge
            .reconcile_through_height(&state, 1)
            .expect_err("an event cannot authorize an unapplied body");
        let PushReplayError::Fatal(PushError::Storage(reason)) = error else {
            panic!("expected unavailable applied history, got {error:?}");
        };
        assert!(
            reason.contains("exceeds State's applied height 0"),
            "{reason}"
        );
        assert_eq!(bridge.applied_block_cursor.lock().height, 0);
        assert_eq!(bridge.queued_count(), 0);
    }
    #[tokio::test]
    async fn event_worker_replays_durable_kura_backlog_before_serving_events() {
        let chain = native_push_chain(false);
        let state = Arc::clone(chain.state());
        let second = chain.committed(2);
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("valid empty push store");
        let (events, _) = tokio::sync::broadcast::channel(4);
        let shutdown = ShutdownSignal::new();
        // Keep the event source alive until shutdown; channel closure is a separate failure.
        let worker = bridge
            .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
            .expect("original State pool admits push retry control")
            .expect("enabled push worker");

        wait_for_cursor(&bridge, 2).await;
        let persisted = read_json::<AppliedBlockCursor>(
            &bridge.applied_block_cursor_path(),
            MAX_PUSH_APPLIED_BLOCK_CURSOR_BYTES,
        )
        .expect("read replayed push cursor");
        assert_eq!(persisted.height, 2);
        assert_eq!(persisted.block_hash, Some(second.block_hash()));

        shutdown.send();
        assert_eq!(
            worker.await.expect("push replay worker joins"),
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        );
        drop(events);
    }
    #[tokio::test]
    async fn observed_applied_height_gap_is_replayed_from_kura() {
        let mut chain = native_push_chain(false);
        let state = Arc::clone(chain.state());
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("valid empty push store");
        let (events, _) = tokio::sync::broadcast::channel(4);
        let shutdown = ShutdownSignal::new();
        let worker = bridge
            .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
            .expect("original State pool admits push retry control")
            .expect("enabled push worker");
        wait_for_cursor(&bridge, 2).await;

        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let fourth = chain.committed(4);
        events
            .send(applied_event(4))
            .expect("send height-four event");

        wait_for_cursor(&bridge, 4).await;
        assert_eq!(
            bridge.applied_block_cursor.lock().block_hash,
            Some(fourth.block_hash())
        );
        shutdown.send();
        assert_eq!(
            worker.await.expect("push gap worker joins"),
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        );
    }
    #[tokio::test]
    async fn original_push_history_capacity_preserves_cursor_queue_and_pool_release() {
        let chain = native_push_chain(false);
        let state = chain.state();
        let pool = state.ivm_execution_budget();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let original = pool.try_reserve_bytes(1).unwrap_err();
        let iroha_allocation::AllocationRefusal::Capacity {
            release: expected, ..
        } = &original
        else {
            panic!("temporarily occupied original pool");
        };
        let temp = tempfile::tempdir().unwrap();
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        let cursor = bridge.applied_block_cursor.lock().clone();
        let Err(PushReplayError::Deferred(reason)) =
            bridge.reconcile_to_authoritative_height(state)
        else {
            panic!("native read capacity cannot become fatal storage or successful absence");
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
            reason.allocation_refusal()
        else {
            panic!("original capacity owner survives push carrier projection");
        };
        assert_eq!(release, expected);
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        drop(occupied);
        bridge.reconcile_to_authoritative_height(state).unwrap();
        assert_eq!(bridge.applied_block_cursor.lock().height, chain.height());
        assert_eq!(
            bridge.applied_block_cursor.lock().block_hash,
            Some(chain.committed(chain.height()).block_hash())
        );
    }

    #[tokio::test]
    async fn push_replay_late_capacity_retains_original_frame_and_waits_for_external_release() {
        use std::{
            future::Future,
            task::{Context, Poll},
        };
        let chain = native_push_chain(false);
        let state = chain.state();
        let pool = state.ivm_execution_budget();
        let baseline = pool.reserved_bytes();
        let frame_bytes = chain.committed(1).block().encode_wire().unwrap().len();
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let mut prepaid = pool.try_reserve_bytes(2 * registration_bytes).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        let mut observation_registration =
            ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        assert!(registration.belongs_to(&pool));
        assert!(observation_registration.belongs_to(&pool));
        let controls = baseline + 2 * registration_bytes;
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - controls - frame_bytes)
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        let cursor = bridge.applied_block_cursor.lock().clone();
        let shutdown = ShutdownSignal::new();
        let observed = Arc::new(Mutex::new(None::<iroha_allocation::AllocationRefusal>));
        let observation = Arc::clone(&observed);
        let mut probe = move |reason: &ExecutionDeferred| {
            let mut first = observation.lock().unwrap();
            if first.is_none() {
                // The running replay retains the move-only owner; this observer borrows
                // its actual pool leaf solely to test that same release registration.
                assert_eq!(
                    reason.reason(),
                    ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                );
                assert_eq!(reason.phase(), None);
                assert!(
                    reason.decode_refusal().is_none()
                        && reason.allocator_refusal().is_none()
                        && reason.verification_refusal().is_none()
                );
                *first = Some(
                    reason
                        .allocation_refusal()
                        .expect("actual observed original pool refusal")
                        .clone(),
                );
            }
        };
        let mut replay = Box::pin(replay_with_queue_drain_observed(
            &bridge,
            state,
            PushReplayTarget::Height(chain.height()),
            &shutdown,
            &mut registration,
            Some(&mut probe),
        ));
        // The old synchronous self-wake loop cannot return its first poll. A
        // separate ordinary shutdown sender bounds that genuine before defect;
        // the corrected operation parks without needing this watchdog to fire.
        let (stop_watchdog, wait_watchdog) = std::sync::mpsc::channel();
        let watchdog_shutdown = shutdown.clone();
        let watchdog = std::thread::spawn(move || {
            if matches!(
                wait_watchdog.recv_timeout(Duration::from_secs(5)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                watchdog_shutdown.send();
            }
        });
        let mut context = Context::from_waker(std::task::Waker::noop());
        let first_poll = replay.as_mut().poll(&mut context);
        let _ = stop_watchdog.send(());
        watchdog.join().unwrap();
        let original = observed
            .lock()
            .unwrap()
            .clone()
            .expect("actual late native refusal");
        let iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        } = &original
        else {
            panic!("genuine original pool capacity refusal");
        };
        assert_eq!(
            *requested_bytes,
            SharedSignedBlock::allocation_layout().size(),
            "the original G1 bytes were read before shared-shell admission refused"
        );
        let mut exact_wait = Box::pin(
            release
                .clone()
                .wait_for_release(&mut observation_registration),
        );
        let original_wait_poll = exact_wait.as_mut().poll(&mut context);
        if original_wait_poll != Poll::Pending || !first_poll.is_pending() {
            // Retire the real replay and both original registrations before
            // reporting a causal before failure; no worker remains detached.
            drop(exact_wait);
            drop(replay);
            drop(occupied);
            drop(registration);
            drop(observation_registration);
            assert_eq!(pool.reserved_bytes(), baseline);
            assert_eq!(
                original_wait_poll,
                Poll::Pending,
                "late original frame refusal must retain custody instead of waking its own replay"
            );
            panic!("the real replay target must park until an external owner releases");
        }
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        drop(occupied);
        assert_eq!(exact_wait.as_mut().poll(&mut context), Poll::Ready(()));
        drop(exact_wait);
        assert!(matches!(
            replay.as_mut().poll(&mut context),
            Poll::Ready(Ok(PushReplayOutcome::Complete))
        ));
        drop(replay);
        assert_eq!(bridge.applied_block_cursor.lock().height, chain.height());
        assert_eq!(
            bridge.applied_block_cursor.lock().block_hash,
            Some(chain.committed(chain.height()).block_hash())
        );
        assert_eq!(pool.reserved_bytes(), controls);

        // Cancellation is a real operation retirement: it releases the retained
        // original bytes and leaves this separate durable cursor unchanged.
        let cancelled_temp = tempfile::tempdir().unwrap();
        let cancelled =
            PushBridge::new_in(test_bridge_config(), cancelled_temp.path().to_path_buf()).unwrap();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - controls - frame_bytes)
            .unwrap();
        let mut replay = Box::pin(replay_with_queue_drain_observed(
            &cancelled,
            state,
            PushReplayTarget::Height(chain.height()),
            &shutdown,
            &mut registration,
            None,
        ));
        assert!(replay.as_mut().poll(&mut context).is_pending());
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        drop(replay);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes() - frame_bytes);
        assert_eq!(cancelled.applied_block_cursor.lock().height, 0);
        assert_eq!(cancelled.queued_count(), 0);
        drop(occupied);
        drop(registration);
        drop(observation_registration);
        assert_eq!(pool.reserved_bytes(), baseline);
    }

    #[tokio::test]
    async fn push_replay_verification_slot_capacity_preserves_original_wait_and_resumes() {
        use iroha_core::sumeragi::certified_chain::{CertifiedPrefix, CommittedBlock};
        use iroha_data_model::sumeragi_finality::certified_result::CertifiedResultV1;
        use std::{
            future::Future,
            mem::size_of,
            task::{Context, Poll},
        };

        // Keep retired fixture World versions from refunding this exact pool
        // while the test deliberately fills each original verification corridor.
        let _epoch = crossbeam_epoch::pin();
        let chain = native_push_chain(false);
        let state = chain.state();
        let pool = state.ivm_execution_budget();
        let baseline = pool.reserved_bytes();
        let wire = chain.committed(1).block().encode_wire().unwrap();
        let frame_bytes = wire.len();
        // Census model-owned decode custody independently of the replay being
        // tested. Native acquisition retains these controls and children beside
        // the original frame until the complete verification retires.
        let decoded_bytes = {
            let census = iroha_allocation::AllocationBudget::new(pool.limit_bytes());
            let mut source = iroha_allocation::ChargedBuffer::new(frame_bytes, &census).unwrap();
            source.append(&wire).unwrap();
            let mut decoder =
                iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&census).unwrap();
            let decoded = decoder
                .decode(
                    &source,
                    norito::core::SequenceSpan {
                        start: 0,
                        end: frame_bytes,
                    },
                    norito::canonical_decode_limits(frame_bytes),
                )
                .unwrap();
            assert_eq!(decoded.encode_wire().unwrap(), wire);
            census.reserved_bytes() - frame_bytes
        };
        let shell_bytes = SharedSignedBlock::allocation_layout().size();
        let carrier_bytes = frame_bytes + decoded_bytes + shell_bytes;
        let prefix_bytes = size_of::<CertifiedPrefix>();
        let committed_bytes = size_of::<CommittedBlock>();
        let result_bytes = size_of::<CertifiedResultV1>();
        // Each stage fails at an actual allocation in the shipping replay. The
        // last case admits the receipt slot before its result slot refuses, so
        // retaining only the wire, shell and prefix would still self-wake.
        for (stage, retained_bytes, requested) in [
            ("prefix", carrier_bytes, prefix_bytes),
            (
                "committed frame",
                carrier_bytes + prefix_bytes,
                committed_bytes,
            ),
            (
                "execution result",
                carrier_bytes + prefix_bytes + committed_bytes,
                result_bytes,
            ),
        ] {
            let registration_bytes = ReleaseRegistration::allocation_layout().size();
            let mut prepaid = pool.try_reserve_bytes(2 * registration_bytes).unwrap();
            let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
            let mut observation_registration =
                ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
            drop(prepaid);
            assert!(registration.belongs_to(&pool));
            assert!(observation_registration.belongs_to(&pool));
            let controls = baseline + 2 * registration_bytes;
            let occupied = pool
                .try_reserve_bytes(pool.limit_bytes() - controls - retained_bytes)
                .unwrap();
            let temp = tempfile::tempdir().unwrap();
            let bridge =
                PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
            let cursor = bridge.applied_block_cursor.lock().clone();
            let shutdown = ShutdownSignal::new();
            let observed = Arc::new(Mutex::new(None::<iroha_allocation::AllocationRefusal>));
            let observation = Arc::clone(&observed);
            let mut probe = move |reason: &ExecutionDeferred| {
                let mut first = observation.lock().unwrap();
                if first.is_none() {
                    // The running replay retains the move-only owner; this observer borrows
                    // its actual pool leaf solely to test that same release registration.
                    assert_eq!(
                        reason.reason(),
                        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                    );
                    assert_eq!(reason.phase(), None);
                    assert!(
                        reason.decode_refusal().is_none()
                            && reason.allocator_refusal().is_none()
                            && reason.verification_refusal().is_none()
                    );
                    *first = Some(
                        reason
                            .allocation_refusal()
                            .expect("actual observed original pool refusal")
                            .clone(),
                    );
                }
            };
            let mut replay = Box::pin(replay_with_queue_drain_observed(
                &bridge,
                state,
                PushReplayTarget::Height(chain.height()),
                &shutdown,
                &mut registration,
                Some(&mut probe),
            ));
            let (stop_watchdog, wait_watchdog) = std::sync::mpsc::channel();
            let watchdog_shutdown = shutdown.clone();
            let watchdog = std::thread::spawn(move || {
                if matches!(
                    wait_watchdog.recv_timeout(Duration::from_secs(5)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    watchdog_shutdown.send();
                }
            });
            let mut context = Context::from_waker(std::task::Waker::noop());
            let first_poll = replay.as_mut().poll(&mut context);
            let _ = stop_watchdog.send(());
            watchdog.join().unwrap();
            let original = observed
                .lock()
                .unwrap()
                .clone()
                .expect("actual late verification refusal");
            let iroha_allocation::AllocationRefusal::Capacity {
                requested_bytes,
                release,
                ..
            } = &original
            else {
                panic!("genuine original pool capacity refusal at {stage}");
            };
            let mut exact_wait = Box::pin(
                release
                    .clone()
                    .wait_for_release(&mut observation_registration),
            );
            let original_wait_poll = exact_wait.as_mut().poll(&mut context);
            if original_wait_poll != Poll::Pending
                || !first_poll.is_pending()
                || *requested_bytes != requested
            {
                // Retire all original owners before reporting a causal failure.
                // The exact release observation takes precedence over the normal
                // watchdog shutdown outcome of an incorrectly spinning replay.
                drop(exact_wait);
                drop(replay);
                drop(occupied);
                drop(registration);
                drop(observation_registration);
                assert_eq!(pool.reserved_bytes(), baseline);
                assert_eq!(
                    original_wait_poll,
                    Poll::Pending,
                    "{stage}: later refusal must not release an earlier original verification slot"
                );
                assert_eq!(*requested_bytes, requested, "actual {stage} slot refused");
                panic!("{stage}: genuine replay must park until external release");
            }
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
            assert_eq!(bridge.queued_count(), 0);
            drop(occupied);
            assert_eq!(exact_wait.as_mut().poll(&mut context), Poll::Ready(()));
            drop(exact_wait);
            assert!(matches!(
                replay.as_mut().poll(&mut context),
                Poll::Ready(Ok(PushReplayOutcome::Complete))
            ));
            drop(replay);
            assert_eq!(bridge.applied_block_cursor.lock().height, chain.height());
            assert_eq!(
                bridge.applied_block_cursor.lock().block_hash,
                Some(chain.committed(chain.height()).block_hash())
            );
            assert_eq!(pool.reserved_bytes(), controls);

            let cancelled_temp = tempfile::tempdir().unwrap();
            let cancelled =
                PushBridge::new_in(test_bridge_config(), cancelled_temp.path().to_path_buf())
                    .unwrap();
            let occupied = pool
                .try_reserve_bytes(pool.limit_bytes() - controls - retained_bytes)
                .unwrap();
            let mut replay = Box::pin(replay_with_queue_drain_observed(
                &cancelled,
                state,
                PushReplayTarget::Height(chain.height()),
                &shutdown,
                &mut registration,
                None,
            ));
            assert!(replay.as_mut().poll(&mut context).is_pending());
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            drop(replay);
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes() - retained_bytes);
            assert_eq!(cancelled.applied_block_cursor.lock().height, 0);
            assert_eq!(cancelled.queued_count(), 0);
            drop(occupied);
            drop(registration);
            drop(observation_registration);
            assert_eq!(pool.reserved_bytes(), baseline);
        }
    }

    #[test]
    fn push_replay_verified_cursor_preserves_pending_successor_and_original_wait() {
        use std::{
            future::Future,
            task::{Context, Poll},
        };
        let chain = native_push_chain(false);
        let state = chain.state();
        let pool = state.ivm_execution_budget();
        let baseline = pool.reserved_bytes();
        let temp = tempfile::tempdir().unwrap();
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        let mut read = PushReplayRead::new(state);
        read.reconcile(&bridge, PushReplayTarget::Height(1))
            .unwrap();
        let cursor = bridge.applied_block_cursor.lock().clone();
        assert_eq!(cursor.height, 1);
        assert_eq!(cursor.block_hash, Some(chain.committed(1).block_hash()));
        assert!(read.pending.is_none());
        assert!(read.cursor_is_verified(&cursor).unwrap());
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "cursor receipt retains no completed graph"
        );

        let mut prepaid = pool
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let controls = pool.reserved_bytes();
        let wire_bytes = chain.committed(1).block().encode_wire().unwrap().len();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - controls - wire_bytes)
            .unwrap();
        let Err(PushReplayError::Deferred(original)) =
            read.reconcile(&bridge, PushReplayTarget::Height(2))
        else {
            panic!("actual successor frame admission must refuse");
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        }) = original.allocation_refusal()
        else {
            panic!("same original State pool supplies the successor refusal");
        };
        assert_eq!(
            *requested_bytes,
            SharedSignedBlock::allocation_layout().size()
        );
        assert_eq!(read.pending.as_ref().unwrap().height().get(), 2);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);

        // This is the production retry sequence: validate durable h1 while the
        // exact h2 read is still pending, without replacing its owner with h1.
        let Err(PushReplayError::Deferred(retry)) =
            read.reconcile(&bridge, PushReplayTarget::Height(2))
        else {
            panic!("same pending successor must preserve its original refusal");
        };
        assert_eq!(retry.allocation_refusal(), original.allocation_refusal());
        assert_eq!(read.pending.as_ref().unwrap().height().get(), 2);
        assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        drop(occupied);
        assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
        drop(wait);
        read.reconcile(&bridge, PushReplayTarget::Height(2))
            .unwrap();
        assert_eq!(bridge.applied_block_cursor.lock().height, 2);
        assert_eq!(
            bridge.applied_block_cursor.lock().block_hash,
            Some(chain.committed(2).block_hash())
        );
        assert!(read.pending.is_none());
        assert_eq!(pool.reserved_bytes(), controls);
        drop(read);
        drop(registration);
        assert_eq!(pool.reserved_bytes(), baseline);
    }

    #[test]
    fn push_replay_cursor_receipt_is_operation_local_and_rejects_rebound_state() {
        let chain = native_push_chain(false);
        // Authenticate the replacement before exhausting the original pool: reading
        // certified history itself requires that pool's allocation authority.
        let replacement_hash = chain.committed(2).block_hash();
        let state = chain.state();
        let pool = state.ivm_execution_budget();
        let baseline = pool.reserved_bytes();
        let temp = tempfile::tempdir().unwrap();
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        let mut initial = PushReplayRead::new(state);
        initial
            .reconcile(&bridge, PushReplayTarget::Height(1))
            .unwrap();
        drop(initial);
        let cursor = bridge.applied_block_cursor.lock().clone();
        assert_eq!(pool.reserved_bytes(), baseline);
        let wire_bytes = chain.committed(1).block().encode_wire().unwrap().len();

        // A new operation has no inherited cursor authority: even though its
        // target already equals the durable cursor, it must read native history.
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - baseline)
            .unwrap();
        let mut fresh = PushReplayRead::new(state);
        let Err(PushReplayError::Deferred(original)) =
            fresh.reconcile(&bridge, PushReplayTarget::Height(1))
        else {
            panic!("persisted h1 requires original native authentication");
        };
        assert!(fresh.verified_cursor.is_none());
        assert_eq!(fresh.pending.as_ref().unwrap().height().get(), 1);
        assert!(matches!(original.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })
                if *requested_bytes == wire_bytes));
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        drop(occupied);
        fresh
            .reconcile(&bridge, PushReplayTarget::Height(1))
            .unwrap();
        assert!(fresh.cursor_is_verified(&cursor).unwrap());
        assert!(fresh.pending.is_none());
        assert_eq!(pool.reserved_bytes(), baseline);

        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - baseline - wire_bytes)
            .unwrap();
        assert!(matches!(
            fresh.reconcile(&bridge, PushReplayTarget::Height(2)),
            Err(PushReplayError::Deferred(_))
        ));
        assert_eq!(fresh.pending.as_ref().unwrap().height().get(), 2);
        // A changed durable cursor cannot borrow a previously verified receipt,
        // nor can it retarget the pending successor's retained physical owners.
        bridge.applied_block_cursor.lock().block_hash = Some(replacement_hash);
        let changed_cursor = bridge.applied_block_cursor.lock().clone();
        assert!(matches!(
            fresh.reconcile(&bridge, PushReplayTarget::Height(2)),
            Err(PushReplayError::Fatal(PushError::Storage(reason)))
                if reason == "push replay's pending target changed"
        ));
        assert_eq!(*bridge.applied_block_cursor.lock(), changed_cursor);
        assert_eq!(bridge.queued_count(), 0);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        drop(fresh);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes() - wire_bytes);
        drop(occupied);
        *bridge.applied_block_cursor.lock() = cursor.clone();
        assert_eq!(pool.reserved_bytes(), baseline);

        let mut rebound = PushReplayRead::new(state);
        rebound
            .reconcile(&bridge, PushReplayTarget::Height(1))
            .unwrap();
        // Replace only fixture State history under its real publication owner.
        // Retain the successor height so the genesis-only guard cannot reject
        // before the operation's original cursor binding is checked.
        // The unchanged durable cursor still matches this operation's receipt,
        // so the mandatory current-State binding check is the rejecting control.
        state.block_hashes.block_and_revert().commit_for_tests();
        let mut replacement = state.block_hashes.block_and_revert();
        replacement.push_for_tests(replacement_hash);
        replacement.push_for_tests(replacement_hash);
        replacement.commit_for_tests();
        assert_eq!(state.committed_height(), 2);
        assert!(matches!(
            rebound.reconcile(&bridge, PushReplayTarget::Height(1)),
            Err(PushReplayError::Fatal(PushError::Storage(reason)))
                if reason == "push replay's original cursor binding changed"
        ));
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        assert!(rebound.pending.is_none());
        drop(rebound);
        assert_eq!(pool.reserved_bytes(), baseline);
    }

    #[tokio::test]
    async fn push_worker_admits_original_retry_control_before_startup_and_refunds_after_shutdown() {
        let state = pristine_push_state(Kura::blank_kura_for_testing());
        let pool = state.ivm_execution_budget();
        let baseline = pool.reserved_bytes();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - baseline)
            .unwrap();
        let expected = pool
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap_err();
        let temp = tempfile::tempdir().unwrap();
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf()).unwrap();
        let cursor = bridge.applied_block_cursor.lock().clone();
        let (events, receiver) = tokio::sync::broadcast::channel(1);
        let receiver_count = events.receiver_count();
        let shutdown = ShutdownSignal::new();
        let error = bridge
            .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
            .expect_err("occupied original pool refuses before subscription or spawn");
        let PushWorkerStartError::Admission(actual) = error else {
            panic!("exact original capacity refusal");
        };
        assert_eq!(actual, expected);
        assert_eq!(events.receiver_count(), receiver_count);
        assert_eq!(*bridge.applied_block_cursor.lock(), cursor);
        assert_eq!(bridge.queued_count(), 0);
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        drop(occupied);
        let worker = bridge
            .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
            .expect("same original pool retries after its refund")
            .expect("enabled worker");
        assert_eq!(
            pool.reserved_bytes(),
            baseline + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(events.receiver_count(), receiver_count + 1);
        shutdown.send();
        assert_eq!(
            worker.await.unwrap(),
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        );
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(events.receiver_count(), receiver_count);
        drop(receiver);
    }

    #[tokio::test]
    async fn push_history_retry_waits_only_on_original_release_and_remains_shutdown_responsive() {
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let pool = iroha_allocation::AllocationBudget::new(registration_bytes + 8);
        let mut prepaid = pool
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let held = pool.try_reserve_bytes(8).unwrap();
        let reason: ExecutionDeferred = pool.try_reserve_bytes(1).unwrap_err().into();
        let shutdown = ShutdownSignal::new();
        let mut retry = Box::pin(wait_for_push_history_retry(
            &reason,
            &shutdown,
            &mut registration,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut retry)
                .await
                .is_err()
        );
        let unrelated = iroha_allocation::AllocationBudget::new(8);
        drop(unrelated.try_reserve_bytes(8).unwrap());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut retry)
                .await
                .is_err()
        );
        drop(held);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut retry)
                .await
                .unwrap()
        );

        drop(retry);
        assert_eq!(pool.reserved_bytes(), registration_bytes);

        let too_small = iroha_allocation::AllocationBudget::new(0);
        let reason: ExecutionDeferred = too_small.try_reserve_bytes(1).unwrap_err().into();
        let shutdown = ShutdownSignal::new();
        let mut retry = Box::pin(wait_for_push_history_retry(
            &reason,
            &shutdown,
            &mut registration,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut retry)
                .await
                .is_err(),
            "a refusal without a release source cannot busy retry"
        );
        shutdown.send();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), &mut retry)
                .await
                .unwrap()
        );
        drop(retry);
        drop(registration);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn full_durable_queue_is_drained_before_replay_retries() {
        let chain = native_push_chain(true);
        let state = Arc::clone(chain.state());
        let temp = tempfile::tempdir().expect("push tempdir");
        let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::Sent]));
        let bridge = PushBridge::with_dispatcher_and_limits_in(
            test_bridge_config(),
            dispatcher,
            test_storage_limits(1, 1),
            temp.path().to_path_buf(),
        )
        .expect("valid bounded push store");
        bridge
            .register_device(register_request("activity-token"))
            .expect("register push activity target");
        let outdated_job = test_job(91);
        let stale_key = outdated_job.dedupe_key.clone();
        bridge
            .persist_job(&outdated_job)
            .expect("persist full queue fixture");
        bridge
            .queue
            .insert(outdated_job.dedupe_key.clone(), outdated_job);

        assert!(matches!(
            bridge.reconcile_to_authoritative_height(&state),
            Err(PushReplayError::Backpressure {
                height: 1,
                queued: 1,
                required: 1,
                maximum: 1,
            })
        ));
        assert_eq!(bridge.applied_block_cursor.lock().height, 0);
        assert_eq!(bridge.queued_count(), 1);

        let (events, _) = tokio::sync::broadcast::channel(4);
        let shutdown = ShutdownSignal::new();
        // Keep the event source alive until shutdown; channel closure is a separate failure.
        let worker = bridge
            .start_event_worker(Arc::clone(&state), events.clone(), shutdown.clone())
            .expect("original State pool admits push retry control")
            .expect("enabled push worker");
        wait_for_cursor(&bridge, chain.height()).await;
        assert_eq!(
            bridge.applied_block_cursor.lock().block_hash,
            Some(chain.committed(chain.height()).block_hash()),
            "backlog replay reaches the exact authenticated native successor"
        );
        assert!(!bridge.queue.contains_key(&stale_key));
        assert!(!bridge.job_path(&stale_key).exists());
        shutdown.send();
        assert_eq!(
            worker.await.expect("backpressured push worker joins"),
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        );
        drop(events);
    }
    #[test]
    fn single_block_larger_than_queue_capacity_fails_explicitly() {
        let chain = native_push_chain(true);
        let state = Arc::clone(chain.state());
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::with_dispatcher_and_limits_in(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            test_storage_limits(2, 1),
            temp.path().to_path_buf(),
        )
        .expect("valid bounded push store");
        bridge
            .register_device(register_request("first-activity-token"))
            .expect("register first activity target");
        bridge
            .register_device(register_request("second-activity-token"))
            .expect("register second activity target");

        let error = bridge
            .reconcile_to_authoritative_height(&state)
            .expect_err("one block cannot exceed the durable queue geometry");

        let PushReplayError::Fatal(PushError::Storage(reason)) = error else {
            panic!("expected actual queue-capacity refusal, got {error:?}");
        };
        assert_eq!(
            reason,
            "push block 1 requires 2 delivery jobs, exceeding the configured durable queue capacity 1"
        );
        assert_eq!(bridge.applied_block_cursor.lock().height, 0);
        assert_eq!(bridge.queued_count(), 0);
    }
    #[test]
    fn cursor_does_not_advance_when_block_jobs_cannot_be_persisted() {
        let chain = native_push_chain(true);
        let state = Arc::clone(chain.state());
        let temp = tempfile::tempdir().expect("push tempdir");
        let bridge = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .expect("valid empty push store");
        bridge
            .register_device(register_request("blocked-queue-token"))
            .expect("register push activity target");
        fs::write(bridge.data_dir.join(QUEUE_DIR), b"not a directory")
            .expect("block push queue directory creation");

        let expected_io = fs::create_dir_all(bridge.data_dir.join(QUEUE_DIR))
            .expect_err("the actual queue parent is a file");
        let error = bridge
            .reconcile_to_authoritative_height(&state)
            .expect_err("queue persistence must fail after authenticating the carrier");
        let PushReplayError::Fatal(PushError::Storage(reason)) = error else {
            panic!("expected actual queue-persistence refusal, got {error:?}");
        };
        assert_eq!(reason, expected_io.to_string());
        assert_eq!(bridge.applied_block_cursor.lock().height, 0);
        assert_eq!(bridge.queued_count(), 0);
        fs::remove_file(bridge.data_dir.join(QUEUE_DIR)).expect("repair queue parent");
        bridge
            .reconcile_to_authoritative_height(&state)
            .expect("the same authenticated carrier proceeds after persistence repair");
        assert_eq!(bridge.applied_block_cursor.lock().height, 2);
        assert_eq!(bridge.queued_count(), 1);
    }
    fn register_request(token: &str) -> RegisterDeviceRequest {
        RegisterDeviceRequest {
            account_id: TEST_ACCOUNT_I105.to_string(),
            platform: "FCM".to_string(),
            token: token.to_string(),
            topics: None,
        }
    }
    fn test_job(index: usize) -> DeliveryJob {
        let token_fingerprint = fingerprint(format!("token-{index}").as_bytes());
        let payload = PushActivityPayload {
            account_id: TEST_ACCOUNT_I105.to_string(),
            activity_kind: "Transfer".to_string(),
            tx_hash: format!("tx-{index}"),
            block_height: 7,
            instruction_index: u64::try_from(index).expect("test index fits u64"),
            direction: "incoming".to_string(),
        };
        DeliveryJob {
            dedupe_key: delivery_dedupe_key(&payload, &token_fingerprint),
            account_id: TEST_ACCOUNT_I105.to_string(),
            token_fingerprint,
            target_platform: Platform::Fcm.label().to_string(),
            payload,
            attempts: 0,
            next_attempt_ms: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }
    #[test]
    fn delivery_dedupe_key_covers_height_and_direction() {
        let job = test_job(1);
        let baseline = delivery_dedupe_key(&job.payload, &job.token_fingerprint);
        let mut changed_height = job.payload.clone();
        changed_height.block_height = changed_height.block_height.saturating_add(1);
        let mut changed_direction = job.payload.clone();
        changed_direction.direction = "outgoing".to_owned();

        assert_ne!(
            baseline,
            delivery_dedupe_key(&changed_height, &job.token_fingerprint)
        );
        assert_ne!(
            baseline,
            delivery_dedupe_key(&changed_direction, &job.token_fingerprint)
        );
    }
    #[test]
    fn encode_jwt_claims_builds_verifiable_compact_token() {
        let mut claims = norito::json::Map::new();
        claims.insert("iss".to_string(), norito::json::Value::from("issuer"));
        claims.insert(
            "iat".to_string(),
            norito::json::Value::from(1_700_000_000_u64),
        );
        let key = EncodingKey::from_secret(b"shared-secret");
        let token = encode_jwt_claims(
            Algorithm::HS256,
            Some("test-key"),
            norito::json::Value::Object(claims),
            &key,
        )
        .expect("JWT should encode");
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: norito::json::Value = norito::json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(parts[0])
                .expect("header should be base64url"),
        )
        .expect("header should decode");
        assert_eq!(header["typ"].as_str(), Some("JWT"));
        assert_eq!(header["alg"].as_str(), Some("HS256"));
        assert_eq!(header["kid"].as_str(), Some("test-key"));
        let payload: norito::json::Value = norito::json::from_slice(
            &BASE64_URL_SAFE_NO_PAD
                .decode(parts[1])
                .expect("payload should be base64url"),
        )
        .expect("payload should decode");
        assert_eq!(payload["iss"].as_str(), Some("issuer"));
        assert_eq!(payload["iat"].as_u64(), Some(1_700_000_000));
        assert!(
            jsonwebtoken::crypto::verify(
                parts[2],
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &jsonwebtoken::DecodingKey::from_secret(b"shared-secret"),
                Algorithm::HS256,
            )
            .expect("signature should verify")
        );
    }
    #[test]
    fn bounded_push_file_read_accepts_exact_limit_and_rejects_limit_plus_one() {
        let directory = tempfile::tempdir().expect("push read directory");
        let path = directory.path().join("input.json");
        fs::write(&path, b"12345678").expect("write bounded input");
        assert_eq!(
            read_bounded_stable_file(&path, 8).expect("exact byte limit"),
            b"12345678"
        );
        let error = read_bounded_stable_file(&path, 7)
            .expect_err("one byte beyond the limit must fail before allocation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[tokio::test]
    async fn provider_response_reader_accepts_exact_limit_and_rejects_max_plus_one() {
        let declared = raw_provider_response(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_PUSH_PROVIDER_RESPONSE_BYTES + 1
            )
            .into_bytes(),
        )
        .await;
        let declared_error = read_push_provider_response_bounded(declared, "test provider")
            .await
            .expect_err("oversized Content-Length must fail before body allocation");
        assert!(declared_error.contains("declared"));
        let exact = raw_provider_response(chunked_provider_response(
            "400 Bad Request",
            MAX_PUSH_PROVIDER_RESPONSE_BYTES,
        ))
        .await;
        assert_eq!(
            read_push_provider_response_bounded(exact, "test provider")
                .await
                .expect("the exact provider response ceiling is accepted")
                .len(),
            MAX_PUSH_PROVIDER_RESPONSE_BYTES
        );
        let streamed = raw_provider_response(chunked_provider_response(
            "400 Bad Request",
            MAX_PUSH_PROVIDER_RESPONSE_BYTES + 1,
        ))
        .await;
        let streamed_error = read_push_provider_response_bounded(streamed, "test provider")
            .await
            .expect_err("chunked max plus one must fail while streaming");
        assert!(streamed_error.contains("while streaming"));
    }
    #[tokio::test]
    async fn successful_provider_responses_skip_oversized_bodies() {
        let oversized_success = || {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_PUSH_PROVIDER_RESPONSE_BYTES + 1
            )
            .into_bytes()
        };
        assert_eq!(
            classify_fcm_response(raw_provider_response(oversized_success()).await).await,
            DispatchOutcome::Sent
        );
        assert_eq!(
            classify_apns_response(raw_provider_response(oversized_success()).await).await,
            DispatchOutcome::Sent
        );
    }
    #[test]
    fn bounded_json_write_rejects_oversize_before_creating_temp_file() {
        let directory = tempfile::tempdir().expect("push write directory");
        let path = directory.path().join("record.json");
        let error = write_json_atomic(&path, &"x".repeat(32), 8)
            .expect_err("oversized JSON must not reach the filesystem");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!path.exists());
        assert!(!path.with_extension("json.tmp").exists());
    }
    #[cfg(unix)]
    #[test]
    fn bounded_push_file_read_rejects_path_replacement_race() {
        let directory = tempfile::tempdir().expect("push race directory");
        let path = directory.path().join("input.json");
        let replacement = directory.path().join("replacement.json");
        fs::write(&path, b"old").expect("write original input");
        fs::write(&replacement, b"replacement").expect("write replacement input");
        let error = read_bounded_stable_file_with(&path, 32, || fs::rename(&replacement, &path))
            .expect_err("path replacement after open must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn bounded_push_file_read_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().expect("push symlink directory");
        let target = directory.path().join("target.json");
        let link = directory.path().join("link.json");
        fs::write(&target, b"{}").expect("write symlink target");
        symlink(&target, &link).expect("create push symlink");
        assert!(read_bounded_stable_file(&link, 32).is_err());
    }
    #[test]
    fn bounded_push_file_read_rejects_hard_link() {
        let directory = tempfile::tempdir().expect("push hard-link directory");
        let path = directory.path().join("input.json");
        let alias = directory.path().join("input-alias.json");
        fs::write(&path, b"{}").expect("write push input");
        fs::hard_link(&path, alias).expect("create push hard link");

        assert!(read_bounded_stable_file(&path, 32).is_err());
    }
    #[test]
    fn write_side_device_capacity_is_hard() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::with_dispatcher_and_limits(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            test_storage_limits(1, 1),
        );
        bridge
            .register_device(register_request("token-1"))
            .expect("first device fits");
        let error = bridge
            .register_device(register_request("token-2"))
            .expect_err("second device must cross the hard capacity");
        assert!(matches!(error, PushError::Storage(_)));
        assert_eq!(bridge.device_count(), 1);
    }
    #[test]
    fn startup_rejects_queue_beyond_hard_candidate_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        write_origin_cursor(temp.path());
        let queue_root = temp.path().join(PUSH_DIR).join(QUEUE_DIR);
        for index in 0..3 {
            let job = test_job(index);
            write_json_atomic(
                &queue_root.join(format!("{}.json", job.dedupe_key)),
                &job,
                MAX_PUSH_QUEUE_JOB_BYTES,
            )
            .expect("write queue fixture");
        }
        let error = PushBridge::with_dispatcher_and_limits_in(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            test_storage_limits(1, 2),
            temp.path().to_path_buf(),
        )
        .err()
        .expect("oversized durable queue must fail startup");
        assert!(matches!(error, PushError::Storage(_)));
    }
    #[tokio::test]
    async fn due_queue_dispatch_collects_only_one_bounded_batch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let mut limits = test_storage_limits(1, 2);
        limits.dispatch_batch_size = 1;
        let bridge = PushBridge::with_dispatcher_and_limits(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            limits,
        );
        for index in 0..2 {
            let job = test_job(index);
            bridge.queue.insert(job.dedupe_key.clone(), job);
        }
        bridge.dispatch_due_once().await;
        assert_eq!(
            bridge.queued_count(),
            1,
            "one dispatch pass must consume at most one configured batch"
        );
    }
    #[test]
    fn write_side_queue_capacity_is_hard() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::with_dispatcher_and_limits(
            test_bridge_config(),
            Arc::new(RealPushDispatcher),
            test_storage_limits(2, 1),
        );
        bridge
            .register_device(register_request("token-1"))
            .expect("first device");
        bridge
            .register_device(register_request("token-2"))
            .expect("second device");
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("account");
        let error = bridge
            .enqueue_activity(
                &account,
                "tx-hash",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect_err("second fan-out job must cross the hard queue capacity");
        assert!(matches!(error, PushError::Storage(_)));
        assert_eq!(bridge.queued_count(), 1);
    }
    #[test]
    fn disabled_rejected() {
        let bridge = PushBridge::new(actual::Push {
            enabled: false,
            ..Default::default()
        });
        let err = bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "t0".to_string(),
                topics: None,
            })
            .expect_err("push disabled");
        matches!(err, PushError::Disabled);
    }
    #[test]
    fn missing_credentials_rejected() {
        let bridge = PushBridge::new(actual::Push {
            enabled: true,
            fcm_project_id: Some("project".to_string()),
            fcm_service_account_path: None,
            ..Default::default()
        });
        let err = bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "t1".to_string(),
                topics: None,
            })
            .expect_err("missing creds");
        assert!(matches!(err, PushError::MissingCredentials { .. }));
    }
    #[test]
    fn too_many_topics_rejected() {
        let bridge = PushBridge::new(actual::Push {
            max_topics_per_device: nonzero!(2_usize),
            ..test_bridge_config()
        });
        let err = bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "t2".to_string(),
                topics: Some(vec!["a".into(), "b".into(), "c".into()]),
            })
            .expect_err("too many topics");
        assert!(matches!(err, PushError::TooManyTopics { max: 2 }));
    }

    #[test]
    fn push_request_identifiers_require_exact_canonical_spelling() {
        assert_eq!(
            Platform::from_label("FCM").expect("canonical FCM"),
            Platform::Fcm
        );
        assert_eq!(
            Platform::from_label("APNS").expect("canonical APNS"),
            Platform::Apns
        );
        for alias in ["fcm", " FCM", "FCM ", "Apns"] {
            assert!(matches!(
                Platform::from_label(alias),
                Err(PushError::InvalidPlatform(value)) if value == alias
            ));
        }

        assert!(canonical_account(TEST_ACCOUNT_I105).is_ok());
        for alias in [
            format!(" {TEST_ACCOUNT_I105}"),
            format!("{TEST_ACCOUNT_I105} "),
        ] {
            assert!(matches!(
                canonical_account(&alias),
                Err(PushError::InvalidAccount(value)) if value == alias
            ));
        }

        assert_eq!(exact_nonempty_ref(Some("project-id")), Some("project-id"));
        for invalid in [
            None,
            Some(""),
            Some(" project"),
            Some("project "),
            Some("pro ject"),
        ] {
            assert!(exact_nonempty_ref(invalid).is_none());
        }
    }

    #[test]
    fn push_device_tokens_are_exact_and_platform_specific() {
        assert_eq!(
            validate_device_token(Platform::Fcm, "opaque:fcm-token_1")
                .expect("canonical FCM token"),
            "opaque:fcm-token_1"
        );
        let apns = "ab".repeat(32);
        assert_eq!(
            validate_device_token(Platform::Apns, &apns).expect("canonical APNS token"),
            apns
        );
        for invalid in [" token", "token ", "tok en", "tökën"] {
            assert!(matches!(
                validate_device_token(Platform::Fcm, invalid),
                Err(PushError::InvalidToken)
            ));
        }
        for invalid in [
            "ab".repeat(31),
            "AB".repeat(32),
            format!("{}g", "ab".repeat(31)),
        ] {
            assert!(matches!(
                validate_device_token(Platform::Apns, &invalid),
                Err(PushError::InvalidToken)
            ));
        }
    }

    #[test]
    fn push_topics_reject_empty_whitespace_and_duplicate_aliases() {
        assert_eq!(
            validate_topics(Some(vec!["incoming".into(), "settled".into()]), 2)
                .expect("canonical topics"),
            vec!["incoming", "settled"]
        );
        for invalid in ["", " incoming", "incoming ", "in coming", "töpic"] {
            assert!(matches!(
                validate_topics(Some(vec![invalid.to_owned()]), 1),
                Err(PushError::InvalidTopic { index: 0 })
            ));
        }
        assert!(matches!(
            validate_topics(Some(vec!["incoming".into(), "incoming".into()]), 2),
            Err(PushError::DuplicateTopic { index: 1 })
        ));
    }
    #[test]
    fn fcm_response_classification_covers_provider_outcomes() {
        assert_eq!(
            classify_fcm_status_body(HttpStatusCode::OK, ""),
            DispatchOutcome::Sent
        );
        assert!(matches!(
            classify_fcm_status_body(HttpStatusCode::TOO_MANY_REQUESTS, "quota"),
            DispatchOutcome::Retry(_)
        ));
        assert!(matches!(
            classify_fcm_status_body(HttpStatusCode::INTERNAL_SERVER_ERROR, "server"),
            DispatchOutcome::Retry(_)
        ));
        assert!(matches!(
            classify_fcm_status_body(HttpStatusCode::BAD_REQUEST, "UNREGISTERED"),
            DispatchOutcome::InvalidToken(_)
        ));
        assert!(matches!(
            classify_fcm_status_body(HttpStatusCode::UNAUTHORIZED, "bad credentials"),
            DispatchOutcome::PermanentFailure(_)
        ));
    }
    #[test]
    fn apns_response_classification_covers_provider_outcomes() {
        assert_eq!(
            classify_apns_status_body(HttpStatusCode::OK, ""),
            DispatchOutcome::Sent
        );
        assert!(matches!(
            classify_apns_status_body(HttpStatusCode::TOO_MANY_REQUESTS, "quota"),
            DispatchOutcome::Retry(_)
        ));
        assert!(matches!(
            classify_apns_status_body(HttpStatusCode::BAD_GATEWAY, "server"),
            DispatchOutcome::Retry(_)
        ));
        assert!(matches!(
            classify_apns_status_body(HttpStatusCode::GONE, "Unregistered"),
            DispatchOutcome::InvalidToken(_)
        ));
        assert!(matches!(
            classify_apns_status_body(HttpStatusCode::BAD_REQUEST, "BadDeviceToken"),
            DispatchOutcome::InvalidToken(_)
        ));
        assert!(matches!(
            classify_apns_status_body(HttpStatusCode::FORBIDDEN, "ExpiredProviderToken"),
            DispatchOutcome::PermanentFailure(_)
        ));
    }
    #[test]
    fn stores_device_on_success_and_loads_from_disk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "token-123".to_string(),
                topics: Some(vec!["incoming".into()]),
            })
            .expect("should store device");
        assert_eq!(bridge.device_count(), 1);
        let loaded = PushBridge::new(test_bridge_config());
        assert_eq!(loaded.device_count(), 1);
        let device = loaded
            .registered_device("token-123")
            .expect("device loaded by fingerprint");
        assert_eq!(device.account_id, TEST_ACCOUNT_I105);
    }
    #[test]
    fn replacement_persistence_failure_preserves_old_registration() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let token = "replacement-token";
        bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: token.to_string(),
                topics: None,
            })
            .expect("register original device");
        let old_path = bridge.device_path(&fingerprint(token.as_bytes()));
        assert!(old_path.is_file());

        let replacement_account = fixture_account(0xA7);
        let blocked_temp = old_path.with_extension("json.tmp");
        fs::create_dir(&blocked_temp).expect("block replacement temporary file");
        let error = bridge
            .register_device(RegisterDeviceRequest {
                account_id: replacement_account,
                platform: "FCM".to_string(),
                token: token.to_string(),
                topics: None,
            })
            .expect_err("replacement publication must fail");
        assert!(matches!(error, PushError::Storage(_)));
        assert!(old_path.is_file());
        assert_eq!(
            bridge
                .registered_device(token)
                .expect("original registration remains in memory")
                .account_id,
            TEST_ACCOUNT_I105
        );
        assert_eq!(
            {
                fs::remove_dir(&blocked_temp).expect("remove injected blocker");
                PushBridge::new(test_bridge_config())
            }
            .registered_device(token)
            .expect("original registration remains durable")
            .account_id,
            TEST_ACCOUNT_I105
        );
    }
    #[test]
    fn replacement_post_publish_sync_failure_keeps_memory_aligned() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let token = "replacement-sync-token";
        bridge
            .register_device(register_request(token))
            .expect("register original device");
        let replacement_account = fixture_account(0xA8);

        let error = bridge
            .register_device_with(
                RegisterDeviceRequest {
                    account_id: replacement_account.clone(),
                    platform: "FCM".to_owned(),
                    token: token.to_owned(),
                    topics: None,
                },
                |record| {
                    write_json_atomic_with_publish_sync(
                        &bridge.device_path(&record.token_fingerprint),
                        record,
                        bridge.storage_limits.max_device_record_bytes,
                        |_| {
                            Err(io::Error::other(
                                "injected directory synchronization failure",
                            ))
                        },
                    )
                },
            )
            .expect_err("post-publication sync failure must be reported");

        assert!(matches!(error, PushError::Storage(_)));
        assert_eq!(
            bridge
                .registered_device(token)
                .expect("published registration remains live")
                .account_id,
            replacement_account
        );
        assert_eq!(
            PushBridge::new(test_bridge_config())
                .registered_device(token)
                .expect("published registration remains readable")
                .account_id,
            replacement_account
        );
    }
    #[test]
    fn account_replacement_uses_one_token_keyed_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let token = "single-record-replacement-token";
        bridge
            .register_device(register_request(token))
            .expect("register original device");
        let replacement_account = fixture_account(0xA9);

        bridge
            .register_device(RegisterDeviceRequest {
                account_id: replacement_account.clone(),
                platform: "FCM".to_owned(),
                token: token.to_owned(),
                topics: None,
            })
            .expect("replace token owner atomically");

        let device_dir = bridge.data_dir.join(DEVICES_DIR);
        assert_eq!(
            read_direct_directory(&device_dir)
                .expect("read flat device directory")
                .count(),
            1
        );
        assert_eq!(
            PushBridge::new(test_bridge_config())
                .registered_device(token)
                .expect("replacement survives restart")
                .account_id,
            replacement_account
        );
    }
    #[test]
    fn device_removal_failure_retains_memory_registration() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let token = "token-delete-failure";
        bridge
            .register_device(register_request(token))
            .expect("register device");
        let token_fingerprint = fingerprint(token.as_bytes());

        let error = bridge
            .remove_device_by_fingerprint_with(&token_fingerprint, |_| {
                Err(AtomicRemovalError {
                    source: io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected deletion failure",
                    ),
                    target_absent: false,
                })
            })
            .expect_err("failed durable deletion must be reported");
        assert!(matches!(error, PushError::Storage(_)));
        assert!(bridge.registered_device(token).is_some());
    }
    #[test]
    fn device_post_unlink_sync_failure_removes_memory_registration() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let token = "token-post-unlink-failure";
        bridge
            .register_device(register_request(token))
            .expect("register device");
        let token_fingerprint = fingerprint(token.as_bytes());

        let error = bridge
            .remove_device_by_fingerprint_with(&token_fingerprint, |path| {
                fs::remove_file(path).map_err(|source| AtomicRemovalError {
                    source,
                    target_absent: false,
                })?;
                Err(AtomicRemovalError {
                    source: io::Error::other(
                        "injected post-unlink directory synchronization failure",
                    ),
                    target_absent: true,
                })
            })
            .expect_err("post-unlink sync failure must be reported");

        assert!(matches!(error, PushError::Storage(_)));
        assert!(bridge.registered_device(token).is_none());
    }
    #[test]
    fn startup_rejects_nested_legacy_device_layout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        write_origin_cursor(temp.path());
        let token = "legacy-nested-token";
        let token_fingerprint = fingerprint(token.as_bytes());
        let root = temp.path().join(PUSH_DIR).join(DEVICES_DIR);
        let record = DeviceRecord {
            account_id: TEST_ACCOUNT_I105.to_owned(),
            platform: Platform::Fcm.label().to_owned(),
            token: token.to_owned(),
            token_fingerprint: token_fingerprint.clone(),
            topics: Vec::new(),
            updated_at_ms: 0,
        };
        write_json_atomic(
            &root
                .join(fingerprint(TEST_ACCOUNT_I105.as_bytes()))
                .join(format!("{token_fingerprint}.json")),
            &record,
            MAX_PUSH_DEVICE_RECORD_BYTES,
        )
        .expect("write nested legacy device fixture");

        let error = PushBridge::new_in(test_bridge_config(), temp.path().to_path_buf())
            .err()
            .expect("nested legacy layout must fail startup");
        assert!(matches!(error, PushError::Storage(_)));
    }
    #[test]
    fn unregister_removes_device() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let bridge = PushBridge::new(test_bridge_config());
        let request = RegisterDeviceRequest {
            account_id: TEST_ACCOUNT_I105.to_string(),
            platform: "FCM".to_string(),
            token: "token-123".to_string(),
            topics: None,
        };
        let encoded = crate::frame_test_support::assert_current_frame(
            &request,
            "iroha_torii::push::RegisterDeviceRequest",
        );
        let mut wrong_owner = encoded.clone();
        wrong_owner[6] ^= 1;
        for invalid in [wrong_owner, encoded[..encoded.len() - 1].to_vec()] {
            let error =
                crate::utils::extractors::decode_body_as_norito_or_json::<RegisterDeviceRequest>(
                    &axum::body::Bytes::from(invalid),
                    crate::utils::TypedRequestContentFormat::Norito,
                )
                .expect_err("invalid device frame must reject after authentication");
            assert_eq!(error.status(), axum::http::StatusCode::BAD_REQUEST);
        }
        let request =
            crate::utils::extractors::decode_body_as_norito_or_json::<RegisterDeviceRequest>(
                &axum::body::Bytes::from(encoded),
                crate::utils::TypedRequestContentFormat::Norito,
            )
            .expect("decode the canonical device request at the actual typed boundary");
        bridge
            .register_device(request.clone())
            .expect("register device");
        bridge
            .unregister_device(request)
            .expect("unregister device");
        assert_eq!(bridge.device_count(), 0);
        assert!(bridge.registered_device("token-123").is_none());
    }
    #[test]
    fn alias_account_id_is_rejected() {
        let bridge = PushBridge::new(test_bridge_config());
        let err = bridge
            .register_device(RegisterDeviceRequest {
                account_id: "alice@wallets".to_string(),
                platform: "FCM".to_string(),
                token: "token-123".to_string(),
                topics: None,
            })
            .expect_err("aliases must be rejected");
        assert!(matches!(err, PushError::InvalidAccount(account) if account == "alice@wallets"));
    }
    #[tokio::test]
    async fn queue_dedupes_and_dispatches_success() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::Sent]));
        let bridge = PushBridge::with_dispatcher(test_bridge_config(), dispatcher.clone());
        bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "token-1".to_string(),
                topics: None,
            })
            .expect("register");
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("account");
        bridge
            .enqueue_activity(
                &account,
                "tx-hash",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect("enqueue");
        bridge
            .enqueue_activity(
                &account,
                "tx-hash",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect("dedupe");
        assert_eq!(bridge.queued_count(), 1);
        bridge.dispatch_due_once().await;
        assert_eq!(bridge.queued_count(), 0);
        assert_eq!(dispatcher.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn re_registered_token_cannot_receive_stale_account_activity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::Sent]));
        let bridge = PushBridge::with_dispatcher(test_bridge_config(), dispatcher.clone());
        let token = "reassigned-token";
        bridge
            .register_device(register_request(token))
            .expect("register original account");
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("account");
        bridge
            .enqueue_activity(
                &account,
                "tx-before-reassignment",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect("enqueue original account activity");
        let job_path = bridge
            .queue
            .iter()
            .next()
            .map(|job| bridge.job_path(&job.dedupe_key))
            .expect("queued job path");
        assert!(job_path.is_file());

        bridge
            .register_device(RegisterDeviceRequest {
                account_id: fixture_account(0xC9),
                platform: "FCM".to_string(),
                token: token.to_string(),
                topics: None,
            })
            .expect("reassign token");
        bridge.dispatch_due_once().await;

        assert!(dispatcher.calls.lock().unwrap().is_empty());
        assert_eq!(bridge.queued_count(), 0);
        assert!(!job_path.exists(), "stale job must be durably discarded");
    }
    #[tokio::test]
    async fn retryable_failure_reschedules_job() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::Retry(
            "timeout".to_string(),
        )]));
        let bridge = PushBridge::with_dispatcher(test_bridge_config(), dispatcher);
        bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "token-2".to_string(),
                topics: None,
            })
            .expect("register");
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("account");
        bridge
            .enqueue_activity(
                &account,
                "tx-hash",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect("enqueue");
        bridge.dispatch_due_once().await;
        assert_eq!(bridge.queued_count(), 1);
        let job = bridge.queue.iter().next().expect("job remains");
        assert_eq!(job.attempts, 1);
        assert!(job.next_attempt_ms > now_ms());
    }
    #[tokio::test]
    async fn invalid_token_removes_device_and_job() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _guard = OverrideGuard::new(temp.path());
        let dispatcher = Arc::new(MockDispatcher::new(vec![DispatchOutcome::InvalidToken(
            "unregistered".to_string(),
        )]));
        let bridge = PushBridge::with_dispatcher(test_bridge_config(), dispatcher);
        bridge
            .register_device(RegisterDeviceRequest {
                account_id: TEST_ACCOUNT_I105.to_string(),
                platform: "FCM".to_string(),
                token: "token-3".to_string(),
                topics: None,
            })
            .expect("register");
        let account = AccountId::parse_encoded(TEST_ACCOUNT_I105).expect("account");
        bridge
            .enqueue_activity(
                &account,
                "tx-hash",
                7,
                0,
                "Transfer",
                AccountActivityRole::Incoming,
            )
            .expect("enqueue");
        bridge.dispatch_due_once().await;
        assert_eq!(bridge.queued_count(), 0);
        assert_eq!(bridge.device_count(), 0);
    }
    struct MockDispatcher {
        outcomes: Mutex<Vec<DispatchOutcome>>,
        calls: Arc<Mutex<Vec<PushDelivery>>>,
    }
    impl MockDispatcher {
        fn new(outcomes: Vec<DispatchOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }
    #[async_trait]
    impl PushDispatcher for MockDispatcher {
        async fn send(
            &self,
            delivery: &PushDelivery,
            _settings: &DispatchSettings,
            _credentials: &ProviderCredentials,
        ) -> DispatchOutcome {
            self.calls.lock().unwrap().push(delivery.clone());
            self.outcomes
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(DispatchOutcome::Sent)
        }
    }
}
