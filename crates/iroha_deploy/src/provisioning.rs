//! Resumable private-root funding, namespace reservation and outbound attachment.
//!
//! The native supervisor is the sole live owner. This store sits outside the child generation
//! so a local reset cannot erase parent authorization or silently register a replacement child.
//! Wallet observations prepare the next operation; only the attachment's independently verified
//! parent receipt establishes anchoring. No private body or listener credential is sent upstream.

use std::{
    fs::File,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use iroha::{client::Client, config::Config};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address::ChainDiscriminantGuard},
    alias_setup::{AliasIntentV1, AliasSetupPlanRequestV1},
    private_dataspace::PrivateDataspaceRegistration,
    sns::{
        DATASPACE_ALIAS_SUFFIX_ID, NameRecordV1, NameSelectorV1, NameStatus,
        lease::VerifiedSnsLeaseV1,
    },
    sumeragi_finality::VerifiedSumeragiBlock,
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
};
use iroha_fs::{FileIdentity, OwnerDirectory, PrivateDirectory, PublishMode};
use iroha_wallet::{
    WalletNetwork, WalletStore,
    namespace::prepare_private_dataspace_request,
    onboarding::{FaucetRequest, OnboardingService, PreparationOptions},
    operations::{AccountService, BoundedTransactionOptions, OperationStatus},
};
use norito::{Decode, Encode};

use crate::{
    attachment::{
        AttachmentIdentity, AttachmentStore, ConfirmedAnchor, LocalPrivateRootSource, RelayParent,
        RelayProgress,
    },
    bootstrap::{AuthenticatedBootstrap, ParentFinalityStore, ReleaseFaucet},
    managed::PreparedLocalnet,
    verify::finality::FinalitySource,
};

const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// Failure to progress an exact retained private attachment.
#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
    /// Native private custody or durable publication failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Retained identity, policy or authorization differs.
    #[error("private provisioning: {0}")]
    Invalid(&'static str),
    /// Independently authenticated parent observation failed.
    #[error(transparent)]
    Bootstrap(#[from] crate::bootstrap::BootstrapError),
    /// Exact attachment verification or recovery failed.
    #[error(transparent)]
    Attachment(#[from] crate::attachment::AttachmentError),
    /// The exact faucet request could not be prepared; no completion is implied.
    #[error("private provisioning: faucet preparation failed; retry the retained request")]
    FaucetPreparation,
    /// Faucet submission or recovery failed; its original journal remains authoritative.
    #[error("private provisioning: faucet recovery failed; retain the original journal")]
    FaucetRecovery,
    /// The exact private namespace could not be quoted.
    #[error("private provisioning: cannot quote the exact private namespace")]
    NamespaceQuote,
    /// The exact paid namespace request could not be prepared.
    #[error("private provisioning: namespace preparation failed; retain the exact request")]
    NamespacePreparation,
    /// Namespace submission or recovery failed; its original journal remains authoritative.
    #[error("private provisioning: namespace recovery failed; retain the original journal")]
    NamespaceRecovery,
    /// The current namespace lease could not be independently authenticated.
    #[error(
        "private provisioning: cannot authenticate current namespace lease; retry from fresh parent quorum"
    )]
    NamespaceObservation,
    /// The caller's existing finite operation budget elapsed without establishing completion.
    #[error("private provisioning: operation deadline elapsed")]
    Deadline,
    /// The original supervisor cancelled new preparation and dispatch.
    #[error("private provisioning: operation cancelled")]
    Cancelled,
}

type Result<T> = std::result::Result<T, ProvisioningError>;

/// Current provisioning work, separate from whether the local validators are ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningStage {
    /// The exact faucet claim has not yet been observed as applied.
    Funding,
    /// The exact paid namespace operation has not yet completed.
    Namespace,
    /// Namespace observations exist but parent registration is not independently confirmed.
    Registering,
    /// A parent receipt independently confirms at least the original private registration.
    Attached,
}

impl ProvisioningStage {
    /// Stable CLI and desktop spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Namespace => "namespace",
            Self::Registering => "registering",
            Self::Attached => "attached",
        }
    }
}

/// Historical provisioning observations; this does not assert fresh parent or local readiness.
#[derive(Clone, Copy, Debug)]
pub struct ProvisioningProgress {
    /// The next required provisioning stage.
    pub stage: ProvisioningStage,
    /// Exact wallet operation observation from this turn, if one was needed.
    pub wallet_status: Option<OperationStatus>,
    /// Last independently verified parent receipt, distinct from private execution.
    pub confirmed: Option<ConfirmedAnchor>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::provisioning::BindingV1")]
struct Binding {
    parent_name: String,
    parent_generation: u64,
    parent_network_id: NetworkId,
    parent_chain_id: String,
    parent_profile: u16,
    parent_torii_root: String,
    alias: String,
    account_alias: String,
    owner: AccountId,
    registration: PrivateDataspaceRegistration,
    faucet: ReleaseFaucet,
}

#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::provisioning::RecordV1")]
struct Record {
    binding: Binding,
    faucet_observed: bool,
    namespace: Option<AliasSetupPlanRequestV1>,
    lease_generation: Option<u64>,
}

/// Exclusive owner of one private root's public parent operations and exact wallet journals.
/// Keep this outside the resettable child directory and release it before another owner opens it.
pub struct RemoteProvisioning {
    directory: PrivateDirectory,
    lock: File,
    record: Record,
    child: Config,
    parent: Config,
    finality: ParentFinalityStore,
    attachment: Option<AttachmentStore>,
    publication_uncertain: bool,
    cancellation: Option<Arc<AtomicBool>>,
}

impl RemoteProvisioning {
    /// Bind the signed private genesis and exact owner alias to an authenticated parent.
    /// Only its owner key is imported into the separate parent wallet; listener credentials stay
    /// in the child context. Reopening never replaces funding terms, journals or a reset child.
    ///
    /// # Errors
    /// Changed child/parent/owner, missing signed funding policy, unsafe or incomplete custody,
    /// competing ownership, or failure to reproduce original signed private genesis execution.
    pub fn open(
        path: &Path,
        bootstrap: &AuthenticatedBootstrap,
        prepared: &PreparedLocalnet,
        account_alias: &str,
    ) -> Result<Self> {
        let registration = prepared.load_private_registration().map_err(|_| {
            ProvisioningError::Invalid("cannot authenticate retained private genesis")
        })?;
        let child = prepared
            .context
            .load_client_config()
            .map_err(|_| ProvisioningError::Invalid("cannot open exact private owner context"))?;
        Self::open_trusted(
            path,
            bootstrap,
            child,
            prepared.context.dataspace_alias.clone(),
            account_alias.into(),
            registration,
        )
    }

    /// Load the exact retained public parent wallet without taking the relay worker's lock.
    ///
    /// This read-only snapshot validates the immutable child/parent binding and original signed
    /// private genesis. It neither creates missing custody nor changes operation progress. The
    /// caller may select only independently authenticated registry roots from this parent;
    /// private listener credentials are never returned.
    ///
    /// # Errors
    /// Missing or unsafe custody, changed identity/policy, invalid private genesis or wallet.
    pub fn load_parent_config(
        path: &Path,
        bootstrap: &AuthenticatedBootstrap,
        prepared: &PreparedLocalnet,
        account_alias: &str,
    ) -> Result<Config> {
        let registration = prepared.load_private_registration().map_err(|_| {
            ProvisioningError::Invalid("cannot authenticate retained private genesis")
        })?;
        let child = prepared
            .context
            .load_client_config()
            .map_err(|_| ProvisioningError::Invalid("cannot open exact private owner context"))?;
        Self::load_parent_config_trusted(
            path,
            bootstrap,
            &child,
            &prepared.context.dataspace_alias,
            account_alias,
            &registration,
        )
    }

    fn load_parent_config_trusted(
        path: &Path,
        bootstrap: &AuthenticatedBootstrap,
        child: &Config,
        alias: &str,
        account_alias: &str,
        registration: &PrivateDataspaceRegistration,
    ) -> Result<Config> {
        let directory = PrivateDirectory::open(path)?;
        let lock = directory.open_existing_lock("lock")?;
        let record = decode_record(&directory.read("provisioning.nrt", MAX_RECORD_BYTES)?)?;
        record.validate()?;
        record.binding.validate_parent(bootstrap)?;
        let expected = Binding::new(
            bootstrap,
            child,
            alias.into(),
            account_alias.into(),
            registration.clone(),
        )?;
        if record.binding.alias != expected.alias
            || record.binding.account_alias != expected.account_alias
            || record.binding.owner != expected.owner
            || record.binding.registration != expected.registration
        {
            return Err(ProvisioningError::Invalid(
                "retained parent wallet belongs to a different child",
            ));
        }
        let wallets = PrivateDirectory::open(directory.path().join("wallets"))?;
        let config = WalletStore::open(wallets.path(), None)
            .and_then(|wallets| wallets.load_config("owner"))
            .map_err(|_| ProvisioningError::Invalid("retained parent wallet is invalid"))?;
        record.binding.validate_config(&config)?;
        wallets.revalidate()?;
        directory.revalidate()?;
        if FileIdentity::of(&directory.open_read("lock")?)? != FileIdentity::of(&lock)? {
            return Err(ProvisioningError::Invalid("provisioning lock was replaced"));
        }
        Ok(config)
    }

    fn open_trusted(
        path: &Path,
        bootstrap: &AuthenticatedBootstrap,
        child: Config,
        alias: String,
        account_alias: String,
        registration: PrivateDataspaceRegistration,
    ) -> Result<Self> {
        let binding = Binding::new(bootstrap, &child, alias, account_alias, registration)?;
        let parent = OwnerDirectory::open_or_create(
            path.parent()
                .ok_or(ProvisioningError::Invalid("provisioning path"))?,
        )?;
        let name = path
            .file_name()
            .ok_or(ProvisioningError::Invalid("provisioning path"))?;
        let initial = Record {
            binding: binding.clone(),
            faucet_observed: false,
            namespace: None,
            lease_generation: None,
        };
        let initial_bytes = record_bytes(&initial)?;
        let directory = match parent
            .publish_private_child(name, &[("lock", &[]), ("provisioning.nrt", &initial_bytes)])
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                PrivateDirectory::open(parent.path().join(name))?
            }
            Err(error) => return Err(error.into()),
        };
        let lock = directory.open_existing_lock("lock")?;
        lock.try_lock()
            .map_err(|_| ProvisioningError::Invalid("provisioning is already owned"))?;
        lock.sync_all()?;
        directory.sync()?;
        let record = decode_record(&directory.read("provisioning.nrt", MAX_RECORD_BYTES)?)?;
        record.binding.validate_parent(bootstrap)?;
        if record.binding.alias != binding.alias
            || record.binding.account_alias != binding.account_alias
            || record.binding.owner != binding.owner
            || record.binding.registration != binding.registration
        {
            return Err(ProvisioningError::Invalid(
                "retained child identity differs; local reset cannot replace a parent attachment",
            ));
        }
        record.validate()?;
        // A missing wallet is retryable only before it has been atomically installed. The retained
        // child's exact key is the source on every retry; no new signer is generated here.
        let wallets = directory.ensure_child("wallets")?;
        let wallet_store = WalletStore::open(wallets.path(), None)
            .map_err(|_| ProvisioningError::Invalid("cannot open parent wallet custody"))?;
        if !path_exists(&wallets.path().join("owner"))? {
            if record.faucet_observed || record.namespace.is_some() {
                return Err(ProvisioningError::Invalid(
                    "retained parent wallet is missing",
                ));
            }
            wallet_store
                .import_key_pair("owner", &record.binding.wallet_network()?, &child.key_pair)
                .map_err(|_| ProvisioningError::Invalid("cannot retain exact parent owner key"))?;
        }
        let parent_config = wallet_store
            .load_config("owner")
            .map_err(|_| ProvisioningError::Invalid("retained parent wallet is invalid"))?;
        record.binding.validate_config(&parent_config)?;
        let finality = ParentFinalityStore::open(&directory.path().join("finality"), bootstrap)?;
        let attachment = record
            .lease_generation
            .map(|generation| {
                AttachmentStore::open(
                    &directory.path().join("attachment"),
                    record.binding.attachment_identity(bootstrap, generation)?,
                )
                .map_err(ProvisioningError::from)
            })
            .transpose()?;
        let result = Self {
            directory,
            lock,
            record,
            child,
            parent: parent_config,
            finality,
            attachment,
            publication_uncertain: false,
            cancellation: None,
        };
        result.revalidate()?;
        Ok(result)
    }

    /// Bind the original supervisor's monotonic cancellation signal to every paid operation.
    /// Reopening under a new owner preserves all retained journals; never reset a live signal.
    ///
    /// # Errors
    /// Refuses replacing an already bound signal with a different owner.
    pub fn with_cancellation(mut self, cancellation: Arc<AtomicBool>) -> Result<Self> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|original| !Arc::ptr_eq(original, &cancellation))
        {
            return Err(ProvisioningError::Invalid(
                "provisioning cancellation owner changed",
            ));
        }
        if let Some(attachment) = self.attachment.as_mut() {
            attachment.bind_cancellation(Arc::clone(&cancellation))?;
        }
        self.cancellation = Some(cancellation);
        Ok(self)
    }

    fn require_active(&self) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            return Err(ProvisioningError::Cancelled);
        }
        Ok(())
    }

    /// Read retained progress without claiming current network liveness.
    pub fn progress(&self) -> ProvisioningProgress {
        let confirmed = self
            .attachment
            .as_ref()
            .and_then(AttachmentStore::confirmed);
        let stage = if confirmed.is_some() {
            ProvisioningStage::Attached
        } else if self.record.lease_generation.is_some() {
            ProvisioningStage::Registering
        } else if self.record.faucet_observed {
            ProvisioningStage::Namespace
        } else {
            ProvisioningStage::Funding
        };
        ProvisioningProgress {
            stage,
            wallet_status: None,
            confirmed,
        }
    }

    /// Obtain fresh parent quorum, then fund and reserve the exact namespace within one deadline.
    /// Any existing signed operation is reconciled before another request can be prepared.
    /// Completion here permits registration; it does not establish parent anchoring.
    ///
    /// # Errors
    /// Expired release/budget, changed policy, unsafe custody, failed quorum or exact operation.
    pub fn provision_once(
        &mut self,
        bootstrap: &AuthenticatedBootstrap,
        deadline: Instant,
    ) -> Result<ProvisioningProgress> {
        let deadline = self.turn_deadline(bootstrap, deadline)?;
        let source = bootstrap
            .parent_http_source(&self.parent, deadline)
            .map_err(|_| {
                ProvisioningError::Invalid("cannot construct approved parent observation clients")
            })?;
        let operations = NativeOperations {
            cancellation: self.cancellation.clone(),
        };
        self.provision_with(bootstrap, deadline, &source, &operations)
    }

    fn provision_with<S: FinalitySource + ?Sized, B: ProvisioningOperations>(
        &mut self,
        bootstrap: &AuthenticatedBootstrap,
        deadline: Instant,
        source: &S,
        backend: &B,
    ) -> Result<ProvisioningProgress> {
        let deadline = self.turn_deadline(bootstrap, deadline)?;
        if self.record.lease_generation.is_some() {
            return Ok(self.progress());
        }
        self.finality.observe(source, &rand::random())?;
        let operations = self.directory.ensure_child("operations")?;
        if !self.record.faucet_observed {
            let mut config = self.parent.clone();
            config.torii_api_url = self
                .record
                .binding
                .faucet
                .torii_root
                .parse()
                .map_err(|_| ProvisioningError::Invalid("retained faucet endpoint"))?;
            let faucet_journal = operations.path().join("faucet");
            if !path_exists(&faucet_journal)? {
                self.require_active()?;
            }
            let status = backend.fund(
                &config,
                &self.record.binding.faucet_request(),
                &faucet_journal,
                deadline,
            )?;
            if !status.is_complete() {
                return Ok(ProvisioningProgress {
                    wallet_status: Some(status),
                    ..self.progress()
                });
            }
            let mut record = self.record.clone();
            record.faucet_observed = true;
            self.publish(record)?;
        }
        let journal = operations.path().join("namespace");
        if self.record.namespace.is_none() {
            self.require_active()?;
            if path_exists(&journal)? {
                return Err(ProvisioningError::Invalid(
                    "namespace journal has no retained request",
                ));
            }
            // Publish the exact two-lease quote once, before preparation can become ambiguous.
            // Every retry retains its original rent guards and fee allowance, even if no
            // transaction journal was installed before the previous attempt failed.
            let request = backend.namespace_request(
                &self.parent,
                &self.record.binding.alias,
                &self.record.binding.account_alias,
                deadline,
            )?;
            self.record.binding.validate_namespace(&request)?;
            let mut record = self.record.clone();
            record.namespace = Some(request);
            self.publish(record)?;
        }
        let request = self
            .record
            .namespace
            .as_ref()
            .ok_or(ProvisioningError::Invalid(
                "namespace journal has no retained request",
            ))?;
        if !path_exists(&journal)? {
            self.require_active()?;
        }
        let status = backend.reserve(
            &self.parent,
            request,
            &self.record.binding.options(deadline),
            &journal,
        )?;
        if !status.is_complete() {
            return Ok(ProvisioningProgress {
                wallet_status: Some(status),
                ..self.progress()
            });
        }
        // Applied/NoOp is not an authenticated namespace generation. Select a fresh independent
        // cut after the operation, then verify its current SNS row before freezing registration.
        self.finality.observe(source, &rand::random())?;
        let tip = self
            .finality
            .verifier()
            .verified_tip()
            .map_err(crate::bootstrap::BootstrapError::from)?;
        let lease = backend.lease(
            &self.parent,
            &LeaseRead {
                alias: &self.record.binding.alias,
                owner: &self.record.binding.owner,
                native_schema: bootstrap.release().native_world_schema,
                block: &tip,
                deadline,
            },
        )?;
        if lease.network_id() != self.parent.network_id
            || lease.height() != tip.height()
            || lease.context_id() != tip.context_id()
        {
            return Err(ProvisioningError::Invalid(
                "namespace proof differs from the independently selected current parent",
            ));
        }
        let generation = self
            .record
            .binding
            .lease_generation(lease.record(), unix_ms()?)?;
        let mut record = self.record.clone();
        record.lease_generation = Some(generation);
        self.publish(record)?;
        let mut attachment = AttachmentStore::open(
            &self.directory.path().join("attachment"),
            self.record
                .binding
                .attachment_identity(bootstrap, generation)?,
        )?;
        if let Some(signal) = &self.cancellation {
            attachment.bind_cancellation(Arc::clone(signal))?;
        }
        self.attachment = Some(attachment);
        Ok(ProvisioningProgress {
            wallet_status: Some(status),
            ..self.progress()
        })
    }

    /// Recover registration or relay one contiguous compact certificate after provisioning.
    /// The caller schedules bounded turns independently of the private validator lifecycle.
    ///
    /// # Errors
    /// Incomplete provisioning, changed context, exhausted deadline or unverified parent evidence.
    pub fn relay_once(
        &mut self,
        bootstrap: &AuthenticatedBootstrap,
        deadline: Instant,
    ) -> Result<RelayProgress> {
        let deadline = self.turn_deadline(bootstrap, deadline)?;
        let attachment = self.attachment.as_mut().ok_or(ProvisioningError::Invalid(
            "namespace provisioning is incomplete",
        ))?;
        let local =
            LocalPrivateRootSource::new(self.child.clone(), attachment.identity(), deadline)?;
        let source = bootstrap
            .parent_http_source(&self.parent, deadline)
            .map_err(|_| {
                ProvisioningError::Invalid("cannot construct approved parent observation clients")
            })?;
        let options = self.record.binding.options(deadline);
        Ok(attachment.relay_once(
            &local,
            RelayParent {
                config: &self.parent,
                bootstrap,
                finality: &mut self.finality,
                source: &source,
                options: &options,
            },
        )?)
    }

    /// Run one explicit administrative AMX registration turn under a separately selected signer.
    /// This never infers CanSetParameters from the SNS owner or schedules itself in relay_once.
    /// The retained signed child and namespace must already exist; all recovery uses the original
    /// administrative journal and original exclusive UTC/fee authorization.
    ///
    /// # Errors
    /// Rejects incomplete custody, changed parent/source/signer/terms, exhausted authorization,
    /// unavailable fresh parent quorum or unauthenticated native transaction inclusion.
    pub fn register_amx_once(
        &mut self,
        bootstrap: &AuthenticatedBootstrap,
        administrator: &Config,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<crate::attachment::AmxRegistrationProgress> {
        let deadline = self.turn_deadline(bootstrap, options.deadline)?;
        self.require_active()?;
        let attachment = self.attachment.as_mut().ok_or(ProvisioningError::Invalid(
            "namespace provisioning is incomplete; administrative AMX registration is separate",
        ))?;
        let source = bootstrap
            .parent_http_source(administrator, deadline)
            .map_err(|_| {
                ProvisioningError::Invalid(
                    "selected AMX administrator differs from approved parent roots",
                )
            })?;
        let mut options = options.clone();
        options.deadline = deadline;
        let progress = attachment.advance_amx_registration(
            administrator,
            bootstrap,
            &mut self.finality,
            &source,
            deadline_unix_ms,
            &options,
        )?;
        self.revalidate()?;
        Ok(progress)
    }

    fn turn_deadline(
        &self,
        bootstrap: &AuthenticatedBootstrap,
        deadline: Instant,
    ) -> Result<Instant> {
        self.revalidate()?;
        self.record.binding.validate_parent(bootstrap)?;
        let now = unix_ms()?;
        if Instant::now() >= deadline {
            return Err(ProvisioningError::Deadline);
        }
        if now < bootstrap.release().issued_at_ms || now >= bootstrap.release().expires_at_ms {
            return Err(ProvisioningError::Invalid(
                "parent release authorization is not current",
            ));
        }
        // Every SDK read, quote, proof-of-work and dispatch in this turn shares the earlier
        // of the caller's budget and the independent release's remaining authorization.
        let release_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                bootstrap.release().expires_at_ms - now,
            ))
            .ok_or(ProvisioningError::Invalid("release deadline overflow"))?;
        Ok(deadline.min(release_deadline))
    }

    fn revalidate(&self) -> Result<()> {
        if self.publication_uncertain {
            return Err(ProvisioningError::Invalid(
                "publication uncertain; reopen provisioning custody",
            ));
        }
        self.directory.revalidate()?;
        if FileIdentity::of(&self.directory.open_read("lock")?)? != FileIdentity::of(&self.lock)? {
            return Err(ProvisioningError::Invalid("provisioning lock was replaced"));
        }
        Ok(())
    }

    fn publish(&mut self, record: Record) -> Result<()> {
        self.revalidate()?;
        record.validate()?;
        if let Err(error) = write_record(&self.directory, &record, PublishMode::Replace) {
            self.publication_uncertain = true;
            return Err(error);
        }
        self.record = record;
        Ok(())
    }
}

mod operations;
use operations::{LeaseRead, NativeOperations, ProvisioningOperations};
mod record;

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(ProvisioningError::Invalid("local clock"))
}

fn decode_record(bytes: &[u8]) -> Result<Record> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ProvisioningError::Invalid(
            "provisioning record exceeds byte bound",
        ));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| ProvisioningError::Invalid("noncanonical provisioning record"))
}

fn write_record(directory: &PrivateDirectory, record: &Record, mode: PublishMode) -> Result<()> {
    let bytes = record_bytes(record)?;
    directory.write_atomic("provisioning.nrt", &bytes, mode)?;
    Ok(())
}

fn record_bytes(record: &Record) -> Result<Vec<u8>> {
    record.validate()?;
    let bytes = norito::encode_canonical(record)
        .map_err(|_| ProvisioningError::Invalid("cannot encode provisioning record"))?;
    decode_record(&bytes)?.validate()?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
