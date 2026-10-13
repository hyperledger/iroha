//! Native software completion custody and durable local checkpoint CAS for publisher bootstrap.
//!
//! Filesystem durability protects process crashes and concurrent writers. Finalized ledger replay
//! remains the independent authority after restoration; this module claims no hardware rollback seal.

use super::*;
#[path = "native_source.rs"]
mod source;
use iroha_crypto::{ExposedPrivateKey, KeyPair};
use iroha_data_model::transaction::Executable;
use iroha_fs::{FileIdentity, FileSnapshot, PrivateDirectory, PublishMode};
use sorafs_node::ProviderIngestSealedCheckpointRecordV1;
use source::NativeAssignedSourceV1;
use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use zeroize::Zeroizing;

/// Prepared credential custody; State is bound once after authenticated replay and before work starts.
pub struct NativeProducerV1 {
    resolver: Arc<NativeResolverV1>,
    checkpoint: Arc<NativeCheckpointV1>,
    source: Arc<NativeAssignedSourceV1>,
    attestation: Option<super::native_attestation::NativeAttestationV1>,
}
impl NativeProducerV1 {
    pub(crate) fn prepare(
        config: &SorafsProviderIngestRuntime,
        provider: ProviderId,
        network_id: NetworkId,
        data_dir: &Path,
    ) -> Result<Self> {
        let path = config
            .native_completion_credential
            .as_ref()
            .ok_or_else(|| eyre::eyre!("native completion credential is absent"))?;
        let bytes =
            crate::runtime_credential::load_bounded_runtime_credential_v1(path, 2, 16 * 1024 + 256)
                .map_err(|_| eyre::eyre!("native completion credential rejected"))?;
        let text = bytes
            .strip_suffix(b"\n")
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(|| eyre::eyre!("native completion credential rejected"))?;
        let private: ExposedPrivateKey = text
            .parse()
            .map_err(|_| eyre::eyre!("native completion credential rejected"))?;
        let canonical = Zeroizing::new(
            private
                .try_to_multihash_string()
                .map_err(|_| eyre::eyre!("native completion credential rejected"))?,
        );
        let key = KeyPair::from_private_key(private.0)
            .map_err(|_| eyre::eyre!("native completion credential rejected"))?;
        if canonical.as_str() != text || key.public_key() != &config.completion_signer_public_key {
            bail!("native completion credential does not match the configured public binding");
        }
        if config.finalized_archive.retention_authority.is_some() {
            bail!("native completion custody does not provide external archive retention");
        }
        let resolver = Arc::new(NativeResolverV1 {
            config: config.clone(),
            provider,
            key: Arc::new(key),
            state: Arc::new(OnceLock::new()),
            completion_signer: AccountId::new(config.completion_signer_public_key.clone()),
        });
        let attestation = config
            .provider_attestation_journal
            .as_ref()
            .map(|journal| {
                super::native_attestation::NativeAttestationV1::open(
                    data_dir,
                    network_id,
                    Arc::clone(&resolver),
                    journal,
                )
            })
            .transpose()?;
        Ok(Self {
            attestation,
            resolver: Arc::clone(&resolver),
            checkpoint: Arc::new(NativeCheckpointV1 {
                handle: config.checkpoint_store_handle.clone(),
                qualification: configured_checkpoint_qualification(config),
                root: data_dir.join("provider-ingest-native-authority"),
                maximum: config.outbox.checkpoint_max_bytes.0,
                gate: Mutex::new(()),
                custody: OnceLock::new(),
            }),
            source: Arc::new(NativeAssignedSourceV1::new(resolver)?),
        })
    }
    pub(crate) fn bind_state(&self, state: Arc<State>) -> Result<()> {
        self.resolver
            .state
            .set(state)
            .map_err(|_| eyre::eyre!("native completion State was already bound"))
    }
    pub(crate) fn attestation(&self) -> Option<&super::native_attestation::NativeAttestationV1> {
        self.attestation.as_ref()
    }
    pub(crate) async fn preflight(
        &self,
        config: &SorafsProviderIngestRuntime,
        provider: ProviderId,
    ) -> Result<QualifiedProviderIngestRuntimeAdaptersV1> {
        preflight_runtime_adapters(
            config,
            provider,
            ProviderIngestRuntimeAdaptersV1::new(self.source.clone(), self.resolver.clone()),
            self.checkpoint.clone(),
        )
        .await
    }
}

#[derive(Clone)]
pub(super) struct NativeResolverV1 {
    pub(super) config: SorafsProviderIngestRuntime,
    pub(super) provider: ProviderId,
    pub(super) key: Arc<KeyPair>,
    pub(super) completion_signer: AccountId,
    pub(super) state: Arc<OnceLock<Arc<State>>>,
}
impl NativeResolverV1 {
    pub(super) fn state(
        &self,
    ) -> std::result::Result<&Arc<State>, ProviderIngestCompletionSignerErrorV1> {
        self.state
            .get()
            .ok_or(ProviderIngestCompletionSignerErrorV1::Unavailable)
    }
    pub(super) fn eligible(
        &self,
        world: &impl iroha_core::state::WorldReadOnly,
        expected: &ProviderIngestCompletionAuthorityV1,
    ) -> bool {
        expected.is_valid()
            && world.accounts().get(&expected.provider_owner).is_some()
            && world.accounts().get(&expected.completion_signer).is_some()
            && expected.completion_signer == self.completion_signer
            && expected.signer_policy == self.config.completion_signer_policy
            && world.provider_owners().get(&self.provider) == Some(&expected.provider_owner)
            && world
                .provider_ingest_completion_authorities()
                .get(&self.provider)
                == Some(expected)
            && iroha_core::query::provider_ingest_source::has_provider_completion_permission_v1(
                world,
                &self.completion_signer,
                self.provider,
            )
    }
    fn check_context(
        &self,
        context: &ProviderIngestCompletionSignerResolutionContextV1,
    ) -> std::result::Result<(), ProviderIngestCompletionSignerErrorV1> {
        let rejected = ProviderIngestCompletionSignerErrorV1::Rejected;
        if !context.is_valid()
            || context.expected_authority.completion_signer != self.completion_signer
            || context.expected_authority.signer_policy != self.config.completion_signer_policy
        {
            return Err(rejected);
        }
        let view = self.state()?.view();
        if !self.eligible(view.world(), &context.expected_authority) {
            return Err(rejected);
        }
        iroha_core::query::signer_finality::verify_signer_finality_v1(
            &view,
            context.finalized_cursor.height,
            context.finalized_cursor.block_hash,
        )
        .map_err(|_| rejected)?;
        let finalized_now = view
            .latest_block()
            .map_err(|error| match error {
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
                    ProviderIngestCompletionSignerErrorV1::Unavailable
                }
                iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => rejected,
            })?
            .ok_or(rejected)?
            .header()
            .creation_time()
            .as_secs();
        let now = finalized_now.max(source::now().map_err(|_| rejected)? / 1000);
        if iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
            &view,
            self.provider,
            now,
        )
        .map_err(|_| rejected)?
        .is_none()
        {
            return Err(rejected);
        }
        Ok(())
    }
    fn sign_exact(
        &self,
        context: &ProviderIngestCompletionSignerResolutionContextV1,
        payload: TransactionPayload,
    ) -> std::result::Result<SignedTransaction, ProviderIngestCompletionSignerErrorV1> {
        let rejected = ProviderIngestCompletionSignerErrorV1::Rejected;
        if !completion_payload_matches_resolution_context(&payload, context, self.provider) {
            return Err(rejected);
        }
        let state = self.state()?;
        let view = state.view();
        if !self.eligible(view.world(), &context.expected_authority)
            || payload.network_id() != Some(state.network_id_ref())
        {
            return Err(rejected);
        }
        iroha_core::query::signer_finality::verify_signer_finality_v1(
            &view,
            context.finalized_cursor.height,
            context.finalized_cursor.block_hash,
        )
        .map_err(|_| rejected)?;
        let finalized_now = view
            .latest_block()
            .map_err(|error| match error {
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
                    ProviderIngestCompletionSignerErrorV1::Unavailable
                }
                iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => rejected,
            })?
            .ok_or(rejected)?
            .header()
            .creation_time()
            .as_secs();
        let now = finalized_now.max(source::now().map_err(|_| rejected)? / 1000);
        if iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
            &view,
            self.provider,
            now,
        )
        .map_err(|_| rejected)?
        .is_none()
        {
            return Err(rejected);
        }
        let Executable::Instructions(instructions) = payload.instructions() else {
            return Err(rejected);
        };
        let completion = instructions[0]
            .as_any()
            .downcast_ref::<CompleteReplicationOrder>()
            .ok_or(rejected)?;
        let order = view
            .world()
            .replication_orders()
            .get(completion.order_id())
            .ok_or(rejected)?;
        let pin = view
            .world()
            .pin_manifests()
            .get(&order.manifest_digest)
            .ok_or(rejected)?;
        let authority = view
            .world()
            .provider_ingest_completion_authorities()
            .get(&self.provider)
            .ok_or(rejected)?;
        if authority != completion.expected_authority() || pin.policy.retention_epoch <= now {
            return Err(rejected);
        }
        let authorization = FinalizedProviderIngestAuthorizationV1::from_finalized_state(
            context.finalized_cursor.height,
            context.finalized_cursor.block_hash,
            *self.provider.as_bytes(),
            *order.order_id.as_bytes(),
            *pin.digest.as_bytes(),
            pin.root_cid.as_bytes().to_vec(),
            pin.chunker.to_handle(),
            pin.chunk_digest_sha3_256,
            pin.por_root,
            pin.content_length,
        )
        .map_err(|_| rejected)?;
        let request = ProviderIngestCompletionPayloadRequestV1 {
            authorization,
            provider_owner: authority.provider_owner.clone(),
            expected_authority: authority.clone(),
            expected_assignment_revision: context.expected_assignment_revision,
            network_id: *state.network_id_ref(),
            completion_epoch: *completion.completion_epoch(),
            finalized_cursor: context.finalized_cursor,
        };
        if now > order.deadline_epoch {
            return Err(rejected);
        }
        validate_completion_order_binding(&request, self.provider, order, pin, finalized_now)
            .map_err(|_| rejected)?;
        // Retain this exact immutable State view until the exact payload is signed. The queue and
        // native completion instruction repeat current authority and assignment checks at commit.
        TransactionBuilder::from_payload(payload)
            .and_then(|builder| builder.try_sign(self.key.private_key()))
            .map_err(|_| rejected)
    }
}
impl ProviderIngestGovernedSignerResolverRuntimeV1 for NativeResolverV1 {
    fn runtime_handle(&self) -> &str {
        &self.config.completion_signer_resolver_handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    > {
        Ok(configured_completion_signer_resolver_qualification(
            &self.config,
        ))
    }
    fn signer_binding(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerBindingV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    > {
        Ok(configured_completion_signer_binding(&self.config))
    }
    fn check_readiness(
        &self,
    ) -> std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1> {
        Ok(())
    }
    fn resolve(
        &self,
        context: ProviderIngestCompletionSignerResolutionContextV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<
            Option<Arc<dyn ProviderIngestCompletionSignerV1>>,
            ProviderIngestCompletionSignerResolverErrorV1,
        >,
    > {
        let resolver = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    resolver
                        .check_context(&context)
                        .map_err(|_| ProviderIngestCompletionSignerResolverErrorV1::Rejected)?;
                    let signer: Arc<dyn ProviderIngestCompletionSignerV1> =
                        Arc::new(NativeSignerV1 { resolver, context });
                    Ok(Some(signer))
                }),
            )
            .await
            .map_err(|_| ProviderIngestCompletionSignerResolverErrorV1::Unavailable)?
        })
    }
}
struct NativeSignerV1 {
    resolver: NativeResolverV1,
    context: ProviderIngestCompletionSignerResolutionContextV1,
}
impl ProviderIngestCompletionSignerV1 for NativeSignerV1 {
    fn runtime_handle(&self) -> &str {
        &self.resolver.config.completion_signer_handle
    }
    fn authority(&self) -> &AccountId {
        &self.resolver.completion_signer
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerQualificationV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        Ok(configured_completion_signer_binding(&self.resolver.config).qualification)
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.resolver.config.completion_signer_policy
    }
    fn current_eligibility(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerPolicyV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        let view = self.resolver.state()?.view();
        if !self
            .resolver
            .eligible(view.world(), &self.context.expected_authority)
        {
            return Err(ProviderIngestCompletionSignerErrorV1::Rejected);
        }
        Ok(self.signer_policy())
    }
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<SignedTransaction, ProviderIngestCompletionSignerErrorV1>,
    > {
        let resolver = self.resolver.clone();
        let context = self.context.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    resolver.sign_exact(&context, payload)
                }),
            )
            .await
            .map_err(|_| ProviderIngestCompletionSignerErrorV1::Unavailable)?
        })
    }
}

struct NativeCheckpointV1 {
    handle: String,
    qualification: ProviderIngestCheckpointProviderQualificationV1,
    root: PathBuf,
    maximum: u64,
    gate: Mutex<()>,
    custody: OnceLock<NativeCheckpointCustodyV1>,
}
impl fmt::Debug for NativeCheckpointV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCheckpointV1").finish_non_exhaustive()
    }
}
/// Retained native namespace and single-writer custody. This is not ledger finality authority.
struct NativeCheckpointCustodyV1 {
    directory: PrivateDirectory,
    lock: File,
    identity: FileIdentity,
}
impl NativeCheckpointCustodyV1 {
    fn revalidate(&self) -> io::Result<()> {
        self.directory.revalidate()?;
        let retained = FileSnapshot::private_journal(&self.lock)?;
        if self.lock.metadata()?.len() != 0 || FileIdentity::of(&self.lock)? != self.identity {
            return Err(io::Error::other("native checkpoint lock changed"));
        }
        let named = self.directory.open_read("lock")?;
        if FileIdentity::of(&named)? != self.identity
            || FileSnapshot::private_journal(&named)? != retained
        {
            return Err(io::Error::other("native checkpoint lock changed"));
        }
        // Only native private regular files can coexist with the authority. Staging leftovers
        // are inert; they never become a checkpoint or reset the CAS lineage.
        self.directory.visit_private_files(128, |_, _| Ok(()))?;
        self.directory.revalidate()
    }
}
impl NativeCheckpointV1 {
    // The caller holds gate across acquisition, read, native publication and final revalidation.
    fn open(
        &self,
    ) -> std::result::Result<&NativeCheckpointCustodyV1, ProviderIngestCheckpointExternalErrorV1>
    {
        let rejected = ProviderIngestCheckpointExternalErrorV1::Rejected;
        if self.custody.get().is_none() {
            let directory = PrivateDirectory::open_or_create(&self.root).map_err(|_| rejected)?;
            let lock = directory
                .open_ownership_lock("lock")
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
            if lock.metadata().map_err(|_| rejected)?.len() != 0 {
                return Err(rejected);
            }
            FileSnapshot::private_journal(&lock).map_err(|_| rejected)?;
            lock.try_lock()
                .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
            let identity = FileIdentity::of(&lock).map_err(|_| rejected)?;
            let custody = NativeCheckpointCustodyV1 {
                directory,
                lock,
                identity,
            };
            custody.revalidate().map_err(|_| rejected)?;
            self.custody.set(custody).map_err(|_| rejected)?;
        }
        let custody = self.custody.get().ok_or(rejected)?;
        custody.revalidate().map_err(|_| rejected)?;
        Ok(custody)
    }
    fn read(
        &self,
        custody: &NativeCheckpointCustodyV1,
    ) -> std::result::Result<
        Option<ProviderIngestSealedCheckpointRecordV1>,
        ProviderIngestCheckpointExternalErrorV1,
    > {
        let rejected = ProviderIngestCheckpointExternalErrorV1::Rejected;
        // Shared native open admits a no-follow regular descriptor before any data read.
        // Unix opens nonblocking; Windows rejects reparse points and retains sharing custody.
        let mut file = match custody.directory.open_read("checkpoint.to") {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                custody.revalidate().map_err(|_| rejected)?;
                return Ok(None);
            }
            Err(_) => return Err(rejected),
        };
        let before = FileSnapshot::of(&file, true).map_err(|_| rejected)?;
        let maximum = self.maximum.checked_add(4096).ok_or(rejected)?;
        let length = file.metadata().map_err(|_| rejected)?.len();
        if length > maximum {
            return Err(rejected);
        }
        let length = usize::try_from(length).map_err(|_| rejected)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
        bytes.resize(length, 0);
        file.read_exact(&mut bytes).map_err(|_| rejected)?;
        let mut extra = [0];
        if file.read(&mut extra).map_err(|_| rejected)? != 0
            || FileSnapshot::of(&file, true).map_err(|_| rejected)? != before
        {
            return Err(rejected);
        }
        let named = custody
            .directory
            .open_read("checkpoint.to")
            .map_err(|_| rejected)?;
        if FileSnapshot::of(&named, true).map_err(|_| rejected)? != before {
            return Err(rejected);
        }
        custody.revalidate().map_err(|_| rejected)?;
        let record =
            ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(&bytes, self.maximum)
                .map_err(|_| rejected)?;
        custody.revalidate().map_err(|_| rejected)?;
        Ok(Some(record))
    }
}
impl ProviderIngestCheckpointRuntimeV1 for NativeCheckpointV1 {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestCheckpointProviderQualificationV1,
        ProviderIngestCheckpointExternalErrorV1,
    > {
        Ok(self.qualification)
    }
    fn load_latest(
        &self,
    ) -> std::result::Result<
        Option<ProviderIngestSealedCheckpointRecordV1>,
        ProviderIngestCheckpointExternalErrorV1,
    > {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
        let custody = self.open()?;
        self.read(custody)
    }
    fn compare_and_swap_latest(
        &self,
        expected: Option<[u8; 32]>,
        next: &ProviderIngestSealedCheckpointRecordV1,
    ) -> std::result::Result<(), ProviderIngestCheckpointExternalErrorV1> {
        let rejected = ProviderIngestCheckpointExternalErrorV1::Rejected;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Unavailable)?;
        let custody = self.open()?;
        next.validate(self.maximum).map_err(|_| rejected)?;
        let current = self.read(custody)?;
        if current.as_ref().map(|value| value.revision) != expected
            || next.predecessor_revision != expected
            || next.predecessor_checkpoint_digest
                != current.as_ref().map(|value| value.checkpoint_digest)
            || next.checkpoint_sequence
                != current
                    .as_ref()
                    .map_or(Some(1), |value| value.checkpoint_sequence.checked_add(1))
                    .ok_or(rejected)?
        {
            return Err(rejected);
        }
        let bytes = next
            .to_canonical_bytes(self.maximum)
            .map_err(|_| rejected)?;
        custody.revalidate().map_err(|_| rejected)?;
        // Shared publication owns private exclusive staging, exact destination admission,
        // atomic native replacement and parent durability. Any returned failure can follow
        // publication, so the caller must retain its original intent and reconcile.
        custody
            .directory
            .write_atomic("checkpoint.to", &bytes, PublishMode::Replace)
            .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Ambiguous)?;
        custody
            .revalidate()
            .map_err(|_| ProviderIngestCheckpointExternalErrorV1::Ambiguous)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_software_tests.rs"]
mod tests;

/// Host UTC is a lease/admission bound, never a finality or external rollback witness.
pub(super) fn native_now_unix_ms()
-> std::result::Result<u64, MusubiProviderAttestationSignerErrorV1> {
    source::now().map_err(|_| MusubiProviderAttestationSignerErrorV1::Unavailable)
}
