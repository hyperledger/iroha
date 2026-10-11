//! Immutable aggregate launch revisions derived from three independently recovered provider histories.
//! The process owner retains the network coordinator lock and exactly four original child handles.
use super::{
    ManagedCustodyEnrollmentInterval, ManagedStreamTokenCustody, ManagedTransactionFinality,
    PreparedLocalnet, Result, RetainedCustodyEnrollment,
    native_operation::{encode, invalid, now_ms, read_optional, require_deadline},
    service_authority::{CheckpointImportScope, NetworkPurpose, ServiceAuthority},
    service_bootstrap::{ManagedServiceBootstrap, ServiceBootstrapProgress},
    service_policies::GeneratedServicePolicies,
};
use crate::localnet::service_authorities::{
    RetainedGatewayCompliancePlan, RetainedProviderServicePlan, RetainedPublicationServicePlan,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId, account::address::ChainDiscriminantGuard, sorafs::capacity::ProviderId,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use zeroize::Zeroizing;
mod carriers;
mod components;
mod config;
mod projections;
mod recovery;
use carriers::{RequiredTransaction, RequiredTransactions};
use components::{ComponentIdentity, PreparedProviderComponent, ProviderComponent};
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_POLICY_BYTES: usize = 384 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
// One Catalog, one initial aggregate and at most 3 * 63 single-provider successors.
const MAX_RETAINED_REVISIONS: usize = 192;
const MAX_RUNTIME_ENTRIES: usize = 256;
const MAX_CUSTODY_BYTES: usize = sorafs_manifest::signer::custody::SIGNER_CUSTODY_MAX_BYTES_V1;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_deploy::managed::generated_service_runtime::GeneratedRuntimeStage")]
pub(super) enum GeneratedRuntimeStage {
    Catalog,
    StreamTokens,
}

#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::generated_service_runtime::Intent")]
struct Intent {
    network: NetworkId,
    genesis: [u8; 32],
    originals: [[u8; 32]; 4],
    policies: [u8; 32],
    providers: [ComponentIdentity; 3],
    stage: GeneratedRuntimeStage,
    components: Option<[[u8; 32]; 3]>,
    required: Vec<RequiredTransaction>,
}
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::generated_service_runtime::Manifest")]
struct Manifest {
    intent: Intent,
    launch_digests: [[u8; 32]; 4],
}

struct RuntimeSelection {
    policies: GeneratedServicePolicies,
    plans: [RetainedProviderServicePlan; 3],
    compliance: [RetainedGatewayCompliancePlan; 3],
    initial: [Option<ManagedCustodyEnrollmentInterval>; 3],
    publication: RetainedPublicationServicePlan,
}
impl RuntimeSelection {
    fn read(authority: &ServiceAuthority) -> Result<Self> {
        let intent = authority.original_intent()?;
        // This read owns one bounded immutable import workspace for its three fresh children.
        // It carries no source, wallet, current-state or authority verdict beyond this call.
        let imports = CheckpointImportScope::for_original(authority);
        #[cfg(test)]
        let imports = tests::import_scope_tests::select_scope(imports);
        // Only immutable projections share this view. Every mutable child read below retains
        // its ordinary native admission, and no projection escapes the full-image exit check.
        let read = intent.runtime_read();
        let result = (|| {
            // RuntimeSelection owns its original projection; copy only at that ownership boundary.
            let plans = intent.provider_plans()?.clone();
            let publication = intent.publication_plan()?;
            if publication.peer_index() != 0
                || publication.network_id() != authority.config.network_id
                || publication.chain_id() != authority.config.chain.as_str()
                || publication.seed_provider() != plans[0].provider_id()
                || publication.ingress_broker() != &authority
                    .provider_inventory(plans[0].provider_id())?
                    .authority(crate::localnet::service_authorities::StreamTokenAuthorityRole::IssuerOperator)?
                    .account
                || publication.pin_authority()
                    != authority.network_role(
                        crate::localnet::service_authorities::NetworkServiceAuthorityRole::MusubiPin,
                    )?
            {
                return Err(invalid("original publication selection differs"));
            }
            let parent = match read.as_ref() {
                Some(read) => ManagedServiceBootstrap::open_existing_in_runtime(authority, read)?,
                None => ManagedServiceBootstrap::open_existing_from_original(authority)?,
            }
            .ok_or_else(|| invalid("original service bootstrap intent is absent"))?;
            let policies = match read.as_ref() {
                Some(read) => parent.selected_policies_in_runtime(read)?,
                None => parent.selected_policies()?,
            };
            drop(parent);
            let mut initial = Vec::with_capacity(3);
            let mut compliance = Vec::with_capacity(3);
            for (index, plan) in plans.iter().enumerate() {
                if plan.peer_index() != index
                    || usize::from(plan.slot()) != index
                    || plan.network_id() != authority.config.network_id
                {
                    return Err(invalid("original generated provider slot differs"));
                }
                policies.provider(plan.provider_id())?;
                let custody = match read.as_ref() {
                    Some(read) => ManagedStreamTokenCustody::open_existing_in_runtime(
                        authority,
                        plan.provider_id(),
                        imports.as_ref(),
                        read,
                    )?,
                    None => ManagedStreamTokenCustody::open_existing_from_original(
                        authority,
                        plan.provider_id(),
                        imports.as_ref(),
                    )?,
                };
                let selected = match custody {
                    Some(custody) => custody.inspect_local_initial_interval_if_present(
                        &policies.provider(plan.provider_id())?.custody,
                    )?,
                    None => None,
                };
                #[cfg(test)]
                tests::import_scope_tests::after_child(index, imports.as_ref());
                initial.push(selected);
                compliance.push(intent.gateway_compliance_plan(plan.provider_id())?);
            }
            intent.validate_policies(&policies)?;
            Ok(Self {
                policies,
                plans,
                publication,
                compliance: compliance
                    .try_into()
                    .map_err(|_| invalid("original compliance count differs"))?,
                initial: initial
                    .try_into()
                    .map_err(|_| invalid("original enrollment count differs"))?,
            })
        })();
        // Every temporary child is already closed. End pure reuse before closing the original
        // intent on both success and ordinary error; neither selection retains this workspace.
        drop(imports);
        #[cfg(test)]
        tests::before_selection_finish();
        // Close custody even when a child or projection failed; an exit refusal supersedes
        // the ordinary result rather than returning material from a changed original image.
        intent.finish()?;
        result
    }
    fn initial(&self, index: usize) -> Result<ManagedCustodyEnrollmentInterval> {
        self.initial
            .get(index)
            .copied()
            .flatten()
            .ok_or_else(|| invalid("generated runtime requires the original selected enrollment"))
    }
    fn identity(&self, authority: &ServiceAuthority, index: usize) -> Result<ComponentIdentity> {
        let plan = self
            .plans
            .get(index)
            .ok_or_else(|| invalid("generated provider index differs"))?;
        Ok(ComponentIdentity {
            network: authority.config.network_id,
            genesis: *authority.genesis.genesis.hash().as_ref(),
            profile: *plan.original_profile_commitment().as_ref(),
            policies: *Hash::new(encode(&self.policies, MAX_POLICY_BYTES)?).as_ref(),
            compliance: *self.compliance[index].original_commitment().as_ref(),
            provider: plan.provider_id(),
            slot: plan.slot(),
        })
    }
    fn index(&self, provider: ProviderId) -> Result<usize> {
        self.plans
            .iter()
            .position(|plan| plan.provider_id() == provider)
            .ok_or_else(|| invalid("provider is not in the original generated profile"))
    }
    fn validate_interval(&self, components: Option<&[Arc<ProviderComponent>; 3]>) -> Result<()> {
        let now = now_ms()?;
        for (index, plan) in self.plans.iter().enumerate() {
            let policy = self.policies.provider(plan.provider_id())?;
            let admission = plan.admission_material();
            let start = admission
                .issued_at
                .checked_mul(1_000)
                .ok_or_else(|| invalid("original provider interval overflows"))?;
            let end = admission
                .retention_epoch
                .checked_mul(1_000)
                .ok_or_else(|| invalid("original provider interval overflows"))?;
            let selected = components.map(|values| values[index].selection());
            if now < start
                || now >= end
                || now < policy.custody.active_from_unix_ms
                || now >= policy.custody.active_until_unix_ms
                || selected.is_some_and(|value| {
                    value.issued_at_unix_ms < start.max(policy.custody.active_from_unix_ms)
                        || value.expires_at_unix_ms > end.min(policy.custody.active_until_unix_ms)
                        || now < value.issued_at_unix_ms
                        || now >= value.expires_at_unix_ms
                        || value.sequence == 1
                            && self.initial[index].is_none_or(|initial| {
                                value.issued_at_unix_ms != initial.issued_at_unix_ms
                                    || value.expires_at_unix_ms != initial.expires_at_unix_ms
                            })
                })
            {
                return Err(invalid(
                    "original generated provider is outside its finite interval",
                ));
            }
        }
        Ok(())
    }
}

pub(super) struct GeneratedServiceRuntimeRevision {
    manifest: Manifest,
    manifest_name: String,
    peers: [GeneratedRuntimePeer; 4],
    cwd: PathBuf,
    components: Option<[Arc<ProviderComponent>; 3]>,
    required: Option<RequiredTransactions>,
}
pub(super) struct GeneratedRuntimePeer {
    path: PathBuf,
    blake3: [u8; 32],
}
impl GeneratedRuntimePeer {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn blake3(&self) -> [u8; 32] {
        self.blake3
    }
}
impl GeneratedServiceRuntimeRevision {
    pub(super) fn stage(&self) -> GeneratedRuntimeStage {
        self.manifest.intent.stage
    }
    pub(super) fn provider_ids(&self) -> [ProviderId; 3] {
        std::array::from_fn(|index| self.manifest.intent.providers[index].provider)
    }
    pub(super) fn peer(&self, index: usize) -> Result<&GeneratedRuntimePeer> {
        self.peers
            .get(index)
            .ok_or_else(|| invalid("generated runtime peer index differs"))
    }
    pub(super) fn cwd(&self) -> &Path {
        &self.cwd
    }
    pub(super) fn selected_enrollment(
        &self,
        provider: ProviderId,
    ) -> Result<Option<&RetainedCustodyEnrollment>> {
        let index = self
            .manifest
            .intent
            .providers
            .iter()
            .position(|value| value.provider == provider)
            .ok_or_else(|| invalid("unknown generated runtime provider"))?;
        Ok(self
            .components
            .as_ref()
            .map(|values| values[index].enrollment()))
    }
    pub(super) fn required_transactions(&self) -> &[ManagedTransactionFinality] {
        self.required
            .as_ref()
            .map_or(&[], RequiredTransactions::originals)
    }
    pub(super) fn observation_floor(&self) -> Result<ManagedTransactionFinality> {
        self.required
            .as_ref()
            .ok_or_else(|| invalid("generated runtime has no native transaction floor"))?
            .observation_floor()
    }
}

pub(super) struct GeneratedServiceRuntime {
    authority: ServiceAuthority,
}
impl GeneratedServiceRuntime {
    pub(super) fn open(prepared: &PreparedLocalnet) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network(prepared, NetworkPurpose::GeneratedRuntime)?,
        })
    }
    pub(super) fn prepare_catalog(
        &self,
        deadline: Instant,
    ) -> Result<GeneratedServiceRuntimeRevision> {
        require_deadline(deadline)?;
        let selection = RuntimeSelection::read(&self.authority)?;
        self.publish(&selection, None, None, deadline)
    }
    pub(super) fn prepare_renewed_stream_tokens(
        &self,
        previous: &GeneratedServiceRuntimeRevision,
        provider: ProviderId,
        sequence: u64,
        deadline: Instant,
    ) -> Result<GeneratedServiceRuntimeRevision> {
        require_deadline(deadline)?;
        let selection = self.validate_material(previous)?;
        self.validate(previous)?;
        let index = selection.index(provider)?;
        let mut components = previous
            .components
            .as_ref()
            .ok_or_else(|| invalid("previous runtime has no provider enrollments"))?
            .clone();
        if components[index].selection().sequence.checked_add(1) != Some(sequence)
            || !(2..=64).contains(&sequence)
        {
            return Err(invalid(
                "runtime renewal requires exact next provider sequence",
            ));
        }
        #[cfg(all(test, unix))]
        tests::before_bootstrap_reopen();
        let mut parent = self.open_original_bootstrap(&self.authority.prepared)?;
        let ServiceBootstrapProgress::Complete(history) = parent.recover(deadline)? else {
            return Err(invalid("renewal requires all original parent execution"));
        };
        let original_carriers = history.ordered_carriers()?;
        drop(parent);
        let mut custody = ManagedStreamTokenCustody::open(&self.authority.prepared, provider)?;
        let policy = &selection.policies.provider(provider)?.custody;
        let enrollment = custody.retained_renewed_enrollment(sequence, policy, deadline)?;
        let prepared = ProviderComponent::prepare(
            selection.identity(&self.authority, index)?,
            enrollment,
            Some(&components[index]),
        )?;
        let required = RequiredTransactions::from_originals(original_carriers.into_iter().chain(
            components.iter().enumerate().map(|(slot, value)| {
                if slot == index {
                    prepared.finalized()
                } else {
                    value.finalized()
                }
            }),
        ))?;
        let digests = std::array::from_fn(|slot| {
            if slot == index {
                prepared.digest()
            } else {
                components[slot].digest()
            }
        });
        let retentions = self.component_retentions(&selection, digests, &required)?;
        components[index] = prepared.retain(&self.authority.directory, retentions[index])?;
        let floor = required.observation_floor()?;
        custody.verify_current_enrollment(
            components[index].enrollment(),
            policy,
            floor.height,
            *floor.block_hash.as_ref(),
            deadline,
        )?;
        drop(custody);
        // A successor never carries the other two providers forward from stale local intent.
        self.verify_current_components(&selection, &components, &required, deadline, false)?;
        self.publish(&selection, Some(components), Some(required), deadline)
    }
    pub(super) fn validate_for(
        &self,
        prepared: &PreparedLocalnet,
        revision: &GeneratedServiceRuntimeRevision,
    ) -> Result<()> {
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "runtime revision belongs to another prepared generation",
            ));
        }
        self.validate(revision)
    }
    pub(super) fn validate(&self, revision: &GeneratedServiceRuntimeRevision) -> Result<()> {
        self.validate_material(revision)?
            .validate_interval(revision.components.as_ref())
    }
    fn validate_material(
        &self,
        revision: &GeneratedServiceRuntimeRevision,
    ) -> Result<RuntimeSelection> {
        let selection = RuntimeSelection::read(&self.authority)?;
        let root = PrivateDirectory::open_exact(generation_path(&self.authority.prepared)?)?;
        let expected = encode(&revision.manifest, MAX_MANIFEST_BYTES)?;
        let required_identities: &[RequiredTransaction] = revision
            .required
            .as_ref()
            .map_or(&[], RequiredTransactions::identities);
        if root.path() != revision.cwd()
            || self
                .authority
                .directory
                .read(&revision.manifest_name, MAX_MANIFEST_BYTES)?
                .as_slice()
                != expected.as_slice()
            || revision.manifest.intent.network != self.authority.config.network_id
            || revision.manifest.intent.genesis != *self.authority.genesis.genesis.hash().as_ref()
            || revision.manifest.intent.policies
                != *Hash::new(encode(&selection.policies, MAX_POLICY_BYTES)?).as_ref()
            || revision.manifest.intent.required.as_slice() != required_identities
            || revision.manifest.intent.components
                != revision
                    .components
                    .as_ref()
                    .map(|values| std::array::from_fn(|index| values[index].digest()))
        {
            return Err(invalid("generated runtime manifest changed"));
        }
        for index in 0..3 {
            let identity = selection.identity(&self.authority, index)?;
            self.authority
                .directory
                .open_child("providers")?
                .open_child(identity.slot.to_string())?
                .revalidate()?;
            if revision.manifest.intent.providers[index] != identity {
                return Err(invalid("generated runtime provider identity changed"));
            }
            if let Some(components) = &revision.components {
                components[index].validate()?;
                if components[index].identity() != identity {
                    return Err(invalid("generated runtime provider component changed"));
                }
            }
        }
        for index in 0..4 {
            let original = root.read(format!("peer{index}.toml"), MAX_CONFIG_BYTES)?;
            let peer = revision.peer(index)?;
            let bytes = root.read(
                peer.path
                    .file_name()
                    .ok_or_else(|| invalid("generated runtime filename absent"))?,
                MAX_CONFIG_BYTES,
            )?;
            if *blake3::hash(&original).as_bytes() != revision.manifest.intent.originals[index]
                || *blake3::hash(&bytes).as_bytes() != peer.blake3
                || peer.blake3 != revision.manifest.launch_digests[index]
            {
                return Err(invalid("generated runtime launch configuration changed"));
            }
        }
        root.revalidate()?;
        self.authority.validate_profile()?;
        Ok(selection)
    }
    fn verify_current_components(
        &self,
        selection: &RuntimeSelection,
        components: &[Arc<ProviderComponent>; 3],
        required: &RequiredTransactions,
        deadline: Instant,
        parallel: bool,
    ) -> Result<()> {
        let floor = required.observation_floor()?;
        self.current_provider_round(selection, deadline, parallel, |index, custody| {
            let provider = selection.plans[index].provider_id();
            custody.verify_current_enrollment(
                components[index].enrollment(),
                &selection.policies.provider(provider)?.custody,
                floor.height,
                *floor.block_hash.as_ref(),
                deadline,
            )
        })
        .map(|_| ())
    }

    /// Only provider-local custody and fresh observations run here. Parent selection and
    /// historical reconstruction stay outside, and every original owner closes before return.
    fn current_provider_round<T: Send>(
        &self,
        selection: &RuntimeSelection,
        deadline: Instant,
        parallel: bool,
        read: impl Fn(usize, &mut ManagedStreamTokenCustody) -> Result<T> + Sync,
    ) -> Result<[T; 3]> {
        let result = super::provider_round::run(
            [0, 1, 2],
            parallel,
            |index| {
                require_deadline(deadline)?;
                let mut custody = ManagedStreamTokenCustody::open(
                    &self.authority.prepared,
                    selection.plans[index].provider_id(),
                )?;
                read(index, &mut custody)
            },
            || invalid("generated provider observation worker did not complete"),
        );
        // Even an ordinary member error waits for every worker and closes the common timer.
        require_deadline(deadline)?;
        result
    }
    fn publication_intent(
        &self,
        selection: &RuntimeSelection,
        originals: &[Zeroizing<Vec<u8>>],
        components: Option<[[u8; 32]; 3]>,
        required: Option<&RequiredTransactions>,
    ) -> Result<Intent> {
        if originals.len() != 4 || components.is_some() != required.is_some() {
            return Err(invalid("generated publication material count differs"));
        }
        let mut identities = Vec::with_capacity(3);
        for index in 0..3 {
            identities.push(selection.identity(&self.authority, index)?);
        }
        Ok(Intent {
            network: self.authority.config.network_id,
            genesis: *self.authority.genesis.genesis.hash().as_ref(),
            originals: std::array::from_fn(|index| {
                *blake3::hash(originals[index].as_slice()).as_bytes()
            }),
            policies: *Hash::new(encode(&selection.policies, MAX_POLICY_BYTES)?).as_ref(),
            providers: identities
                .try_into()
                .map_err(|_| invalid("generated runtime provider count differs"))?,
            stage: if components.is_some() {
                GeneratedRuntimeStage::StreamTokens
            } else {
                GeneratedRuntimeStage::Catalog
            },
            components,
            required: required.map_or_else(Vec::new, |values| values.identities().to_vec()),
        })
    }

    fn retained_manifest(&self, intent: &Intent) -> Result<(String, Option<Vec<u8>>)> {
        let id = hex::encode(Hash::new(encode(intent, MAX_MANIFEST_BYTES)?).as_ref());
        let name = format!("revision-{id}.nrt");
        let committed = read_optional(&self.authority.directory, &name, MAX_MANIFEST_BYTES)?;
        if let Some(bytes) = committed.as_ref() {
            let retained: Manifest = norito::decode_canonical_with_limits(
                bytes,
                norito::DecodeLimits::new(
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES * 4,
                    24,
                ),
            )
            .map_err(|_| invalid("invalid generated runtime manifest"))?;
            if &retained.intent != intent {
                return Err(invalid("retained generated runtime intent differs"));
            }
        }
        Ok((name, committed))
    }

    /// Retained references only strengthen custody requirements; actual native heads still
    /// exclusively select components. No filename order or local manifest grants authority.
    fn component_retentions(
        &self,
        selection: &RuntimeSelection,
        digests: [[u8; 32]; 3],
        required: &RequiredTransactions,
    ) -> Result<[Retention; 3]> {
        let root = PrivateDirectory::open_exact(generation_path(&self.authority.prepared)?)?;
        let originals = (0..4)
            .map(|index| root.read(format!("peer{index}.toml"), MAX_CONFIG_BYTES))
            .collect::<std::io::Result<Vec<_>>>()?;
        let expected =
            self.publication_intent(selection, &originals, Some(digests), Some(required))?;
        let directory = &self.authority.directory;
        let names = directory.entries(MAX_RUNTIME_ENTRIES)?;
        let mut retention = [Retention::PublishCurrent; 3];
        let mut revisions = 0;
        for name in &names {
            let name = name
                .to_str()
                .ok_or_else(|| invalid("invalid runtime material filename"))?;
            if !name.starts_with("revision-") {
                continue;
            }
            revisions += 1;
            if revisions > MAX_RETAINED_REVISIONS {
                return Err(invalid("retained runtime revisions exceed finite history"));
            }
            let bytes = directory.read(name, MAX_MANIFEST_BYTES)?;
            let retained: Manifest = norito::decode_canonical_with_limits(
                &bytes,
                norito::DecodeLimits::new(
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES,
                    MAX_MANIFEST_BYTES * 4,
                    24,
                ),
            )
            .map_err(|_| invalid("invalid retained runtime reference manifest"))?;
            let intent = &retained.intent;
            let canonical = format!(
                "revision-{}.nrt",
                hex::encode(Hash::new(encode(intent, MAX_MANIFEST_BYTES)?).as_ref())
            );
            if canonical != name
                || intent.network != expected.network
                || intent.genesis != expected.genesis
                || intent.originals != expected.originals
                || intent.policies != expected.policies
                || intent.providers != expected.providers
                || retained
                    .launch_digests
                    .iter()
                    .any(|value| *value == [0; 32])
            {
                return Err(invalid(
                    "retained runtime reference differs from original profile",
                ));
            }
            match (intent.stage, intent.components) {
                (GeneratedRuntimeStage::Catalog, None) if intent.required.is_empty() => {}
                (GeneratedRuntimeStage::StreamTokens, Some(components))
                    if !intent.required.is_empty()
                        && intent.required.len() <= carriers::MAX_REQUIRED_TRANSACTIONS
                        && components.iter().all(|value| *value != [0; 32]) =>
                {
                    for transaction in &intent.required {
                        transaction.validate()?;
                    }
                    for slot in 0..3 {
                        if components[slot] == digests[slot] {
                            retention[slot] = Retention::ExistingMaterial;
                        }
                    }
                }
                _ => return Err(invalid("retained runtime reference stage differs")),
            }
        }
        if directory.entries(MAX_RUNTIME_ENTRIES)? != names {
            return Err(invalid("retained runtime reference inventory changed"));
        }
        directory.revalidate()?;
        root.revalidate()?;
        Ok(retention)
    }

    fn publish(
        &self,
        selection: &RuntimeSelection,
        components: Option<[Arc<ProviderComponent>; 3]>,
        required: Option<RequiredTransactions>,
        deadline: Instant,
    ) -> Result<GeneratedServiceRuntimeRevision> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        selection.policies.validate(&self.authority)?;
        selection.validate_interval(components.as_ref())?;
        if components.is_some() != required.is_some() {
            return Err(invalid("generated runtime stage evidence differs"));
        }
        for index in 0..3 {
            let identity = selection.identity(&self.authority, index)?;
            if let Some(values) = &components {
                values[index].validate()?;
                if values[index].identity() != identity
                    || !required.as_ref().is_some_and(|required| {
                        required.originals().contains(&values[index].finalized())
                    })
                {
                    return Err(invalid(
                        "generated runtime lacks exact provider transaction",
                    ));
                }
            }
        }
        let root = PrivateDirectory::open_exact(generation_path(&self.authority.prepared)?)?;
        let _chain =
            ChainDiscriminantGuard::enter(self.authority.config.account_chain_discriminant);
        let originals = (0..4)
            .map(|index| root.read(format!("peer{index}.toml"), MAX_CONFIG_BYTES))
            .collect::<std::io::Result<Vec<_>>>()?;
        let intent = self.publication_intent(
            selection,
            &originals,
            components
                .as_ref()
                .map(|values| std::array::from_fn(|index| values[index].digest())),
            required.as_ref(),
        )?;
        let id = hex::encode(Hash::new(encode(&intent, MAX_MANIFEST_BYTES)?).as_ref());
        let (name, committed) = self.retained_manifest(&intent)?;
        let retention = if committed.is_some() {
            Retention::ExistingMaterial
        } else {
            Retention::PublishCurrent
        };
        let existing = components.is_some() || committed.is_some();
        let providers = if existing {
            self.authority.directory.open_child("providers")?
        } else {
            self.authority.directory.ensure_child("providers")?
        };
        let provider_material = (0..3)
            .map(|index| {
                if existing {
                    providers.open_child(index.to_string())
                } else {
                    providers.ensure_child(index.to_string())
                }
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut peers = Vec::with_capacity(4);
        let mut configurations = Vec::with_capacity(4);
        for (index, original) in originals.iter().enumerate() {
            require_deadline(deadline)?;
            let name = format!("peer{index}.services-{id}.toml");
            let destination = root.path().join(&name);
            let rendered = config::render(
                &self.authority,
                selection,
                &intent,
                components.as_ref(),
                index,
                original,
                &destination,
                &self.authority.directory,
                provider_material.get(index),
            )?;
            configurations.push((name, rendered));
            peers.push(GeneratedRuntimePeer {
                path: destination,
                blake3: *blake3::hash(configurations[index].1.as_bytes()).as_bytes(),
            });
        }
        let peers: [GeneratedRuntimePeer; 4] = peers
            .try_into()
            .map_err(|_| invalid("generated runtime peer count differs"))?;
        let manifest = Manifest {
            intent,
            launch_digests: std::array::from_fn(|index| peers[index].blake3),
        };
        let manifest_bytes = encode(&manifest, MAX_MANIFEST_BYTES)?;
        if committed
            .as_ref()
            .is_some_and(|bytes| bytes != &manifest_bytes)
        {
            return Err(invalid("retained generated runtime manifest changed"));
        }
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        for (name, bytes) in &configurations {
            require_deadline(deadline)?;
            retain_revision_file(&root, name, bytes.as_bytes(), MAX_CONFIG_BYTES, retention)?;
        }
        retain_revision_file(
            &self.authority.directory,
            &name,
            &manifest_bytes,
            MAX_MANIFEST_BYTES,
            retention,
        )?;
        let revision = GeneratedServiceRuntimeRevision {
            manifest,
            manifest_name: name,
            peers,
            cwd: root.path().to_owned(),
            components,
            required,
        };
        self.validate(&revision)?;
        Ok(revision)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retention {
    PublishCurrent,
    ExistingMaterial,
}
fn retain_revision_file(
    directory: &PrivateDirectory,
    name: &str,
    bytes: &[u8],
    maximum: usize,
    retention: Retention,
) -> Result<()> {
    match retention {
        Retention::PublishCurrent => retain_exact(directory, name, bytes, maximum),
        Retention::ExistingMaterial => {
            if bytes.is_empty()
                || bytes.len() > maximum
                || directory.read(name, maximum)?.as_slice() != bytes
            {
                return Err(invalid("original runtime ancestor bytes differ"));
            }
            Ok(())
        }
    }
}
fn retain_receipt_custody(directory: &PrivateDirectory, committed: bool) -> Result<()> {
    let receipts = if committed {
        directory.open_child("stream-token-receipts")?
    } else {
        directory.ensure_child("stream-token-receipts")?
    };
    receipts.revalidate()?;
    Ok(())
}
fn generation_path(prepared: &PreparedLocalnet) -> Result<&Path> {
    prepared
        .context
        .client_config
        .parent()
        .ok_or_else(|| invalid("generated runtime has no original directory"))
}
fn custody_name(digest: [u8; 32]) -> String {
    format!("enrollment-{}.nrt", hex::encode(digest))
}
fn retain_exact(
    directory: &PrivateDirectory,
    name: &str,
    bytes: &[u8],
    maximum: usize,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("generated runtime material exceeds bound"));
    }
    match read_optional(directory, name, maximum)? {
        Some(retained) if retained.as_slice() == bytes => Ok(()),
        Some(_) => Err(invalid("retained generated runtime bytes differ")),
        None => {
            directory.write_atomic(name, bytes, PublishMode::CreateNew)?;
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "generated_service_runtime/tests.rs"]
mod tests;

#[cfg(test)]
mod protected_config_tests {
    use super::*;
    use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
    use iroha_primitives::numeric::Quantity;
    use iroha_wallet::operations::BoundedTransactionOptions;
    use std::{collections::BTreeMap, time::Duration};

    #[test]
    fn catalog_intent_borrows_private_originals_and_empty_carriers_validate() {
        let _guard = crate::managed::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "runtime-protected-originals",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let options = BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::from([(
                AssetDefinitionId::parse_address_literal(
                    crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
                )
                .unwrap(),
                Quantity::from(1_000u64),
            )]),
            deadline: Instant::now() + Duration::from_secs(300),
        };
        let mut bootstrap = ManagedServiceBootstrap::open(&prepared).unwrap();
        bootstrap.authorize_test_startup(&options).unwrap().unwrap();
        drop(bootstrap);
        let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
        let selection = RuntimeSelection::read(&owner.authority).unwrap();
        let root = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
        let originals: Vec<zeroize::Zeroizing<Vec<u8>>> = (0..4)
            .map(|index| {
                root.read(format!("peer{index}.toml"), MAX_CONFIG_BYTES)
                    .unwrap()
            })
            .collect();
        let addresses: [_; 4] = std::array::from_fn(|index| originals[index].as_ptr());
        let digests: [_; 4] =
            std::array::from_fn(|index| *blake3::hash(originals[index].as_slice()).as_bytes());
        let intent = owner
            .publication_intent(&selection, &originals, None, None)
            .unwrap();
        assert_eq!(intent.originals, digests);
        assert!(intent.required.is_empty());
        assert!(intent.components.is_none());
        assert_eq!(intent.stage, GeneratedRuntimeStage::Catalog);
        for index in 0..4 {
            assert_eq!(
                originals[index].as_ptr(),
                addresses[index],
                "original private backing stays owned"
            );
            assert_eq!(
                *blake3::hash(originals[index].as_slice()).as_bytes(),
                digests[index]
            );
        }
        assert!(
            owner
                .publication_intent(&selection, &originals[..3], None, None)
                .is_err()
        );
        assert!(
            owner
                .publication_intent(&selection, &originals, Some([[1; 32]; 3]), None)
                .is_err()
        );
        let revision = owner.prepare_catalog(options.deadline).unwrap();
        assert_eq!(revision.manifest.intent.originals, digests);
        assert!(revision.required_transactions().is_empty());
        owner.validate_material(&revision).unwrap();
    }
}
