//! Original authenticated G1/H2 custody for fresh managed AMX private genesis.
//!
//! The attachment request lock and generation operation lock serialize this owner. A complete
//! pair is published once before signing, and a visible generation can never recreate it.
//! TODO: complete nested offline decode/verifier funding and global tracker/relay integration
//! remain separate. Historical bootstrap verification is not fresh committee readiness.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use iroha_crypto::Hash;
use iroha_data_model::{NetworkId, isi::sumeragi_amx::RegisterAmxParticipantV1};
use iroha_fs::{FileSnapshot, LocalFileSnapshot, PrivateDirectory, PublishMode, RetainedFile};
use iroha_genesis::{RawGenesisTransaction, SIGNED_GENESIS_MAX_BYTES_V1};
use iroha_model_base::chain::ChainId;
use norito::{Decode, Encode};

use super::{AuthenticatedBootstrap, BootstrapError, CheckpointTransport, Result, decode};
use crate::localnet::PrivateRootSpec;

const DIRECTORY: &str = "amx-bootstrap";
const STAGING: &str = ".amx-bootstrap-preparing";
const RECORD: &str = "identity.nrt";
const G1: &str = "global-g1.nrt";
const H2: &str = "global-h2.nrt";
const MAX_RECORD: usize = 16 * 1024;
type LocalObjectIdentity = (u8, u64, [u8; 16]);
type OriginalPair = (zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>);

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::bootstrap::AmxSourceIdentityV1")]
struct Identity {
    network_name: String,
    generation: u64,
    network_id: NetworkId,
    chain_id: String,
    genesis_hash: Hash,
    successor_hash: Hash,
    directory_identity: LocalObjectIdentity,
    genesis_identity: LocalFileSnapshot,
    successor_identity: LocalFileSnapshot,
}

/// Borrow the caller's authenticated release and original private attachment directory.
pub(crate) struct AmxSourceSelection<'a> {
    pub(crate) bootstrap: &'a AuthenticatedBootstrap,
    pub(crate) attachment: &'a PrivateDirectory,
    pub(crate) deadline: Instant,
}

/// Closed immutable file custody; no response-selected network or verifier is retained.
pub(crate) struct ParentBootstrapSources {
    directory: PrivateDirectory,
    identity: Identity,
    originals: [RetainedFile; 3],
}

impl AmxSourceSelection<'_> {
    /// Called only under the generation operation lock. Initial absence is permitted only
    /// before a generation exists; an absent/partial pair never repairs a published identity.
    pub(crate) fn retain(
        &self,
        spec: &PrivateRootSpec,
        may_create: bool,
    ) -> Result<ParentBootstrapSources> {
        self.retain_with(spec, may_create, &CheckpointTransport::new(), unix_ms)
    }

    fn retain_with(
        &self,
        spec: &PrivateRootSpec,
        may_create: bool,
        transport: &CheckpointTransport,
        now: impl Fn() -> Result<u64>,
    ) -> Result<ParentBootstrapSources> {
        spec.validate()
            .map_err(|_| BootstrapError::Invalid("invalid selected AMX private scope"))?;
        self.require_live_release(spec, now()?)?;
        if let Some(directory) = self.attachment.open_child_optional(DIRECTORY)? {
            let original = ParentBootstrapSources::open(directory, self.bootstrap, spec)?;
            // DEP3 restores admission after retained authentication outlives its release.
            #[cfg(not(all(test, sumeragi_deploy_mutation = "DEP3")))]
            self.require_live_release(spec, now()?)?;
            return Ok(original);
        }
        // DEP1 restores HTTP reconstruction of a lost published generation.
        if !may_create && !cfg!(all(test, sumeragi_deploy_mutation = "DEP1")) {
            return Err(BootstrapError::Invalid(
                "published private generation lost its original AMX sources",
            ));
        }
        // A visible unpublished stage is an incomplete original publication, never a reason
        // to fetch a replacement pair or grant a new acquisition deadline.
        if self.attachment.open_child_optional(STAGING)?.is_some() {
            return Err(BootstrapError::Invalid(
                "incomplete original AMX source publication",
            ));
        }
        let (genesis, successor) = transport
            .fetch_amx_pair(self.bootstrap, self.deadline)
            .map_err(|_| BootstrapError::Invalid("bounded original AMX source retrieval failed"))?;
        crate::genesis::amx::authenticate_global_sources(
            &self
                .bootstrap
                .release()
                .chain_id
                .parse()
                .map_err(|_| BootstrapError::Invalid("invalid selected AMX chain"))?,
            spec.parent_network_id,
            &genesis,
            &successor,
        )
        .map_err(|_| BootstrapError::Invalid("original AMX global G1/H2 authentication failed"))?;
        // DEP4 restores publication after acquisition outlives the original release.
        #[cfg(not(all(test, sumeragi_deploy_mutation = "DEP4")))]
        self.require_live_release(spec, now()?)?;
        // Keep one native directory and its actual files while deriving the local record.
        // No machine identity is added to the signed G1/H2 or private genesis instruction.
        let staging = self.attachment.create_child(STAGING)?;
        staging.write_atomic(G1, &genesis, PublishMode::CreateNew)?;
        staging.write_atomic(H2, &successor, PublishMode::CreateNew)?;
        let release = self.bootstrap.release();
        let identity = Identity {
            network_name: release.network_name.clone(),
            generation: release.generation,
            network_id: release.network_id,
            chain_id: release.chain_id.clone(),
            genesis_hash: Hash::new(&genesis),
            successor_hash: Hash::new(&successor),
            directory_identity: staging.identity()?.local_parts(),
            genesis_identity: FileSnapshot::of(&staging.open_read(G1)?, true)?.local_parts(),
            successor_identity: FileSnapshot::of(&staging.open_read(H2)?, true)?.local_parts(),
        };
        let record = norito::encode_canonical(&identity)
            .map_err(|_| BootstrapError::Invalid("cannot encode AMX source identity"))?;
        if record.len() > MAX_RECORD {
            return Err(BootstrapError::Invalid("AMX source identity exceeds bound"));
        }
        // A publication error may follow an actual rename. Never replace or blindly repair:
        // retry reopens and authenticates the original complete directory above.
        staging.write_atomic(RECORD, &record, PublishMode::CreateNew)?;
        staging.sync()?;
        #[cfg(not(all(test, sumeragi_deploy_mutation = "DEP4")))]
        self.require_live_release(spec, now()?)?;
        let directory = staging.rename_to_sibling(DIRECTORY, PublishMode::CreateNew)?;
        let original = ParentBootstrapSources::open(directory, self.bootstrap, spec)?;
        self.require_live_release(spec, now()?)?;
        Ok(original)
    }

    fn require_live_release(&self, spec: &PrivateRootSpec, now_ms: u64) -> Result<()> {
        let release = self.bootstrap.release();
        if release.network_id != spec.parent_network_id
            || now_ms < release.issued_at_ms
            || now_ms >= release.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(BootstrapError::Invalid(
                "AMX sources require the original live selected parent release",
            ));
        }
        Ok(())
    }
}

impl ParentBootstrapSources {
    fn open(
        directory: PrivateDirectory,
        bootstrap: &AuthenticatedBootstrap,
        spec: &PrivateRootSpec,
    ) -> Result<Self> {
        if directory.entries(3)? != [G1, H2, RECORD].map(std::ffi::OsString::from) {
            return Err(BootstrapError::Invalid(
                "retained AMX capsule has an incomplete or foreign file inventory",
            ));
        }
        let originals = [
            directory.open_retained_private(RECORD)?,
            directory.open_retained_private(G1)?,
            directory.open_retained_private(H2)?,
        ];
        let identity: Identity = decode(&directory.read(RECORD, MAX_RECORD)?, MAX_RECORD)?;
        let release = bootstrap.release();
        if identity.network_name != release.network_name
            || identity.generation != release.generation
            || identity.network_id != spec.parent_network_id
            || identity.network_id != release.network_id
            || identity.chain_id != release.chain_id
        {
            return Err(BootstrapError::Invalid(
                "retained AMX sources differ from selected parent generation",
            ));
        }
        let original = Self {
            directory,
            identity,
            originals,
        };
        // DEP5 restores content-only reopen without the originally published native snapshot.
        #[cfg(not(all(test, sumeragi_deploy_mutation = "DEP5")))]
        original.require_original_local_objects()?;
        let (genesis, successor) = original.read_pair()?;
        crate::genesis::amx::authenticate_global_sources(
            &original.chain_id()?,
            original.identity.network_id,
            &genesis,
            &successor,
        )
        .map_err(|_| BootstrapError::Invalid("retained AMX G1/H2 authentication failed"))?;
        Ok(original)
    }

    fn chain_id(&self) -> Result<ChainId> {
        self.identity
            .chain_id
            .parse()
            .map_err(|_| BootstrapError::Invalid("invalid retained AMX chain"))
    }

    fn read_pair(&self) -> Result<OriginalPair> {
        if self.directory.entries(3)? != [G1, H2, RECORD].map(std::ffi::OsString::from) {
            return Err(BootstrapError::Invalid(
                "original AMX capsule file inventory changed",
            ));
        }
        // Original descriptors keep same-byte pathname replacement distinguishable from reuse.
        // PrivateDirectory::read additionally checks per-read extent/content/native custody.
        for original in &self.originals {
            // DEP2 restores equality-only custody of a replaced original inode.
            if !cfg!(all(test, sumeragi_deploy_mutation = "DEP2")) {
                original.revalidate()?;
            }
        }
        let genesis = self.directory.read(G1, SIGNED_GENESIS_MAX_BYTES_V1)?;
        let successor = self.directory.read(
            H2,
            iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
        )?;
        let current: Identity = decode(&self.directory.read(RECORD, MAX_RECORD)?, MAX_RECORD)?;
        if current.network_name != self.identity.network_name
            || current.generation != self.identity.generation
            || current.network_id != self.identity.network_id
            || current.chain_id != self.identity.chain_id
            || current.genesis_hash != self.identity.genesis_hash
            || current.successor_hash != self.identity.successor_hash
            || current.directory_identity != self.identity.directory_identity
            || current.genesis_identity != self.identity.genesis_identity
            || current.successor_identity != self.identity.successor_identity
            || Hash::new(&genesis) != self.identity.genesis_hash
            || Hash::new(&successor) != self.identity.successor_hash
        {
            return Err(BootstrapError::Invalid(
                "original AMX source files were substituted",
            ));
        }
        for original in &self.originals {
            // DEP2 restores equality-only custody of a replaced original inode.
            if !cfg!(all(test, sumeragi_deploy_mutation = "DEP2")) {
                original.revalidate()?;
            }
        }
        self.directory.revalidate()?;
        Ok((genesis, successor))
    }

    // Local native identities are checked against the originally published private record.
    // This checks ordinary object/metadata replacement across reopen under honest native
    // filesystem/clock and private-record custody. IDs/timestamps are not non-reusable across
    // closed handles; the record is neither crypto authority nor a defense against its owner
    // replacing all local anchors. Live reads retain the separate DEP2 descriptor fences.
    #[cfg(not(all(test, sumeragi_deploy_mutation = "DEP5")))]
    fn require_original_local_objects(&self) -> Result<()> {
        if self.directory.identity()?.local_parts() != self.identity.directory_identity
            || FileSnapshot::of(self.originals[1].file(), true)?.local_parts()
                != self.identity.genesis_identity
            || FileSnapshot::of(self.originals[2].file(), true)?.local_parts()
                != self.identity.successor_identity
        {
            return Err(BootstrapError::Invalid(
                "AMX source objects differ from their original local publication",
            ));
        }
        Ok(())
    }

    /// Move the exact retained input frames into one original fresh manifest before signing.
    pub(crate) fn append_to(
        &self,
        manifest: RawGenesisTransaction,
    ) -> Result<RawGenesisTransaction> {
        let (mut genesis, mut successor) = self.read_pair()?;
        crate::genesis::amx::append_amx_participant(
            manifest,
            self.chain_id()?,
            std::mem::take(&mut *genesis),
            std::mem::take(&mut *successor),
        )
        .map_err(|_| {
            BootstrapError::Invalid(
                "cannot assemble original AMX participant before private signing",
            )
        })
    }

    /// A retained signed generation must already contain exactly the same original pair.
    /// This verifies source equality only; existing signed-genesis validation remains mandatory.
    pub(crate) fn require_signed_generation(
        &self,
        prepared: &crate::managed::PreparedLocalnet,
    ) -> Result<()> {
        let root = prepared
            .context
            .client_config
            .parent()
            .ok_or(BootstrapError::Invalid(
                "private generation has no original source directory",
            ))?;
        let directory = PrivateDirectory::open(root)?;
        let bytes = directory.read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)?;
        let block = iroha_genesis::decode_signed_genesis(&bytes).map_err(|_| {
            BootstrapError::Invalid("cannot read original signed AMX private generation")
        })?;
        let metadata = iroha_genesis::signed_genesis_consensus_metadata(&block)
            .map_err(|_| BootstrapError::Invalid("invalid signed AMX private-root context"))?;
        if metadata.sumeragi_context.root_scope
            != (iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                parent_network_id: self.identity.network_id,
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(
                    prepared.context.dataspace_id,
                ),
            })
        {
            return Err(BootstrapError::Invalid(
                "signed AMX generation differs from the selected parent and private scope",
            ));
        }
        let (genesis, successor) = self.read_pair()?;
        let mut selected = None;
        for transaction in block.external_transactions() {
            for instruction in transaction.instructions().explicit_instructions() {
                if let Some(registration) = instruction
                    .as_any()
                    .downcast_ref::<RegisterAmxParticipantV1>()
                {
                    if selected.is_some() {
                        return Err(BootstrapError::Invalid(
                            "private generation repeats AMX participant registration",
                        ));
                    }
                    selected = Some(registration);
                }
            }
        }
        let registration = selected.ok_or(BootstrapError::Invalid(
            "published private generation omitted AMX participant",
        ))?;
        if registration.dataspace.as_u64() != prepared.context.dataspace_id
            || registration.global_chain_id != self.chain_id()?
            || registration.global_genesis.as_slice() != genesis.as_slice()
            || registration.global_successor.as_slice() != successor.as_slice()
        {
            return Err(BootstrapError::Invalid(
                "published private generation changed original AMX sources",
            ));
        }
        Ok(())
    }
}

fn unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(BootstrapError::Invalid("AMX source clock is unavailable"))
}

#[cfg(test)]
mod tests;
