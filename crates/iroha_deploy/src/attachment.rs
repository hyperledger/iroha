//! Durable public attachment receipts, separate from private execution and transaction dispatch.
//!
//! Only independently verified parent ordinary-write proofs advance this store. A successful
//! HTTP submission, an `Applied` status, or a valid child certificate alone cannot establish
//! parent anchoring. The wallet operation journal separately retains every exact fee-paying
//! transaction and its pre-dispatch marker. No child body or owner credential enters this store.

use std::{
    fs::File,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::consensus::SumeragiRootScope,
    isi::private_dataspace::{AnchorPrivateDataspace, RegisterPrivateDataspace},
    private_dataspace::{
        MAX_PRIVATE_DATASPACE_ANCHOR_BYTES, MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
        PrivateDataspaceAnchor, PrivateDataspaceAnchorError, PrivateDataspaceAnchorOutcome,
        PrivateDataspaceCursor, PrivateDataspaceRecordProof, PrivateDataspaceRegistration,
    },
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
    sumeragi_finality::SumeragiFinalityCheckpoint,
};
use iroha_fs::{FileIdentity, OwnerDirectory, PrivateDirectory, PublishMode};
use iroha_model_base::topology::DataSpaceId;
use norito::{Decode, Encode};

use crate::{
    bootstrap::{AuthenticatedBootstrap, ParentFinalityStore},
    verify::finality::{FinalityError, FinalityVerifier},
};

mod amx_registration;
pub use amx_registration::{AmxRegistrationFinality, AmxRegistrationProgress};
mod operations;
mod relay;
mod replay;
pub use operations::AttachmentProgress;
pub use relay::{LocalPrivateRootSource, PrivateRootSource, RelayParent, RelayProgress};

// A developer context retains multiple independent verification checkpoints. Bound their
// aggregate custody rather than multiplying each protocol envelope's maximum allocation.
const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

/// A custody, identity or independently verified attachment failure.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// Native private custody or durable publication failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The exact selected attachment or retained proof changed.
    #[error("private attachment: {0}")]
    Invalid(&'static str),
    /// Native compact child or parent-inclusion verification failed.
    #[error(transparent)]
    Proof(#[from] PrivateDataspaceAnchorError),
    /// The independently selected parent's certified chain failed verification.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// Fresh parent observation or durable checkpoint publication failed.
    #[error(transparent)]
    Bootstrap(#[from] crate::bootstrap::BootstrapError),
    /// Original administrative carrier or durable native operation validation failed.
    #[error(transparent)]
    NativeOperation(#[from] crate::managed::Error),
    /// An exact wallet or SDK operation could not be completed; details stay in its private journal.
    #[error("private attachment: {0}")]
    Operation(&'static str),
    /// The original owner cancelled preparation of any new parent operation.
    #[error("private attachment: operation cancelled")]
    Cancelled,
}

type Result<T> = std::result::Result<T, AttachmentError>;

/// Exact locally retained child identity and parent lease selected for one attachment.
///
/// The registration must come from the retained signed private genesis and its actual execution,
/// not from an untrusted first HTTP response. The parent independently enforces the named owner,
/// ownership generation and active SNS lease when processing the native registration instruction.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::AttachmentIdentityV1")]
pub struct AttachmentIdentity {
    parent_name: String,
    parent_generation: u64,
    parent_network_id: NetworkId,
    parent_chain_id: String,
    alias: String,
    owner: AccountId,
    ownership_generation: u64,
    registration: PrivateDataspaceRegistration,
}

impl AttachmentIdentity {
    /// Bind a retained private root to an independently authenticated parent release and lease.
    ///
    /// # Errors
    /// Rejects a foreign parent, malformed child, noncanonical alias, incorrect full-width SNS
    /// identity, universal namespace or zero ownership generation.
    pub fn new(
        parent: &AuthenticatedBootstrap,
        alias: String,
        owner: AccountId,
        ownership_generation: u64,
        registration: PrivateDataspaceRegistration,
    ) -> Result<Self> {
        let release = parent.release();
        let result = Self {
            parent_name: release.network_name.clone(),
            parent_generation: release.generation,
            parent_network_id: release.network_id,
            parent_chain_id: release.chain_id.clone(),
            alias,
            owner,
            ownership_generation,
            registration,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        self.registration.validate()?;
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, &self.alias)
            .map_err(|_| AttachmentError::Invalid("invalid SNS alias"))?;
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: self.parent_network_id,
            dataspace_id: DataSpaceId::from_hash(&selector.name_hash()),
        };
        if self.alias == "universal"
            || selector.normalized_label() != self.alias
            || self.registration.scope != scope
            || self.ownership_generation == 0
            || self.parent_generation == 0
            || self.parent_chain_id.is_empty()
            || self.parent_name.is_empty()
        {
            return Err(AttachmentError::Invalid(
                "child, parent and SNS lease binding differs",
            ));
        }
        encode_bounded(&self.registration, MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES)?;
        Ok(())
    }

    /// Immutable child identity whose exact public projection may cross the parent boundary.
    pub fn registration(&self) -> &PrivateDataspaceRegistration {
        &self.registration
    }

    /// Exact full-width parent SNS identifier.
    pub fn dataspace_id(&self) -> DataSpaceId {
        self.registration.scope.dataspace_id()
    }
}

#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::ConfirmedParentReceiptV1")]
struct ConfirmedReceipt {
    checkpoint: Vec<u8>,
    proof: PrivateDataspaceRecordProof,
}

#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::AttachmentRecordV1")]
struct Record {
    identity: AttachmentIdentity,
    confirmed: Option<ConfirmedReceipt>,
    pending: Option<operations::PendingOperation>,
}

/// Historical parent anchoring fact. This says nothing about the child's current local tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedAnchor {
    /// Certified parent block that wrote this public record.
    pub parent_height: u64,
    /// Exact child decision authenticated by that parent record.
    pub child: PrivateDataspaceCursor,
}

/// One exclusive attachment cursor advanced only by verified parent inclusion evidence.
pub struct AttachmentStore {
    directory: PrivateDirectory,
    lock: File,
    record: Record,
    publication_uncertain: bool,
    cancellation: Option<Arc<AtomicBool>>,
}

impl AttachmentStore {
    /// Initialize an exact attachment or reopen it without replacing incomplete/corrupt custody.
    ///
    /// # Errors
    /// Invalid identity, competing owner, missing lock/record, changed selected attachment or
    /// invalid retained native parent proof. A parent reset always requires another context.
    pub fn open(path: &Path, identity: AttachmentIdentity) -> Result<Self> {
        identity.validate()?;
        let name = path
            .file_name()
            .ok_or(AttachmentError::Invalid("attachment path"))?;
        let parent = OwnerDirectory::open_or_create(
            path.parent()
                .ok_or(AttachmentError::Invalid("attachment path"))?,
        )?;
        let initial_record = Record {
            identity: identity.clone(),
            confirmed: None,
            pending: None,
        };
        let initial = record_bytes(&initial_record)?;
        let (directory, created) = match parent
            .publish_private_child(name, &[("lock", &[]), ("attachment.nrt", &initial)])
        {
            Ok(directory) => (directory, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                (PrivateDirectory::open(parent.path().join(name))?, false)
            }
            Err(error) => return Err(error.into()),
        };
        let lock = directory.open_existing_lock("lock")?;
        lock.try_lock()
            .map_err(|_| AttachmentError::Invalid("attachment custody already in use"))?;
        lock.sync_all()?;
        directory.sync()?;
        let record = if created {
            initial_record
        } else {
            let bytes = directory.read("attachment.nrt", MAX_RECORD_BYTES)?;
            let record: Record = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .map_err(|_| AttachmentError::Invalid("invalid retained attachment"))?;
            if record.identity != identity {
                return Err(AttachmentError::Invalid(
                    "retained attachment differs from selected identity",
                ));
            }
            if let Some(receipt) = &record.confirmed {
                validate_retained_receipt(&record.identity, receipt)?;
            }
            if let Some(pending) = &record.pending {
                pending.validate(&record.identity)?;
            }
            record
        };
        let result = Self {
            directory,
            lock,
            record,
            publication_uncertain: false,
            cancellation: None,
        };
        Ok(result)
    }

    /// Bind all parent wallet operations to the same original supervisor cancellation signal.
    pub(crate) fn bind_cancellation(&mut self, cancellation: Arc<AtomicBool>) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|original| !Arc::ptr_eq(original, &cancellation))
        {
            return Err(AttachmentError::Invalid(
                "attachment cancellation owner changed",
            ));
        }
        self.cancellation = Some(cancellation);
        Ok(())
    }

    fn require_active(&self) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            return Err(AttachmentError::Cancelled);
        }
        Ok(())
    }

    /// Exact selected local child and parent lease.
    pub fn identity(&self) -> &AttachmentIdentity {
        &self.record.identity
    }

    /// Last durably confirmed parent anchoring fact; `None` means registration is unconfirmed.
    pub fn confirmed(&self) -> Option<ConfirmedAnchor> {
        self.record
            .confirmed
            .as_ref()
            .map(|receipt| ConfirmedAnchor {
                parent_height: receipt.proof.parent_height,
                child: receipt.proof.record.anchor.cursor(),
            })
    }

    /// Parent-authenticated child tracker for preparing the next exact wallet anchor operation.
    /// This immutable view grants no fresh lease or current local-tip claim.
    pub fn confirmed_child_state(
        &self,
    ) -> Option<&iroha_data_model::private_dataspace::PrivateDataspaceAnchorState> {
        self.record
            .confirmed
            .as_ref()
            .map(|receipt| &receipt.proof.record.anchor)
    }

    /// Prepare only the compact native registration when no parent receipt is retained yet.
    /// The caller quotes and journals this exact instruction before its sole dispatch.
    ///
    /// # Errors
    /// Invalid custody or an already confirmed registration. No transaction is dispatched here.
    pub fn registration_instruction(&self) -> Result<RegisterPrivateDataspace> {
        self.revalidate()?;
        if self.record.confirmed.is_some() {
            return Err(AttachmentError::Invalid(
                "registration is already parent-confirmed",
            ));
        }
        Ok(RegisterPrivateDataspace {
            alias: self.record.identity.alias.clone(),
            expected_ownership_generation: self.record.identity.ownership_generation,
            registration: encode_bounded(
                &self.record.identity.registration,
                MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
            )?,
        })
    }

    /// Verify the next genuine child decision before constructing its compact parent instruction.
    /// Exact replay of the already confirmed cursor returns `None` and incurs no new fee.
    /// Preparing this instruction does not advance the confirmed parent cursor.
    ///
    /// # Errors
    /// Unconfirmed registration, invalid custody, foreign authority, history gap or invalid QC.
    pub fn anchor_instruction(
        &self,
        anchor: &PrivateDataspaceAnchor,
    ) -> Result<Option<AnchorPrivateDataspace>> {
        self.revalidate()?;
        let receipt = self
            .record
            .confirmed
            .as_ref()
            .ok_or(AttachmentError::Invalid(
                "registration has no authenticated parent receipt",
            ))?;
        let mut state = receipt.proof.record.anchor.clone();
        if state.apply(anchor)? == PrivateDataspaceAnchorOutcome::AlreadyAnchored {
            return Ok(None);
        }
        Ok(Some(AnchorPrivateDataspace {
            dataspace_id: self.record.identity.dataspace_id(),
            anchor: encode_bounded(anchor, MAX_PRIVATE_DATASPACE_ANCHOR_BYTES)?,
        }))
    }

    /// Authenticate one original parent write against the independently advancing parent store,
    /// then durably retain the receipt before reporting anchoring. The parent store must be at
    /// this exact carrier height; retain operation checkpoints before advancing beyond a carrier.
    ///
    /// # Errors
    /// Wrong identity, native inclusion failure, regressed/forked cursor or uncertain publication.
    /// An error never reports a newly anchored child decision.
    pub fn confirm_record(
        &mut self,
        proof: PrivateDataspaceRecordProof,
        parent: &ParentFinalityStore,
    ) -> Result<ConfirmedAnchor> {
        if parent.network_name() != self.record.identity.parent_name
            || parent.generation() != self.record.identity.parent_generation
        {
            return Err(AttachmentError::Invalid(
                "parent reset generation differs from attachment",
            ));
        }
        self.confirm_with_verifier(proof, parent.verifier())
    }

    fn confirm_with_verifier(
        &mut self,
        proof: PrivateDataspaceRecordProof,
        parent: &FinalityVerifier,
    ) -> Result<ConfirmedAnchor> {
        self.publish_confirmation(proof, parent, false)
    }

    fn confirm_completed_operation(
        &mut self,
        proof: PrivateDataspaceRecordProof,
        parent: &FinalityVerifier,
    ) -> Result<ConfirmedAnchor> {
        let target = self
            .record
            .pending
            .as_ref()
            .ok_or(AttachmentError::Invalid(
                "no retained parent operation to complete",
            ))?
            .target(&self.record.identity)?;
        let cursor = proof.record.anchor.cursor();
        if cursor.height < target.height || (cursor.height == target.height && cursor != target) {
            return Err(AttachmentError::Invalid(
                "parent record does not fulfill the retained operation",
            ));
        }
        self.publish_confirmation(proof, parent, true)
    }

    fn publish_confirmation(
        &mut self,
        proof: PrivateDataspaceRecordProof,
        parent: &FinalityVerifier,
        complete_pending: bool,
    ) -> Result<ConfirmedAnchor> {
        self.revalidate()?;
        let identity = &self.record.identity;
        if parent.checkpoint().network_id() != identity.parent_network_id
            || parent.checkpoint().chain_id() != identity.parent_chain_id
        {
            return Err(AttachmentError::Invalid(
                "parent verifier differs from attachment",
            ));
        }
        proof.verify(identity.dataspace_id(), &parent.verified_tip()?)?;
        validate_record_identity(identity, &proof)?;
        if let Some(previous) = &self.record.confirmed {
            if previous.proof.parent_height == proof.parent_height {
                let retained = SumeragiFinalityCheckpoint::decode_canonical(&previous.checkpoint)
                    .map_err(|_| {
                    AttachmentError::Invalid("invalid retained parent checkpoint")
                })?;
                if retained.block_hash() != parent.checkpoint().block_hash()
                    || previous.proof.parent_result != proof.parent_result
                {
                    return Err(AttachmentError::Invalid(
                        "parent equivocated at the retained carrier",
                    ));
                }
            }
        }
        let next = ConfirmedAnchor {
            parent_height: proof.parent_height,
            child: proof.record.anchor.cursor(),
        };
        if let Some(previous) = self.confirmed() {
            if next.parent_height < previous.parent_height
                || next.child.height < previous.child.height
                || (next.child.height == previous.child.height && next.child != previous.child)
                || (next.parent_height == previous.parent_height && next != previous)
            {
                return Err(AttachmentError::Invalid(
                    "parent receipt regresses or forks retained progress",
                ));
            }
        }
        let receipt = ConfirmedReceipt {
            checkpoint: parent
                .checkpoint()
                .encode_canonical()
                .map_err(|_| AttachmentError::Invalid("cannot encode parent receipt checkpoint"))?,
            proof,
        };
        let next_record = Record {
            identity: identity.clone(),
            confirmed: Some(receipt),
            pending: if complete_pending {
                None
            } else {
                self.record.pending.clone()
            },
        };
        self.publish(&next_record, PublishMode::Replace)?;
        self.record = next_record;
        Ok(next)
    }

    fn revalidate(&self) -> Result<()> {
        if self.publication_uncertain {
            return Err(AttachmentError::Invalid(
                "attachment publication uncertain; reopen custody",
            ));
        }
        self.directory.revalidate()?;
        if FileIdentity::of(&self.directory.open_read("lock")?)? != FileIdentity::of(&self.lock)? {
            return Err(AttachmentError::Invalid("attachment lock was replaced"));
        }
        Ok(())
    }

    fn publish(&mut self, record: &Record, mode: PublishMode) -> Result<()> {
        self.revalidate()?;
        let bytes = record_bytes(record)?;
        if let Err(error) = self.directory.write_atomic("attachment.nrt", &bytes, mode) {
            self.publication_uncertain = true;
            return Err(error.into());
        }
        Ok(())
    }
}

fn record_bytes(record: &Record) -> Result<Vec<u8>> {
    let bytes = encode_bounded(record, MAX_RECORD_BYTES)?;
    // Use the exact reopen decoder before either initial directory or later record publication.
    let _: Record =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .map_err(|_| AttachmentError::Invalid("attachment record exceeds reopen policy"))?;
    Ok(bytes)
}

fn validate_record_identity(
    identity: &AttachmentIdentity,
    proof: &PrivateDataspaceRecordProof,
) -> Result<()> {
    let record = &proof.record;
    if proof.parent_network_id != identity.parent_network_id
        || record.dataspace_id != identity.dataspace_id()
        || record.alias != identity.alias
        || record.owner != identity.owner
        || record.ownership_generation != identity.ownership_generation
        || record.anchor.registration() != &identity.registration
    {
        return Err(AttachmentError::Invalid(
            "parent record substituted the selected attachment",
        ));
    }
    Ok(())
}

fn validate_retained_receipt(
    identity: &AttachmentIdentity,
    receipt: &ConfirmedReceipt,
) -> Result<()> {
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&receipt.checkpoint)
        .map_err(|_| AttachmentError::Invalid("invalid retained receipt checkpoint"))?;
    let parent = FinalityVerifier::from_checkpoint(
        checkpoint,
        identity.parent_network_id,
        &identity.parent_chain_id,
    )?;
    receipt
        .proof
        .verify(identity.dataspace_id(), &parent.verified_tip()?)?;
    validate_record_identity(identity, &receipt.proof)
}

fn encode_bounded<T: norito::NoritoSerialize>(value: &T, bound: usize) -> Result<Vec<u8>> {
    let bytes = norito::encode_canonical(value)
        .map_err(|_| AttachmentError::Invalid("cannot encode attachment record"))?;
    if bytes.len() > bound {
        return Err(AttachmentError::Invalid(
            "attachment record exceeds its bound",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
