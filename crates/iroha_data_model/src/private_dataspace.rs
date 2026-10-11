//! Opaque private-root anchors, independently of AMX transactions or monetary settlement.
//!
//! A parent authenticates an owner-authorized registration of the exact child genesis, root
//! scope and initial committee. It does not replay that private genesis. Subsequent anchors
//! reuse the native AMX foreign-committee verifier, then extend one contiguous decision cursor.
//! Only roots, counts and public consensus credentials cross this boundary; full block wires,
//! genesis wires, transactions, execution writes and contract artifacts stay on the child.
//!
//! This first developer profile is permissioned with four fixed validators. Its sole epoch extends
//! through `u64::MAX`; changing credentials requires an explicit governed registration change.
//! It rejects beacon/application control demands, including Permissioned Parliament pulses;
//! the private runtime must exclude those demands before this profile can anchor every block.
//! Parent admission binds the registry to active SNS ownership and chain policy. Core persists it
//! as canonical World state and certified ordinary writes. TODO: Complete private-node export,
//! relaying and complete runtime qualification; component verification does not establish network privacy.

use iroha_model_base::{chain::ChainId, topology::DataSpaceId};
use iroha_schema::IntoSchema;
use iroha_sumeragi::message::{BlockHeader as CoreHeader, Qc};
use norito::codec::{Decode, Encode};

mod proof;
mod registry;
pub use proof::{MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES, PrivateDataspaceRecordProof};
pub use registry::{
    MAX_PRIVATE_DATASPACE_ROOTS, PrivateDataspaceAdmissionPolicy, PrivateDataspaceRecord,
    PrivateDataspaceRegistry, private_dataspace_record_witness_key,
};

use crate::{
    NetworkId,
    block::{CommitCertificate, consensus::SumeragiRootScope},
    parameter::system::ConsensusMode,
    sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_amx::{
        AmxCertifiedBlockV1, AmxForeignInstanceV1, MAX_AMX_HEADER_BYTES, MAX_AMX_QC_BYTES,
    },
    sumeragi_finality::{
        ExecutionResultCommitment, FinalityValidator, MAX_RESULT_PREIMAGE_BYTES, ProofCrypto,
        ScheduledSlot,
    },
};

/// Maximum complete canonical anchor envelope, including the three bounded certificate parts.
pub const MAX_PRIVATE_DATASPACE_ANCHOR_BYTES: usize =
    MAX_AMX_HEADER_BYTES + MAX_AMX_QC_BYTES + MAX_RESULT_PREIMAGE_BYTES + 4096;

/// Maximum complete canonical owner-registration envelope for the fixed four-validator profile.
pub const MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES: usize = 32 * 1024;

/// Why a private-root registration or certified extension was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("private dataspace anchor: {0}")]
pub struct PrivateDataspaceAnchorError(pub String);

fn require(condition: bool, reason: &'static str) -> Result<(), PrivateDataspaceAnchorError> {
    if condition {
        Ok(())
    } else {
        Err(PrivateDataspaceAnchorError(reason.into()))
    }
}
fn failure(error: impl std::fmt::Display) -> PrivateDataspaceAnchorError {
    PrivateDataspaceAnchorError(error.to_string())
}

/// One exact decision in a private root's contiguous certified history.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceCursor")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceCursor {
    /// Child height; signed genesis is height one.
    pub height: u64,
    /// Core consensus hash, equal to the signed genesis hash at height one.
    pub consensus_hash: [u8; 32],
    /// Canonical execution-result commitment `R`.
    pub result: [u8; 32],
}

/// Exact owner-authorized parent trust record. Decoding this record grants no authority.
///
/// Parent admission must authorize the dataspace owner and bind this entire record atomically.
/// The registered initial result is owner-authorized; the first genuine successor certificate
/// independently authenticates it through `parent_result`. No private genesis wire is required.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceRegistration")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceRegistration {
    /// Genesis-bound parent network and full-width dataspace identity.
    pub scope: SumeragiRootScope,
    /// Exact canonical child chain label used in native instance derivation.
    pub child_chain_id: ChainId,
    /// Exact signed private genesis commitment, also the child network identity.
    pub child_network_id: NetworkId,
    /// Dataspace root instance, derived from child genesis, child chain and root index zero.
    pub instance: [u8; 32],
    /// Original genesis decision, before any ordinary anchor has been received.
    pub genesis_cursor: PrivateDataspaceCursor,
    /// Original four-validator epoch and exact BLS proofs of possession.
    pub initial_epoch: ValidatorEpochContextV1,
}

impl PrivateDataspaceRegistration {
    /// Decode a bounded canonical registration without granting parent authorization.
    ///
    /// # Errors
    /// Rejects excessive allocation demands, malformed wire data or inconsistent authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateDataspaceAnchorError> {
        require(
            bytes.len() <= MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
            "registration exceeds its wire bound",
        )?;
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            part_limits(MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES),
        )
        .map_err(failure)?;
        value.validate()?;
        Ok(value)
    }

    /// Construct a registration to be authorized by the parent dataspace owner.
    ///
    /// # Errors
    /// Rejects a global or universal scope, foreign context, or unsupported committee profile.
    pub fn new(
        scope: SumeragiRootScope,
        child_chain_id: ChainId,
        child_network_id: NetworkId,
        genesis_result: [u8; 32],
        initial_epoch: ValidatorEpochContextV1,
    ) -> Result<Self, PrivateDataspaceAnchorError> {
        let instance = private_instance(scope, child_network_id, &child_chain_id, &initial_epoch)?;
        let value = Self {
            scope,
            child_chain_id,
            child_network_id,
            instance,
            genesis_cursor: PrivateDataspaceCursor {
                height: 1,
                consensus_hash: *child_network_id.as_bytes(),
                result: genesis_result,
            },
            initial_epoch,
        };
        value.validate()?;
        Ok(value)
    }

    /// Check structural and cryptographic consistency; this does not authorize registration.
    ///
    /// # Errors
    /// Rejects wrong network/scope, genesis cursor, instance, epoch or committee credentials.
    pub fn validate(&self) -> Result<(), PrivateDataspaceAnchorError> {
        let (parent, dataspace) = self.parent_scope()?;
        require(
            parent != self.child_network_id,
            "child and parent network are equal",
        )?;
        require(
            dataspace != DataSpaceId::UNIVERSAL,
            "private dataspace cannot be universal",
        )?;
        require(
            self.genesis_cursor.height == 1
                && self.genesis_cursor.consensus_hash == *self.child_network_id.as_bytes()
                && self.genesis_cursor.result != [0; 32],
            "genesis cursor differs from the signed child genesis commitment",
        )?;
        self.initial_epoch.validate().map_err(failure)?;
        require(
            self.initial_epoch.network_id == self.child_network_id
                && self.initial_epoch.authorization.epoch == 0
                && self.initial_epoch.authorization.first_height == 1
                && self.initial_epoch.authorization.last_height == u64::MAX,
            "initial epoch is not the child genesis epoch",
        )?;
        self.fixed_context(&self.initial_epoch)?;
        require(
            self.instance
                == private_instance(
                    self.scope,
                    self.child_network_id,
                    &self.child_chain_id,
                    &self.initial_epoch,
                )?,
            "private root instance differs from its genesis and chain",
        )
    }

    fn parent_scope(&self) -> Result<(NetworkId, DataSpaceId), PrivateDataspaceAnchorError> {
        match self.scope {
            SumeragiRootScope::Dataspace {
                parent_network_id,
                dataspace_id,
            } => Ok((parent_network_id, dataspace_id)),
            SumeragiRootScope::Global => Err(PrivateDataspaceAnchorError(
                "global scope is not a private root".into(),
            )),
        }
    }

    fn fixed_context(
        &self,
        context: &ValidatorEpochContextV1,
    ) -> Result<(), PrivateDataspaceAnchorError> {
        require(
            context.mode == ConsensusMode::Permissioned
                && context.network_id == self.child_network_id
                && context.committee.len() == 4
                && context == &self.initial_epoch,
            "private root requires its registered permissioned four-validator authority",
        )
    }
}

fn private_instance(
    scope: SumeragiRootScope,
    network: NetworkId,
    chain: &ChainId,
    epoch: &ValidatorEpochContextV1,
) -> Result<[u8; 32], PrivateDataspaceAnchorError> {
    require(
        epoch.committee.len() == 4,
        "private developer roots require exactly four validators",
    )?;
    let validators: Vec<_> = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let (crypto, _) = ProofCrypto::new(&validators).map_err(failure)?;
    Ok(scope
        .instance_id(&crypto, network, chain.as_str())
        .map_err(failure)?
        .0)
}

/// Bounded public envelope containing only a native compact certificate.
///
/// No full-block, genesis, artifact, transaction or execution-write field exists in this type.
/// Hashes and counts still expose consensus activity and are not zero-knowledge evidence.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceAnchor")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceAnchor {
    /// Exact registered parent network.
    pub parent_network_id: NetworkId,
    /// Exact registered full-width private dataspace.
    pub dataspace_id: DataSpaceId,
    /// Exact registered child genesis commitment.
    pub child_network_id: NetworkId,
    /// Native header, `CommitQC` and canonical execution-result commitment only.
    pub certificate: AmxCertifiedBlockV1,
}

impl PrivateDataspaceAnchor {
    /// Project an already locally verified native certificate without exporting its block body.
    /// This bounds and validates the public projection; parent admission still verifies its QC.
    ///
    /// # Errors
    /// Rejects unsupported private-root controls, malformed or oversized certificate parts.
    pub fn from_certificate(
        registration: &PrivateDataspaceRegistration,
        certificate: &CommitCertificate,
    ) -> Result<Self, PrivateDataspaceAnchorError> {
        registration.validate()?;
        // Bound borrowed parts before allocating the owned public envelope.
        bounds(
            certificate.consensus_header(),
            certificate.commit_qc(),
            certificate.result_preimage(),
        )?;
        let (parent_network_id, dataspace_id) = registration.parent_scope()?;
        let anchor = Self {
            parent_network_id,
            dataspace_id,
            child_network_id: registration.child_network_id,
            certificate: AmxCertifiedBlockV1::from_certificate(certificate),
        };
        let (header, result) = anchor.public_parts()?;
        require(
            header.instance.0 == registration.instance,
            "exported certificate belongs to another private root",
        )?;
        registration.fixed_context(&result.schedule.current)?;
        Ok(anchor)
    }

    /// Decode one bounded canonical anchor; decoded bytes do not confer finality authority.
    ///
    /// # Errors
    /// Refuses trailing data, oversized allocation demands and private-body/control witnesses.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateDataspaceAnchorError> {
        require(
            bytes.len() <= MAX_PRIVATE_DATASPACE_ANCHOR_BYTES,
            "anchor exceeds its wire bound",
        )?;
        let anchor: Self = norito::decode_canonical_with_limits(
            bytes,
            part_limits(MAX_PRIVATE_DATASPACE_ANCHOR_BYTES),
        )
        .map_err(failure)?;
        anchor.public_parts()?;
        Ok(anchor)
    }

    /// Read the bounded public header's claimed height without authenticating its certificate.
    ///
    /// # Errors
    /// Rejects malformed or oversized public parts and private-body/control witnesses.
    pub fn height(&self) -> Result<u64, PrivateDataspaceAnchorError> {
        Ok(self.public_parts()?.0.height)
    }

    fn public_parts(
        &self,
    ) -> Result<(CoreHeader, ExecutionResultCommitment), PrivateDataspaceAnchorError> {
        let block = &self.certificate;
        bounds(
            &block.consensus_header,
            &block.commit_qc,
            &block.result_preimage,
        )?;
        let header: CoreHeader = norito::decode_canonical_with_limits(
            &block.consensus_header,
            part_limits(MAX_AMX_HEADER_BYTES),
        )
        .map_err(failure)?;
        let _: Qc =
            norito::decode_canonical_with_limits(&block.commit_qc, part_limits(MAX_AMX_QC_BYTES))
                .map_err(failure)?;
        let result = ExecutionResultCommitment::decode(&block.result_preimage).map_err(failure)?;
        require(
            header.control_witness.is_empty() && result.beacon.is_none(),
            "private developer anchors cannot export application control witnesses",
        )?;
        Ok((header, result))
    }
}

fn part_limits(maximum: usize) -> norito::DecodeLimits {
    // Byte vectors (including the 96-byte BLS PoPs and certificate parts) consume sequence
    // elements too. The wire and total allocation bounds constrain them independently.
    norito::DecodeLimits::new(maximum, maximum, maximum, maximum * 4, 128)
}

fn bounds(header: &[u8], qc: &[u8], result: &[u8]) -> Result<(), PrivateDataspaceAnchorError> {
    require(
        !header.is_empty()
            && header.len() <= MAX_AMX_HEADER_BYTES
            && !qc.is_empty()
            && qc.len() <= MAX_AMX_QC_BYTES
            && !result.is_empty()
            && result.len() <= MAX_RESULT_PREIMAGE_BYTES,
        "certificate parts are empty or exceed their bounds",
    )
}

/// Result of an authenticated parent anchor admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateDataspaceAnchorOutcome {
    /// Exactly the next child decision was appended.
    Advanced,
    /// The current tip decision was independently reverified; no state changed.
    AlreadyAnchored,
}

/// Parent-owned contiguous child history, persisted only inside authenticated parent state.
///
/// A decoded state is not a trust root. Restore it only from verified parent World state;
/// accepting arbitrary serialized state would bypass owner registration and certified history.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceAnchorState")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceAnchorState {
    registration: PrivateDataspaceRegistration,
    tracker: AmxForeignInstanceV1,
    cursor: PrivateDataspaceCursor,
}

impl PrivateDataspaceAnchorState {
    /// Start from the complete registration independently authorized by the parent owner.
    ///
    /// # Errors
    /// Rejects structurally inconsistent registration or invalid original committee credentials.
    pub fn from_authorized_registration(
        registration: PrivateDataspaceRegistration,
    ) -> Result<Self, PrivateDataspaceAnchorError> {
        registration.validate()?;
        let tracker =
            AmxForeignInstanceV1::new(registration.instance, registration.initial_epoch.clone())
                .map_err(failure)?;
        let cursor = registration.genesis_cursor;
        Ok(Self {
            registration,
            tracker,
            cursor,
        })
    }

    /// Validate structural invariants when restoring authenticated parent World state.
    ///
    /// This checks the retained trust record, fixed committee and contiguous cursor shape.
    /// It does not authenticate a standalone snapshot or replay old certificates.
    ///
    /// # Errors
    /// Rejects a substituted tracker, unsupported handoff, or malformed genesis/tip cursor.
    pub fn validate(&self) -> Result<(), PrivateDataspaceAnchorError> {
        self.registration.validate()?;
        self.tracker.validate().map_err(failure)?;
        require(
            self.tracker.instance == self.registration.instance && self.tracker.previous.is_none(),
            "tracker differs from the registered fixed private root",
        )?;
        self.registration.fixed_context(&self.tracker.current)?;
        require(
            self.cursor.height >= 1
                && self.cursor.consensus_hash != [0; 32]
                && self.cursor.result != [0; 32],
            "retained private cursor has invalid height or empty commitments",
        )?;
        require(
            self.cursor.height != 1 || self.cursor == self.registration.genesis_cursor,
            "height-one cursor differs from the registered genesis",
        )
    }

    /// The exact owner-authorized registration whose immutable binding this state follows.
    #[must_use]
    pub fn registration(&self) -> &PrivateDataspaceRegistration {
        &self.registration
    }

    /// Highest accepted contiguous decision; height one is the owner-authorized genesis cursor.
    #[must_use]
    pub fn cursor(&self) -> PrivateDataspaceCursor {
        self.cursor
    }

    /// Verify and atomically append one opaque native decision of the fixed registered epoch.
    /// Failed validation leaves the tracker and cursor unchanged. Exact tip replay is idempotent;
    /// older proofs, gaps, parent mismatches and same-height conflicting decisions are rejected.
    ///
    /// # Errors
    /// Refuses another parent, dataspace, child, malformed proof, invalid quorum or discontinuity.
    pub fn apply(
        &mut self,
        anchor: &PrivateDataspaceAnchor,
    ) -> Result<PrivateDataspaceAnchorOutcome, PrivateDataspaceAnchorError> {
        self.validate()?;
        let (parent, dataspace) = self.registration.parent_scope()?;
        require(
            anchor.parent_network_id == parent
                && anchor.dataspace_id == dataspace
                && anchor.child_network_id == self.registration.child_network_id,
            "anchor differs from registered parent, dataspace or child",
        )?;
        let (header, commitment) = anchor.public_parts()?;
        let verified = self
            .tracker
            .verify_block(&anchor.certificate)
            .map_err(failure)?;
        self.registration
            .fixed_context(&commitment.schedule.current)?;
        for slot in [&commitment.schedule.next, &commitment.schedule.after_next] {
            if let ScheduledSlot::Ready(scheduled) = slot {
                self.registration.fixed_context(&scheduled.epoch)?;
            }
        }
        if let Some(boundary) = &commitment.schedule.boundary {
            self.registration.fixed_context(&boundary.next)?;
        }
        let cursor = PrivateDataspaceCursor {
            height: verified.height,
            consensus_hash: verified.block_hash,
            result: verified.result,
        };
        if cursor == self.cursor {
            return Ok(PrivateDataspaceAnchorOutcome::AlreadyAnchored);
        }
        require(
            self.cursor.height.checked_add(1) == Some(cursor.height),
            "anchor must immediately extend the current cursor",
        )?;
        require(
            header.parent_hash.0 == self.cursor.consensus_hash
                && header.parent_result.0 == self.cursor.result,
            "anchor parent differs from the retained decision",
        )?;
        self.cursor = cursor;
        Ok(PrivateDataspaceAnchorOutcome::Advanced)
    }
}

#[cfg(test)]
mod tests;
