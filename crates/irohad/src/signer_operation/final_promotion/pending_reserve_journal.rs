//! Bounded private staging of the original signed Current Check and role-15 Reserve.
//!
//! A record is durable before Reserve transport and is useful for exact, read-only restart
//! reconciliation. It is not an independently issued floor pin, native admission, signing
//! authority or permission to resubmit a recovered envelope. Those production gates remain open.
//! TODO: Authenticate the independently issued historical floor pin and exact finalized
//! Current Check/Reserve lineage after restart, then reconcile ambiguous transport read-only.

use std::path::Path;

/// Distinct retained receipt signer, account signer and observer identities for one Reserve.
#[derive(Clone, Copy)]
pub(super) struct ReserveBindings<'a> {
    pub(super) receipt_binding: &'a SignerCustodyBindingV1,
    pub(super) account_binding: &'a SignerCustodyBindingV1,
    pub(super) observer: &'a AccountId,
}

use iroha_core::query::{
    final_promotion_account_custody::observation::final_promotion_native_signed_entry_frame_v1,
    final_promotion_authority::observation::{
        FinalPromotionCheckFloorV1, VerifiedFinalPromotionCheckV1,
    },
};
use iroha_data_model::{
    account::AccountId,
    block::consensus::HeightContextId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::{
        FinalPromotionAuthorityActionV1, FinalPromotionCheckSubjectV1,
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use sorafs_manifest::signer::{
    custody::SignerCustodyBindingV1,
    final_promotion::SignerFinalPromotionRequestV1,
    protocol::{
        SignerKeyAlgorithmV1, SignerOperationActionV1, SignerPurposeBindingV1, SignerRoleV1,
    },
};

use super::super::journal::{
    PinnedReceipt, SignerJournalInventoryPoolV1, SignerPendingReserveFilesV1,
};

const INTENT_MAX_BYTES: usize = 4096;
const SIGNED_FRAME_MAX_BYTES: usize = 64 * 1024;
const RECORD_MAX_BYTES: usize = 136 * 1024;
const MAX_SOURCE_SPAN: u64 = 4096;
const RECORD_VERSION: u8 = 1;

/// Secret-free failure of private pending-Reserve staging or recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalPromotionPendingReserveJournalErrorV1 {
    /// Private record or authoritative identity unavailable or invalid.
    Unavailable,
    /// Local inventory or canonical-frame resources are unavailable; retain the same signed
    /// pending operation. This fixed error does not itself carry a retry continuation.
    LocalCapacity,
}
impl std::fmt::Display for FinalPromotionPendingReserveJournalErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("final-promotion pending Reserve journal unavailable")
    }
}
impl std::error::Error for FinalPromotionPendingReserveJournalErrorV1 {}
use self::FinalPromotionPendingReserveJournalErrorV1 as Error;

#[derive(Clone, Copy, PartialEq, Eq, norito::Decode, norito::Encode, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "irohad::signer_operation::final_promotion::RetainedFloorV1")]
struct RetainedFloorV1 {
    height: u64,
    block_hash: [u8; 32],
    context_id: HeightContextId,
}
impl From<FinalPromotionCheckFloorV1> for RetainedFloorV1 {
    fn from(floor: FinalPromotionCheckFloorV1) -> Self {
        Self {
            height: floor.height,
            block_hash: floor.block_hash,
            context_id: floor.context_id,
        }
    }
}
impl From<RetainedFloorV1> for FinalPromotionCheckFloorV1 {
    fn from(floor: RetainedFloorV1) -> Self {
        Self {
            height: floor.height,
            block_hash: floor.block_hash,
            context_id: floor.context_id,
        }
    }
}

#[derive(Clone, PartialEq, Eq, norito::Decode, norito::Encode, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "irohad::signer_operation::final_promotion::PendingReserveIntentV1")]
struct PendingReserveIntentV1 {
    version: u8,
    sequence: u64,
    predecessor_digest: [u8; 32],
    request: SignerFinalPromotionRequestV1,
    receipt_binding: SignerCustodyBindingV1,
    account_binding: SignerCustodyBindingV1,
    observer: AccountId,
    source_floor: RetainedFloorV1,
    current_check_height: u64,
    current_check_entry_hash: [u8; 32],
    reserve_entry_hash: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, norito::Decode, norito::Encode, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "irohad::signer_operation::final_promotion::PendingReserveRecordV1")]
struct PendingReserveRecordV1 {
    intent: PendingReserveIntentV1,
    signed_current_check: Vec<u8>,
    signed_reserve: Vec<u8>,
}

/// Separate owner-only pending-Reserve directory; receipt purposes and ceilings are unchanged.
///
/// The path must be a pre-existing canonical `pending-reserve-v1` sibling of the receipt
/// directory, owned by this process with mode 0700. Opening an unsafe or occupied path fails.
pub struct FinalPromotionPendingReserveJournalV1 {
    files: SignerPendingReserveFilesV1,
}
impl FinalPromotionPendingReserveJournalV1 {
    /// Pin the dedicated private directory and exclusive lease.
    ///
    /// # Errors
    /// Rejects unsafe path components, contents, ownership, permissions or a competing owner.
    pub fn open(path: &Path, pool: &SignerJournalInventoryPoolV1) -> Result<Self, Error> {
        Ok(Self {
            files: SignerPendingReserveFilesV1::open(path, pool).map_err(|error| {
                if error.is_local_capacity() {
                    Error::LocalCapacity
                } else {
                    Error::Unavailable
                }
            })?,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_test(path: &Path) -> Result<Self, Error> {
        Self::open(path, super::super::journal::test_inventory_pool())
    }

    /// Recover one exact private record for read-only reconciliation after process loss.
    ///
    /// This grants no signing, native submission, renewed Check or historical floor authority.
    ///
    /// # Errors
    /// Rejects missing, partial, corrupt, substituted or noncanonical records.
    pub fn recover(&self, operation_id: [u8; 32]) -> Result<RecoveredPendingReserveV1, Error> {
        let pinned = self.files.recover(operation_id).map_err(|error| {
            if error.is_local_capacity() {
                Error::LocalCapacity
            } else {
                Error::Unavailable
            }
        })?;
        let record = decode_record(pinned.bytes())?;
        if record.intent.request.operation_id != operation_id {
            return Err(Error::Unavailable);
        }
        pinned.recheck().map_err(|_| Error::Unavailable)?;
        Ok(RecoveredPendingReserveV1 { pinned, record })
    }

    pub(super) fn stage(
        &self,
        request: SignerFinalPromotionRequestV1,
        bindings: ReserveBindings<'_>,
        source_floor: FinalPromotionCheckFloorV1,
        current_check: &VerifiedFinalPromotionCheckV1,
        reserve: &SignedTransaction,
    ) -> Result<RecoveredPendingReserveV1, Error> {
        let ReserveBindings {
            receipt_binding,
            account_binding,
            observer,
        } = bindings;
        let reserve_entry = TransactionEntrypoint::External(reserve.clone());
        let signed_reserve = encode_signed_frame(&reserve_entry)?;
        let record = PendingReserveRecordV1 {
            intent: PendingReserveIntentV1 {
                version: RECORD_VERSION,
                sequence: 1,
                predecessor_digest: [0; 32],
                request,
                receipt_binding: receipt_binding.clone(),
                account_binding: account_binding.clone(),
                observer: observer.clone(),
                source_floor: source_floor.into(),
                current_check_height: current_check.check_height(),
                current_check_entry_hash: *current_check.entry_hash().as_ref(),
                reserve_entry_hash: *reserve.hash_as_entrypoint().as_ref(),
            },
            signed_current_check: current_check.canonical_external().to_vec(),
            signed_reserve,
        };
        validate_record(&record)?;
        let bytes = norito::encode_canonical(&record).map_err(|_| Error::Unavailable)?;
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(Error::Unavailable);
        }
        let staged = self
            .files
            .stage(request.operation_id, &bytes)
            .map_err(|error| {
                if error.is_local_capacity() {
                    Error::LocalCapacity
                } else {
                    Error::Unavailable
                }
            })?;
        staged.recheck().map_err(|_| Error::Unavailable)?;
        // A separate descriptor readback is mandatory before the original Reserve reaches
        // transport. The immutable file and exclusive directory lease remain pinned afterward.
        let recovered = self.recover(request.operation_id)?;
        if recovered.record != record || recovered.pinned.bytes() != bytes {
            return Err(Error::Unavailable);
        }
        Ok(recovered)
    }
}

/// One recovered immutable record with no method to expose a transaction or submit it.
pub struct RecoveredPendingReserveV1 {
    pinned: PinnedReceipt,
    record: PendingReserveRecordV1,
}
impl RecoveredPendingReserveV1 {
    /// Recheck the original directory and file identity and exact retained bytes.
    ///
    /// # Errors
    /// Rejects any replacement, in-place mutation, mode change, hardlink or lost ancestor.
    pub fn recheck(&self) -> Result<(), Error> {
        self.pinned.recheck().map_err(|_| Error::Unavailable)?;
        if decode_record(self.pinned.bytes())? != self.record {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    /// Untrusted original operation identifier for exact finalized-state reconciliation only.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 32] {
        self.record.intent.request.operation_id
    }

    /// Untrusted historical floor coordinates retained from the original pending attempt.
    /// The independent floor issuer and native pin must authenticate this before any use.
    #[must_use]
    pub fn source_floor(&self) -> FinalPromotionCheckFloorV1 {
        self.record.intent.source_floor.into()
    }

    pub(super) fn matches_live(
        &self,
        request: &SignerFinalPromotionRequestV1,
        source_floor: FinalPromotionCheckFloorV1,
        current_check: &VerifiedFinalPromotionCheckV1,
        reserve: &SignedTransaction,
    ) -> Result<(), Error> {
        self.recheck()?;
        if &self.record.intent.request != request
            || self.source_floor() != source_floor
            || self.record.intent.current_check_height != current_check.check_height()
            || self.record.intent.current_check_entry_hash != *current_check.entry_hash().as_ref()
            || self.record.intent.reserve_entry_hash != *reserve.hash_as_entrypoint().as_ref()
            || self.record.signed_current_check != current_check.canonical_external()
            || self.record.signed_reserve
                != encode_signed_frame(&TransactionEntrypoint::External(reserve.clone()))?
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

fn decode_record(bytes: &[u8]) -> Result<PendingReserveRecordV1, Error> {
    if bytes.is_empty() || bytes.len() > RECORD_MAX_BYTES {
        return Err(Error::Unavailable);
    }
    let record: PendingReserveRecordV1 = norito::decode_canonical_with_limits(
        bytes,
        norito::DecodeLimits::new(16 * 1024, RECORD_MAX_BYTES, 8192, 512 * 1024, 24),
    )
    .map_err(|_| Error::Unavailable)?;
    validate_record(&record)?;
    Ok(record)
}

fn validate_lengths(record: &PendingReserveRecordV1) -> Result<(), Error> {
    let intent_size =
        norito::canonical_frame_len(&record.intent).map_err(|_| Error::Unavailable)?;
    let record_size = norito::canonical_frame_len(record).map_err(|_| Error::Unavailable)?;
    validate_length_parts(
        intent_size,
        record.signed_current_check.len(),
        record.signed_reserve.len(),
        record_size,
    )
}

fn validate_length_parts(
    intent_size: usize,
    current_size: usize,
    reserve_size: usize,
    record_size: usize,
) -> Result<(), Error> {
    if intent_size == 0
        || intent_size > INTENT_MAX_BYTES
        || current_size == 0
        || current_size > SIGNED_FRAME_MAX_BYTES
        || reserve_size == 0
        || reserve_size > SIGNED_FRAME_MAX_BYTES
        || record_size == 0
        || record_size > RECORD_MAX_BYTES
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn validate_record(record: &PendingReserveRecordV1) -> Result<(), Error> {
    validate_lengths(record)?;
    let intent = &record.intent;
    let source = intent.source_floor;
    let (
        SignerPurposeBindingV1::FinalPromotionProvenance {
            deployment_id: receipt_deployment,
        },
        SignerPurposeBindingV1::FinalPromotionAccountTransaction {
            deployment_id: account_deployment,
        },
    ) = (
        &intent.receipt_binding.purpose,
        &intent.account_binding.purpose,
    )
    else {
        return Err(Error::Unavailable);
    };
    if intent.version != RECORD_VERSION
        || intent.sequence != 1
        || intent.predecessor_digest != [0; 32]
        || intent
            .request
            .validate_binding(&intent.receipt_binding)
            .is_err()
        || intent.account_binding.validate().is_err()
        || intent.receipt_binding.role != SignerRoleV1::FinalPromotionProvenance
        || intent.account_binding.role != SignerRoleV1::FinalPromotionAccountTransaction
        || intent.receipt_binding.algorithm != SignerKeyAlgorithmV1::Ed25519
        || intent.account_binding.algorithm != SignerKeyAlgorithmV1::Ed25519
        || intent.receipt_binding.network_id != intent.account_binding.network_id
        || intent.receipt_binding.chain_id != intent.account_binding.chain_id
        || intent.receipt_binding.public_key == intent.account_binding.public_key
        || receipt_deployment != account_deployment
        || source.height == 0
        || source.block_hash == [0; 32]
        || intent.current_check_height == 0
        || intent.current_check_height > source.height
        || source.height - intent.current_check_height > MAX_SOURCE_SPAN
        || intent.current_check_entry_hash == [0; 32]
        || intent.reserve_entry_hash == [0; 32]
    {
        return Err(Error::Unavailable);
    }
    let current = decode_signed_frame(&record.signed_current_check)?;
    let reserve = decode_signed_frame(&record.signed_reserve)?;
    let current_instruction = sole_final_promotion_instruction(&current)?;
    let reserve_instruction = sole_final_promotion_instruction(&reserve)?;
    let FinalPromotionAuthorityActionV1::Check(check) = &current_instruction.action else {
        return Err(Error::Unavailable);
    };
    let FinalPromotionCheckSubjectV1::Current(audit) = &check.subject else {
        return Err(Error::Unavailable);
    };
    let FinalPromotionAuthorityActionV1::Reserve(reservation) = &reserve_instruction.action else {
        return Err(Error::Unavailable);
    };
    if current.hash_as_entrypoint().as_ref() != &intent.current_check_entry_hash
        || reserve.hash_as_entrypoint().as_ref() != &intent.reserve_entry_hash
        || current.authority() != &intent.observer
        || reserve.authority() != &AccountId::new(intent.account_binding.public_key.clone())
        || current
            .network_id()
            .map(iroha_data_model::NetworkId::as_bytes)
            != Some(&intent.receipt_binding.network_id)
        || reserve
            .network_id()
            .map(iroha_data_model::NetworkId::as_bytes)
            != Some(&intent.receipt_binding.network_id)
        || &current_instruction.deployment_id != receipt_deployment
        || &reserve_instruction.deployment_id != receipt_deployment
        || current_instruction.expected_control_revision
            != reserve_instruction.expected_control_revision
        || current_instruction.expected_control_digest
            != reserve_instruction.expected_control_digest
        || check.network_id != intent.receipt_binding.network_id
        || check.request != intent.request
        || check.expected_operator != AccountId::new(intent.account_binding.public_key.clone())
        || reserve_instruction.expected_control_digest
            != intent.request.original_custody.control_state_digest
        || reservation.intent.action != SignerOperationActionV1::Sign
        || reservation.intent.operation_id != intent.request.operation_id
        || reservation.intent.request_digest
            != intent.request.digest().map_err(|_| Error::Unavailable)?
        || reservation.intent.previous_audit != *audit
        || reservation.custody != intent.request.original_custody
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

// The caller retains any live signed Reserve; this fixed staging error does not create a
// signing retry continuation. Local frame refusal cannot be labelled malformed journal content.
fn encode_signed_frame(entry: &TransactionEntrypoint) -> Result<Vec<u8>, Error> {
    use iroha_core::execution_attempt::ExecutionAttemptError;
    final_promotion_native_signed_entry_frame_v1(entry).map_err(|error| match error {
        ExecutionAttemptError::Deferred(_) => Error::LocalCapacity,
        ExecutionAttemptError::Rejected(_) => Error::Unavailable,
    })
}

fn decode_signed_frame(frame: &[u8]) -> Result<SignedTransaction, Error> {
    if frame.is_empty() || frame.len() > SIGNED_FRAME_MAX_BYTES {
        return Err(Error::Unavailable);
    }
    let entry: TransactionEntrypoint = norito::decode_canonical_with_limits(
        frame,
        norito::DecodeLimits::new(16 * 1024, SIGNED_FRAME_MAX_BYTES, 8192, 256 * 1024, 24),
    )
    .map_err(|_| Error::Unavailable)?;
    if encode_signed_frame(&entry)? != frame {
        return Err(Error::Unavailable);
    }
    let TransactionEntrypoint::External(signed) = entry else {
        return Err(Error::Unavailable);
    };
    signed.verify_signature().map_err(|_| Error::Unavailable)?;
    Ok(signed)
}

fn sole_final_promotion_instruction(
    signed: &SignedTransaction,
) -> Result<&MutateSorafsFinalPromotionAuthority, Error> {
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Err(Error::Unavailable);
    };
    instructions
        .first()
        .filter(|_| instructions.len() == 1)
        .and_then(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        })
        .ok_or(Error::Unavailable)
}

#[cfg(test)]
mod tests;
