//! Recent block-event certificates from the actual captured State execution source.
//!
//! This is an off-chain event reader, not deterministic instruction metering. Its
//! opaque tip and immutable journal are captured together by State before I/O. Every
//! reverse parent link is checked against that tip's core/result and the exact hash
//! journal; a historical target's executed parent therefore supplies its original
//! schedule, including committee transitions. The target still runs the shared exact
//! QC, signed availability, schedule-successor and boundary verifier. No checkpoint
//! or event/cache scalar is certificate authority.
//! TODO: this preserves the inherited decoder scope and original source pool; it does
//! not complete the separate nested graph/cryptographic allocation-funding obligation.

use super::*;
use iroha_data_model::query::error::QueryExecutionFail;

/// Authenticate one recent target without retaining a World view or replaying genesis.
/// The caller retains the exact native target descriptor acquired before any body I/O.
/// Signed genesis and every actual tip-to-parent source count against one allowance.
/// No source refusal falls back to a prefix, checkpoint or different physical pool.
pub(crate) fn read_event_execution(
    source: crate::state::CanonicalHistorySource<'_>,
    chain_id: &ChainId,
    network: NetworkId,
    height: NonZeroUsize,
    original_target: &crate::kura::NativeFrameRead<'_>,
    max_work: u64,
    max_bytes: u64,
) -> Result<(AuthenticatedExecutionBlock, u64, u64), ExecutionAttemptError<QueryExecutionFail>> {
    let invalid = |message: &str| {
        ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message.into()))
    };
    let parent_height = height
        .get()
        .checked_sub(1)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| invalid("genesis alone has no native CommitQC"))?;
    let target_height =
        u64::try_from(height.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    let mut source_blocks = 0_u64;
    let mut source_bytes = 0_u64;
    let mut admit = |count: u64, bytes: u64| {
        let next_blocks = source_blocks
            .checked_add(count)
            .filter(|work| *work <= max_work)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        let next_bytes = source_bytes
            .checked_add(bytes)
            .filter(|total| *total <= max_bytes)
            .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
        if bytes > max_bytes.min(crate::kura::STRICT_INIT_MAX_BLOCK_BYTES) {
            return Err(QueryExecutionFail::GasBudgetExceeded.into());
        }
        source_blocks = next_blocks;
        source_bytes = next_bytes;
        Ok(())
    };
    let genesis = source.block_with_admission(NonZeroUsize::MIN, &mut admit)?;
    let (_, instance) = authenticate_genesis(&genesis, &network, chain_id).map_err(|error| {
        error.map_rejection(|error| QueryExecutionFail::Conversion(error.to_string()))
    })?;
    let mut parent = None;
    let mut current = None;
    source.visit_executed_backwards_with_original_target(
        parent_height,
        height,
        original_target,
        &mut admit,
        |receipt| {
            if receipt.height() == target_height {
                current = Some(receipt);
            } else {
                parent = Some(receipt);
            }
            Ok(())
        },
    )?;
    let parent = parent.ok_or_else(|| invalid("authenticated parent is absent"))?;
    let current = current.ok_or_else(|| invalid("authenticated target is absent"))?;
    let certified = PrefixVerifierContext { instance }
        .verify_executed_successor(&parent, current)
        .map_err(state_certificate::verification_attempt_failure)?;
    let authenticated = certified.into_authenticated_execution().map_err(|error| {
        ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(error.to_string()))
    })?;
    Ok((authenticated, source_blocks, source_bytes))
}
