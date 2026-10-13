//! One finite encoder and last-byte memory owner for native complete-state projections.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_core::{
    state::StateReadOnly,
    sumeragi::certified_chain::{CertifiedChain, CommittedBlock, QcVerification},
};
use iroha_data_model::sumeragi::finality::NativeFinalityLimits;
use norito::json::{BoundedJsonError, JsonWriteSink};

pub fn capacity() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
    ))
}

// One current-cut acquisition under the request's unchanged decode and source allowance.
pub fn current_global_tip(
    view: &impl StateReadOnly,
    height: u64,
    limits: NativeFinalityLimits,
    unavailable: fn() -> Error,
) -> Result<CommittedBlock, Error> {
    current_root_tip(
        view,
        height,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        unavailable,
    )
}

/// Authenticate the current cut of the independently selected native root.
pub(crate) fn current_root_tip(
    view: &impl StateReadOnly,
    height: u64,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
    limits: NativeFinalityLimits,
    unavailable: fn() -> Error,
) -> Result<CommittedBlock, Error> {
    limits.validate().map_err(|_| capacity())?;
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(view.world()) != Some(scope) {
        return Err(unavailable());
    }
    if height < 2 || u64::try_from(view.height()).ok() != Some(height) {
        return Err(unavailable());
    }
    let index = usize::try_from(height)
        .ok()
        .and_then(std::num::NonZeroUsize::new)
        .ok_or_else(unavailable)?;
    let mut frames_left = limits.block_count as u64;
    let mut bytes_left = limits.journal_bytes as u64;
    let mut admit = |frames: u64, bytes: u64| {
        if bytes > limits.block_bytes as u64 {
            return Err(
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            );
        }
        let next_frames = frames_left.checked_sub(frames).ok_or(
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ),
        )?;
        let next_bytes = bytes_left.checked_sub(bytes).ok_or(
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ),
        )?;
        frames_left = next_frames;
        bytes_left = next_bytes;
        Ok(())
    };
    let query_error = crate::canonical_history::query_attempt_error;
    let chain = CertifiedChain::new_with_source_admission(view, &mut admit).map_err(query_error)?;
    let certified = chain
        .certified_from_execution(index, &mut admit)
        .map_err(query_error)?;
    if certified.verification() != QcVerification::Verified {
        return Err(unavailable());
    }
    Ok(certified.into_committed())
}

pub struct EncodedBody {
    bytes: iroha_allocation::ChargedBuffer<u8>,
    pub(crate) memory: Option<QueryFanoutMemoryReservation>,
}
impl AsRef<[u8]> for EncodedBody {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
struct ChargedWriter(iroha_allocation::ChargedBuffer<u8>);
impl std::io::Write for ChargedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity().saturating_sub(self.0.as_slice().len()) {
            return Err(std::io::Error::other("native response length changed"));
        }
        for byte in bytes {
            self.0.push_reserved(*byte);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl JsonWriteSink for ChargedWriter {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        std::io::Write::write_all(self, value.as_bytes())
            .map_err(|_| BoundedJsonError::LengthMismatch)
    }
}
struct CountJson {
    length: usize,
    limit: usize,
    depth: usize,
}
impl JsonWriteSink for CountJson {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        let next = self
            .length
            .checked_add(value.len())
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if next > self.limit {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.length = next;
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if next >= norito::json::MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}
pub fn encode_canonical<T: norito::core::NoritoSerialize>(
    payload: &T,
    limit: usize,
    budget: &AllocationBudget,
    unavailable: fn() -> Error,
) -> Result<iroha_allocation::ChargedBuffer<u8>, Error> {
    let length = norito::canonical_frame_len(payload).map_err(|_| unavailable())?;
    if length > limit {
        return Err(capacity());
    }
    let bytes = iroha_allocation::ChargedBuffer::new(length, budget).map_err(|_| capacity())?;
    let mut writer = ChargedWriter(bytes);
    norito::core::write_canonical_to_writer(payload, &mut writer).map_err(|_| unavailable())?;
    if writer.0.as_slice().len() != length {
        return Err(unavailable());
    }
    Ok(writer.0)
}

pub fn encode<T: norito::core::NoritoSerialize + norito::json::JsonSerialize>(
    payload: &T,
    format: ResponseFormat,
    limit: usize,
    budget: &AllocationBudget,
    unavailable: fn() -> Error,
) -> Result<EncodedBody, Error> {
    let bytes = match format {
        ResponseFormat::Norito => encode_canonical(payload, limit, budget, unavailable)?,
        ResponseFormat::Json => {
            let mut count = CountJson {
                length: 0,
                limit,
                depth: 0,
            };
            payload
                .json_serialize_to(&mut count)
                .map_err(|_| capacity())?;
            let bytes = iroha_allocation::ChargedBuffer::new(count.length, budget)
                .map_err(|_| capacity())?;
            let mut writer = ChargedWriter(bytes);
            payload
                .json_serialize_to(&mut writer)
                .map_err(|_| unavailable())?;
            if writer.0.as_slice().len() != count.length {
                return Err(unavailable());
            }
            writer.0
        }
    };
    Ok(EncodedBody {
        bytes,
        memory: None,
    })
}

/// Prepay both committee vector layouts and their original key/PoP backing.
pub fn native_committee_original_bytes<'a>(
    expected: usize,
    members: impl IntoIterator<Item = (&'a iroha_crypto::PublicKey, &'a [u8])>,
) -> Result<usize, Error> {
    // proof_committee retains a tuple Vec; build_proof collects FinalityValidator.
    // Do not assume allocator reuse of two different element layouts. Both Vec
    // geometries and the cloned compact key/PoP backing are prepaid before
    // that backing moves from the intermediate tuples into the final values.
    let tuples = std::alloc::Layout::array::<(iroha_crypto::PublicKey, Vec<u8>)>(expected)
        .map_err(|_| capacity())?
        .size();
    let final_values = std::alloc::Layout::array::<
        iroha_data_model::sumeragi_finality::FinalityValidator,
    >(expected)
    .map_err(|_| capacity())?
    .size();
    let mut bytes = tuples.checked_add(final_values).ok_or_else(capacity)?;
    let mut seen = 0usize;
    for (key, pop) in members {
        seen = seen.checked_add(1).ok_or_else(capacity)?;
        if seen > expected {
            return Err(capacity());
        }
        bytes = bytes
            .checked_add(key.retained_allocation_layout().size())
            .and_then(|value| value.checked_add(pop.len()))
            .ok_or_else(capacity)?;
    }
    if seen != expected {
        return Err(capacity());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn canonical_originals_preflight_length_and_keep_exact_backing_charge() {
        let payload = 42_u64;
        let length = norito::canonical_frame_len(&payload).unwrap();
        let budget = AllocationBudget::new(length);
        assert!(encode_canonical(&payload, length - 1, &budget, capacity).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        let bytes = encode_canonical(&payload, length, &budget, capacity).unwrap();
        assert_eq!(bytes.as_slice().len(), length);
        assert_eq!(budget.reserved_bytes(), length);
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn charged_native_output_rejects_growth_and_refunds_only_when_backing_drops() {
        let budget = AllocationBudget::new(3);
        let mut writer = ChargedWriter(iroha_allocation::ChargedBuffer::new(3, &budget).unwrap());
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.0.as_slice(), b"abc");
        let bytes = Bytes::from_owner(EncodedBody {
            bytes: writer.0,
            memory: None,
        });
        let retained = bytes.clone();
        drop(bytes);
        assert_eq!(budget.reserved_bytes(), 3);
        drop(retained);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn json_preflight_counts_utf8_and_rejects_length_and_depth_before_output() {
        let mut count = CountJson {
            length: 0,
            limit: 4,
            depth: 0,
        };
        count.push('😀').unwrap();
        assert_eq!(count.length, 4);
        assert_eq!(count.push('a'), Err(BoundedJsonError::BodyTooLarge));
        assert_eq!(count.length, 4);
        for _ in 1..norito::json::MAX_JSON_VALUE_NESTING_DEPTH {
            count.begin_container().unwrap();
        }
        assert_eq!(count.begin_container(), Err(BoundedJsonError::Unsupported));
    }

    #[test]
    fn native_response_last_byte_retains_real_aggregate_query_permit() {
        let pool = ByteWeightedMemoryPool::new(3).unwrap();
        let permit = pool.try_acquire_parts([3]).unwrap();
        let budget = AllocationBudget::new(3);
        let mut writer = ChargedWriter(iroha_allocation::ChargedBuffer::new(3, &budget).unwrap());
        writer.write_all(b"abc").unwrap();
        let bytes = Bytes::from_owner(EncodedBody {
            bytes: writer.0,
            memory: Some(QueryFanoutMemoryReservation::new(permit)),
        });
        let retained = bytes.slice(1..);
        drop(bytes);
        assert!(pool.try_acquire_parts([1]).is_none());
        assert_eq!(budget.reserved_bytes(), 3);
        drop(retained);
        assert!(pool.try_acquire_parts([3]).is_some());
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn variable_committees_are_fully_prepaid_in_the_original_pool() {
        let key =
            iroha_crypto::KeyPair::from_seed(vec![71; 32], iroha_crypto::Algorithm::BlsNormal);
        let pop = iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap();
        let bytes = native_committee_original_bytes(
            1024,
            std::iter::repeat_n((key.public_key(), pop.as_slice()), 1024),
        )
        .unwrap();
        assert!(
            bytes > 16 * 1024,
            "fixed metadata overhead is insufficient for supported large committees"
        );
        let budget = AllocationBudget::new(16 * 1024);
        assert!(budget.try_reserve_bytes(bytes).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        let budget = AllocationBudget::new(bytes);
        let charge = budget.try_reserve_bytes(bytes).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(native_committee_original_bytes(2, [(key.public_key(), pop.as_slice())]).is_err());
        assert!(native_committee_original_bytes(0, [(key.public_key(), pop.as_slice())]).is_err());
        assert!(native_committee_original_bytes(usize::MAX, std::iter::empty()).is_err());
    }
}
