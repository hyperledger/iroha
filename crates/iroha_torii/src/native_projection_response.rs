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

/// Original producer failure, retained until the route's HTTP or snapshot boundary.
#[derive(Debug, thiserror::Error)]
pub enum NativeProjectionError {
    /// The exact output cannot fit the unchanged response contract.
    #[error("native response requires {requested} bytes, exceeding its {limit}-byte bound")]
    ResponseLimit {
        /// Measured canonical frame extent.
        requested: usize,
        /// Original route limit.
        limit: usize,
    },
    /// Exact output backing retains the original admission or allocator refusal.
    #[error("native response backing: {0}")]
    Buffer(#[from] iroha_allocation::ChargedBufferError),
    /// Canonical serialization retains its original classified codec failure.
    #[error("native response serialization: {0}")]
    Encoding(#[source] norito::core::DecodeAttemptError),
    /// The canonical root reader retains its actual local decoding refusal.
    #[error("native root read: {0}")]
    RootScope(#[source] iroha_core::execution_attempt::ExecutionDeferred),
    /// The original certified-chain reader failed without a projected HTTP error.
    #[error("native current-cut history: {0}")]
    History(
        #[source]
        iroha_core::execution_attempt::ExecutionAttemptError<
            iroha_data_model::query::error::QueryExecutionFail,
        >,
    ),
    /// Original invalid source limits or impossible committee geometry.
    #[error("native projection: {0}")]
    Invalid(String),
    /// The route's selected source is unavailable or differs from its required binding.
    #[error("native projection source: {0}")]
    Unavailable(#[source] Error),
}

impl From<NativeProjectionError> for Error {
    fn from(error: NativeProjectionError) -> Self {
        use iroha_allocation::{AllocationRefusal, ChargedBufferError};
        use iroha_core::execution_attempt::ExecutionAttemptError;
        match error {
            NativeProjectionError::Buffer(
                ChargedBufferError::Admission(AllocationRefusal::Capacity { .. })
                | ChargedBufferError::Allocator { .. },
            )
            | NativeProjectionError::RootScope(_) => capacity(),
            NativeProjectionError::Encoding(ref error)
                if error.kind() != norito::core::DecodeAttemptErrorKind::Invalid =>
            {
                capacity()
            }
            NativeProjectionError::History(ExecutionAttemptError::Deferred(ref error))
                if !matches!(
                    error.allocation_refusal(),
                    Some(
                        AllocationRefusal::ExceedsLimit { .. } | AllocationRefusal::DemandOverflow
                    )
                ) =>
            {
                capacity()
            }
            NativeProjectionError::History(ExecutionAttemptError::Rejected(error)) => {
                Error::Query(iroha_data_model::ValidationFail::QueryFailed(error))
            }
            NativeProjectionError::Unavailable(error) => error,
            error => conversion_error(error.to_string()),
        }
    }
}

// One current-cut acquisition under the request's unchanged decode and source allowance.
pub fn current_global_tip(
    view: &impl StateReadOnly,
    height: u64,
    limits: NativeFinalityLimits,
    unavailable: fn() -> Error,
) -> Result<CommittedBlock, NativeProjectionError> {
    current_root_tip(
        view,
        height,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        limits,
        unavailable,
    )
}

/// Authenticate the current cut of the independently selected native root.
pub fn current_root_tip(
    view: &impl StateReadOnly,
    height: u64,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
    limits: NativeFinalityLimits,
    unavailable: fn() -> Error,
) -> Result<CommittedBlock, NativeProjectionError> {
    limits.validate().map_err(NativeProjectionError::Invalid)?;
    if iroha_core::sumeragi::lanes::routing::read_routing_root_scope(view.world())
        .map_err(NativeProjectionError::RootScope)?
        != Some(scope)
    {
        return Err(NativeProjectionError::Unavailable(unavailable()));
    }
    if height < 2 || u64::try_from(view.height()).ok() != Some(height) {
        return Err(NativeProjectionError::Unavailable(unavailable()));
    }
    let index = usize::try_from(height)
        .ok()
        .and_then(std::num::NonZeroUsize::new)
        .ok_or_else(|| NativeProjectionError::Unavailable(unavailable()))?;
    let mut frames_left = limits.block_count as u64;
    let mut bytes_left = limits.journal_bytes as u64;
    // These are unchanged per-request source limits, not occupied-pool refusals.
    let source_limit = || {
        iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(
                "native current cut exceeds its finite source policy".into(),
            ),
        )
    };
    let mut admit = |frames: u64, bytes: u64| {
        if bytes > limits.block_bytes as u64 {
            return Err(source_limit());
        }
        let next_frames = frames_left.checked_sub(frames).ok_or_else(source_limit)?;
        let next_bytes = bytes_left.checked_sub(bytes).ok_or_else(source_limit)?;
        frames_left = next_frames;
        bytes_left = next_bytes;
        Ok(())
    };
    let query_error = NativeProjectionError::History;
    let chain = CertifiedChain::new_with_source_admission(view, &mut admit).map_err(query_error)?;
    let certified = chain
        .certified_from_execution(index, &mut admit)
        .map_err(query_error)?;
    if certified.verification() != QcVerification::Verified {
        return Err(NativeProjectionError::Unavailable(unavailable()));
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
) -> Result<iroha_allocation::ChargedBuffer<u8>, NativeProjectionError> {
    let length = norito::core::classify_decode_attempt(|| norito::canonical_frame_len(payload))
        .map_err(NativeProjectionError::Encoding)?;
    if length > limit {
        return Err(NativeProjectionError::ResponseLimit {
            requested: length,
            limit,
        });
    }
    let bytes = iroha_allocation::ChargedBuffer::new(length, budget)?;
    let mut writer = ChargedWriter(bytes);
    norito::core::classify_decode_attempt(|| {
        norito::core::write_canonical_to_writer(payload, &mut writer)
    })
    .map_err(NativeProjectionError::Encoding)?;
    if writer.0.as_slice().len() != length {
        return Err(NativeProjectionError::Invalid(
            "canonical response length changed".into(),
        ));
    }
    Ok(writer.0)
}

pub fn encode<T: norito::core::NoritoSerialize + norito::json::JsonSerialize>(
    payload: &T,
    format: ResponseFormat,
    limit: usize,
    budget: &AllocationBudget,
) -> Result<EncodedBody, NativeProjectionError> {
    let bytes = match format {
        ResponseFormat::Norito => encode_canonical(payload, limit, budget)?,
        ResponseFormat::Json => {
            let mut count = CountJson {
                length: 0,
                limit,
                depth: 0,
            };
            // The existing JSON codec conversion retains scoped refusal owners.
            // Classification occurs before that original serialization scope exits.
            norito::core::classify_decode_attempt(|| {
                payload
                    .json_serialize_to(&mut count)
                    .map_err(BoundedJsonError::into_core_error)
            })
            .map_err(NativeProjectionError::Encoding)?;
            let bytes = iroha_allocation::ChargedBuffer::new(count.length, budget)?;
            let mut writer = ChargedWriter(bytes);
            norito::core::classify_decode_attempt(|| {
                payload
                    .json_serialize_to(&mut writer)
                    .map_err(BoundedJsonError::into_core_error)
            })
            .map_err(NativeProjectionError::Encoding)?;
            if writer.0.as_slice().len() != count.length {
                return Err(NativeProjectionError::Invalid(
                    "JSON response length changed".into(),
                ));
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
) -> Result<usize, NativeProjectionError> {
    let invalid =
        || NativeProjectionError::Invalid("committee geometry or cardinality is invalid".into());
    // proof_committee retains a tuple Vec; build_proof collects FinalityValidator.
    // Do not assume allocator reuse of two different element layouts. Both Vec
    // geometries and the cloned compact key/PoP backing are prepaid before
    // that backing moves from the intermediate tuples into the final values.
    let tuples = std::alloc::Layout::array::<(iroha_crypto::PublicKey, Vec<u8>)>(expected)
        .map_err(|_| invalid())?
        .size();
    let final_values = std::alloc::Layout::array::<
        iroha_data_model::sumeragi_finality::FinalityValidator,
    >(expected)
    .map_err(|_| invalid())?
    .size();
    let mut bytes = tuples.checked_add(final_values).ok_or_else(invalid)?;
    let mut seen = 0usize;
    for (key, pop) in members {
        seen = seen.checked_add(1).ok_or_else(invalid)?;
        if seen > expected {
            return Err(invalid());
        }
        bytes = bytes
            .checked_add(key.retained_allocation_layout().size())
            .and_then(|value| value.checked_add(pop.len()))
            .ok_or_else(invalid)?;
    }
    if seen != expected {
        return Err(invalid());
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
        assert!(encode_canonical(&payload, length - 1, &budget).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        let bytes = encode_canonical(&payload, length, &budget).unwrap();
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

#[cfg(test)]
#[path = "native_projection_response/classification_tests.rs"]
mod classification_tests;
