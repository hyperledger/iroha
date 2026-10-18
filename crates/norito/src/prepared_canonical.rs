//! One canonical decoding attempt with originally prepaid protocol counter controls.

use std::alloc::Layout;

use iroha_allocation::{AllocationReservation, PrepaidSharedError};

use crate::{
    CanonicalDecodeScope, DecodeLimits, Error, NoritoDeserialize, NoritoSerialize,
    canonical_decode_limits, checked_canonical_header,
    core::{DecodeAttemptError, DecodeBudgetContext, TypedFieldSlot, classify_decode_attempt},
    decode_canonical_with_scopes_into_slot,
};

/// The two protocol counter controls of one exact canonical frame decoder.
///
/// Their native allocations are constructed only from the caller's original reservation.
/// This does not fund input bytes, a decoded graph, or custom serializer scratch. An enclosing
/// physical owner must retain those allocations and its cumulative decode-budget context.
/// The schema and canonical default scopes still enter inside the admission observer, so
/// protocol limits remain invalid input and enclosing limits retain their original provenance.
/// Consuming the decoder prevents reuse of its single-attempt counters.
pub struct PreparedCanonicalDecode {
    frame_bytes: usize,
    defaults: DecodeBudgetContext,
    schema: DecodeBudgetContext,
}

impl PreparedCanonicalDecode {
    /// Exact concrete layouts of the canonical default and schema counter controls.
    #[must_use]
    pub fn allocation_layouts() -> [Layout; 2] {
        [DecodeBudgetContext::allocation_layout(); 2]
    }

    /// Construct both controls from an existing original reservation before frame decoding.
    /// The fixed default policy remains derived from the complete frame byte length.
    ///
    /// # Errors
    /// Returns the original reservation shortage or allocator refusal. Partially constructed
    /// controls retire before their credits are refunded; no decoded graph is constructed.
    pub fn from_reservation(
        frame_bytes: usize,
        limits: DecodeLimits,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, PrepaidSharedError> {
        let defaults = DecodeBudgetContext::from_reservation(
            canonical_decode_limits(frame_bytes),
            reservation,
        )?;
        let schema = DecodeBudgetContext::from_reservation(limits, reservation)?;
        Ok(Self {
            frame_bytes,
            defaults,
            schema,
        })
    }

    /// Decode and authenticate one exact canonical frame through the ordinary shared kernel.
    ///
    /// # Errors
    /// Returns ordinary canonical/header/codec errors, a length mismatch if the frame differs
    /// from the admitted size, or a local refusal with unchanged enclosing-scope provenance.
    pub fn decode<T>(self, bytes: &[u8]) -> Result<T, DecodeAttemptError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        self.decode_into(bytes, |value| value)
    }

    /// Decode one canonical frame and transfer its graph into a physical owner exactly once.
    /// The consumer only runs after the complete shared canonical checks succeed.
    ///
    /// # Errors
    /// Returns the same failures as [`Self::decode`]; the consumer's own result is unchanged.
    pub fn decode_into<T, Output>(
        self,
        bytes: &[u8],
        finish: impl FnOnce(T) -> Output,
    ) -> Result<Output, DecodeAttemptError>
    where
        T: NoritoSerialize,
        for<'de> T: NoritoDeserialize<'de>,
    {
        let mut slot = TypedFieldSlot::<T>::new();
        let decoded = classify_decode_attempt(|| {
            if bytes.len() != self.frame_bytes {
                return Err(Error::LengthMismatch);
            }
            let header = checked_canonical_header(bytes)?;
            decode_canonical_with_scopes_into_slot(
                bytes,
                header,
                &mut slot,
                CanonicalDecodeScope::Prepared(&self.defaults),
                CanonicalDecodeScope::Prepared(&self.schema),
            )?;
            // Keep the initialized value in its original slot while the observer retires.
            slot.value().map(|_| ())
        });
        match decoded {
            Ok(()) => Ok(crate::finish_canonical_admission(&mut slot, finish)),
            Err(error) => {
                // The rejected graph must not clean up under an uncalled consumer's guards.
                // Keep this decoder's original controls alive through both cleanups.
                drop(finish);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::DecodeAttemptErrorKind;
    use iroha_allocation::AllocationBudget;

    fn decoder(bytes: &[u8], pool: &AllocationBudget) -> PreparedCanonicalDecode {
        let mut original = pool
            .try_reserve_layouts(PreparedCanonicalDecode::allocation_layouts())
            .expect("original controls");
        PreparedCanonicalDecode::from_reservation(
            bytes.len(),
            canonical_decode_limits(bytes.len()),
            &mut original,
        )
        .expect("prepared controls")
    }

    #[test]
    fn prepared_canonical_matches_ordinary_frames_and_rejections() {
        let pool = AllocationBudget::new(65_536);
        let value = vec![vec![1_u64, 2], vec![], vec![3]];
        let frame = crate::encode_canonical(&value).unwrap();
        let decoded: Vec<Vec<u64>> = decoder(&frame, &pool).decode(&frame).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(pool.reserved_bytes(), 0);
        for malformed in [
            &frame[..frame.len() - 1],
            &frame[..frame.len() / 2],
            &[][..],
        ] {
            let ordinary = crate::decode_canonical::<Vec<Vec<u64>>>(malformed).unwrap_err();
            let prepared = decoder(malformed, &pool)
                .decode::<Vec<Vec<u64>>>(malformed)
                .unwrap_err();
            assert_eq!(prepared.error().to_string(), ordinary.to_string());
            assert_eq!(prepared.kind(), DecodeAttemptErrorKind::Invalid);
            drop(prepared);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let wrong_length = decoder(&frame, &pool)
            .decode::<Vec<Vec<u64>>>(&frame[..frame.len() - 1])
            .unwrap_err();
        assert!(matches!(wrong_length.error(), Error::LengthMismatch));
    }

    #[test]
    fn prepared_canonical_controls_refuse_before_allocation_and_retry_original_pool() {
        let bytes = crate::encode_canonical(&7_u64).unwrap();
        let layouts = PreparedCanonicalDecode::allocation_layouts();
        let exact = layouts.iter().map(Layout::size).sum();
        let original = AllocationBudget::new(exact);
        let competing = original.try_reserve_bytes(1).unwrap();
        assert!(original.try_reserve_layouts(layouts).is_err());
        let foreign = AllocationBudget::new(exact);
        drop(foreign.try_reserve_layouts(layouts).unwrap());
        assert!(original.try_reserve_layouts(layouts).is_err());
        drop(competing);
        let prepared = decoder(&bytes, &original);
        assert_eq!(original.reserved_bytes(), exact);
        assert_eq!(prepared.decode::<u64>(&bytes).unwrap(), 7);
        assert_eq!(original.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_canonical_distinguishes_original_physical_and_protocol_limits() {
        let frame = crate::encode_canonical(&vec![1_u64, 2]).unwrap();
        let pool = AllocationBudget::new(65_536);
        let physical =
            DecodeBudgetContext::try_new_owned(DecodeLimits::new(1000, 1000, 1000, 0, 100), &pool)
                .unwrap();
        let prepared = decoder(&frame, &pool);
        let refused = physical
            .with(|| prepared.decode::<Vec<u64>>(&frame))
            .unwrap_err();
        assert_eq!(refused.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        assert!(refused.local_refusal().is_some());
        drop(refused);
        drop(physical);
        assert_eq!(pool.reserved_bytes(), 0);

        let mut original = pool
            .try_reserve_layouts(PreparedCanonicalDecode::allocation_layouts())
            .unwrap();
        let prepared = PreparedCanonicalDecode::from_reservation(
            frame.len(),
            DecodeLimits::new(1, 1000, 1000, 1000, 100),
            &mut original,
        )
        .unwrap();
        let invalid = prepared.decode::<Vec<u64>>(&frame).unwrap_err();
        assert_eq!(invalid.kind(), DecodeAttemptErrorKind::Invalid);
        assert!(invalid.local_refusal().is_none());
        drop(invalid);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_canonical_consumer_preserves_fixed_value_scopes_and_original_controls() {
        let value = [[7_u64; 32]; 32];
        let frame = crate::encode_canonical(&value).unwrap();
        let nested = crate::encode_canonical(&vec![5_u64; 64]).unwrap();
        let canonical = canonical_decode_limits(frame.len());
        let limits = DecodeLimits::new(
            32,
            canonical.max_field_bytes(),
            canonical.max_total_elements(),
            canonical.max_total_allocated_bytes(),
            canonical.max_nesting_depth(),
        );
        let exact = PreparedCanonicalDecode::allocation_layouts()
            .iter()
            .map(Layout::size)
            .sum();
        let pool = AllocationBudget::new(exact);
        let mut original = pool
            .try_reserve_layouts(PreparedCanonicalDecode::allocation_layouts())
            .unwrap();
        let prepared =
            PreparedCanonicalDecode::from_reservation(frame.len(), limits, &mut original).unwrap();
        drop(original);
        assert_eq!(pool.reserved_bytes(), exact);

        let alternate_flags =
            crate::core::default_encode_flags() ^ crate::core::header_flags::COMPACT_LEN;
        let _ambient_flags = crate::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_payload = b"original prepared consumer context";
        let _ambient_payload = crate::core::PayloadCtxGuard::enter(ambient_payload);
        let context_before = crate::core::payload_ctx();
        let encoding_before = crate::core::to_bytes(&value).unwrap();
        let calls = std::cell::Cell::new(0);
        let result = prepared
            .decode_into(&frame, |decoded: [[u64; 32]; 32]| {
                calls.set(calls.get() + 1);
                assert_eq!(crate::encode_canonical(&decoded).unwrap(), frame);
                assert_eq!(decoded.iter().flatten().sum::<u64>(), 7 * 32 * 32);
                assert_eq!(crate::core::payload_ctx(), context_before);
                assert_eq!(crate::core::to_bytes(&decoded).unwrap(), encoding_before);
                // The consumer has a new decode scope, beyond the retired schema's 32 elements.
                assert_eq!(
                    crate::decode_canonical::<Vec<u64>>(&nested).unwrap(),
                    vec![5; 64]
                );
                // Retired scopes must not refund the original decoder's counter controls early.
                assert_eq!(pool.reserved_bytes(), exact);
                assert!(pool.try_reserve_bytes(1).is_err());
                Err::<u64, _>("consumer semantic failure")
            })
            .unwrap();
        assert_eq!(result, Err("consumer semantic failure"));
        assert_eq!(calls.get(), 1);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(crate::core::payload_ctx(), context_before);
        assert_eq!(crate::core::to_bytes(&value).unwrap(), encoding_before);
    }

    #[test]
    fn prepared_canonical_consumer_unwind_retires_original_controls() {
        let pool = AllocationBudget::new(65_536);
        let frame = crate::encode_canonical(&11_u64).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = decoder(&frame, &pool)
                .decode_into::<u64, ()>(&frame, |_| panic!("injected canonical consumer unwind"));
        }));
        assert!(result.is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
