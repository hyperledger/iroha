//! Allocation-free scalar leaves and the same generated walk for inline records.
//!
//! Ordinary owning field decoding may allocate alignment backing even for Copy
//! values. These adapters use the canonical slice primitives and shared record
//! walk directly; they never call an archived owning decoder.

use super::*;
use common::*;
use iroha_data_model::{consensus::GlobalThresholdBeaconDkgSessionV1, id::NetworkId};
use norito::core::DecodeFromSlice;

pub(super) trait InlineValue: Copy {
    fn decode_payload(bytes: &[u8]) -> DecodeResult<Self>;
}
macro_rules! scalar {
    ($ty:ty) => {
        impl InlineValue for $ty {
            fn decode_payload(bytes: &[u8]) -> DecodeResult<Self> {
                let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                complete(used, bytes)?;
                Ok(value)
            }
        }
    };
}
scalar!(u16);
scalar!(u64);
scalar!(NetworkId);
impl<const N: usize> InlineValue for [u8; N] {
    fn decode_payload(bytes: &[u8]) -> DecodeResult<Self> {
        // Sequence elements retain the generic array wire. Direct record fields
        // use their CanonicalField raw-array decoder in the field macro below.
        let (value, used) = <Self as DecodeFromSlice>::decode_from_slice(bytes)?;
        complete(used, bytes)?;
        Ok(value)
    }
}

struct Destination<T>(T);
impl<T> FieldDestination for Destination<T> {
    type Error = DestinationError;
}
macro_rules! field {
    ($record:ty, $index:literal, $name:ident, [u8; $length:expr]) => {
        impl DecodeField<$index, [u8; $length]> for Destination<$record> {
            type Value = ();
            fn decode_field(
                &mut self,
                value: CanonicalField<'_, [u8; $length]>,
            ) -> DecodeResult<()> {
                self.0.$name = value.decode_owned()?;
                Ok(())
            }
        }
    };
    ($record:ty, $index:literal, $name:ident, $ty:ty) => {
        impl DecodeField<$index, $ty> for Destination<$record> {
            type Value = ();
            fn decode_field(&mut self, value: CanonicalField<'_, $ty>) -> DecodeResult<()> {
                self.0.$name = value.with_payload(<$ty as InlineValue>::decode_payload)?;
                Ok(())
            }
        }
    };
}
macro_rules! record {
    ($record:ty, $initial:expr) => {
        impl InlineValue for $record {
            fn decode_payload(bytes: &[u8]) -> DecodeResult<Self> {
                let mut destination = Destination($initial);
                let (_, used) = <$record>::decode_fields(bytes, &mut destination)?;
                complete(used, bytes)?;
                Ok(destination.0)
            }
        }
    };
}
field!(
    GlobalThresholdBeaconDkgConstantProofV1,
    0,
    commitment,
    [u8; 96]
);
field!(
    GlobalThresholdBeaconDkgConstantProofV1,
    1,
    response,
    [u8; 32]
);
record!(
    GlobalThresholdBeaconDkgConstantProofV1,
    GlobalThresholdBeaconDkgConstantProofV1 {
        commitment: [0; 96],
        response: [0; 32],
    }
);
field!(GlobalThresholdBeaconPublicShareV1, 0, index, u16);
field!(
    GlobalThresholdBeaconPublicShareV1,
    1,
    participant_seat_binding,
    [u8; 32]
);
field!(
    GlobalThresholdBeaconPublicShareV1,
    2,
    public_key_share,
    [u8; 96]
);
record!(
    GlobalThresholdBeaconPublicShareV1,
    GlobalThresholdBeaconPublicShareV1 {
        index: 0,
        participant_seat_binding: [0; 32],
        public_key_share: [0; 96],
    }
);
field!(GlobalThresholdBeaconDkgSessionV1, 0, version, u16);
field!(GlobalThresholdBeaconDkgSessionV1, 1, network_id, NetworkId);
field!(GlobalThresholdBeaconDkgSessionV1, 2, session_id, [u8; 32]);
field!(GlobalThresholdBeaconDkgSessionV1, 3, attempt_id, [u8; 32]);
field!(
    GlobalThresholdBeaconDkgSessionV1,
    4,
    authority_generation,
    u64
);
field!(GlobalThresholdBeaconDkgSessionV1, 5, roster_hash, [u8; 32]);
field!(GlobalThresholdBeaconDkgSessionV1, 6, committee_size, u16);
field!(GlobalThresholdBeaconDkgSessionV1, 7, threshold, u16);
field!(GlobalThresholdBeaconDkgSessionV1, 8, start_height, u64);
field!(
    GlobalThresholdBeaconDkgSessionV1,
    9,
    commitments_end_height,
    u64
);
field!(
    GlobalThresholdBeaconDkgSessionV1,
    10,
    deliveries_end_height,
    u64
);
field!(
    GlobalThresholdBeaconDkgSessionV1,
    11,
    acceptances_end_height,
    u64
);
// The initial identity is only initialized destination storage. The shared
// generated walk must replace every field before this record can be returned.
record!(
    GlobalThresholdBeaconDkgSessionV1,
    GlobalThresholdBeaconDkgSessionV1 {
        version: 0,
        network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0; 32])
        )),
        session_id: [0; 32],
        attempt_id: [0; 32],
        authority_generation: 0,
        roster_hash: [0; 32],
        committee_size: 0,
        threshold: 0,
        start_height: 0,
        commitments_end_height: 0,
        deliveries_end_height: 0,
        acceptances_end_height: 0,
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_allocations::allocations_during;
    use norito::core::{
        DecodeFlagsGuard, header_flags, serialize_to_buffer, write_len_header_to_vec,
    };

    fn encoded(value: &impl SerializePayload) -> Vec<u8> {
        let mut bytes = Vec::new();
        serialize_to_buffer(value, &mut bytes).unwrap();
        bytes
    }

    fn proof_fields(commitment: &[u8], response: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_len_header_to_vec(&mut bytes, commitment.len() as u64);
        bytes.extend_from_slice(commitment);
        write_len_header_to_vec(&mut bytes, response.len() as u64);
        bytes.extend_from_slice(response);
        bytes
    }

    #[test]
    fn inline_records_keep_distinct_raw_32_and_96_fields_without_allocating() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let proof = GlobalThresholdBeaconDkgConstantProofV1 {
                commitment: std::array::from_fn(|i| (i as u8).wrapping_add(0x31)),
                response: std::array::from_fn(|i| (i as u8).wrapping_add(0x73)),
            };
            let wire = encoded(&proof);
            assert_eq!(wire, proof_fields(&proof.commitment, &proof.response));
            let share = GlobalThresholdBeaconPublicShareV1 {
                index: 3,
                participant_seat_binding: std::array::from_fn(|i| (i as u8).wrapping_add(0x17)),
                public_key_share: std::array::from_fn(|i| (i as u8).wrapping_add(0x91)),
            };
            let share_wire = encoded(&share);
            let mut session = crate::beacon::fixtures::adaptive_dkg_session_fixture();
            session.session_id = std::array::from_fn(|i| (i as u8).wrapping_add(0x23));
            session.attempt_id = std::array::from_fn(|i| (i as u8).wrapping_add(0x47));
            session.roster_hash = std::array::from_fn(|i| (i as u8).wrapping_add(0xb3));
            let session_wire = encoded(&session);
            let mut decoded = None;
            assert_eq!(
                allocations_during(|| {
                    decoded = Some((
                        GlobalThresholdBeaconDkgConstantProofV1::decode_payload(&wire),
                        GlobalThresholdBeaconPublicShareV1::decode_payload(&share_wire),
                        GlobalThresholdBeaconDkgSessionV1::decode_payload(&session_wire),
                    ));
                }),
                0
            );
            let (actual_proof, actual_share, actual_session) = decoded.unwrap();
            assert_eq!(actual_proof.unwrap(), proof);
            assert_eq!(actual_share.unwrap(), share);
            assert_eq!(actual_session.unwrap(), session);
        }
    }

    #[test]
    fn inline_raw_fields_reject_wrong_widths_and_generic_array_substitutes() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let commitment: [u8; 96] = std::array::from_fn(|i| (i as u8).wrapping_add(0x31));
            let response: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_add(0x73));
            let generic_commitment = encoded(&commitment);
            let generic_response = encoded(&response);
            assert_ne!(generic_commitment, commitment);
            assert_ne!(generic_response, response);
            let short_commitment = &commitment[..95];
            let long_commitment = [0x31; 97];
            let short_response = &response[..31];
            let long_response = [0x73; 33];
            for wire in [
                proof_fields(short_commitment, &response),
                proof_fields(&long_commitment, &response),
                proof_fields(&commitment, short_response),
                proof_fields(&commitment, &long_response),
                proof_fields(&generic_commitment, &response),
                proof_fields(&commitment, &generic_response),
            ] {
                let mut result = None;
                assert_eq!(
                    allocations_during(|| {
                        result = Some(GlobalThresholdBeaconDkgConstantProofV1::decode_payload(
                            &wire,
                        ));
                    }),
                    0
                );
                assert!(matches!(
                    result.unwrap(),
                    Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
                ));
            }
        }
    }

    #[test]
    fn generic_coefficient_sequence_keeps_array_element_framing_without_allocating() {
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let coefficients: Vec<[u8; 96]> = vec![
                std::array::from_fn(|i| (i as u8).wrapping_add(0x29)),
                std::array::from_fn(|i| (i as u8).wrapping_add(0x83)),
            ];
            let wire = encoded(&coefficients);
            let budget = AllocationBudget::new(1 << 20);
            let mut destination = CopySequence::new(coefficients.len(), [0; 96], &budget).unwrap();
            let reserved = budget.reserved_bytes();
            let mut result = None;
            assert_eq!(
                allocations_during(|| result = Some(destination.decode(&wire))),
                0
            );
            result.unwrap().unwrap();
            assert_eq!(destination.values.as_slice(), coefficients.as_slice());
            assert_eq!(budget.reserved_bytes(), reserved);
            drop(destination);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
