//! Original-pool ownership and canonical codec regressions for retained RS16 row bytes.

use crate::availability::{MAX_DA_CHUNK_SIZE_BYTES, RowBytes};
use crate::bytes::ByteAdmissionError;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use norito::codec::{DecodeAll as _, Encode as _};

#[test]
fn source_admission_clone_and_final_refund_preserve_actual_backing() {
    let budget = AllocationBudget::new(1 << 20);
    let foreign = AllocationBudget::new(1 << 20);
    let mut bytes = ChargedBuffer::new(3, &budget).unwrap();
    bytes.append(&[1, 2, 3]).unwrap();
    let pointer = bytes.as_slice().as_ptr();
    let value = RowBytes::from_charged(bytes, &budget)
        .unwrap_or_else(|(_, error)| panic!("funded witness rejected: {error:?}"));
    let reserved = budget.reserved_bytes();
    assert!(reserved > 3);
    assert!(value.admitted_to(&budget));
    assert!(!value.admitted_to(&foreign));
    assert_eq!(pointer, value.as_slice().as_ptr());
    let mut clone = value.clone();
    assert_eq!(clone.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), reserved);
    assert!(matches!(
        clone.admit(&foreign),
        Err(ByteAdmissionError::ForeignBudget)
    ));
    drop(value);
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(clone.as_slice(), &[1, 2, 3]);
    drop(clone);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn refused_control_returns_same_original_buffer_for_retry() {
    let budget = AllocationBudget::new(3);
    let mut bytes = ChargedBuffer::new(3, &budget).unwrap();
    bytes.append(&[1, 2, 3]).unwrap();
    let pointer = bytes.as_slice().as_ptr();
    let (bytes, error) = RowBytes::from_charged(bytes, &budget).unwrap_err();
    assert!(matches!(error, ByteAdmissionError::ControlAdmission(_)));
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), 3);
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn in_place_control_refusal_keeps_original_copy_across_retry_and_untrusted_clone() {
    let budget = AllocationBudget::new(4096);
    let occupied = ChargedBuffer::<u8>::new(3896, &budget).unwrap();
    let mut witness = RowBytes::from_untrusted(vec![7; 200]).unwrap();
    let source_pointer = witness.as_slice().as_ptr();
    let canonical = witness.encode();
    assert!(matches!(
        witness.admit(&budget),
        Err(ByteAdmissionError::ControlAdmission(_))
    ));
    let original_copy = witness.as_slice().as_ptr();
    assert_ne!(original_copy, source_pointer);
    assert_eq!(budget.reserved_bytes(), 4096);
    assert!(!witness.admitted_to(&budget));
    assert_eq!(witness.encode(), canonical);
    let clone = witness.clone();
    assert_eq!(clone.as_slice().as_ptr(), source_pointer);
    assert!(!clone.admitted_to(&budget));
    drop(clone);
    assert_eq!(budget.reserved_bytes(), 4096);
    let foreign = AllocationBudget::new(4096);
    assert!(matches!(
        witness.admit(&foreign),
        Err(ByteAdmissionError::ForeignBudget)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(witness.as_slice().as_ptr(), original_copy);
    assert!(witness.admit(&budget).unwrap_err().is_local_refusal());
    assert_eq!(witness.as_slice().as_ptr(), original_copy);
    drop(occupied);
    witness.admit(&budget).unwrap();
    assert!(witness.admitted_to(&budget));
    assert_eq!(witness.as_slice().as_ptr(), original_copy);
    assert_eq!(witness.encode(), canonical);
    let clone = witness.clone();
    assert_eq!(clone.as_slice().as_ptr(), original_copy);
    let charged = budget.reserved_bytes();
    witness.admit(&budget).unwrap();
    assert_eq!(budget.reserved_bytes(), charged);
    drop(witness);
    assert_eq!(budget.reserved_bytes(), charged);
    drop(clone);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn dropping_pending_admission_frees_only_its_actual_original_backing() {
    let budget = AllocationBudget::new(200);
    let mut witness = RowBytes::from_untrusted(vec![1; 200]).unwrap();
    assert!(matches!(
        witness.admit(&budget),
        Err(ByteAdmissionError::ControlAdmission(_))
    ));
    let clone = witness.clone();
    assert_eq!(budget.reserved_bytes(), 200);
    drop(witness);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(clone.as_slice(), &[1; 200]);
    assert!(!clone.admitted_to(&budget));
}

#[test]
fn sole_canonical_byte_sequence_never_encodes_admission_state() {
    let budget = AllocationBudget::new(2 * MAX_DA_CHUNK_SIZE_BYTES as usize);
    let bytes = vec![9; MAX_DA_CHUNK_SIZE_BYTES as usize];
    let untrusted = RowBytes::from_untrusted(bytes.clone()).unwrap();
    let mut admitted = untrusted.clone();
    admitted.admit(&budget).unwrap();
    let encoded = admitted.encode();
    assert_eq!(encoded, bytes.encode());
    assert_eq!(encoded, untrusted.encode());
    let decoded = RowBytes::decode_all(&mut encoded.as_slice()).unwrap();
    assert_eq!(decoded, admitted);
    assert!(!decoded.admitted_to(&budget));
    assert!(
        RowBytes::decode_all(
            &mut [u64::MAX.to_le_bytes().as_slice(), &[1]]
                .concat()
                .as_slice()
        )
        .is_err()
    );
    assert!(
        RowBytes::decode_all(
            &mut (MAX_DA_CHUNK_SIZE_BYTES as usize as u64 + 1)
                .to_le_bytes()
                .as_slice()
        )
        .is_err()
    );
    assert!(RowBytes::decode_all(&mut 0_u64.to_le_bytes().as_slice()).is_err());
    assert!(RowBytes::decode_all(&mut 3_u64.to_le_bytes().as_slice()).is_err());
}
