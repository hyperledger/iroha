//! Byte equivalence, fixed layout, writer bounds and unchanged original codec errors.

use super::*;
use iroha_data_model::transaction::{
    SignedTransaction, TransactionEntrypoint,
    signed::{
        SealedTransactionCommitmentPayload, SealedTransactionReveal,
        SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
    },
};
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
use std::{cell::Cell, io};

use super::super::wire_v1_test_support as support;

// Independent test-only oracle for the previously established wire contract: version one,
// then the canonical default-layout bare payload. This is not a production fallback encoder.
fn established_wire(value: &impl norito::NoritoSerialize) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut bytes = vec![1];
    norito::core::serialize_to_buffer(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn original_signed_and_entrypoint_vectors_traits_and_roundtrips_match() {
    for profile in [
        "advance",
        "check",
        "check-present",
        "check-metadata",
        "large",
        "multisig-a",
        "multisig-b",
    ] {
        let signed = support::signed(profile);
        let original = established_wire(&signed);
        assert_eq!(signed.encode_wire_v1().unwrap(), original);
        let plan = WireV1Plan::new(&signed).unwrap();
        assert_eq!(plan.wire_length(), original.len());
        assert_eq!(plan.into_vec().unwrap(), original);
        assert_eq!(signed.encode_versioned(), original);
        assert_eq!(
            SignedTransaction::decode_all_versioned(&original).unwrap(),
            signed
        );
        let entry = TransactionEntrypoint::External(signed);
        let original_entry = established_wire(&entry);
        assert_eq!(entry.encode_wire_v1().unwrap(), original_entry);
        assert_eq!(
            WireV1Plan::new(&entry).unwrap().into_vec().unwrap(),
            original_entry
        );
        assert_eq!(entry.encode_versioned(), original_entry);
        assert_eq!(
            TransactionEntrypoint::decode_all_versioned(&original_entry).unwrap(),
            entry
        );
        assert_ne!(original, original_entry);
        assert_ne!(original_entry, norito::encode_canonical(&entry).unwrap());
    }
}

#[test]
fn same_payload_with_different_authorization_has_different_exact_wire() {
    let first = support::signed("multisig-a");
    let second = support::signed("multisig-b");
    assert_eq!(first.hash(), second.hash());
    assert_ne!(
        WireV1Plan::new(&first).unwrap().into_vec().unwrap(),
        WireV1Plan::new(&second).unwrap().into_vec().unwrap()
    );
}

#[test]
fn sealed_entrypoint_variants_preserve_canonical_wire_and_roundtrip() {
    let signed = support::signed("advance");
    let keypair =
        iroha_crypto::KeyPair::from_seed(vec![0x91; 32], iroha_crypto::Algorithm::Ed25519);
    let network = *signed.network_id().unwrap();
    let salt = [0xA5; 32];
    let commitment = compute_sealed_transaction_commitment(&network, &signed, salt, 42);
    let payload = SealedTransactionCommitmentPayload::new(
        network,
        signed.authority().clone(),
        commitment,
        10,
        42,
        std::num::NonZeroU64::new(7),
    );
    let sealed =
        SignedSealedTransactionCommitment::try_sign(payload, keypair.private_key()).unwrap();
    sealed.verify_signature().unwrap();
    for entry in [
        TransactionEntrypoint::SealedCommitment(sealed),
        TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(commitment, signed, salt)),
    ] {
        let original = established_wire(&entry);
        assert_eq!(entry.encode_wire_v1().unwrap(), original);
        let _outer = DecodeFlagsGuard::enter(0);
        let plan = WireV1Plan::new(&entry).unwrap();
        assert_eq!(plan.wire_length(), original.len());
        assert_eq!(plan.into_vec().unwrap(), original);
        assert_eq!(norito::core::effective_decode_flags(), Some(0));
        assert_eq!(entry.encode_versioned(), original);
        assert_eq!(
            TransactionEntrypoint::decode_all_versioned(&original).unwrap(),
            entry
        );
    }
}

#[test]
fn ambient_fixed_length_layout_cannot_change_v1_and_is_restored() {
    let signed = support::signed("large");
    let canonical = signed.encode_wire_v1().unwrap();
    let _outer = DecodeFlagsGuard::enter(0);
    let before = norito::core::encoded_payload_len(&signed).unwrap();
    assert_ne!(before + 1, canonical.len());
    assert_eq!(
        WireV1Plan::new(&signed).unwrap().into_vec().unwrap(),
        canonical
    );
    assert_eq!(norito::core::encoded_payload_len(&signed).unwrap(), before);
}

struct Changing {
    length: Cell<usize>,
    fail: Cell<bool>,
}

impl SerializePayload for Changing {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        if self.fail.get() {
            return Err(Error::AllocationFailed { bytes: 73 });
        }
        for _ in 0..self.length.get() {
            writer.write_all(&[7])?;
        }
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(usize::MAX)
    }
}

#[test]
fn count_traverses_real_serializer_and_both_changed_extents_refuse() {
    let value = Changing {
        length: Cell::new(3),
        fail: Cell::new(false),
    };
    let plan = WireV1Plan::new(&value).unwrap();
    assert_eq!(plan.wire_length(), 4);
    value.length.set(4);
    let mut output = Vec::new();
    assert!(matches!(
        plan.write_to(&mut output),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(output.len(), 4);
    value.length.set(2);
    output.clear();
    assert!(matches!(
        plan.write_to(&mut output),
        Err(Error::LengthMismatch)
    ));
    assert_eq!(output, [1, 7, 7]);
}

#[test]
fn serializer_errors_survive_both_counting_and_writing() {
    let _outer = DecodeFlagsGuard::enter(0);
    let value = Changing {
        length: Cell::new(3),
        fail: Cell::new(true),
    };
    assert!(matches!(
        WireV1Plan::new(&value),
        Err(Error::AllocationFailed { bytes: 73 })
    ));
    assert_eq!(norito::core::effective_decode_flags(), Some(0));
    value.fail.set(false);
    let plan = WireV1Plan::new(&value).unwrap();
    value.fail.set(true);
    assert!(matches!(
        plan.write_to(&mut Vec::new()),
        Err(Error::AllocationFailed { bytes: 73 })
    ));
    assert_eq!(norito::core::effective_decode_flags(), Some(0));
}

struct OneByteWriter {
    bytes: Vec<u8>,
    fail_after: Option<usize>,
}
impl Write for OneByteWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_after == Some(self.bytes.len()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        self.bytes.push(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("encoding must not flush or publish")
    }
}

#[test]
fn partial_destination_writes_work_and_original_io_refusal_survives() {
    let signed = support::signed("advance");
    let plan = WireV1Plan::new(&signed).unwrap();
    let mut output = OneByteWriter {
        bytes: Vec::new(),
        fail_after: None,
    };
    plan.write_to(&mut output).unwrap();
    assert_eq!(output.bytes, signed.encode_wire_v1().unwrap());
    output.bytes.clear();
    output.fail_after = Some(7);
    let _outer = DecodeFlagsGuard::enter(0);
    assert!(
        matches!(plan.write_to(&mut output), Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(output.bytes.len(), 7);
    assert_eq!(norito::core::effective_decode_flags(), Some(0));
}

#[test]
fn ordinary_output_obeys_zero_and_cumulative_inherited_allowance() {
    let value = Changing {
        length: Cell::new(3),
        fail: Cell::new(false),
    };
    let limits = |bytes| norito::DecodeLimits::new(4096, 4096, 4096, bytes, 32);
    norito::with_decode_limits(limits(0), || {
        let error = WireV1Plan::new(&value)?.into_vec().unwrap_err();
        assert!(norito::core::decode_error_matches_active_limits(&error));
        Ok(())
    })
    .unwrap();
    norito::with_decode_limits(limits(4), || {
        assert_eq!(WireV1Plan::new(&value)?.into_vec()?, [1, 7, 7, 7]);
        let error = WireV1Plan::new(&value)?.into_vec().unwrap_err();
        assert!(norito::core::decode_error_matches_active_limits(&error));
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        WireV1Plan::new(&value).unwrap().into_vec_bounded(3),
        Err(Error::LengthMismatch)
    ));
}
