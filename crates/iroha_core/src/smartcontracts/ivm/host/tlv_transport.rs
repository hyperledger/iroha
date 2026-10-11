//! Canonical Core pointer-ABI TLV emission.

use super::{CoreHostImpl, QueryStateAccess};
use iroha_crypto::Hash;
use iroha_data_model::smart_contract::entrypoint::ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1;
use ivm::{IVM, PointerType, VMError};

fn envelope_bytes(payload_bytes: usize) -> Result<usize, VMError> {
    u32::try_from(payload_bytes).map_err(|_| VMError::NoritoInvalid)?;
    payload_bytes
        .checked_add(ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1)
        .ok_or(VMError::NoritoInvalid)
}

/// Emit the sole Core TLV layout directly into the caller's backing owner.
fn write_tlv_payload(
    pointer_type: PointerType,
    payload: &[u8],
    mut append: impl FnMut(&[u8]) -> Result<(), VMError>,
) -> Result<(), VMError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
    let mut header = [0_u8; 7];
    header[..2].copy_from_slice(&(pointer_type as u16).to_be_bytes());
    header[2] = 1;
    header[3..].copy_from_slice(&payload_len.to_be_bytes());
    append(&header)?;
    append(payload)?;
    append(Hash::new(payload).as_ref())
}

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn alloc_tlv_payload(
        vm: &mut IVM,
        pointer_type: PointerType,
        payload: &[u8],
    ) -> Result<u64, VMError> {
        let out = Self::encode_tlv_payload(pointer_type, payload)?;
        vm.alloc_host_tlv(&out)
    }

    pub(super) fn encode_tlv_payload(
        pointer_type: PointerType,
        payload: &[u8],
    ) -> Result<Vec<u8>, VMError> {
        let mut out = Vec::with_capacity(envelope_bytes(payload.len())?);
        write_tlv_payload(pointer_type, payload, |part| {
            out.extend_from_slice(part);
            Ok(())
        })?;
        Ok(out)
    }

    pub(super) fn alloc_norito_bytes(vm: &mut IVM, payload: &[u8]) -> Result<u64, VMError> {
        Self::alloc_tlv_payload(vm, PointerType::NoritoBytes, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_tlv_authenticates_the_exact_type_and_payload() {
        for kind in [PointerType::Blob, PointerType::NoritoBytes] {
            for payload in [&[][..], &[0, 1, 127, 255][..]] {
                let envelope = super::super::CoreHost::encode_tlv_payload(kind, payload).unwrap();
                assert_eq!(
                    envelope.len(),
                    payload.len() + ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1
                );
                let decoded = ivm::pointer_abi::validate_tlv_bytes(&envelope).unwrap();
                assert_eq!(decoded.type_id, kind);
                assert_eq!(decoded.payload, payload);
                let mut corrupt = envelope;
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(ivm::pointer_abi::validate_tlv_bytes(&corrupt).is_err());
            }
        }
    }
}
