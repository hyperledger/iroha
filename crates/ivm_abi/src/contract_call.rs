//! Authenticated target binding for the sole typed cross-contract call boundary.

use iroha_crypto::Hash;
use norito::{Decode, Encode};

/// Maximum framed size of the fixed V1 binding, checked before decoding.
pub const MAX_CONTRACT_CALL_BINDING_BYTES_V1: usize = 128;

/// An exact public entrypoint of the complete artifact used during compilation.
///
/// The caller embeds this record as an immutable `NoritoBytes` literal. A host must compare the
/// live instance's active code hash and admitted entrypoint ordinal before capturing argument
/// words or executing effects. The code hash commits the complete argument and return schemas,
/// entrypoint kind, and authorization declarations; a selector string is not an alternative.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::contract_call::ContractCallBindingV1")]
pub struct ContractCallBindingV1 {
    /// Complete authenticated callee artifact hash.
    pub code_hash: Hash,
    /// Ordinal in that artifact's signed public entrypoint table.
    pub entrypoint: u32,
}

impl ContractCallBindingV1 {
    /// Encode the fixed record with canonical V1 framing.
    ///
    /// # Errors
    /// Returns a Norito encoding error if the canonical frame cannot be produced.
    pub fn to_bytes(&self) -> Result<Vec<u8>, norito::Error> {
        norito::encode_canonical(self)
    }

    /// Decode only the bounded, canonical framed V1 record.
    ///
    /// # Errors
    /// Rejects oversized, unframed, truncated, extended, or noncanonical records.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, norito::Error> {
        if bytes.len() > MAX_CONTRACT_CALL_BINDING_BYTES_V1 {
            return Err(norito::Error::LengthMismatch);
        }
        let value: Self = norito::decode_canonical(bytes)?;
        if value.to_bytes()? != bytes {
            return Err(norito::Error::Message(
                "noncanonical contract call binding".to_owned(),
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_artifact_and_ordinal_roundtrip() {
        let binding = ContractCallBindingV1 {
            code_hash: Hash::new(b"callee artifact"),
            entrypoint: u32::MAX,
        };
        let encoded = binding.to_bytes().expect("encode binding");
        assert!(encoded.len() <= MAX_CONTRACT_CALL_BINDING_BYTES_V1);
        assert_eq!(
            ContractCallBindingV1::from_bytes(&encoded).unwrap(),
            binding
        );
        assert_ne!(
            ContractCallBindingV1 {
                entrypoint: 0,
                ..binding
            }
            .to_bytes()
            .unwrap(),
            encoded
        );
    }

    #[test]
    fn rejects_retired_unframed_truncated_and_extended_records() {
        let encoded = ContractCallBindingV1 {
            code_hash: Hash::new(b"callee artifact"),
            entrypoint: 1,
        }
        .to_bytes()
        .unwrap();
        for end in 0..encoded.len() {
            assert!(ContractCallBindingV1::from_bytes(&encoded[..end]).is_err());
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(ContractCallBindingV1::from_bytes(&extended).is_err());
        assert!(ContractCallBindingV1::from_bytes(b"swap").is_err());
        assert!(ContractCallBindingV1::from_bytes(&[0; 129]).is_err());
    }
}
