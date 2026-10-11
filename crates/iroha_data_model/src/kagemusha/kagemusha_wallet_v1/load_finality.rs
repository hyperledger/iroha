//! Retained native Commit certificates and counted successful-Load event inclusion.
//!
//! Decoding is only a shape check. The wallet authenticates BLS signatures against its
//! independently selected signed genesis and certified epoch successors before Advance.

use super::{
    WalletResult, decode_frame_v1, encode_frame_v1, invalid_v1, require_canonical_field_v1,
    require_version_v1,
};
use crate::{
    events::{
        EventBox,
        data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
    },
    isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
    sumeragi_finality::{
        FinalityError, SumeragiCommitCertificateV1, SumeragiCommitVerifierV1,
        SumeragiFinalityVerifier,
    },
};
use iroha_crypto::{HashOf, MerkleProof};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Maximum canonical native finality envelope for one receipt certificate and event proof.
/// Epoch transitions are synchronized separately as bounded original certificates.
/// This online custody bound does not change the 10,000-byte peer Payment bound.
pub const KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1: usize = 256 * 1024;

/// Original native consensus evidence for one successful ordinary Load receipt.
/// There are no proving keys, recursive proofs, accumulator claims or delegated signers.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLoadFinalityV1"
)]
pub struct KagemushaWalletLoadFinalityV1 {
    /// First-release version, exactly one.
    pub version: u16,
    /// Canonical digest of the exact original receipt being credited.
    pub receipt_digest: [u8; 32],
    /// The receipt block's original native certificate, without an epoch-history prefix.
    pub certificate: SumeragiCommitCertificateV1,
    /// Counted inclusion of the exact successful-Load event in the final signed result.
    pub event_proof: MerkleProof<EventBox>,
}

impl KagemushaWalletLoadFinalityV1 {
    /// Validate finite canonical data shape without granting finality authority.
    ///
    /// # Errors
    /// Rejects another version, noncanonical receipt digest, malformed certificate or size bounds.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("load_finality.version", self.version)?;
        require_canonical_field_v1("load_finality.receipt_digest", &self.receipt_digest)?;
        if self.event_proof.audit_path().len() > 32 {
            return Err(invalid_v1("load_finality.event_proof"));
        }
        self.certificate
            .validate_shape()
            .map_err(|_| invalid_v1("load_finality.certificate"))?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1)?;
        Ok(())
    }

    /// Encode one validated complete canonical evidence frame.
    ///
    /// # Errors
    /// Rejects malformed fields, encoding errors or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1)
    }

    /// Decode one bounded canonical evidence frame without granting finality authority.
    ///
    /// # Errors
    /// Rejects oversized, noncanonical or malformed native evidence.
    pub fn decode_canonical(bytes: &[u8]) -> WalletResult<Self> {
        let evidence: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1)?;
        evidence.validate()?;
        Ok(evidence)
    }

    /// Verify direct BLS finality and exact receipt inclusion under a selected native root.
    /// This check must succeed before the wallet permits its Load Advance signature.
    ///
    /// # Errors
    /// Rejects another receipt, forged BLS, omitted/changed epoch authority, substituted
    /// event inclusion, private roots or a different genesis/chain.
    pub fn verify(
        &self,
        native: &SumeragiFinalityVerifier,
        receipt: &KagemushaWalletLoadReceiptV1,
    ) -> Result<(), FinalityError> {
        self.verify_with(&mut SumeragiCommitVerifierV1::new(native)?, receipt)
    }

    /// Verify against the receipt epoch restored from authenticated native custody.
    /// Epoch synchronization and its durable promotion are separate from this receipt envelope.
    ///
    /// # Errors
    /// The same finality and inclusion failures as [`Self::verify`]. Failure never updates
    /// the caller's authenticated epoch state.
    pub fn verify_with(
        &self,
        selected: &mut SumeragiCommitVerifierV1,
        receipt: &KagemushaWalletLoadReceiptV1,
    ) -> Result<(), FinalityError> {
        self.validate()
            .map_err(|error| FinalityError(error.to_string()))?;
        let digest = receipt
            .receipt_digest()
            .map_err(|error| FinalityError(error.to_string()))?;
        if digest != self.receipt_digest {
            return Err(FinalityError("native Load receipt digest differs".into()));
        }
        let mut candidate = selected.clone();
        let verified = candidate.verify(&self.certificate)?;
        if verified.height() != receipt.block_height {
            return Err(FinalityError(
                "native Load certificate height differs".into(),
            ));
        }
        let event = KagemushaLoadCommittedV1::from_receipt(receipt)
            .map_err(|error| FinalityError(error.to_string()))?;
        let event = EventBox::Data(DataEvent::KagemushaLoadCommitted(event).into());
        let root = verified
            .execution()
            .event_commitment
            .as_ref()
            .ok_or_else(|| FinalityError("native Load certificate has no events".into()))?;
        if !self.event_proof.verify(&HashOf::new(&event), root) {
            return Err(FinalityError("native Load event inclusion differs".into()));
        }
        *selected = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_schema_matches_direct_finality() {
        use crate::sumeragi_finality::SumeragiCommitCheckpointV1;
        let mut schema = KagemushaWalletLoadFinalityV1::schema();
        SumeragiCommitCheckpointV1::update_schema_map(&mut schema);
        let generated = norito::json::to_value(&schema).unwrap();
        let names = [
            KagemushaWalletLoadFinalityV1::type_name(),
            SumeragiCommitCertificateV1::type_name(),
            SumeragiCommitCheckpointV1::type_name(),
            iroha_sumeragi::types::Hash32::type_name(),
            MerkleProof::<EventBox>::type_name(),
            Vec::<Option<HashOf<EventBox>>>::type_name(),
            Option::<HashOf<EventBox>>::type_name(),
            HashOf::<EventBox>::type_name(),
        ];
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/references/schema.json");
        let mut saved: norito::json::Value =
            norito::json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if std::env::var_os("IROHA_UPDATE_KAGEMUSHA_WALLET_VECTORS")
            .is_some_and(|value| value == "1")
        {
            let entries = saved.as_object_mut().unwrap();
            entries.remove(&Vec::<SumeragiCommitCertificateV1>::type_name());
            for name in &names {
                entries.insert(
                    name.clone(),
                    generated
                        .get(name.as_str())
                        .expect("canonical schema entry")
                        .clone(),
                );
            }
            let mut json = norito::json::to_string_pretty(&saved).unwrap();
            json.push('\n');
            std::fs::write(&path, json).unwrap();
        }
        for name in names {
            assert_eq!(
                saved.get(name.as_str()),
                generated.get(name.as_str()),
                "native finality schema descriptor {name}"
            );
        }
    }

    #[test]
    fn bounded_canonical_evidence_roundtrip_is_shape_only() {
        let tree: iroha_crypto::MerkleTree<EventBox> = [HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"shape-only event"),
        )]
        .into_iter()
        .collect();
        let evidence = KagemushaWalletLoadFinalityV1 {
            version: 1,
            receipt_digest: [2; 32],
            certificate: SumeragiCommitCertificateV1 {
                consensus_header: vec![1; 32],
                commit_qc: vec![2; 32],
                result_preimage: vec![3; 32],
            },
            event_proof: tree.get_proof(0).unwrap(),
        };
        let encoded = evidence.to_canonical_bytes().unwrap();
        assert_eq!(
            KagemushaWalletLoadFinalityV1::decode_canonical(&encoded).unwrap(),
            evidence
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(KagemushaWalletLoadFinalityV1::decode_canonical(&trailing).is_err());
        assert!(
            KagemushaWalletLoadFinalityV1::decode_canonical(&encoded[..encoded.len() - 1]).is_err()
        );
        for bad in [
            KagemushaWalletLoadFinalityV1 {
                version: 2,
                ..evidence.clone()
            },
            KagemushaWalletLoadFinalityV1 {
                receipt_digest: [255; 32],
                ..evidence.clone()
            },
            KagemushaWalletLoadFinalityV1 {
                event_proof: MerkleProof::from_audit_path(0, vec![None; 33]),
                ..evidence.clone()
            },
            KagemushaWalletLoadFinalityV1 {
                certificate: SumeragiCommitCertificateV1 {
                    consensus_header: vec![],
                    ..evidence.certificate.clone()
                },
                ..evidence
            },
        ] {
            assert!(bad.to_canonical_bytes().is_err());
        }
    }
}
