//! A rejected retry's reference to the original successful settlement.

use iroha_crypto::HashOf;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{block::BlockHeader, isi::SettlementId};

/// Why a new direct payment carrier cannot consume an existing business identity.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::executor::settlement::SettlementReplayDispositionV1")]
pub enum SettlementReplayDispositionV1 {
    /// The complete signed payment intent already succeeded.
    AlreadySettled,
    /// This business identity belongs to a different successful intent.
    ConflictingIntent,
}

/// Consensus outcome of an uncharged direct-payment retry, pointing at its original receipt.
///
/// This rejects only the new carrier. It neither reverses the original settlement nor
/// proves its success by itself. A client must independently authenticate the original
/// certified block and successful input/output before constructing a verified receipt.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::executor::settlement::SettlementReplayV1")]
pub struct SettlementReplayV1 {
    /// Original payer-scoped business identity.
    pub settlement_id: SettlementId,
    /// Whether the new complete intent matches the original successful intent.
    pub disposition: SettlementReplayDispositionV1,
    /// Height containing the original successful settlement.
    pub committed_block_height: u64,
    /// Exact original successful settlement's block hash.
    pub committed_block_hash: HashOf<BlockHeader>,
}

impl core::fmt::Display for SettlementReplayV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "settlement {}: {:?}; original block {} ({})",
            self.settlement_id,
            self.disposition,
            self.committed_block_height,
            self.committed_block_hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};

    #[test]
    fn settlement_replay_preserves_original_identity_in_canonical_and_json_frames() {
        let payer = crate::account::AccountId::new(
            KeyPair::from_seed(vec![0x72; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        for disposition in [
            SettlementReplayDispositionV1::AlreadySettled,
            SettlementReplayDispositionV1::ConflictingIntent,
        ] {
            let replay = SettlementReplayV1 {
                settlement_id: SettlementId::new(
                    payer.clone(),
                    "customer-payment-9".parse().unwrap(),
                ),
                disposition,
                committed_block_height: 42,
                committed_block_hash: HashOf::from_untyped_unchecked(Hash::new(
                    b"original settlement",
                )),
            };
            let bytes = norito::encode_canonical(&replay).unwrap();
            assert_eq!(
                norito::decode_canonical::<SettlementReplayV1>(&bytes).unwrap(),
                replay
            );
            let json = norito::json::to_json(&replay).unwrap();
            assert_eq!(
                norito::json::from_str::<SettlementReplayV1>(&json).unwrap(),
                replay
            );
            assert!(replay.to_string().contains("original block 42"));
            let failure = crate::ValidationFail::SettlementReplay(Box::new(replay));
            let bytes = norito::encode_canonical(&failure).unwrap();
            assert_eq!(
                norito::decode_canonical::<crate::ValidationFail>(&bytes).unwrap(),
                failure
            );
            assert!(core::mem::size_of::<crate::ValidationFail>() < 128);
        }
    }
}
