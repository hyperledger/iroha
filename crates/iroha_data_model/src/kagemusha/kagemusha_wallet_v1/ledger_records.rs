//! Canonical ledger keys and immutable payout records shared by execution and wallet finality verification.
//! These values carry no authority without an authenticated finalized World row.

use iroha_schema::IntoSchema;
use norito::{Decode, Encode};

/// WSV key `(kind, scheme, owner, entry)`; each fixed tag has exactly one value schema.
/// Owner is the asset digest for registration, wallet for wallet/load records, and object or
/// claim identity for immutable historical records. Unused words are exactly zero.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::LedgerKey")]
pub struct KagemushaWalletLedgerKeyV1([u8; 97]);
impl KagemushaWalletLedgerKeyV1 {
    /// Construct the exact fixed key without granting authority to its row.
    #[must_use]
    pub fn from_parts(kind: u8, scheme: [u8; 32], owner: [u8; 32], entry: [u8; 32]) -> Self {
        let mut bytes = [0; 97];
        bytes[0] = kind;
        bytes[1..33].copy_from_slice(&scheme);
        bytes[33..65].copy_from_slice(&owner);
        bytes[65..].copy_from_slice(&entry);
        Self(bytes)
    }
    /// Return the row tag, scheme, owner and entry words.
    #[must_use]
    pub fn components(self) -> (u8, [u8; 32], [u8; 32], [u8; 32]) {
        let mut scheme = [0; 32];
        let mut owner = [0; 32];
        let mut entry = [0; 32];
        scheme.copy_from_slice(&self.0[1..33]);
        owner.copy_from_slice(&self.0[33..65]);
        entry.copy_from_slice(&self.0[65..]);
        (self.0[0], scheme, owner, entry)
    }
}
impl norito::json::JsonKeyCodec for KagemushaWalletLedgerKeyV1 {
    fn encode_json_key(&self, out: &mut String) {
        self.0.encode_json_key(out);
    }
    fn encode_json_key_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> std::result::Result<(), norito::json::BoundedJsonError> {
        self.0.encode_json_key_to(out)
    }
    fn decode_json_key(encoded: &str) -> std::result::Result<Self, norito::json::Error> {
        if encoded.bytes().any(|byte| matches!(byte, b'a'..=b'f')) {
            return Err(norito::json::Error::Message(
                "KAGEMUSHA ledger keys require uppercase hex".into(),
            ));
        }
        <[u8; 97] as norito::json::JsonKeyCodec>::decode_json_key(encoded).map(Self)
    }
}

/// Separate replay namespaces prevent fee identities from colliding with unload nullifiers.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    norito::NoritoSchema,
    IntoSchema,
)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::ClaimKey")]
pub enum KagemushaWalletPayoutKeyV1 {
    /// Domain-separated unload nullifier.
    Unload([u8; 32]),
    /// Committed Send credit identity.
    Fee([u8; 32]),
}
/// Durable original payout result returned by every valid exact retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema, IntoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::Payout")]
#[repr(align(16))]
pub struct KagemushaWalletPayoutRecordV1 {
    /// Permanent exact-once key.
    pub key: KagemushaWalletPayoutKeyV1,
    /// Package digest (Unload) or Payment digest (fee).
    pub source: [u8; 32],
    /// Total reserve liability released; includes a quoted unload charge.
    pub amount: u128,
    /// Ledger transaction which first paid this claim.
    pub transaction: [u8; 32],
}
impl KagemushaWalletPayoutKeyV1 {
    /// Select the canonical immutable payout row in the ledger table.
    #[must_use]
    pub fn ledger_key(self, scheme: [u8; 32]) -> KagemushaWalletLedgerKeyV1 {
        let (kind, owner) = match self {
            Self::Unload(nullifier) => (4, nullifier),
            Self::Fee(credit_id) => (5, credit_id),
        };
        KagemushaWalletLedgerKeyV1::from_parts(kind, scheme, owner, [0; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::json::JsonKeyCodec as _;

    #[test]
    fn ledger_records_preserve_exact_keys_and_canonical_roundtrip() {
        for claim in [
            KagemushaWalletPayoutKeyV1::Unload([2; 32]),
            KagemushaWalletPayoutKeyV1::Fee([2; 32]),
        ] {
            let key = claim.ledger_key([1; 32]);
            let kind = if matches!(claim, KagemushaWalletPayoutKeyV1::Unload(_)) {
                4
            } else {
                5
            };
            assert_eq!(key.components(), (kind, [1; 32], [2; 32], [0; 32]));
            let bytes = norito::to_bytes(&key).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<KagemushaWalletLedgerKeyV1>(&bytes).unwrap(),
                key
            );
            let mut json = String::new();
            key.encode_json_key(&mut json);
            let json: String = norito::json::from_str(&json).unwrap();
            assert_eq!(
                KagemushaWalletLedgerKeyV1::decode_json_key(&json).unwrap(),
                key
            );
            let payout = KagemushaWalletPayoutRecordV1 {
                key: claim,
                source: [3; 32],
                amount: 17,
                transaction: [4; 32],
            };
            let bytes = norito::to_bytes(&payout).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<KagemushaWalletPayoutRecordV1>(&bytes).unwrap(),
                payout
            );
        }
        let key = KagemushaWalletLedgerKeyV1::from_parts(1, [0xAB; 32], [2; 32], [3; 32]);
        let mut json = String::new();
        key.encode_json_key(&mut json);
        let json: String = norito::json::from_str(&json).unwrap();
        assert!(KagemushaWalletLedgerKeyV1::decode_json_key(&json.to_lowercase()).is_err());
        assert!(KagemushaWalletLedgerKeyV1::decode_json_key(&json[..193]).is_err());
    }
}
