//! Native occurrence identities, distinct from a proposal's instruction fingerprint.
use super::*;
use core::{fmt, str::FromStr};

macro_rules! occurrence_bytes {
    ($name:ident, $schema:literal, $description:literal) => {
        #[doc = $description]
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
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(name = $schema)]
        #[norito(validate = "Self::checked")]
        pub struct $name([u8; 32]);
        impl $name {
            /// Borrow the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            fn checked(self) -> Result<Self, norito::Error> {
                if self.0 == [0; 32] {
                    Err(norito::Error::Message(
                        "multisig occurrence identity must be nonzero".into(),
                    ))
                } else {
                    Ok(self)
                }
            }
        }
        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
        impl FromStr for $name {
            type Err = norito::Error;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(norito::Error::Message(
                        "multisig occurrence identity requires 64 lowercase hexadecimal digits"
                            .into(),
                    ));
                }
                let mut bytes = [0; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| {
                        norito::Error::Message("invalid multisig occurrence identity".into())
                    })?;
                }
                Self(bytes).checked()
            }
        }
        impl JsonSerialize for $name {
            fn json_serialize(&self, out: &mut String) {
                json::write_json_string(&self.to_string(), out);
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn json::JsonWriteSink,
            ) -> Result<(), json::BoundedJsonError> {
                json::write_json_string_to(&self.to_string(), out)
            }
        }
        impl JsonDeserialize for $name {
            fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
                String::json_deserialize(parser)?
                    .parse()
                    .map_err(|error: norito::Error| json::Error::Message(error.to_string()))
            }
        }
    };
}
occurrence_bytes!(
    MultisigProposalNonce,
    "iroha_executor_data_model::isi::multisig::MultisigProposalNonce",
    "A nonzero caller nonce retained for one multisig proposal occurrence."
);
occurrence_bytes!(
    MultisigProposalId,
    "iroha_executor_data_model::isi::multisig::MultisigProposalId",
    "Native network/account/nonce identity of one multisig proposal occurrence."
);

impl MultisigProposalNonce {
    /// Validate a caller-generated nonce; zero is never a proposal occurrence.
    /// # Errors
    /// Returns an error for the all-zero nonce.
    pub fn new(bytes: [u8; 32]) -> Result<Self, norito::Error> {
        Self(bytes).checked()
    }
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_executor_data_model::isi::multisig::ProposalOccurrenceIdentity")]
struct ProposalIdentity {
    domain: String,
    network_id: NetworkId,
    account: AccountId,
    nonce: MultisigProposalNonce,
}
impl MultisigProposalId {
    /// Derive an occurrence from its immutable native network, account and nonce.
    /// Instructions deliberately do not enter this identity: conflicting nonce reuse
    /// must address the same ledger slot, not create another proposal.
    #[must_use]
    pub fn derive(network: &NetworkId, account: &AccountId, nonce: &MultisigProposalNonce) -> Self {
        Self(
            *HashOf::new(&ProposalIdentity {
                domain: "iroha.multisig.proposal-occurrence.v1".into(),
                network_id: *network,
                account: account.clone(),
                nonce: *nonce,
            })
            .as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    fn network(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([seed; 32])))
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }
    #[test]
    fn occurrence_identity_binds_only_original_network_account_and_nonzero_nonce() {
        let nonce = MultisigProposalNonce::new([7; 32]).unwrap();
        let id = MultisigProposalId::derive(&network(1), &account(2), &nonce);
        assert_eq!(
            id,
            MultisigProposalId::derive(&network(1), &account(2), &nonce)
        );
        assert_ne!(
            id,
            MultisigProposalId::derive(&network(3), &account(2), &nonce)
        );
        assert_ne!(
            id,
            MultisigProposalId::derive(&network(1), &account(4), &nonce)
        );
        assert_ne!(
            id,
            MultisigProposalId::derive(
                &network(1),
                &account(2),
                &MultisigProposalNonce::new([8; 32]).unwrap()
            )
        );
        assert_eq!(id.to_string().len(), 64);
        assert_eq!(id.to_string().parse::<MultisigProposalId>().unwrap(), id);
        for value in [
            "".into(),
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            format!("0x{}", "a".repeat(64)),
            format!(" {}", "a".repeat(64)),
        ] {
            assert!(value.parse::<MultisigProposalNonce>().is_err(), "{value}");
            assert!(value.parse::<MultisigProposalId>().is_err(), "{value}");
        }
        assert!(MultisigProposalNonce::new([0; 32]).is_err());
    }
    #[test]
    fn occurrence_codecs_require_exact_lowercase_string_and_reject_zero_binary() {
        let nonce = MultisigProposalNonce::new([0xab; 32]).unwrap();
        let json = json::to_json(&nonce).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(
            json::from_str::<MultisigProposalNonce>(&json).unwrap(),
            nonce
        );
        assert!(json::from_str::<MultisigProposalNonce>(&json.to_uppercase()).is_err());
        assert!(json::from_str::<MultisigProposalNonce>("[1,2]").is_err());
        let bytes = norito::to_bytes(&nonce).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<MultisigProposalNonce>(&bytes).unwrap(),
            nonce
        );
        // Encode a zero value only inside this type's private test module: the public constructor refuses it.
        let zero = norito::to_bytes(&MultisigProposalNonce([0; 32])).unwrap();
        assert!(norito::decode_from_bytes::<MultisigProposalNonce>(&zero).is_err());
    }
}
