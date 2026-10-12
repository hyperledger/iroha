//! Destination deployments bound by SCCP v1 route revisions (`specs/sccp.md` §4.14.1, §3.4).
//!
//! Each route revision binds exactly one deployed destination contract. The deployment's
//! [`destination_word`](SccpDeploymentV1::destination_word) is the contract-visible identity
//! committed by transfer and control leaves; it is unique across all routes and revisions.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, bridge::SccpNetworkV1};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// A destination's initial native committee generation (§4.14.3 P1).
///
/// This record carries a pin, not its authentication. Registration must bind it to the
/// original retained native generation and enforce every deployment and launch check.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::deployment::SccpCommitteePinV1")]
pub struct SccpCommitteePinV1 {
    /// Retained native generation, starting at one.
    pub generation: u64,
    /// Root of the original canonical BLS committee keys.
    pub committee_root: [u8; 32],
    /// First native height signed under the generation.
    pub start_height: u64,
    /// Original generation deadline in Unix milliseconds.
    pub until_ms: u64,
}

impl SccpCommitteePinV1 {
    /// Check only the pin's fixed-field shape, without granting generation authority.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.generation != 0
            && self.committee_root != [0; 32]
            && self.start_height != 0
            && self.until_ms != 0
    }
}

/// Cell reference of TON contract code: representation hash and depth.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::deployment::SccpTonCodeRefV1")]
pub struct SccpTonCodeRefV1 {
    /// Representation hash of the code cell.
    pub hash: [u8; 32],
    /// Depth of the code cell.
    pub depth: u16,
}

/// EVM deployment (Ethereum or BSC).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::deployment::SccpEvmDeploymentV1")]
pub struct SccpEvmDeploymentV1 {
    /// Bridge-token contract address.
    pub address: [u8; 20],
    /// Keccak-256 of the deployed runtime bytecode (reviewed off-chain, §4.14.4).
    pub runtime_code_hash: [u8; 32],
}

/// TON deployment: the Jetton master (bridge) and its code references.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::deployment::SccpTonDeploymentV1")]
pub struct SccpTonDeploymentV1 {
    /// Basechain account id of the Jetton master; Taira recomputes it at registration.
    pub master_account: [u8; 32],
    /// Minter (Jetton master) code.
    pub minter_code: SccpTonCodeRefV1,
    /// Jetton wallet code.
    pub wallet_code: SccpTonCodeRefV1,
    /// Replay bucket code.
    pub bucket_code: SccpTonCodeRefV1,
}

/// Destination contract bound by one route revision (`SccpDeploymentV1`, §4.14.1).
///
/// Family index 1 and the JSON family `tron` belonged to the removed TRON deployment. Both stay
/// unassigned and fail decoding.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "family", content = "deployment")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::deployment::SccpDeploymentV1")]
pub enum SccpDeploymentV1 {
    /// Ethereum or BSC contract.
    #[codec(index = 0)]
    #[norito(rename = "evm")]
    Evm(SccpEvmDeploymentV1),
    /// TON Jetton master.
    #[codec(index = 2)]
    #[norito(rename = "ton")]
    Ton(SccpTonDeploymentV1),
}

impl SccpDeploymentV1 {
    /// Return the contract-visible `destination_word` of §3.4.
    ///
    /// EVM: `word(address20)`, twelve zero bytes then the address. TON: the Jetton master's
    /// account id.
    #[must_use]
    pub fn destination_word(&self) -> [u8; 32] {
        match self {
            Self::Evm(deployment) => evm_word(&deployment.address),
            Self::Ton(deployment) => deployment.master_account,
        }
    }

    /// Return whether this deployment family and address shape fit `network`.
    ///
    /// EVM fits Ethereum and BSC with a nonzero address; TON fits TON with a nonzero account
    /// id. Nothing fits `sora-taira`.
    #[must_use]
    pub fn fits_network(&self, network: SccpNetworkV1) -> bool {
        match (self, network) {
            (Self::Evm(deployment), SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet) => {
                deployment.address != [0; 20]
            }
            (Self::Ton(deployment), SccpNetworkV1::TonMainnet) => {
                deployment.master_account != [0; 32]
            }
            _ => false,
        }
    }
}

fn evm_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address);
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::DecodeAll as _;

    #[test]
    fn committee_pin_roundtrips_only_the_current_declared_layout() {
        let pin = SccpCommitteePinV1 {
            generation: 7,
            committee_root: [0x31; 32],
            start_height: 7000,
            until_ms: 1_791_209_600_000,
        };
        assert!(pin.is_well_formed());
        assert_eq!(
            SccpCommitteePinV1::decode_all(&mut pin.encode().as_slice()).unwrap(),
            pin
        );
        let json = norito::json::to_json(&pin).unwrap();
        assert_eq!(
            norito::json::from_str::<SccpCommitteePinV1>(&json).unwrap(),
            pin
        );
        for field in ["generation", "committee_root", "start_height", "until_ms"] {
            let mut missing: norito::json::Value = norito::json::from_str(&json).unwrap();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                norito::json::from_json::<SccpCommitteePinV1>(
                    &norito::json::to_json(&missing).unwrap()
                )
                .is_err(),
                "missing {field}"
            );
        }
        let mut fields: norito::json::Value = norito::json::from_str(&json).unwrap();
        fields.as_object_mut().unwrap().insert(
            "roster_digest".into(),
            norito::json::Value::String("retired".into()),
        );
        assert!(
            norito::json::from_json::<SccpCommitteePinV1>(&norito::json::to_json(&fields).unwrap())
                .is_err()
        );
        for invalid in [
            SccpCommitteePinV1 {
                generation: 0,
                ..pin
            },
            SccpCommitteePinV1 {
                committee_root: [0; 32],
                ..pin
            },
            SccpCommitteePinV1 {
                start_height: 0,
                ..pin
            },
            SccpCommitteePinV1 { until_ms: 0, ..pin },
        ] {
            assert!(!invalid.is_well_formed());
        }
    }

    const NETWORKS: [SccpNetworkV1; 4] = [
        SccpNetworkV1::SoraTaira,
        SccpNetworkV1::EthereumMainnet,
        SccpNetworkV1::BscMainnet,
        SccpNetworkV1::TonMainnet,
    ];

    fn code(seed: u8) -> SccpTonCodeRefV1 {
        SccpTonCodeRefV1 {
            hash: [seed; 32],
            depth: u16::from(seed),
        }
    }

    fn evm(address: [u8; 20]) -> SccpDeploymentV1 {
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address,
            runtime_code_hash: [0xc0; 32],
        })
    }

    fn ton(master_account: [u8; 32]) -> SccpDeploymentV1 {
        SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account,
            minter_code: code(1),
            wallet_code: code(2),
            bucket_code: code(3),
        })
    }

    #[test]
    fn destination_word_vectors() {
        // EVM: the §3.4 control-leaf example destination word, 12 zero bytes then 0x22 × 20.
        let mut expected = [0_u8; 32];
        expected[12..].copy_from_slice(&[0x22; 20]);
        assert_eq!(evm([0x22; 20]).destination_word(), expected);

        let address: [u8; 20] = core::array::from_fn(|index| u8::try_from(index + 1).unwrap());
        let mut expected = [0_u8; 32];
        expected[12..].copy_from_slice(&address);
        assert_eq!(evm(address).destination_word(), expected);

        // TON: the Jetton master account id is taken verbatim.
        let master: [u8; 32] = core::array::from_fn(|index| u8::try_from(0xa0 + index).unwrap());
        assert_eq!(ton(master).destination_word(), master);
    }

    #[test]
    fn fits_network_matrix() {
        let cases = [
            (evm([0x22; 20]), [false, true, true, false]),
            (ton([0x33; 32]), [false, false, false, true]),
        ];
        for (deployment, fits) in cases {
            for (network, expected) in NETWORKS.into_iter().zip(fits) {
                assert_eq!(
                    deployment.fits_network(network),
                    expected,
                    "{deployment:?} on {network:?}"
                );
            }
        }
    }

    #[test]
    fn fits_network_rejects_degenerate_addresses() {
        assert!(!evm([0; 20]).fits_network(SccpNetworkV1::EthereumMainnet));
        assert!(!evm([0; 20]).fits_network(SccpNetworkV1::BscMainnet));
        let mut one = [0_u8; 20];
        one[19] = 1;
        assert!(evm(one).fits_network(SccpNetworkV1::EthereumMainnet));

        assert!(!ton([0; 32]).fits_network(SccpNetworkV1::TonMainnet));
        let mut last = [0_u8; 32];
        last[31] = 1;
        assert!(ton(last).fits_network(SccpNetworkV1::TonMainnet));
    }

    #[test]
    fn binary_and_json_roundtrip() {
        for deployment in [evm([0x22; 20]), ton([0x24; 32])] {
            let encoded = deployment.encode();
            assert_eq!(
                SccpDeploymentV1::decode_all(&mut encoded.as_slice()).expect("decode"),
                deployment
            );
            let framed = norito::to_bytes(&deployment).expect("frame");
            assert_eq!(
                norito::decode_from_bytes::<SccpDeploymentV1>(&framed).expect("decode frame"),
                deployment
            );
            let json = norito::json::to_json(&deployment).expect("serialize");
            assert_eq!(
                norito::json::from_json::<SccpDeploymentV1>(&json).expect("deserialize"),
                deployment
            );
        }
        let reference = code(9);
        let json = norito::json::to_json(&reference).expect("serialize");
        assert_eq!(
            norito::json::from_json::<SccpTonCodeRefV1>(&json).expect("deserialize"),
            reference
        );
    }

    #[test]
    fn unknown_family_and_fields_are_rejected() {
        let mut value = norito::json::to_value(&evm([0x22; 20])).expect("to value");
        let norito::json::Value::Object(object) = &mut value else {
            panic!("deployment JSON is an object");
        };
        let tag = object
            .keys()
            .find(|key| key.as_str() != "deployment")
            .cloned()
            .expect("tag key");
        object.insert(tag, norito::json::Value::String("solana".to_owned()));
        let hostile = norito::json::to_json(&value).expect("serialize");
        assert!(norito::json::from_json::<SccpDeploymentV1>(&hostile).is_err());

        let mut value = norito::json::to_value(&SccpEvmDeploymentV1 {
            address: [1; 20],
            runtime_code_hash: [2; 32],
        })
        .expect("to value");
        value
            .as_object_mut()
            .expect("object")
            .insert("verifier_key_hash".to_owned(), norito::json::Value::Null);
        let hostile = norito::json::to_json(&value).expect("serialize");
        assert!(norito::json::from_json::<SccpEvmDeploymentV1>(&hostile).is_err());

        for unsupported_tag in [3_u32, 4, u32::MAX] {
            let mut encoded = unsupported_tag.encode();
            encoded.extend_from_slice(&[0x11; 160]);
            assert!(
                SccpDeploymentV1::decode_all(&mut encoded.as_slice()).is_err(),
                "deployment tag {unsupported_tag} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn retired_tron_family_does_not_decode() {
        // Family index 1 with the retired body: a 0x41-prefixed address and a code hash.
        let mut encoded = 1_u32.encode();
        encoded.push(0x41);
        encoded.extend_from_slice(&[0x22; 20]);
        encoded.extend_from_slice(&[0xc1; 32]);
        assert!(SccpDeploymentV1::decode_all(&mut encoded.as_slice()).is_err());
        assert_eq!(evm([0x22; 20]).encode().get(..4), Some(&[0, 0, 0, 0][..]));
        assert_eq!(ton([0x24; 32]).encode().get(..4), Some(&[2, 0, 0, 0][..]));

        let mut value = norito::json::to_value(&evm([0x22; 20])).expect("to value");
        value.as_object_mut().expect("object").insert(
            "family".to_owned(),
            norito::json::Value::String("tron".to_owned()),
        );
        let hostile = norito::json::to_json(&value).expect("serialize");
        assert!(norito::json::from_json::<SccpDeploymentV1>(&hostile).is_err());
    }
}
