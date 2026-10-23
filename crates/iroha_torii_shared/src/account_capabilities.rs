//! Public account-bootstrap capabilities projected from the original committed crypto policy.

use iroha_data_model::{NetworkId, crypto_admission_policy::CryptoAdmissionPolicyV1};
use norito::derive::{JsonDeserialize, JsonSerialize};

/// Maximum JSON representation accepted by first-release bootstrap clients.
pub const ACCOUNT_CAPABILITIES_MAX_BYTES_V1: usize = 4 * 1024;

/// Public, account-free projection for `GET /v1/accounts/capabilities`.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AccountCapabilitiesV1 {
    /// Exact bootstrap schema version.
    pub schema_version: u16,
    /// Genesis-derived signing identity; never a display chain label.
    pub network_id: NetworkId,
    /// Canonical I105 address network discriminant.
    pub network_prefix: u16,
    /// Exact admitted names in canonical algorithm-tag order; no signer preference is implied.
    pub allowed_signing: Vec<String>,
}

impl AccountCapabilitiesV1 {
    /// Project the original validated policy without sorting, deduplicating or adding a default.
    pub fn from_policy(
        network_id: NetworkId,
        network_prefix: u16,
        policy: &CryptoAdmissionPolicyV1,
    ) -> Self {
        Self {
            schema_version: 1,
            network_id,
            network_prefix,
            allowed_signing: policy
                .allowed_algorithms()
                .iter()
                .map(|algorithm| algorithm.as_static_str().to_owned())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf};

    fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"account capability exact genesis identity",
        )))
    }

    #[test]
    fn account_capabilities_preserve_identity_and_canonical_policy_order() {
        let policy = CryptoAdmissionPolicyV1::new(Algorithm::ALL.to_vec()).unwrap();
        let response = AccountCapabilitiesV1::from_policy(network_id(), 369, &policy);
        assert_eq!(response.network_id, network_id());
        assert_eq!(response.network_prefix, 369);
        assert_eq!(
            response.allowed_signing,
            Algorithm::ALL
                .iter()
                .map(|algorithm| algorithm.as_static_str())
                .collect::<Vec<_>>()
        );
        let json = norito::json::to_vec(&response).expect("encode account capabilities");
        assert!(json.len() < ACCOUNT_CAPABILITIES_MAX_BYTES_V1);
        let value: norito::json::Value = norito::json::from_slice(&json).expect("parse JSON");
        assert_eq!(value.as_object().expect("object").len(), 4);
        assert_eq!(value["schema_version"].as_u64(), Some(1));
        assert_eq!(
            value["network_id"].as_str(),
            Some(network_id().to_string().as_str())
        );
        let decoded: AccountCapabilitiesV1 = norito::json::from_slice(&json).expect("decode DTO");
        assert_eq!(decoded, response);
    }

    #[test]
    fn account_capabilities_preserve_policy_without_implicit_ed25519() {
        let policy = CryptoAdmissionPolicyV1::new(vec![Algorithm::Secp256k1]).unwrap();
        let response = AccountCapabilitiesV1::from_policy(network_id(), u16::MAX, &policy);
        assert_eq!(response.allowed_signing, ["secp256k1"]);
        let mut json = norito::json::to_value(&response).unwrap();
        json.as_object_mut().unwrap().insert(
            "default_signing".into(),
            norito::json::Value::from("ed25519"),
        );
        assert!(norito::json::from_value::<AccountCapabilitiesV1>(json).is_err());
    }
}
