//! Strict platform input adapter for native multisig occurrence identity.
use crate::{CodecError, CodecResult, codec_error, exact_json_object_fields};
use iroha_data_model::{account::address::AccountAddress, id::NetworkId};
use iroha_executor_data_model::isi::multisig::{MultisigProposalId, MultisigProposalNonce};
use norito::json;

/// Derive an occurrence ID from the exact network, account and original nonce.
/// This pure codec grants no authority and never hashes the proposed instructions.
///
/// # Errors
/// Rejects noncanonical or missing identities, duplicate/extra fields and oversized JSON.
pub fn derive_multisig_proposal_id_json(input: &str) -> CodecResult<String> {
    if input.is_empty() || input.len() > 4096 {
        return Err(CodecError::failure(
            "multisig occurrence input exceeds bound",
        ));
    }
    json::validate_json(input).map_err(codec_error)?;
    let value: json::Value = json::from_str(input).map_err(codec_error)?;
    exact_json_object_fields(
        &value,
        &["network_id", "account_id", "proposal_nonce"],
        "multisig occurrence",
    )?;
    let field = |key: &str| {
        value
            .get(key)
            .and_then(json::Value::as_str)
            .ok_or_else(|| CodecError::failure(format!("exact {key} required")))
    };
    let network_literal = field("network_id")?;
    let network: NetworkId = network_literal.parse().map_err(codec_error)?;
    if network.to_string() != network_literal {
        return Err(CodecError::failure("noncanonical network identity"));
    }
    let account_literal = field("account_id")?;
    let prefix = AccountAddress::i105_discriminant(account_literal).map_err(codec_error)?;
    let account = AccountAddress::from_i105_for_discriminant(account_literal, Some(prefix))
        .map_err(codec_error)?
        .to_account_id()
        .map_err(codec_error)?;
    let nonce: MultisigProposalNonce = field("proposal_nonce")?.parse().map_err(codec_error)?;
    Ok(MultisigProposalId::derive(&network, &account, &nonce).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::AccountId;
    #[test]
    fn occurrence_depends_on_exact_network_account_and_nonce() {
        let network = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
        let account = AccountId::new(
            KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let literal = account.to_i105_for_discriminant(369).unwrap();
        let input = |nonce: &str| {
            let mut fields = json::Map::new();
            fields.insert("network_id".into(), json::Value::String(network.into()));
            fields.insert("account_id".into(), json::Value::String(literal.clone()));
            fields.insert("proposal_nonce".into(), json::Value::String(nonce.into()));
            json::to_json(&json::Value::Object(fields)).unwrap()
        };
        let a = input(&"01".repeat(32));
        let expected = MultisigProposalId::derive(
            &network.parse().unwrap(),
            &account,
            &MultisigProposalNonce::new([1; 32]).unwrap(),
        );
        assert_eq!(
            derive_multisig_proposal_id_json(&a).unwrap(),
            expected.to_string()
        );
        assert_ne!(
            derive_multisig_proposal_id_json(&a).unwrap(),
            derive_multisig_proposal_id_json(&input(&"02".repeat(32))).unwrap()
        );
        for nonce in ["00".repeat(32), "AB".repeat(32), "01".repeat(31)] {
            assert!(derive_multisig_proposal_id_json(&input(&nonce)).is_err());
        }
        assert!(derive_multisig_proposal_id_json(&a.replace("{", "{\"extra\":true,")).is_err());
    }
}
