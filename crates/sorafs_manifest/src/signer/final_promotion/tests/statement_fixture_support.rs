// Test-only exact-binding statement helper; requires a lexical `manifest` alias.

/// Adapt the independent canonical ASCII golden to one exact synthetic custody binding.
pub fn statement_message(binding: &manifest::signer::custody::SignerCustodyBindingV1) -> Vec<u8> {
    use iroha_crypto::sha256;
    use manifest::signer::{
        final_promotion::{
            SIGNER_FINAL_PROMOTION_PAYLOAD_DOMAIN_V1,
            statement::prepare_final_promotion_statement_v1,
        },
        protocol::SignerPurposeBindingV1,
    };
    let golden = include_bytes!("statement_fixture.message");
    let json = golden
        .strip_prefix(SIGNER_FINAL_PROMOTION_PAYLOAD_DOMAIN_V1)
        .unwrap();
    let mut value: norito::json::Value = norito::json::from_slice(json).unwrap();
    let body = value.as_object_mut().unwrap();
    let SignerPurposeBindingV1::FinalPromotionProvenance { deployment_id } = &binding.purpose
    else {
        panic!("fixture requires the exact final-promotion purpose")
    };
    body.insert(
        "chain_id".into(),
        norito::json::Value::from(binding.chain_id.clone()),
    );
    body.insert(
        "network_id_hex".into(),
        norito::json::Value::from(hex::encode(binding.network_id)),
    );
    body.insert(
        "deployment_id".into(),
        norito::json::Value::from(deployment_id.clone()),
    );
    let authentication = body
        .get_mut("authentication")
        .unwrap()
        .as_object_mut()
        .unwrap();
    authentication.insert(
        "service_id".into(),
        norito::json::Value::from(binding.service_id.clone()),
    );
    authentication.insert(
        "administrator_id".into(),
        norito::json::Value::from(binding.administrator_id.clone()),
    );
    authentication.insert(
        "key_revision".into(),
        norito::json::Value::from(binding.key_revision),
    );
    authentication.insert(
        "policy_revision".into(),
        norito::json::Value::from(binding.policy_revision),
    );
    authentication.insert(
        "policy_digest_sha256".into(),
        norito::json::Value::from(hex::encode(binding.policy_digest)),
    );
    authentication.insert(
        "public_key_fingerprint_sha256".into(),
        norito::json::Value::from(hex::encode(sha256(binding.public_key.to_bytes().1))),
    );
    // Every fixture string is ASCII; BTreeMap ordering and compact Norito JSON preserve this golden.
    let mut message = SIGNER_FINAL_PROMOTION_PAYLOAD_DOMAIN_V1.to_vec();
    message.extend(norito::json::to_vec(&value).unwrap());
    prepare_final_promotion_statement_v1(&message, binding).expect("canonical synthetic statement");
    message
}
