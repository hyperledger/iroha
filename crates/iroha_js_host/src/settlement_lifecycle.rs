//! Native settlement, repo, alias-plan, faucet and external-signing helpers for JavaScript.
//!
//! Every function delegates ordering, hashing and admission to the shared Rust owners
//! (`iroha_js_codec`, `iroha_data_model` and the `iroha` client crate). The JavaScript SDK
//! never re-implements Norito encodings or native ordering for these values.

use iroha::client::{
    AccountFaucetClaimV1, AccountFaucetPolicyV1, AccountFaucetPreparedTransactionV1,
    PreparedOperationBindingV1, verify_account_faucet_prepared_transaction_v1,
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    asset::AssetDefinitionId,
    transaction::{FeePaymentIntent, signed::TransactionBuilder},
};
use iroha_primitives::numeric::Quantity;
use napi::bindgen_prelude::{Buffer, Uint8Array};
use napi_derive::napi;
use norito::json;

use crate::{
    EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES, codec_to_napi, parse_account_id,
    parse_transaction_network_id_bytes, scoped_chain_discriminant_for_literal,
};

/// Upper bound for JSON accepted by these helpers.
const LIFECYCLE_JSON_MAX_BYTES: usize = 1024 * 1024;

fn invalid(message: impl Into<String>) -> napi::Error {
    napi::Error::new(napi::Status::InvalidArg, message.into())
}

fn bounded_json(source: &str, label: &str) -> napi::Result<json::Value> {
    if source.is_empty() || source.len() > LIFECYCLE_JSON_MAX_BYTES {
        return Err(invalid(format!("{label} must contain 1..=1048576 bytes")));
    }
    json::from_str(source).map_err(|error| invalid(format!("{label} is not JSON: {error}")))
}

fn network_guard(network_prefix: f64) -> napi::Result<ChainDiscriminantGuard> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    Ok(ChainDiscriminantGuard::enter(prefix))
}

fn render_json(value: &json::Value) -> napi::Result<String> {
    json::to_json(value).map_err(|error| invalid(error.to_string()))
}

fn hash_literal(hash: &iroha_crypto::Hash) -> napi::Result<String> {
    match json::to_value(hash).map_err(|error| invalid(error.to_string()))? {
        json::Value::String(literal) => Ok(literal),
        _ => Err(invalid("hash literal must render as a JSON string")),
    }
}

/// Sort `Settlement.Atomic` movements by native `(AssetId, AccountId)` order.
///
/// Returns the complete canonical instruction JSON admitted by the strict codec.
#[napi(js_name = "canonicalSettleAtomicInstructionJson")]
pub fn canonical_settle_atomic_instruction_json(
    instruction_json: String,
    network_prefix: f64,
) -> napi::Result<String> {
    let _network = network_guard(network_prefix)?;
    let value = bounded_json(&instruction_json, "atomic settlement instruction")?;
    let canonical =
        iroha_js_codec::canonical_atomic_settlement_json(value).map_err(codec_to_napi)?;
    render_json(&canonical)
}

/// Return the exact `CanExecuteSettlement.intent_hash` literal for a canonical atomic settlement.
#[napi(js_name = "settleAtomicIntentHashJson")]
pub fn settle_atomic_intent_hash_json(
    instruction_json: String,
    network_prefix: f64,
) -> napi::Result<String> {
    let _network = network_guard(network_prefix)?;
    let value = bounded_json(&instruction_json, "atomic settlement instruction")?;
    let hash = iroha_js_codec::atomic_settlement_intent_hash(value).map_err(codec_to_napi)?;
    hash_literal(&hash)
}

/// Repo initiation and maturity consent hashes rendered as canonical hash literals.
#[napi(object)]
pub struct JsRepoIntentHashes {
    /// Counterparty cash-debit consent hash.
    pub initiation: String,
    /// Collateral-holder maturity-release consent hash.
    pub maturity: String,
}

/// Return the exact consent hashes for one `Repo.Initiate` instruction.
#[napi(js_name = "repoIntentHashesJson")]
pub fn repo_intent_hashes_json(
    instruction_json: String,
    network_prefix: f64,
) -> napi::Result<JsRepoIntentHashes> {
    let _network = network_guard(network_prefix)?;
    let value = bounded_json(&instruction_json, "repo instruction")?;
    let hashes = iroha_js_codec::repo_intent_hashes(value).map_err(codec_to_napi)?;
    Ok(JsRepoIntentHashes {
        initiation: hash_literal(&hashes.initiation)?,
        maturity: hash_literal(&hashes.maturity)?,
    })
}

/// Convert one planner-issued `(wire_id, framed_payload)` pair into strict instruction JSON.
#[napi(js_name = "instructionJsonFromWirePair")]
pub fn instruction_json_from_wire_pair(
    wire_id: String,
    framed_payload: Uint8Array,
    network_prefix: f64,
) -> napi::Result<String> {
    let _network = network_guard(network_prefix)?;
    if framed_payload.is_empty() || framed_payload.len() > LIFECYCLE_JSON_MAX_BYTES {
        return Err(invalid("framedPayload must contain 1..=1048576 bytes"));
    }
    let value = iroha_js_codec::instruction_json_from_wire_pair(&wire_id, framed_payload.as_ref())
        .map_err(codec_to_napi)?;
    render_json(&value)
}

/// Return the 32 bytes an external Ed25519 signer signs for one canonical payload.
///
/// This is `HashOf<TransactionPayload>` of the exact decoded payload (BLAKE2b-256 with the
/// Iroha marker bit). The payload must decode canonically without trailing bytes.
#[napi(js_name = "transactionPayloadSigningHash")]
pub fn transaction_payload_signing_hash(payload_bytes: Uint8Array) -> napi::Result<Buffer> {
    if payload_bytes.is_empty() || payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(invalid("payloadBytes must contain 1..=1048576 bytes"));
    }
    let builder = TransactionBuilder::decode_payload(payload_bytes.as_ref())
        .map_err(|error| invalid(format!("invalid canonical transaction payload: {error}")))?;
    Ok(Buffer::from(builder.payload_hash_bytes().to_vec()))
}

/// Decode one canonical unsigned transaction payload into its model JSON.
///
/// The payload must decode canonically without trailing bytes. Account literals render
/// with `network_prefix`; instructions render as canonical base64 `InstructionBox` frames.
#[napi(js_name = "decodeTransactionPayloadJson")]
pub fn decode_transaction_payload_json(
    payload_bytes: Uint8Array,
    network_prefix: f64,
) -> napi::Result<String> {
    let _network = network_guard(network_prefix)?;
    if payload_bytes.is_empty() || payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(invalid("payloadBytes must contain 1..=1048576 bytes"));
    }
    let builder = TransactionBuilder::decode_payload(payload_bytes.as_ref())
        .map_err(|error| invalid(format!("invalid canonical transaction payload: {error}")))?;
    json::to_json(builder.payload()).map_err(|error| invalid(error.to_string()))
}

fn faucet_claim(claim_json: &str) -> napi::Result<AccountFaucetClaimV1> {
    let value = bounded_json(claim_json, "faucet claim")?;
    let claim: AccountFaucetClaimV1 = json::from_value(value.clone())
        .map_err(|error| invalid(format!("faucet claim: {error}")))?;
    if json::to_value(&claim).map_err(|error| invalid(error.to_string()))? != value {
        return Err(invalid(
            "faucet claim must use its exact canonical JSON fields",
        ));
    }
    Ok(claim)
}

/// Build the exact prepared-operation binding (including the claim semantic hash) for a faucet claim.
#[napi(js_name = "accountFaucetBindingJson")]
pub fn account_faucet_binding_json(
    claim_json: String,
    request_id: String,
    execution_expires_at_unix_ms: f64,
) -> napi::Result<String> {
    let claim = faucet_claim(&claim_json)?;
    let _network = scoped_chain_discriminant_for_literal(&claim.account_id)?;
    if !((1.0..=9_007_199_254_740_991.0).contains(&execution_expires_at_unix_ms)
        && execution_expires_at_unix_ms.fract() == 0.0)
    {
        return Err(invalid(
            "executionExpiresAtUnixMs must be a positive safe integer",
        ));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let deadline = execution_expires_at_unix_ms as u64;
    let binding = PreparedOperationBindingV1::faucet(&claim, request_id, deadline)
        .map_err(|error| invalid(format!("{error:#}")))?;
    json::to_json(&binding).map_err(|error| invalid(error.to_string()))
}

/// Trusted faucet policy plus the exact prepared envelope returned by Torii.
#[napi(object)]
pub struct JsAccountFaucetPreparedVerification {
    /// Exact 32 genesis-hash bytes of the expected network.
    pub network_id: Buffer,
    /// Prepared envelope JSON exactly as returned by `/v1/accounts/faucet/prepare`.
    pub prepared_json: String,
    /// Exact solved claim JSON sent to prepare.
    pub claim_json: String,
    /// Exact binding JSON sent to prepare.
    pub binding_json: String,
    /// Trusted faucet authority account.
    pub policy_authority: String,
    /// Trusted faucet asset definition.
    pub policy_asset_definition_id: String,
    /// Trusted faucet issuance amount.
    pub policy_amount: String,
}

/// Authenticate a prepared faucet transaction and return its lowercase transaction hash.
#[napi(js_name = "verifyAccountFaucetPreparedTransactionJson")]
pub fn verify_account_faucet_prepared_transaction_json(
    input: JsAccountFaucetPreparedVerification,
) -> napi::Result<String> {
    let network_id = parse_transaction_network_id_bytes(input.network_id.as_ref())?;
    let claim = faucet_claim(&input.claim_json)?;
    let _network = scoped_chain_discriminant_for_literal(&claim.account_id)?;
    let binding: PreparedOperationBindingV1 =
        json::from_value(bounded_json(&input.binding_json, "faucet binding")?)
            .map_err(|error| invalid(format!("faucet binding: {error}")))?;
    let prepared: AccountFaucetPreparedTransactionV1 = json::from_value(bounded_json(
        &input.prepared_json,
        "prepared faucet transaction",
    )?)
    .map_err(|error| invalid(format!("prepared faucet transaction: {error}")))?;
    let authority = parse_account_id(&input.policy_authority, "faucet policy authority")?;
    let asset_definition_id: AssetDefinitionId = input
        .policy_asset_definition_id
        .parse()
        .map_err(|error| invalid(format!("faucet policy asset definition: {error}")))?;
    let amount: Quantity = input
        .policy_amount
        .parse()
        .map_err(|error| invalid(format!("faucet policy amount: {error}")))?;
    let policy = AccountFaucetPolicyV1::try_new(authority, asset_definition_id, amount)
        .map_err(|error| invalid(format!("{error:#}")))?;
    let transaction = verify_account_faucet_prepared_transaction_v1(
        network_id,
        &prepared,
        &claim,
        &binding,
        &FeePaymentIntent::authority(Vec::new(), None),
        &policy,
    )
    .map_err(|error| invalid(format!("{error:#}")))?;
    Ok(hex::encode(transaction.hash().as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::AccountId;

    #[test]
    fn faucet_binding_matches_the_shared_prepared_transaction_fixture() {
        let fixture: json::Value = json::from_str(include_str!(
            "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
        ))
        .expect("fixture JSON");
        let vector = fixture["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|vector| vector["name"] == json::Value::String("faucet_prepared".into()))
            .expect("faucet vector");
        let claim = &vector["response"]["claim"];
        let expected = vector["response"]["semantic_hash_hex"]
            .as_str()
            .expect("semantic hash");
        let binding = account_faucet_binding_json(
            json::to_json(claim).expect("claim JSON"),
            "22".repeat(32),
            1_900_000_000_000.0,
        )
        .expect("binding");
        let binding: json::Value = json::from_str(&binding).expect("binding JSON");
        assert_eq!(binding["semantic_hash_hex"].as_str(), Some(expected));
        assert_eq!(binding["kind"].as_str(), Some("faucet"));
        assert!(
            account_faucet_binding_json(
                json::to_json(claim).expect("claim JSON"),
                "not-hex".into(),
                1_900_000_000_000.0,
            )
            .is_err()
        );
    }

    #[test]
    fn faucet_prepared_fixture_verifies_against_its_trusted_policy_only() {
        let fixture: json::Value = json::from_str(include_str!(
            "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
        ))
        .expect("fixture JSON");
        let vector = fixture["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|vector| vector["name"] == json::Value::String("faucet_prepared".into()))
            .expect("faucet vector");
        let response = &vector["response"];
        let network_literal = vector["network_id"].as_str().expect("network id");
        let body = network_literal
            .strip_prefix("hash:")
            .and_then(|rest| rest.split('#').next())
            .expect("hash literal body");
        let input = |amount: &str| JsAccountFaucetPreparedVerification {
            network_id: Buffer::from(hex::decode(body).expect("network bytes")),
            prepared_json: json::to_json(response).expect("prepared JSON"),
            claim_json: json::to_json(&response["claim"]).expect("claim JSON"),
            binding_json: json::to_json(&response["binding"]).expect("binding JSON"),
            policy_authority: vector["signer_account_id"]
                .as_str()
                .expect("signer")
                .to_owned(),
            policy_asset_definition_id: response["asset_definition_id"]
                .as_str()
                .expect("asset definition")
                .to_owned(),
            policy_amount: amount.to_owned(),
        };
        assert_eq!(
            verify_account_faucet_prepared_transaction_json(input("5")).expect("verified"),
            response["transaction_hash_hex"]
                .as_str()
                .expect("transaction hash")
        );
        assert!(verify_account_faucet_prepared_transaction_json(input("6")).is_err());
    }

    #[test]
    fn payload_decoder_and_signing_hash_cover_the_exact_built_payload() {
        use iroha_data_model::{NetworkId, isi::Log, transaction::FeePaymentIntent};
        let authority = AccountId::new(
            KeyPair::try_from_seed(vec![6; 32], Algorithm::Ed25519)
                .expect("key")
                .public_key()
                .clone(),
        );
        let network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"payload-review"),
            ));
        let builder = TransactionBuilder::new(
            network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(iroha_data_model::Level::INFO, "review".into())]);
        let bytes = builder.encode_payload();
        let json_text = decode_transaction_payload_json(Uint8Array::from(bytes.clone()), 369.0)
            .expect("decode");
        let value: json::Value = json::from_str(&json_text).expect("payload JSON");
        let _network = ChainDiscriminantGuard::enter(369);
        assert_eq!(
            value["authority"],
            json::to_value(&authority).expect("authority JSON")
        );
        assert_eq!(
            transaction_payload_signing_hash(Uint8Array::from(bytes.clone()))
                .expect("signing hash")
                .to_vec(),
            builder.payload_hash_bytes().to_vec()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(
            decode_transaction_payload_json(Uint8Array::from(trailing.clone()), 369.0).is_err()
        );
        assert!(transaction_payload_signing_hash(Uint8Array::from(trailing)).is_err());
    }

    #[test]
    fn faucet_claim_rejects_alternate_spellings() {
        let account = AccountId::new(
            KeyPair::try_from_seed(vec![4; 32], Algorithm::Ed25519)
                .expect("key")
                .public_key()
                .clone(),
        );
        let _network = ChainDiscriminantGuard::enter(369);
        let literal = account.to_string();
        let good = format!(
            r#"{{"account_id":"{literal}","pow_anchor_height":7,"pow_nonce_hex":"00000000000000ff"}}"#
        );
        assert!(account_faucet_binding_json(good.clone(), "11".repeat(32), 5.0).is_ok());
        for bad in [
            good.replace(r#""pow_anchor_height":7"#, r#""pow_anchor_height":"7""#),
            good.replace(r#""pow_nonce_hex""#, r#""nonce""#),
            good.replace('}', r#","extra":1}"#),
        ] {
            assert!(account_faucet_binding_json(bad, "11".repeat(32), 5.0).is_err());
        }
        assert!(account_faucet_binding_json(good, "11".repeat(32), 0.5).is_err());
    }
}
