//! Generates the canonical detached-contract transaction fixture used by SDK tests.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    parameter::system::SumeragiNposParameters,
    smart_contract::ContractAddress,
    transaction::{
        Executable, FeeChargeKind, FeeChargeLimit, FeePaymentIntent,
        executable::{ContractArgumentRecord, ContractInvocation},
        signed::TransactionBuilder,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_version::codec::EncodeVersioned as _;
use std::{num::NonZeroU64, str::FromStr as _, time::Duration};
fn main() {
    let authority_keypair =
        KeyPair::try_from_seed(vec![0x41; 32], Algorithm::Ed25519).expect("authority key");
    let placeholder_keypair =
        KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519).expect("placeholder key");
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let contract_address =
        ContractAddress::from_str("irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh")
            .expect("fixture contract address");
    let merchant = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D";
    let expected_code_hash = Hash::new(b"detached-fixture-contract-code");
    let payload = format!(r#"{{"amount":"750","merchant_account_id":"{merchant}"}}"#,);
    let mut metadata = Metadata::default();
    for (key, value) in [
        ("contract_address", contract_address.to_string()),
        ("contract_code_hash", expected_code_hash.to_string()),
        ("contract_alias", "bisp::hbl.sbp".to_owned()),
        ("contract_entrypoint", "spend_to_merchant".to_owned()),
    ] {
        metadata.insert(key.parse().expect("metadata key"), Json::new(value));
    }
    metadata.insert(
        "contract_payload".parse().expect("metadata key"),
        Json::new(payload),
    );
    let fee_asset = SumeragiNposParameters::default()
        .xor_asset_definition_id()
        .clone();
    let fee_payment = FeePaymentIntent::authority(
        vec![
            FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset.clone(),
                Quantity::from_str("1").expect("canonical Nexus maximum"),
            ),
            FeeChargeLimit::new(
                FeeChargeKind::PipelineGas,
                fee_asset,
                Quantity::from_str("100").expect("canonical gas maximum"),
            ),
        ],
        NonZeroU64::new(500_000),
    );
    let invocation = ContractInvocation::new(
        contract_address,
        expected_code_hash,
        "spend_to_merchant".to_owned(),
        Some(ContractArgumentRecord::try_new(vec![0x01]).expect("bounded contract arguments")),
    );
    let mut builder = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"swift-detached-contract-fixture",
        ))),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_fee_payment_intent(fee_payment)
    .with_metadata(metadata)
    .with_executable(Executable::ContractCall(invocation));
    builder.set_creation_time(Duration::from_millis(4_102_444_800_000));
    builder.set_ttl(Duration::from_millis(120_000));
    let payload = builder.into_payload().expect("valid exact payload");
    let placeholder_signature = Signature::try_new(
        placeholder_keypair.private_key(),
        HashOf::new(&payload).as_ref(),
    )
    .expect("placeholder signature");
    let scaffold = TransactionBuilder::from_payload(payload)
        .expect("valid exact payload")
        .build_with_signature(placeholder_signature);
    let scaffold_bytes = scaffold.encode_versioned();
    let payload_hash = HashOf::new(scaffold.payload());
    let signature = Signature::try_new(authority_keypair.private_key(), payload_hash.as_ref())
        .expect("authority signature");
    let payload_bytes = norito::codec::encode_adaptive(scaffold.payload());
    let signed = TransactionBuilder::decode_payload(&payload_bytes)
        .expect("decode payload")
        .build_with_signature(signature.clone());
    signed.verify_signature().expect("final signature");
    println!("authority={authority}");
    println!("scaffold_b64={}", STANDARD.encode(scaffold_bytes));
    println!("signing_hash_hex={}", hex::encode(payload_hash.as_ref()));
    println!("signature_b64={}", STANDARD.encode(signature.payload()));
    println!(
        "scaffold_entrypoint_hash_hex={}",
        hex::encode(scaffold.hash_as_entrypoint().as_ref())
    );
    println!(
        "transaction_hash_hex={}",
        hex::encode(signed.hash().as_ref())
    );
    println!(
        "entrypoint_hash_hex={}",
        hex::encode(signed.hash_as_entrypoint().as_ref())
    );
    println!("signed_b64={}", STANDARD.encode(signed.encode_versioned()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_fixture_uses_current_fee_identity_and_verifies_native_signatures() {
        main();
    }
}
