//! Generates Norito-encoded fixtures for Kotlin SDK parity tests.
//!
//! Instruction subcommands output wire payload hex followed by input parameters.
//! `multisig-accounts-v1` emits checked complete-controller vectors as Norito JSON.
//! `fastpq-balance-keys-v1` emits their canonical typed FASTPQ balance keys.
//! `native-sumeragi-status-v1` and `native-sumeragi-lanes-v1` emit the exact
//! `GET /v1/sumeragi/status` and `GET /v1/sumeragi/lanes` JSON bodies with their
//! canonical framed Norito encodings.
//!
//! When the Rust data model changes, this binary produces different
//! bytes, causing the Kotlin parity tests to fail until the
//! corresponding encoder is updated.
use iroha_crypto::{Hash, PublicKey, default_bfv_programmed_hidden_program};
use iroha_crypto::{RamLfeBackend, RamLfeVerificationMode};
use iroha_data_model::account::{
    AccountId, NewAccount, OpaqueAccountId, address::ChainDiscriminantGuard,
};
use iroha_data_model::asset::{AssetBalanceScope, AssetDefinitionId, AssetId};
use iroha_data_model::identifier::{
    IdentifierPolicyId, IdentifierResolutionReceipt, IdentifierResolutionReceiptPayload,
};
use iroha_data_model::isi::identifier::ClaimIdentifier;
use iroha_data_model::isi::register::{Register, RegisterBox};
use iroha_data_model::isi::smart_contract_code::{
    AcceptContractOwnership, ActivateContractInstance, CancelContractOwnershipOffer,
    DeactivateContractInstance, OfferContractOwnership, SetContractParliamentDelegation,
};
use iroha_data_model::isi::transfer::{Transfer, TransferBox};
use iroha_data_model::nexus::UniversalAccountId;
use iroha_data_model::prelude::Quantity;
use iroha_data_model::ram_lfe::{
    RamLfeExecutionReceiptPayload, RamLfeOutputOpening, RamLfeOutputOpeningPayload,
    RamLfeProgramId, RamLfeReceiptAttestation,
};
use iroha_data_model::smart_contract::{ContractAddress, ContractLifecycleOwnerV1};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use std::env;
mod fastpq_balance_keys;
mod identifier_owner_execute;
mod multisig_accounts;
mod native_sumeragi_lanes;
mod native_sumeragi_status;
/// Well-known public key shared with the Kotlin parity tests.
const PARITY_PUBLIC_KEY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
const TAIRA_CHAIN_DISCRIMINANT: u16 = 369;
fn parity_account_id() -> AccountId {
    let pk: PublicKey = PARITY_PUBLIC_KEY.parse().expect("parse public key");
    AccountId::new(pk)
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!(
            "Usage: {} <register-account|transfer-asset|transfer-asset-scoped|claim-identifier|contract-lifecycle|hidden-ram-fhe-program|multisig-accounts-v1|fastpq-balance-keys-v1|native-sumeragi-status-v1|native-sumeragi-lanes-v1|identifier-owner-execute-v1>",
            args[0]
        );
        std::process::exit(1);
    }
    match args[1].as_str() {
        "identifier-owner-execute-v1" => identifier_owner_execute::emit(),
        "register-account" => emit_register_account(),
        "transfer-asset" => emit_transfer_asset(),
        "transfer-asset-scoped" => emit_transfer_asset_scoped(),
        "claim-identifier" => emit_claim_identifier(),
        "contract-lifecycle" => emit_contract_lifecycle(),
        "hidden-ram-fhe-program" => emit_hidden_ram_fhe_program(),
        "multisig-accounts-v1" => multisig_accounts::emit(),
        "fastpq-balance-keys-v1" => fastpq_balance_keys::emit(),
        "native-sumeragi-status-v1" => native_sumeragi_status::emit(),
        "native-sumeragi-lanes-v1" => native_sumeragi_lanes::emit(),
        other => {
            eprintln!("Unknown fixture: {other}");
            std::process::exit(1);
        }
    }
}
fn emit_contract_lifecycle() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let contract_address: ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("canonical contract address");
    let account_id = parity_account_id();
    let code_hash = Hash::new(b"contract-lifecycle-activation-parity");
    let deactivate = DeactivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 5,
        reason: Some("planned rotation".to_owned()),
    };
    let activate = ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 6,
        code_hash,
    };
    let set_delegation = SetContractParliamentDelegation {
        contract_address: contract_address.clone(),
        expected_revision: 7,
        delegated: true,
    };
    let offer_account = OfferContractOwnership {
        contract_address: contract_address.clone(),
        expected_revision: 8,
        new_owner: ContractLifecycleOwnerV1::Account(account_id.clone()),
    };
    let offer_parliament = OfferContractOwnership {
        contract_address: contract_address.clone(),
        expected_revision: 9,
        new_owner: ContractLifecycleOwnerV1::Parliament,
    };
    let accept = AcceptContractOwnership {
        contract_address: contract_address.clone(),
        expected_revision: 10,
    };
    let cancel = CancelContractOwnershipOffer {
        contract_address: contract_address.clone(),
        expected_revision: 11,
    };
    println!(
        "{}",
        hex::encode(norito::to_bytes(&deactivate).expect("encode deactivation"))
    );
    println!(
        "{}",
        hex::encode(norito::to_bytes(&activate).expect("encode activation"))
    );
    println!(
        "{}",
        hex::encode(norito::to_bytes(&set_delegation).expect("encode delegation"))
    );
    println!(
        "{}",
        hex::encode(norito::to_bytes(&offer_account).expect("encode account ownership offer"))
    );
    println!(
        "{}",
        hex::encode(
            norito::to_bytes(&offer_parliament).expect("encode Parliament ownership offer")
        )
    );
    println!(
        "{}",
        hex::encode(norito::to_bytes(&accept).expect("encode ownership acceptance"))
    );
    println!(
        "{}",
        hex::encode(norito::to_bytes(&cancel).expect("encode ownership-offer cancellation"))
    );
    println!("{contract_address}");
    println!("{account_id}");
    println!("{code_hash}");
}
fn emit_hidden_ram_fhe_program() {
    let program = default_bfv_programmed_hidden_program();
    let encoded = norito::to_bytes(&program).expect("encode HiddenRamFheProgram");
    println!("{}", hex::encode(encoded));
}
fn emit_register_account() {
    let account_id = parity_account_id();
    let new_account = NewAccount::new(account_id);
    let register_box = RegisterBox::Account(Register::account(new_account));
    let encoded = norito::to_bytes(&register_box).expect("encode RegisterBox");
    println!("{}", hex::encode(encoded));
}
fn emit_transfer_asset() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let account_id = parity_account_id();
    let domain = DomainId::try_new("wonderland", "universal").expect("domain id");
    let name: Name = "rose".parse().unwrap();
    let asset_def_id = AssetDefinitionId::derive_from_components(domain, name);
    let asset_id = AssetId::new(asset_def_id.clone(), account_id.clone());
    let amount = Quantity::from(100_u64);
    let destination = account_id.clone();
    let transfer = Transfer::asset_quantity(asset_id, amount, destination);
    let transfer_box: TransferBox = transfer.into();
    let encoded = norito::to_bytes(&transfer_box).expect("encode TransferBox");
    // Line 1: wire payload hex
    println!("{}", hex::encode(encoded));
    // Line 2: asset ID string (<base58-def>#<i105-account>)
    println!("{}#{}", asset_def_id, account_id);
    // Line 3: amount
    println!("100");
    // Line 4: destination account I105
    println!("{}", account_id);
}
fn emit_transfer_asset_scoped() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(TAIRA_CHAIN_DISCRIMINANT);
    let account_id = parity_account_id();
    let domain = DomainId::try_new("wonderland", "universal").expect("domain id");
    let name: Name = "rose".parse().unwrap();
    let asset_def_id = AssetDefinitionId::derive_from_components(domain, name);
    let asset_id = AssetId::with_scope(
        asset_def_id.clone(),
        account_id.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(42)),
    );
    let amount = Quantity::from(100_u64);
    let destination = account_id.clone();
    let transfer = Transfer::asset_quantity(asset_id, amount, destination);
    let transfer_box: TransferBox = transfer.into();
    let encoded = norito::to_bytes(&transfer_box).expect("encode scoped TransferBox");
    println!("{}", hex::encode(encoded));
    println!("{}#{}#dataspace:42", asset_def_id, account_id);
    println!("100");
    println!("{}", account_id);
}
fn emit_claim_identifier() {
    let account_id = parity_account_id();
    let policy_id = IdentifierPolicyId::new("email".parse().unwrap(), "retail".parse().unwrap());
    let program_id: RamLfeProgramId = "parity_test".parse().unwrap();
    let dummy_hash = iroha_crypto::Hash::new([0xAB; 32]);
    let execution = RamLfeExecutionReceiptPayload {
        program_id: program_id.clone(),
        program_digest: dummy_hash,
        backend: RamLfeBackend::HkdfSha3_512PrfV1,
        verification_mode: RamLfeVerificationMode::Signed,
        input_ciphertext_hash: dummy_hash,
        output_ciphertext_hash: dummy_hash,
        parameter_digest: dummy_hash,
        evaluation_key_digest: dummy_hash,
        output_hash: dummy_hash,
        associated_data_hash: dummy_hash,
        executed_at_ms: 1_735_000_000_000,
        expires_at_ms: Some(1_735_000_120_000),
    };
    let opaque_id = OpaqueAccountId::from_hash(dummy_hash);
    let uaid = UniversalAccountId::from_hash(dummy_hash);
    // Deterministic signature bytes (64 bytes of 0xCD).
    let signature_bytes = [0xCD_u8; 64];
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"kotlin-identifier-component-network",
        )),
    );
    let receipt_payload = IdentifierResolutionReceiptPayload {
        network_id,
        policy_id,
        execution,
        opening: RamLfeOutputOpening {
            payload: RamLfeOutputOpeningPayload {
                program_id,
                input_ciphertext_hash: dummy_hash,
                output_ciphertext_hash: dummy_hash,
                parameter_digest: dummy_hash,
                evaluation_key_digest: dummy_hash,
                opened_output_hash: dummy_hash,
                opened_at_ms: 1_735_000_000_000,
                expires_at_ms: Some(1_735_000_120_000),
            },
            signature: iroha_crypto::Signature::try_from_bytes(&signature_bytes)
                .expect("Kotlin fixture opening signature is non-empty and nonzero"),
        },
        opaque_id,
        receipt_hash: dummy_hash,
        uaid,
        account_id: account_id.clone(),
    };
    let signature = iroha_crypto::Signature::try_from_bytes(&signature_bytes)
        .expect("Kotlin fixture receipt signature is non-empty and nonzero");
    let receipt = IdentifierResolutionReceipt {
        payload: receipt_payload,
        attestation: RamLfeReceiptAttestation::Signed(signature),
        phone_retail_canonicality: None,
    };
    let claim = ClaimIdentifier {
        account: account_id.clone(),
        receipt,
    };
    let encoded = norito::to_bytes(&claim).expect("encode ClaimIdentifier");
    // Line 1: full wire payload hex
    println!("{}", hex::encode(encoded));
    // Line 2: account I105
    println!("{}", account_id);
    // Line 3: signature bytes hex
    println!("{}", hex::encode(signature_bytes));
    // Line 4: canonical hash hex used by receipt fields
    println!("{}", hex::encode(&dummy_hash.as_ref()[..]));
    // Line 5: exact DATA network used by the signed receipt payload.
    println!("{}", hex::encode(network_id.as_bytes()));
}
