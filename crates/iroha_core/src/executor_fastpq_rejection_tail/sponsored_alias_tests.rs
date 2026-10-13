//! Rejection-tail sizing uses the frozen sponsor and canonical committed receiver.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    account::{
        AccountAddress,
        rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
    },
    isi::Log,
    nexus::DataSpaceCatalog,
    sns::{NameControllerV1, NameRecordV1},
    transaction::TransactionBuilder,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use nonzero_ext::nonzero;

fn fixture() -> (State, FeeSponsorProgramId, AssetDefinitionId) {
    let domain = DomainId::try_new("fees", "universal").unwrap();
    let mut world = World::with(
        [Domain::new(domain.clone()).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let alias = AccountAlias::new(
        "collector".parse().unwrap(),
        Some(AccountAliasDomain::new(domain.name().clone())),
        DataSpaceId::UNIVERSAL,
    );
    let selector =
        crate::sns::selector_for_account_alias(&alias, &DataSpaceCatalog::default()).unwrap();
    let address = AccountAddress::from_account_id(&ALICE_ID).unwrap();
    let lease = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        100,
        200,
        300,
        iroha_model_base::metadata::Metadata::default(),
    );
    world.smart_contract_state_mut_for_testing().insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&lease),
    );
    world
        .account_aliases
        .insert(alias.clone(), ALICE_ID.clone());
    world
        .replace_account_rekey_record_for_testing(AccountRekeyRecord::new(alias, ALICE_ID.clone()));
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let program = FeeSponsorProgramId::new(ALICE_ID.clone(), "tail-gas".parse().unwrap());
    let asset = AssetDefinitionId::derive_from_components(domain, "gas".parse().unwrap());
    (state, program, asset)
}

fn source(state: &State, program: FeeSponsorProgramId) -> SignedTransaction {
    TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::sponsor(program, 1, Vec::new(), None),
    )
    .with_instructions([Log::new(
        iroha_logger::Level::INFO,
        "rejection tail".to_owned(),
    )])
    .sign(ALICE_KEYPAIR.private_key())
}

fn quote(program: FeeSponsorProgramId, asset: AssetDefinitionId) -> FeeAdmissionQuote {
    FeeAdmissionQuote {
        charges: vec![FeeChargeBound {
            kind: FeeChargeKind::PipelineGas,
            asset_definition_id: asset,
            max_bound: Quantity::one(),
        }],
        debit_source: FeeDebitSource::SponsorProgram(program),
        program_revision: Some(1),
        relay_leases: BTreeMap::new(),
        capacities: BTreeMap::new(),
        authority_balances: BTreeMap::new(),
        authority_charge_assets: BTreeMap::new(),
    }
}

#[test]
fn sponsored_tail_uses_canonical_receiver_without_creating_transfer_work() {
    let (state, program, asset) = fixture();
    let signed = source(&state, program.clone());
    let quote = quote(program, asset);
    let hash = iroha_crypto::Hash::from(signed.hash_as_entrypoint());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 50, 0));
    let mut tx = block.transaction_for_fastpq_testing(hash);
    tx.pipeline.gas.tech_account_id = AccountAddress::from_account_id(&ALICE_ID)
        .unwrap()
        .to_i105_for_discriminant(427)
        .unwrap();
    tx.nexus.fees.sponsor_vault_custody_account_id = BOB_ID.clone();
    assert_eq!(
        crate::pipeline_gas_policy::receiver_id(&tx.pipeline.gas.tech_account_id).unwrap(),
        *ALICE_ID
    );
    let before = tx.fastpq_rejection_tail_context(hash).unwrap();
    preflight(&mut tx, &ALICE_ID, &signed, Some(&quote), None).unwrap();
    assert_eq!(tx.fastpq_rejection_tail_context(hash).unwrap(), before);
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.last_tx_gas_used, 0);
}

#[test]
fn an_alias_cannot_replace_the_committed_fee_receiver_before_work() {
    let (state, program, asset) = fixture();
    let signed = source(&state, program.clone());
    let quote = quote(program, asset);
    let hash = iroha_crypto::Hash::from(signed.hash_as_entrypoint());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 50, 0));
    let mut tx = block.transaction_for_fastpq_testing(hash);
    tx.pipeline.gas.tech_account_id = "collector@fees.universal".to_owned();
    tx.nexus.fees.sponsor_vault_custody_account_id = BOB_ID.clone();
    assert_eq!(
        parse_account_id_literal(
            &tx.world,
            &tx.nexus.dataspace_catalog,
            &tx.pipeline.gas.tech_account_id,
            50
        )
        .unwrap(),
        Some(ALICE_ID.clone())
    );
    assert!(matches!(
        preflight(&mut tx, &ALICE_ID, &signed, Some(&quote), None),
        Err(ValidationFail::InternalError(_))
    ));
    assert!(tx.fastpq_rejection_tail_context(hash).is_err());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.last_tx_gas_used, 0);
}

#[test]
fn foreign_sponsor_quote_cannot_supply_a_tail_owner() {
    let (state, program, asset) = fixture();
    let signed = source(&state, program);
    let foreign = FeeSponsorProgramId::new(BOB_ID.clone(), "foreign-tail".parse().unwrap());
    let quote = quote(foreign, asset);
    let hash = iroha_crypto::Hash::from(signed.hash_as_entrypoint());
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 50, 0));
    let mut tx = block.transaction_for_fastpq_testing(hash);
    tx.pipeline.gas.tech_account_id = ALICE_ID.to_string();
    assert!(matches!(
        preflight(&mut tx, &ALICE_ID, &signed, Some(&quote), None),
        Err(ValidationFail::InternalError(_))
    ));
    assert!(tx.fastpq_rejection_tail_context(hash).is_err());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.last_tx_gas_used, 0);
}
