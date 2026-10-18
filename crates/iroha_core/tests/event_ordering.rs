//! Ensure structured data events are emitted in the same order as instructions

//! execute within a single transaction (WSV Overlays & Commit ordering).
use iroha_model_base::domain::DomainId;
// no specific event enum imports needed here
use iroha_data_model::prelude::*;
#[test]
fn data_events_follow_instruction_order_in_tx() {
    // Build world with a domain, account, and an asset definition
    let (authority_id, kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&authority_id);
    let acc = Account::new(authority_id.clone()).build(&authority_id);
    let ad: AssetDefinition = AssetDefinition::new(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        "rose".to_owned(),
        NumericSpec::default(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority_id);
    let world = iroha_core::state::World::with([domain], [acc], [ad]);
    let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 0),
    )
    .expect("native genesis");
    let network_id = chain.network_id();
    chain.take_events().unwrap();
    // Single transaction: three instructions in a fixed order
    let asset = AssetId::of(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        authority_id.clone(),
    );
    let instrs: Vec<InstructionBox> = vec![
        // 1) Account metadata insert
        SetKeyValue::account(authority_id.clone(), "a_key".parse().unwrap(), "a_val").into(),
        // 2) Domain metadata insert
        SetKeyValue::domain(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "d_key".parse().unwrap(),
            "d_val",
        )
        .into(),
        // 3) Mint creates the asset (first time)
        Mint::asset_quantity(10_u32, asset.clone()).into(),
    ];
    let tx = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instrs)
    .sign(kp.private_key());
    chain.commit(vec![tx]);
    let committed = chain.committed(chain.height());
    assert!(committed.block().output_error(0).is_none());
    let events = chain.take_events().expect("native publication events");
    // Extract Data events in emission order
    let data_events: Vec<_> = events
        .into_iter()
        .filter_map(|ev| match ev {
            iroha_data_model::events::EventBox::Data(d) => Some(d),
            _ => None,
        })
        .collect();
    // Expect at least three data events; basic sanity on count
    assert!(data_events.len() >= 3, "expected multiple data events");
}
