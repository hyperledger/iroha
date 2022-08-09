#![allow(clippy::restriction)]

mod queries;
mod revoke_and_grant;

use std::str::FromStr as _;

use super::*;

/// A test environment that contains test domains, accounts, and assets.
struct TestEnv {
    /// Alice's Id that owns Gold and Bronze assets.
    alice_id: AccountId,
    /// Bob's Id that owns Silver asset.
    bob_id: AccountId,
    /// Carol's Id that owns Bronze asset.
    carol_id: AccountId,
    /// Gold asset Id.
    gold_asset_id: AssetId,
    /// Gold asset definition Id.
    gold_asset_definition_id: AssetDefinitionId,
    /// Silver asset Id.
    silver_asset_id: AssetId,
    /// Silver asset definition Id.
    silver_asset_definition_id: AssetDefinitionId,
    /// Bronze asset Id.
    bronze_asset_id: AssetId,
    /// Bronze asset definition Id.
    bronze_asset_definition_id: AssetDefinitionId,
    /// Wonderland is the domain where Alice is registered
    wonderland: (DomainId, Domain),
    /// Denoland is the domain where Carol is registered
    denoland: (DomainId, Domain),
    /// World state view contains wonderland and denoland domains.
    wsv: WorldStateView,
    /// A trigger that mints Gold asset created by Alice
    mintbox_gold_trigger_id: TriggerId,
}

impl TestEnv {
    /// Create a test environment
    fn new() -> Self {
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let mut alice = Account::new(alice_id.clone(), []).build();

        let gold_asset_definition_id =
            AssetDefinitionId::from_str("gold#wonderland").expect("Valid");
        let gold_asset_id = AssetId::new(gold_asset_definition_id.clone(), alice_id.clone());
        let gold_asset = Asset::new(gold_asset_id.clone(), AssetValue::Quantity(100));

        alice.add_asset(gold_asset);

        let bob_id = AccountId::from_str("bob@wonderland").expect("Valid");
        let mut bob = Account::new(bob_id.clone(), []).build();

        let silver_asset_definition_id =
            AssetDefinitionId::from_str("silver#wonderland").expect("Valid");
        let silver_asset_id = AssetId::new(silver_asset_definition_id.clone(), bob_id.clone());
        let silver_asset = Asset::new(silver_asset_id.clone(), AssetValue::Quantity(200));

        bob.add_asset(silver_asset);

        let carol_id = AccountId::from_str("carol@denoland").expect("Valid");
        let mut carol = Account::new(carol_id.clone(), []).build();

        let bronze_asset_definition_id =
            AssetDefinitionId::from_str("bronze#denoland").expect("Valid");
        let bronze_asset_id = AssetId::new(bronze_asset_definition_id.clone(), carol_id.clone());
        let bronze_asset = Asset::new(bronze_asset_id.clone(), AssetValue::Quantity(300));

        carol.add_asset(bronze_asset.clone());

        alice.add_asset(bronze_asset);

        let wonderland_id = DomainId::from_str("wonderland").expect("Valid");
        let mut wonderland = Domain::new(wonderland_id.clone()).build();

        wonderland.add_account(alice);

        wonderland.add_account(bob);

        let denoland_id = DomainId::from_str("denoland").expect("Valid");
        let mut denoland = Domain::new(denoland_id.clone()).build();

        denoland.add_account(carol);

        let world = World::with([wonderland.clone(), denoland.clone()], Vec::new());

        let wsv = WorldStateView::new(world);

        let mintbox_gold_trigger_id = TriggerId::from_str("mint_box_gold_asset").expect("Valid");

        wsv.modify_triggers(|triggers| {
            let trigger_instructions = vec![MintBox::new(1_u32, gold_asset_id.clone()).into()];
            let trigger: Trigger<FilterBox> = Trigger::new(
                mintbox_gold_trigger_id.clone(),
                Action::new(
                    Executable::from(trigger_instructions),
                    Repeats::Indefinitely,
                    alice_id.clone(),
                    FilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
                ),
            );

            triggers.add_time_trigger(trigger.try_into().expect("Valid"));

            Ok(TriggerEvent::Created(mintbox_gold_trigger_id.clone()))
        })
        .expect("Valid");

        Self {
            alice_id,
            bob_id,
            carol_id,
            gold_asset_id,
            gold_asset_definition_id,
            silver_asset_id,
            silver_asset_definition_id,
            bronze_asset_id,
            bronze_asset_definition_id,
            wonderland: (wonderland_id, wonderland),
            denoland: (denoland_id, denoland),
            mintbox_gold_trigger_id,
            wsv,
        }
    }
}
