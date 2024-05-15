//! Smartcontract which creates new nft for every user
#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{format, string::ToString};

use iroha_trigger::prelude::*;
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

#[iroha_trigger::main]
fn main(_id: TriggerId, _owner: AccountId, _event: EventBox) {
    iroha_trigger::log::info!("Executing trigger");

    let accounts_cursor = FindAllAccounts.execute().dbg_unwrap();

    let limits = MetadataLimits::new(256, 256);

    let bad_domain_ids: [DomainId; 2] = [
        "genesis".parse().dbg_unwrap(),
        "garden_of_live_flowers".parse().dbg_unwrap(),
    ];

    for account in accounts_cursor {
        let account = account.dbg_unwrap();

        if bad_domain_ids.contains(account.id().domain_id()) {
            continue;
        }

        let mut metadata = Metadata::new();
        let name = format!(
            "nft_for_{}_in_{}",
            account.id().signatory(),
            account.id().domain_id()
        )
        .parse()
        .dbg_unwrap();
        metadata.insert_with_limits(name, true, limits).dbg_unwrap();

        let nft_id = generate_new_nft_id(account.id());
        let nft_definition = AssetDefinition::store(nft_id.clone())
            .mintable_once()
            .with_metadata(metadata);
        let account_nft_id = AssetId::new(nft_id, account.id().clone());
        let account_nft = Asset::new(account_nft_id, Metadata::new());

        Register::asset_definition(nft_definition)
            .execute()
            .dbg_unwrap();
        Register::asset(account_nft).execute().dbg_unwrap();
    }

    iroha_trigger::log::info!("Smart contract executed successfully");
}

fn generate_new_nft_id(account_id: &AccountId) -> AssetDefinitionId {
    let assets = FindAssetsByAccountId::new(account_id.clone())
        .execute()
        .dbg_unwrap();

    let new_number = assets
        .into_iter()
        .map(|res| res.dbg_unwrap())
        .filter(|asset| asset.id().definition_id().to_string().starts_with("nft_"))
        .count()
        .checked_add(1)
        .dbg_unwrap();
    iroha_trigger::log::debug!(&format!("New number: {}", new_number));

    format!(
        "nft_number_{}_for_{}#{}",
        new_number,
        account_id.signatory(),
        account_id.domain_id()
    )
    .parse()
    .dbg_unwrap()
}
