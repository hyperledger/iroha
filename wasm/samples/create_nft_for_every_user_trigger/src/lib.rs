//! Smartcontract which creates new nft for every user
#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{format, string::ToString};

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::prelude::*;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_trigger::stub_getrandom);

#[iroha_trigger::main]
fn main(host: Iroha, _context: Context) {
    iroha_trigger::log::info!("Executing trigger");
    let accounts_cursor = host.query(FindAccounts).execute().dbg_unwrap();

    let bad_domain_ids: [DomainId; 3] = [
        "system".parse().dbg_unwrap(),
        "genesis".parse().dbg_unwrap(),
        "garden_of_live_flowers".parse().dbg_unwrap(),
    ];

    for account in accounts_cursor {
        let account = account.dbg_unwrap();

        if bad_domain_ids.contains(account.id().domain()) {
            continue;
        }

        let mut metadata = Metadata::default();
        let name = format!(
            "nft_for_{}_in_{}",
            account.id().signatory(),
            account.id().domain()
        )
        .parse()
        .dbg_unwrap();
        metadata.insert(name, true);

        let nft_id = generate_new_nft_id(&host, account.id());
        let nft_definition = AssetDefinition::store(nft_id.clone())
            .mintable_once()
            .with_metadata(metadata);
        let account_nft_id = AssetId::new(nft_id, account.id().clone());
        let account_nft = Asset::new(account_nft_id, Metadata::default());

        host.submit(&Register::asset_definition(nft_definition))
            .dbg_unwrap();
        host.submit(&Register::asset(account_nft)).dbg_unwrap();
    }

    iroha_trigger::log::info!("Smart contract executed successfully");
}

fn generate_new_nft_id(host: &Iroha, account_id: &AccountId) -> AssetDefinitionId {
    let assets = host
        .query(FindAssets)
        .filter_with(|asset| asset.id.account.eq(account_id.clone()))
        .execute()
        .dbg_unwrap();

    let new_number = assets
        .map(|res| res.dbg_unwrap())
        .filter(|asset| asset.id().definition().to_string().starts_with("nft_"))
        .count()
        .checked_add(1)
        .dbg_unwrap();
    iroha_trigger::log::debug!(&format!("New number: {}", new_number));

    format!(
        "nft_number_{}_for_{}#{}",
        new_number,
        account_id.signatory(),
        account_id.domain()
    )
    .parse()
    .dbg_unwrap()
}
