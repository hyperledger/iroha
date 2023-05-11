//! Smartcontract which creates new nft for every user
//!
//! This module isn't included in the build-tree,
//! but instead it is being built by a `client/build.rs`
#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{format, string::ToString};

use iroha_wasm::{data_model::prelude::*, prelude::*};

#[iroha_wasm::main]
fn main() {
    iroha_wasm::info!("Executing trigger");

    let accounts = FindAllAccounts.execute();
    let limits = MetadataLimits::new(256, 256);

    for account in accounts {
        let mut metadata = Metadata::new();
        let name = format!(
            "nft_for_{}_in_{}",
            account.id().name(),
            account.id().domain_id()
        )
        .parse()
        .dbg_unwrap();
        metadata
            .insert_with_limits(name, true.into(), limits)
            .dbg_unwrap();

        let nft_id = generate_new_nft_id(account.id());
        let nft_definition = AssetDefinition::store(nft_id.clone())
            .mintable_once()
            .with_metadata(metadata);
        let account_nft_id = <Asset as Identifiable>::Id::new(nft_id, account.id().clone());
        let account_nft = Asset::new(account_nft_id, Metadata::new());

        RegisterBox::new(nft_definition).execute();
        RegisterBox::new(account_nft).execute();
    }

    iroha_wasm::info!("Smart contract executed successfully");
}

fn generate_new_nft_id(account_id: &<Account as Identifiable>::Id) -> AssetDefinitionId {
    let assets = FindAssetsByAccountId::new(account_id.clone()).execute();

    let new_number = assets
        .into_iter()
        .filter(|asset| asset.id().definition_id().to_string().starts_with("nft_"))
        .count()
        .checked_add(1)
        .dbg_unwrap();
    iroha_wasm::debug!(&format!("New number: {}", new_number));

    format!(
        "nft_number_{}_for_{}#{}",
        new_number,
        account_id.name(),
        account_id.domain_id()
    )
    .parse()
    .dbg_unwrap()
}
