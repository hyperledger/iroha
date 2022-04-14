#![no_std]
#![no_main]

extern crate alloc;

use alloc::{format, string::ToString, vec::Vec};
use core::str::FromStr;

use iroha_wasm::{data_model::prelude::*, Execute};

#[iroha_wasm::iroha_wasm]
fn smartcontract_entry_point(_account_id: AccountId) {
    let query = QueryBox::FindAllAccounts(FindAllAccounts {});
    let accounts: Vec<Account> = query.execute().try_into().unwrap();

    let limits = MetadataLimits::new(256, 256);

    for account in accounts {
        let mut metadata = Metadata::new();
        metadata
            .insert_with_limits(
                format!("nft_for_{}", account.id()).parse().unwrap(),
                true.into(),
                limits,
            )
            .unwrap();

        let nft_id = generate_new_nft_id(account.id());
        let nft_definition = AssetDefinition::store(nft_id.clone())
            .mintable_once()
            .with_metadata(metadata)
            .build();
        let account_nft_id = <Asset as Identifiable>::Id::new(nft_id, account.id().clone());

        Instruction::Register(RegisterBox::new(nft_definition)).execute();
        Instruction::SetKeyValue(SetKeyValueBox::new(
            account_nft_id,
            Name::from_str("has_this_nft").unwrap(),
            Value::Bool(true),
        ))
        .execute();
    }
}

fn generate_new_nft_id(account_id: &<Account as Identifiable>::Id) -> AssetDefinitionId {
    let query = QueryBox::FindAssetsByAccountId(FindAssetsByAccountId::new(account_id.clone()));
    let assets: Vec<Asset> = query.execute().try_into().unwrap();

    let new_number = assets
        .into_iter()
        .filter(|asset| asset.id().definition_id.to_string().starts_with("nft_"))
        .count()
        + 1;

    format!("nft_{}_{}", account_id, new_number)
        .parse()
        .unwrap()
}
