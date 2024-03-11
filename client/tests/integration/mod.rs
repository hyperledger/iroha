use iroha_crypto::KeyPair;
use iroha_data_model::account::{Account, AccountId, NewAccount};

mod add_account;
mod add_domain;
mod asset;
mod asset_propagation;
mod burn_public_keys;
mod domain_owner_permissions;
mod events;
mod extra_functional;
mod multisignature_account;
mod multisignature_transaction;
mod non_mintable;
mod pagination;
mod permissions;
mod queries;
mod roles;
mod set_parameter;
mod sorting;
mod transfer_asset;
mod triggers;
mod tx_chain_id;
mod tx_history;
mod tx_rollback;
mod upgrade;

fn new_account_with_random_public_key(account_id: AccountId) -> NewAccount {
    Account::new(account_id, KeyPair::random().into_parts().0)
}
