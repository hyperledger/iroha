#[cfg(test)]
mod tests {
    use iroha::{
        model::{
            block::Block,
            commands::{
                accounts::{CreateAccount, CreateRole},
                assets::{CreateAsset, TransferAsset},
                domains::CreateDomain,
                oob::Command,
            },
            tx::Transaction,
        },
        storage::kura,
    };

    #[async_std::test]
    async fn transfer_asset_from_account1_to_account2() {
        let create_role_command = Command {
            version: 1,
            command_type: 0,
            payload: CreateRole {
                role_name: "user".to_string(),
                permissions: Vec::new(),
            }
            .into(),
        };
        let create_domain_command = Command {
            version: 1,
            command_type: 0,
            payload: CreateDomain {
                domain_id: "domain".to_string(),
                default_role: "user".to_string(),
            }
            .into(),
        };
        let account1_id = "account1_name@domain".to_string();
        let account2_id = "account2_name@domain".to_string();
        let create_account1_command = Command {
            version: 1,
            command_type: 0,
            payload: CreateAccount {
                account_name: "account1_name".to_string(),
                domain_id: "domain".to_string(),
                public_key: [63; 32],
            }
            .into(),
        };
        let create_account2_command = Command {
            version: 1,
            command_type: 0,
            payload: CreateAccount {
                account_name: "account2_name".to_string(),
                domain_id: "domain".to_string(),
                public_key: [63; 32],
            }
            .into(),
        };
        let create_asset_command = Command {
            version: 1,
            command_type: 0,
            payload: CreateAsset {
                asset_name: "xor".to_string(),
                domain_id: "domain".to_string(),
                precision: 0,
            }
            .into(),
        };
        let transfer_asset_command: Command = TransferAsset {
            source_account_id: account1_id.clone(),
            destination_account_id: account2_id.clone(),
            asset_id: "xor".to_string(),
            description: "description".to_string(),
            amount: 200.2,
        }
        .into();
        let block = Block {
            height: 0,
            timestamp: 0,
            transactions: vec![
                Transaction {
                    commands: vec![
                        create_role_command,
                        create_domain_command,
                        create_account1_command,
                        create_account2_command,
                        create_asset_command,
                    ],
                    creation_time: 0,
                    account_id: "source@domain".to_string(),
                    quorum: 1,
                    signatures: vec![],
                },
                Transaction {
                    commands: vec![transfer_asset_command],
                    creation_time: 1,
                    account_id: "source@domain".to_string(),
                    quorum: 1,
                    signatures: vec![],
                },
            ],
            previous_block_hash: [0; 32],
            rejected_transactions_hashes: Option::None,
        };
        //TODO: replace with `strict_init` when validation will be ready.
        let mut kura = kura::Kura::fast_init().await;
        assert!(kura.store(block).await.is_ok());
        assert_eq!(
            kura.world_state_view
                .get_assets_by_account_id(&account1_id)
                .len(),
            0
        );
        assert_eq!(
            kura.world_state_view
                .get_assets_by_account_id(&account2_id)
                .len(),
            1
        );
    }
}
