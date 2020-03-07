#[cfg(test)]
mod tests {

    use iroha::{model::model, storage::kura};

    #[test]
    fn transfer_asset_from_account1_to_account2() {
        //TODO: replace with `strict_init` when validation will be ready.
        let mut kura = kura::Kura::fast_init();
        let create_role_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::CreateRole {
                role_name: "user".to_string(),
                permissions: Vec::new(),
            }
            .into(),
        };
        let create_domain_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::CreateDomain {
                domain_id: "domain".to_string(),
                default_role: "user".to_string(),
            }
            .into(),
        };
        let create_account1_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::CreateAccount {
                account_name: "account1_name".to_string(),
                domain_id: "domain".to_string(),
                public_key: [63; 32],
            }
            .into(),
        };
        let create_account2_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::CreateAccount {
                account_name: "account1_name".to_string(),
                domain_id: "domain".to_string(),
                public_key: [63; 32],
            }
            .into(),
        };
        let create_asset_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::CreateAsset {
                asset_name: "xor".to_string(),
                domain_id: "domain".to_string(),
                precision: 0,
            }
            .into(),
        };
        let transfer_asset_command = model::Command {
            version: 1,
            command_type: 0,
            payload: model::commands::TransferAsset {
                source_account_id: "source@domain".to_string(),
                destination_account_id: "destination@domain".to_string(),
                asset_id: "xor".to_string(),
                description: "description".to_string(),
                amount: 200.2,
            }
            .into(),
        };
        let block = model::Block {
            height: 0,
            timestamp: 0,
            transactions: vec![
                model::Transaction {
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
                model::Transaction {
                    commands: vec![transfer_asset_command],
                    creation_time: 1,
                    account_id: "source@domain".to_string(),
                    quorum: 1,
                    signatures: vec![],
                },
            ],
            previous_block_hash: model::Hash {},
            rejected_transactions_hashes: Option::None,
        };
        assert!(kura.store(block).is_ok());
    }
}
