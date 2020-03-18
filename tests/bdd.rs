#[cfg(test)]
mod tests {
    use iroha::{
        client::Client,
        consensus::sumeragi::Sumeragi,
        model::{
            block::*,
            commands::{accounts::*, assets::*, domains::*},
            tx::Transaction,
        },
        networking::torii::Torii,
        storage::kura,
    };
    use std::thread;

    #[async_std::test]
    async fn client_can_transfer_asset_to_another_account() {
        // Given
        let create_role = &CreateRole {
            role_name: "user".to_string(),
            permissions: Vec::new(),
        };
        let create_domain = &CreateDomain {
            domain_id: "domain".to_string(),
            default_role: "user".to_string(),
        };
        let account1_id = "account1_name@domain";
        let account2_id = "account2_name@domain";
        let create_account1 = &CreateAccount {
            account_name: "account1_name".to_string(),
            domain_id: "domain".to_string(),
            public_key: [63; 32],
        };
        let create_account2 = &CreateAccount {
            account_name: "account2_name".to_string(),
            domain_id: "domain".to_string(),
            public_key: [63; 32],
        };
        let create_asset = &CreateAsset {
            asset_name: "xor".to_string(),
            domain_id: "domain".to_string(),
            precision: 0,
        };
        let mut blockchain = Blockchain::new(kura::Kura::fast_init().await);
        blockchain.accept(vec![Transaction::builder(
            vec![
                create_role.into(),
                create_domain.into(),
                create_account1.into(),
                create_account2.into(),
                create_asset.into(),
            ],
            String::from(account1_id),
        )
        .build()]);
        thread::spawn(|| {
            let mut torii = Torii::new(Sumeragi::new(blockchain));
            torii.start();
        });

        //When
        let asset_id = "xor";
        let transfer_asset = &TransferAsset {
            source_account_id: String::from(account1_id),
            destination_account_id: String::from(account2_id),
            asset_id: String::from(asset_id),
            description: "description".to_string(),
            amount: 200.2,
        };
        let iroha_client = Client::new();
        iroha_client
            .submit(transfer_asset.into())
            .expect("Failed to submit command.");

        //Then
        // iroha_peer::receive(command) --> queue.push(tx::from(command).validate()) -->
        // timer::every_minute( |txs: Vec<Tx::Valid>| consensus.sign(txs)) -->
        // match cons_res
        // Agreed => txs.for_each(peer.sign(tx))
        // consensus.publish(txs: Vec<Tx::Signed>)
        // kura.store(txs: Vec<Tx::Signed>)
        // WSV.update(txs: Vec<Tx::Signed>)
        let asset = iroha_client
            .assets()
            .by_id(asset_id)
            .expect("Failed to find asset.");
        assert_eq!(account2_id, asset.account_id);
    }
}
