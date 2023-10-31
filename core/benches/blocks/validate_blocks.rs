use eyre::Result;
use iroha_core::prelude::*;
use iroha_data_model::{isi::InstructionExpr, prelude::*};

#[path = "./common.rs"]
mod common;

use common::*;

#[derive(Clone)]
pub struct WsvValidateBlocks {
    wsv: WorldStateView,
    instructions: Vec<Vec<InstructionExpr>>,
    key_pair: KeyPair,
    account_id: AccountId,
}

impl WsvValidateBlocks {
    /// Create [`WorldStateView`] and blocks for benchmarking
    ///
    /// # Errors
    /// - Failed to parse [`AccountId`]
    /// - Failed to generate [`KeyPair`]
    /// - Failed to create instructions for block
    pub fn setup() -> Result<Self> {
        let domains = 100;
        let accounts_per_domain = 1000;
        let assets_per_domain = 1000;
        let account_id: AccountId = "alice@wonderland".parse()?;
        let key_pair = KeyPair::generate()?;
        let wsv = build_wsv(&account_id, &key_pair);

        let nth = 100;
        let instructions = [
            populate_wsv(domains, accounts_per_domain, assets_per_domain, &account_id),
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ]
        .into_iter()
        .collect::<Vec<_>>();

        Ok(Self {
            wsv,
            instructions,
            key_pair,
            account_id,
        })
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If wsv isn't one block ahead of finalized wsv.
    pub fn measure(
        Self {
            wsv,
            instructions,
            key_pair,
            account_id,
        }: Self,
    ) -> Result<()> {
        let mut finalized_wsv = wsv;
        let mut wsv = finalized_wsv.clone();

        assert_eq!(wsv.height(), 0);
        for (instructions, i) in instructions.into_iter().zip(1..) {
            finalized_wsv = wsv.clone();
            let block = create_block(&mut wsv, instructions, account_id.clone(), key_pair.clone());
            wsv.apply_without_execution(&block)?;
            assert_eq!(wsv.height(), i);
            assert_eq!(wsv.height(), finalized_wsv.height() + 1);
        }

        Ok(())
    }
}
