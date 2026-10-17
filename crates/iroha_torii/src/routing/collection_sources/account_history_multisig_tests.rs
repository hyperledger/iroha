//! Account history reports executed multisig value movements from real certified chains.
//!
//! Include as a child of `routing::collection_sources`. These fixtures submit signed
//! transactions through production execution; they never install claimed execution records.

use super::*;
use iroha_core::{
    state::{World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    isi::{
        Grant, InstructionBox, Mint, Register, Transfer, TransferAssetBatch,
        TransferAssetBatchEntry,
    },
    permission::Permission,
};
use iroha_executor_data_model::isi::multisig::{
    DEFAULT_MULTISIG_TTL_MS, MultisigApprove, MultisigCancel, MultisigProposalId,
    MultisigProposalNonce, MultisigPropose, MultisigRegister, MultisigSpec,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::list_query::field;
use norito::json::Map;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU64},
};

struct HistoryOccurrence {
    id: MultisigProposalId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    propose: InstructionBox,
}

struct HistorySubmission {
    entrypoint_hash: String,
    height: u64,
    succeeded: bool,
}

struct MultisigHistoryFixture {
    chain: CertifiedTestChain,
    first: KeyPair,
    second: KeyPair,
    account: AccountId,
    recipient: AccountId,
    holding: AssetId,
}

impl MultisigHistoryFixture {
    fn new(quorum: u16) -> Self {
        let key = |seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("deterministic history fixture key")
        };
        let first = key(0xA1);
        let second = key(0xA2);
        let first_id = AccountId::new(first.public_key().clone());
        let second_id = AccountId::new(second.public_key().clone());
        let recipient = AccountId::new(key(0xA3).public_key().clone());
        let anchor = AccountId::new(key(0xA4).public_key().clone());
        let domain = DomainId::try_new("multisig_history", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
        let mut config = TestChainConfig::new(World::new(), 1_000);
        let genesis_key = config.genesis_key.clone();
        config.genesis_instructions = vec![
            Register::domain(Domain::new(domain.clone())).into(),
            Register::account(Account::new(first_id.clone())).into(),
            Register::account(Account::new(second_id.clone())).into(),
            Register::account(Account::new(recipient.clone())).into(),
            Register::asset_definition(AssetDefinition::numeric(
                definition.clone(),
                "Multisig history coin",
                AssetBalancePolicy::Global,
                Some(domain.clone()),
            ))
            .into(),
        ];
        let mut chain = CertifiedTestChain::start(config).expect("certified history genesis");
        let spec = MultisigSpec::new(
            BTreeMap::from([(first_id, 1), (second_id, 1)]),
            NonZeroU16::new(quorum).unwrap(),
            NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
        );
        let register = chain.sign(
            &genesis_key,
            [MultisigRegister::with_account(anchor, domain, spec).into()],
            2_000,
        );
        assert_eq!(chain.commit_at(2_000, vec![register]), [true]);
        let account = chain
            .state()
            .view()
            .world()
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .expect("native registered multisig account")
            .id()
            .clone();
        let holding = AssetId::new(definition, account.clone());
        let mint = chain.sign(
            &genesis_key,
            [Mint::asset_quantity(10_u32, holding.clone()).into()],
            3_000,
        );
        assert_eq!(chain.commit_at(3_000, vec![mint]), [true]);
        let fixture = Self {
            chain,
            first,
            second,
            account,
            recipient,
            holding,
        };
        fixture.assert_balances(10, 0);
        fixture
    }

    fn transfer(&self, amount: u32) -> InstructionBox {
        Transfer::asset_quantity(self.holding.clone(), amount, self.recipient.clone()).into()
    }

    fn batch_leg(&self, leg_id: &str, amount: u32) -> TransferAssetBatchEntry {
        TransferAssetBatchEntry::with_leg_id(
            leg_id,
            self.account.clone(),
            self.recipient.clone(),
            self.holding.definition().clone(),
            amount,
        )
    }

    fn allow_first_to_transfer(&mut self) {
        // Native owner consent lets the very same batch body execute both
        // directly under the first signer and inside a multisig occurrence.
        let permission: Permission =
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: self.holding.clone(),
            }
            .into();
        let grant =
            Grant::account_permission(permission, AccountId::new(self.first.public_key().clone()));
        let occurrence = self.occurrence(0x40, vec![grant.into()], None);
        let execution = self.submit(
            false,
            vec![occurrence.propose.clone(), self.approval(&occurrence)],
        );
        assert!(
            execution.succeeded,
            "native source owner grants exact asset consent"
        );
        self.assert_balances(10, 0);
    }

    fn occurrence(
        &self,
        nonce: u8,
        instructions: Vec<InstructionBox>,
        ttl: Option<NonZeroU64>,
    ) -> HistoryOccurrence {
        let nonce = MultisigProposalNonce::new([nonce; 32]).unwrap();
        HistoryOccurrence {
            id: MultisigProposalId::derive(&self.chain.network_id(), &self.account, &nonce),
            instructions_hash: HashOf::new(&instructions),
            propose: MultisigPropose::new(self.account.clone(), nonce, instructions, ttl).into(),
        }
    }

    fn approval(&self, occurrence: &HistoryOccurrence) -> InstructionBox {
        MultisigApprove::new(
            self.account.clone(),
            occurrence.id,
            occurrence.instructions_hash,
        )
        .into()
    }

    fn submit(
        &mut self,
        second_signer: bool,
        instructions: Vec<InstructionBox>,
    ) -> HistorySubmission {
        let current = self.chain.committed(self.chain.height());
        let next_time = u64::try_from(current.block().header().creation_time().as_millis())
            .unwrap()
            .checked_add(1_000)
            .unwrap();
        let signer = if second_signer {
            &self.second
        } else {
            &self.first
        };
        let signed = self.chain.sign(signer, instructions, next_time);
        let entrypoint_hash = signed.hash_as_entrypoint().to_string();
        let outcomes = self.chain.commit_at(next_time, vec![signed]);
        assert_eq!(outcomes.len(), 1);
        HistorySubmission {
            entrypoint_hash,
            height: self.chain.height(),
            succeeded: outcomes[0],
        }
    }

    fn assert_balances(&self, sender: u32, recipient: u32) {
        let view = self.chain.state().view();
        let recipient_asset =
            AssetId::new(self.holding.definition().clone(), self.recipient.clone());
        for (asset, expected) in [(&self.holding, sender), (&recipient_asset, recipient)] {
            let actual = view
                .world()
                .assets()
                .get(asset)
                .map_or_else(|| Quantity::from(0_u32), |value| value.as_ref().clone());
            assert_eq!(
                actual,
                Quantity::from(expected),
                "actual balance of {asset}"
            );
        }
    }

    async fn incoming(&self, page_size: u32) -> Vec<Map> {
        let base = ListQuery::new()
            .filter(field("direction").eq("incoming"))
            .limit(page_size);
        let target = CollectionTarget::AccountHistory(self.recipient.to_string());
        let mut query = base.clone();
        let mut rows = Vec::new();
        let mut seen_rows = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        for _ in 0..32 {
            let page = execute_collection_local(
                None,
                self.chain.state(),
                &target,
                query,
                &MaybeTelemetry::for_tests(),
                &DataspaceReadVisibility::all_for_tests(),
            )
            .await
            .expect("active account history collection");
            assert!(page.items.len() <= page_size as usize);
            for row in &page.items {
                assert!(
                    seen_rows.insert(row["id"].as_str().unwrap().to_owned()),
                    "history pagination duplicated a movement"
                );
            }
            rows.extend(page.items);
            let Some(cursor) = page.next_cursor else {
                return rows;
            };
            assert!(
                seen_cursors.insert(cursor.clone()),
                "history cursor repeated"
            );
            query = base.clone().cursor(cursor);
        }
        panic!("small history fixture exceeded the bounded page walk");
    }

    fn assert_transfer(&self, row: &Map, amount: u32, execution: &HistorySubmission) {
        assert!(execution.succeeded);
        assert_eq!(row["direction"].as_str(), Some("incoming"));
        assert_eq!(row["type"].as_str(), Some("TRANSFER"));
        assert_eq!(row["status"].as_str(), Some("SUCCESS"));
        assert_eq!(row["result_ok"].as_bool(), Some(true));
        assert_eq!(row["amount"].as_str(), Some(amount.to_string().as_str()));
        assert_eq!(
            row["account_id"].as_str(),
            Some(self.recipient.to_string().as_str())
        );
        assert_eq!(
            row["counterparty_account_id"].as_str(),
            Some(self.account.to_string().as_str())
        );
        assert_eq!(
            row["asset_definition_id"].as_str(),
            Some(self.holding.definition().to_string().as_str())
        );
        let recipient_asset =
            AssetId::new(self.holding.definition().clone(), self.recipient.clone());
        assert_eq!(
            row["asset_id"].as_str(),
            Some(recipient_asset.to_string().as_str())
        );
        assert_eq!(
            row["tx_hash"].as_str(),
            Some(execution.entrypoint_hash.as_str())
        );
        assert_eq!(row["block_height"].as_u64(), Some(execution.height));
    }
}

#[tokio::test]
async fn account_history_multisig_waits_for_quorum_and_retains_occurrence_identity() {
    let mut fixture = MultisigHistoryFixture::new(2);
    let first = fixture.occurrence(1, vec![fixture.transfer(3)], None);
    let proposal = fixture.submit(false, vec![first.propose.clone()]);
    assert!(proposal.succeeded);
    fixture.assert_balances(10, 0);
    assert!(
        fixture.incoming(1).await.is_empty(),
        "a proposal is not a credit"
    );

    // Propose already counts the first signer. Its explicit approval is still
    // below quorum, even though that approval transaction succeeds.
    let below_quorum = fixture.submit(false, vec![fixture.approval(&first)]);
    assert!(below_quorum.succeeded);
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());

    let execution = fixture.submit(true, vec![fixture.approval(&first)]);
    assert!(execution.succeeded);
    fixture.assert_balances(7, 3);
    let once = fixture.incoming(1).await;
    assert_eq!(once.len(), 1);
    fixture.assert_transfer(&once[0], 3, &execution);
    assert_ne!(execution.entrypoint_hash, proposal.entrypoint_hash);
    assert_ne!(execution.entrypoint_hash, below_quorum.entrypoint_hash);
    assert_eq!(fixture.incoming(10).await, once);

    // A fresh signed envelope retries the same occurrence, so duplicate
    // envelope admission cannot hide an erroneous second business execution.
    let replay = fixture.submit(true, vec![fixture.approval(&first)]);
    assert!(!replay.succeeded);
    fixture.assert_balances(7, 3);
    assert_eq!(fixture.incoming(1).await, once);

    let second = fixture.occurrence(2, vec![fixture.transfer(3)], None);
    assert_eq!(second.instructions_hash, first.instructions_hash);
    assert_ne!(second.id, first.id);
    assert!(
        fixture
            .submit(false, vec![second.propose.clone()])
            .succeeded
    );
    assert_eq!(fixture.incoming(1).await, once);
    let second_execution = fixture.submit(true, vec![fixture.approval(&second)]);
    fixture.assert_balances(4, 6);
    let twice = fixture.incoming(1).await;
    assert_eq!(twice.len(), 2);
    fixture.assert_transfer(&twice[0], 3, &second_execution);
    fixture.assert_transfer(&twice[1], 3, &execution);
    assert_ne!(twice[0]["id"], twice[1]["id"]);
    assert_eq!(fixture.incoming(10).await, twice);
}

#[tokio::test]
async fn account_history_multisig_failed_inner_transfer_never_credits() {
    let mut fixture = MultisigHistoryFixture::new(2);
    let occurrence = fixture.occurrence(3, vec![fixture.transfer(99)], None);
    assert!(
        fixture
            .submit(false, vec![occurrence.propose.clone()])
            .succeeded
    );
    assert!(fixture.incoming(1).await.is_empty());
    let execution = fixture.submit(true, vec![fixture.approval(&occurrence)]);
    assert!(
        !execution.succeeded,
        "insufficient funds must reject execution"
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
    let retry = fixture.submit(true, vec![fixture.approval(&occurrence)]);
    assert!(!retry.succeeded);
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
}

#[tokio::test]
async fn account_history_multisig_cancellation_never_projects_target_transfer() {
    let mut fixture = MultisigHistoryFixture::new(2);
    let target = fixture.occurrence(4, vec![fixture.transfer(3)], None);
    assert!(
        fixture
            .submit(false, vec![target.propose.clone()])
            .succeeded
    );
    let cancel = MultisigCancel::new(fixture.account.clone(), target.id, target.instructions_hash);
    let cancellation = fixture.occurrence(5, vec![cancel.into()], None);
    assert!(
        fixture
            .submit(false, vec![cancellation.propose.clone()])
            .succeeded
    );
    assert!(fixture.incoming(1).await.is_empty());
    assert!(
        fixture
            .submit(true, vec![fixture.approval(&cancellation)])
            .succeeded
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
    assert!(
        !fixture
            .submit(true, vec![fixture.approval(&target)])
            .succeeded
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
}

#[tokio::test]
async fn account_history_multisig_expired_approval_succeeds_without_crediting() {
    let mut fixture = MultisigHistoryFixture::new(2);
    let target = fixture.occurrence(6, vec![fixture.transfer(3)], NonZeroU64::new(1));
    assert!(
        fixture
            .submit(false, vec![target.propose.clone()])
            .succeeded
    );
    assert!(fixture.incoming(1).await.is_empty());
    // Each submit advances beyond the previous committed block by 1,000 ms.
    // Expiry is determined by native block time, with no wall-clock sleeps.
    let expired = fixture.submit(true, vec![fixture.approval(&target)]);
    assert!(
        expired.succeeded,
        "expiry records a successful NotExecuted approval"
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
    assert!(
        !fixture
            .submit(true, vec![fixture.approval(&target)])
            .succeeded
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
}

#[tokio::test]
async fn account_history_multisig_same_entrypoint_keeps_each_executed_leaf_once() {
    let mut fixture = MultisigHistoryFixture::new(1);
    let occurrence = fixture.occurrence(7, vec![fixture.transfer(2), fixture.transfer(3)], None);
    let execution = fixture.submit(
        false,
        vec![occurrence.propose.clone(), fixture.approval(&occurrence)],
    );
    assert!(execution.succeeded);
    fixture.assert_balances(5, 5);
    let rows = fixture.incoming(1).await;
    assert_eq!(
        rows.len(),
        2,
        "one row per executed transfer, not per proposal payload"
    );
    let amounts: BTreeSet<_> = rows
        .iter()
        .map(|row| row["amount"].as_str().unwrap())
        .collect();
    assert_eq!(amounts, BTreeSet::from(["2", "3"]));
    for row in &rows {
        fixture.assert_transfer(
            row,
            row["amount"].as_str().unwrap().parse().unwrap(),
            &execution,
        );
    }
    assert_ne!(rows[0]["id"], rows[1]["id"]);
    assert_eq!(fixture.incoming(10).await, rows);
}

#[tokio::test]
async fn account_history_multisig_nested_executed_approval_projects_transfer_once() {
    let mut fixture = MultisigHistoryFixture::new(1);
    let target = fixture.occurrence(8, vec![fixture.transfer(3)], None);
    assert!(
        fixture
            .submit(false, vec![target.propose.clone()])
            .succeeded
    );
    let wrapper = fixture.occurrence(9, vec![fixture.approval(&target)], None);
    assert!(
        fixture
            .submit(false, vec![wrapper.propose.clone()])
            .succeeded
    );
    fixture.assert_balances(10, 0);
    assert!(fixture.incoming(1).await.is_empty());
    let execution = fixture.submit(false, vec![fixture.approval(&wrapper)]);
    assert!(execution.succeeded);
    fixture.assert_balances(7, 3);
    let rows = fixture.incoming(1).await;
    assert_eq!(rows.len(), 1);
    fixture.assert_transfer(&rows[0], 3, &execution);
    assert_eq!(fixture.incoming(10).await, rows);
}

#[tokio::test]
async fn account_history_multisig_nested_pending_proposal_waits_for_its_own_execution() {
    let mut fixture = MultisigHistoryFixture::new(1);
    let target = fixture.occurrence(10, vec![fixture.transfer(3)], None);
    let wrapper = fixture.occurrence(11, vec![target.propose.clone()], None);
    assert!(
        fixture
            .submit(false, vec![wrapper.propose.clone()])
            .succeeded
    );
    let wrapper_execution = fixture.submit(false, vec![fixture.approval(&wrapper)]);
    assert!(wrapper_execution.succeeded);
    fixture.assert_balances(10, 0);
    assert!(
        fixture.incoming(1).await.is_empty(),
        "executing a proposal creation does not execute its proposed transfer"
    );
    let target_execution = fixture.submit(false, vec![fixture.approval(&target)]);
    assert!(target_execution.succeeded);
    fixture.assert_balances(7, 3);
    let rows = fixture.incoming(1).await;
    assert_eq!(rows.len(), 1);
    fixture.assert_transfer(&rows[0], 3, &target_execution);
    assert_ne!(
        target_execution.entrypoint_hash,
        wrapper_execution.entrypoint_hash
    );
}

#[tokio::test]
async fn account_history_multisig_identical_direct_and_nested_batches_keep_each_actual_receipt() {
    let mut fixture = MultisigHistoryFixture::new(1);
    fixture.allow_first_to_transfer();
    let batch: InstructionBox = TransferAssetBatch::new(vec![fixture.batch_leg("same", 1)]).into();
    let wrapper = fixture.occurrence(12, vec![batch.clone(), batch.clone()], None);
    let execution = fixture.submit(
        false,
        vec![
            batch.clone(),
            batch,
            wrapper.propose.clone(),
            fixture.approval(&wrapper),
        ],
    );
    assert!(execution.succeeded);
    fixture.assert_balances(6, 4);
    let rows = fixture.incoming(1).await;
    assert_eq!(
        rows.len(),
        4,
        "four executions of the same body are four movements"
    );
    for row in &rows {
        fixture.assert_transfer(row, 1, &execution);
    }
    assert_eq!(
        rows.iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        4,
        "identical payloads and leg ids must not collapse separate receipt occurrences"
    );
    assert_eq!(fixture.incoming(10).await, rows);
}

#[tokio::test]
async fn account_history_multisig_independent_batches_project_only_applied_receipts() {
    let mut fixture = MultisigHistoryFixture::new(1);
    fixture.allow_first_to_transfer();
    let batch: InstructionBox = TransferAssetBatch::independent(vec![
        fixture.batch_leg("applied", 1),
        fixture.batch_leg("insufficient", 99),
    ])
    .into();
    let wrapper = fixture.occurrence(13, vec![batch.clone()], None);
    let execution = fixture.submit(
        false,
        vec![batch, wrapper.propose.clone(), fixture.approval(&wrapper)],
    );
    assert!(
        execution.succeeded,
        "independent rejected legs do not reject the transaction"
    );
    fixture.assert_balances(8, 2);
    let rows = fixture.incoming(1).await;
    assert_eq!(
        rows.len(),
        2,
        "only the two actual Applied legs are credits"
    );
    for row in &rows {
        fixture.assert_transfer(row, 1, &execution);
    }
    assert_ne!(rows[0]["id"], rows[1]["id"]);
    assert_eq!(fixture.incoming(10).await, rows);
}
