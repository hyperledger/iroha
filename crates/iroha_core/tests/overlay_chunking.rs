//! Overlay chunking: ensure overlays apply correctly when chunk size is small.

//! Builds a transaction with many `SetKeyValue` instructions and sets
#![allow(clippy::cast_possible_truncation)]
//! `overlay_chunk_instructions` to a tiny value to force many chunks.
use iroha_core::{
    state::WorldReadOnly,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
#[test]
fn overlay_apply_respects_chunking_and_preserves_effects() {
    // Build world with one domain/account
    let (account_id, kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = iroha_core::state::World::with([domain], [account], []);
    let mut config = TestChainConfig::new(world, 1000);
    config.chain_id = ChainId::from("overlay-chunking");
    config.pipeline.overlay_chunk_instructions = 2;
    let mut chain = CertifiedTestChain::start(config).unwrap();
    // Build one transaction with many SetKeyValue instructions on the same account
    let n_instr = 50usize;
    let mut instrs: Vec<InstructionBox> = Vec::with_capacity(n_instr);
    for i in 0..n_instr {
        let key: Name = format!("k{i}").parse().unwrap();
        instrs.push(
            SetKeyValue::account(
                account_id.clone(),
                key,
                iroha_primitives::json::Json::new(i as u32),
            )
            .into(),
        );
    }
    let tx = chain.sign(&kp, instrs, 2000);
    assert_eq!(chain.commit(vec![tx]), vec![true]);
    // Verify all metadata keys were set on the account
    let view = chain.state().view();
    let acc = view
        .world()
        .account(&account_id)
        .expect("account must exist");
    for i in 0..n_instr {
        let key: Name = format!("k{i}").parse().unwrap();
        let val = acc
            .value()
            .0
            .metadata
            .get(&key)
            .cloned()
            .and_then(|j| j.try_into_any_norito::<u32>().ok())
            .unwrap_or(9999);
        assert_eq!(val, i as u32, "metadata key k{i} must equal {i}");
    }
}
