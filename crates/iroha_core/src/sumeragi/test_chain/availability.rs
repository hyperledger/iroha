//! Genuine signed availability and cold restoration owned by a certified fixture's State pool.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::io;

use iroha_allocation::ChargedBuffer;
use iroha_sumeragi::{
    availability::{AuthoringError, PayloadAuthoring, PayloadBytes},
    types::HeightConfig,
};

use super::*;

impl CertifiedTestChain {
    /// The original State allocation pool funding this fixture's execution and availability.
    /// Lane fixtures must share this owner rather than create an unrelated admission budget.
    #[must_use]
    pub fn execution_budget(&self) -> iroha_allocation::AllocationBudget {
        self.state.ivm_execution_budget()
    }

    /// Author the exact supplied payload with this chain's independently scheduled proposer.
    /// The original State pool funds payload backing, all RS16 work and original signatures.
    /// This supplies availability only; application execution and certification remain mandatory.
    ///
    /// # Panics
    /// The header differs from authenticated authority, fixture custody does not own its proposer,
    /// bytes differ from the declared payload, or the original allocation pool refuses the work.
    #[must_use]
    pub fn author_payload(&self, header: BlockHeader, payload: Vec<u8>) -> AvailableBody {
        assert_eq!(header.instance, self.instance, "original chain instance");
        let config = self
            .availability
            .height_config(header.height)
            .expect("read original authenticated historical availability authority")
            .expect("exact height has a ready authenticated configuration");
        self.author_payload_in_context(header, payload, &config)
            .unwrap_or_else(|(_, error)| panic!("original signed RS16 authoring: {error:?}"))
    }

    /// Author genuine negative input under an explicitly untrusted test context.
    /// This never resolves or replaces the State's authenticated schedule. The executor must
    /// reject a context differing from that schedule even when the original signatures verify.
    /// Every byte remains funded by this chain's State and signed by its real proposer custody.
    ///
    /// # Errors
    /// Returns the exact original authoring owner and protocol failure for invalid input.
    ///
    /// # Panics
    /// The supplied committee has no matching fixture proposer key or the State pool is exhausted.
    #[cfg(test)]
    pub(in crate::sumeragi) fn author_payload_under_test_context(
        &self,
        header: BlockHeader,
        payload: Vec<u8>,
        config: &HeightConfig,
    ) -> Result<AvailableBody, (PayloadAuthoring, AuthoringError)> {
        self.author_payload_in_context(header, payload, config)
    }

    fn author_payload_in_context(
        &self,
        header: BlockHeader,
        payload: Vec<u8>,
        config: &HeightConfig,
    ) -> Result<AvailableBody, (PayloadAuthoring, AuthoringError)> {
        let instance = header.instance;
        let proposer = config
            .committee
            .get(header.proposer)
            .expect("original proposer belongs to the exact scheduled committee");
        let signer = self
            .signers
            .iter()
            .find(|signer| signer.public_key() == proposer)
            .expect("fixture owns this exact scheduled proposer key");
        let budget = self.state.ivm_execution_budget();
        let mut backing = ChargedBuffer::new(payload.len(), &budget)
            .expect("the original State pool funds the actual payload backing");
        backing
            .append(&payload)
            .expect("exact fixture payload length");
        drop(payload);
        let payload = PayloadBytes::from_charged(backing, &budget)
            .unwrap_or_else(|(_, error)| panic!("original payload control admission: {error}"));
        PayloadAuthoring::new(header, payload)
            .complete(instance, config, &budget, &*self.crypto, signer)
            .map(|authored| authored.body)
    }

    /// Restore the original stored signed body and CommitQC into this chain's State pool.
    /// The Kura adapter verifies the complete historical certificate and original availability;
    /// it never substitutes a body funded or signed by another fixture's State owner.
    ///
    /// # Errors
    /// Original storage corruption, unresolved authority, I/O or resource refusal.
    pub fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        self.blocks.committed_body(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_budget_retains_the_original_state_owner() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let backing = ChargedBuffer::<u8>::new(64, &chain.execution_budget()).unwrap();
        assert!(backing.belongs_to(&chain.state.ivm_execution_budget()));
        assert!(!backing.belongs_to(&iroha_allocation::AllocationBudget::new(1 << 27)));
    }

    /// Authoring retains the exact independent context and original actual allocation pool.
    #[test]
    fn authored_fixture_body_uses_original_state_pool_and_schedule() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let proposal = chain.proposal(Some(2_000), Vec::new());
        let payload = payload::encode(&proposal).unwrap();
        let config = chain.availability.height_config(2).unwrap().unwrap();
        let header = BlockHeader {
            instance: chain.instance,
            epoch: config.epoch.id,
            height: 2,
            origin_view: 0,
            parent_hash: chain.tip.1,
            parent_result: chain.tip.2,
            payload_hash: payload_hash(&*chain.crypto, &payload),
            payload_len: u32::try_from(payload.len()).unwrap(),
            availability_digest: Hash32::ZERO,
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: Default::default(),
        };
        let body = chain.author_payload(header, payload.clone());
        assert_eq!(body.source().config(), &config);
        assert_eq!(body.source().instance(), chain.instance);
        assert_eq!(body.source().height(), 2);
        assert_eq!(body.source().block_hash(), body.hash(&*chain.crypto));
        assert_eq!(body.payload().as_slice(), payload);
        assert!(!body.availability().as_slice().is_empty());
        assert!(body.admitted_to(&chain.state.ivm_execution_budget()));
        assert!(!body.admitted_to(&iroha_allocation::AllocationBudget::new(1 << 27)));
    }

    /// Cold replay uses the exact original certificate and target-funded restoration, not re-signing.
    #[test]
    fn committed_fixture_body_restores_into_target_state_without_replacement() {
        let mut source =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let mut target =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        source.commit_at(2_000, Vec::new());
        let (original, original_qc) = source.committed_body(2).unwrap().unwrap();
        assert!(!original.admitted_to(&target.state.ivm_execution_budget()));
        let original_wire = source.committed(2).block().encode_wire().unwrap();
        target.replay_from(&source).unwrap();
        let (restored, restored_qc) = target.committed_body(2).unwrap().unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored_qc, original_qc);
        assert!(restored.admitted_to(&target.state.ivm_execution_budget()));
        assert!(!restored.admitted_to(&source.state.ivm_execution_budget()));
        assert_eq!(
            target.committed(2).block().encode_wire().unwrap(),
            original_wire
        );
        assert_eq!(target.tip, source.tip);
        assert!(target.committed_body(3).unwrap().is_none());
    }
}
