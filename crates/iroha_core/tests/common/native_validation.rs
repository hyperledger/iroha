//! Native proposal validation over original signed and executed fixture history.

use iroha_core::{
    block::{BlockValidationError, ValidBlock},
    state::WorldReadOnly,
    sumeragi::{
        crypto::BlsCrypto,
        lanes::merge::{NoLanes, expand},
        network_topology::Topology,
        payload::{self, Assembly},
        test_chain::CertifiedTestChain,
    },
    tx::AcceptedTransaction,
};
use iroha_data_model::{block::SignedBlock, transaction::SignedTransaction};
use iroha_sumeragi::{message::BlockHeader, preimage::payload_hash};
use std::{borrow::Cow, time::Duration};

pub(super) fn proposal(chain: &CertifiedTestChain, txs: Vec<SignedTransaction>) -> SignedBlock {
    let inputs = txs
        .into_iter()
        .map(|tx| AcceptedTransaction::new_unchecked(Cow::Owned(tx)))
        .collect::<Vec<_>>();
    payload::assemble(
        chain.state(),
        Assembly {
            parent: chain.committed(chain.height()).block(),
            view: 0,
            cadence: Duration::from_millis(1),
        },
        &inputs,
    )
    .expect("native resultless proposal assembly")
}

pub(super) fn validate(
    chain: &CertifiedTestChain,
    proposal: SignedBlock,
) -> Result<ValidBlock, Box<BlockValidationError>> {
    let bytes = proposal.encode_wire().expect("canonical native frame");
    let parent = chain.committed(chain.height());
    let view = chain.state().view();
    let scheduled = view
        .world()
        .consensus_schedule()
        .ready(chain.height() + 1)
        .unwrap();
    let header = BlockHeader {
        control_witness: Default::default(),
        instance: chain.instance(),
        epoch: iroha_core::sumeragi::schedule::core_epoch(&scheduled.epoch)
            .unwrap()
            .id,
        height: proposal.header().height().get(),
        origin_view: proposal.header().view_change_index(),
        parent_hash: parent.core_hash(),
        parent_result: parent.result(),
        payload_hash: payload_hash(&BlsCrypto::new(), &bytes),
        payload_len: u32::try_from(bytes.len()).unwrap(),
        availability_digest: iroha_sumeragi::types::Hash32::ZERO,
        proposer: 0,
        skipped_leaders: Vec::new(),
    };
    let body = chain.author_payload(header, bytes.clone());
    let header = body.header();
    let expansion = expand(chain.state(), &proposal, &NoLanes, Duration::ZERO).unwrap();
    let topology = Topology::new(chain.validators().iter().map(|(peer, _)| peer.clone()));
    ValidBlock::validate_sumeragi_block(
        proposal,
        &topology,
        chain.genesis_account(),
        Duration::from_millis(scheduled.params.block_time_ms),
        iroha_data_model::parameter::system::ConsensusMode::Permissioned,
        expansion,
        header,
        &bytes,
        chain.state(),
    )
    .unpack(|_| {})
    .map(|(valid, _)| valid)
    .map_err(|(_, error)| error)
}
