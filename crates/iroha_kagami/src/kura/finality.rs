//! Bounded current-consensus inspection rooted in the store's signed genesis.

use super::*;
use iroha_core::{state::AllocationBudget, sumeragi::certified_chain::CertifiedPrefix};
use iroha_data_model::{
    NetworkId,
    block::SharedSignedBlock,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityProof, authenticated_genesis},
};
use iroha_model_base::chain::ChainId;

const MAX_PREFIX_HEIGHT: u64 = 4_096;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

fn read_block(
    store: &mut BlockStore,
    height: u64,
    budget: &AllocationBudget,
) -> color_eyre::Result<SharedSignedBlock> {
    let mut index = [BlockIndex {
        start: 0,
        length: 0,
    }];
    store.read_block_indices(height - 1, &mut index)?;
    let index = index[0];
    if index.length == 0 || index.length > MAX_EXECUTED_BLOCK_WIRE_BYTES {
        return Err(eyre!(
            "block {height} has invalid wire length {}",
            index.length
        ));
    }
    let length = usize::try_from(index.length).wrap_err("block length does not fit usize")?;
    let mut wire = Vec::new();
    wire.try_reserve_exact(length)
        .wrap_err("reserve bounded block frame")?;
    wire.resize(length, 0);
    store.read_block_data(index.start, &mut wire)?;
    let block = decode_framed_signed_block(&wire)
        .wrap_err_with(|| format!("failed to decode canonical block at {height}"))?;
    if block.header().height().get() != height {
        return Err(eyre!("canonical block height differs from index {height}"));
    }
    SharedSignedBlock::try_new(block, budget)
        .map_err(|(_, error)| error)
        .wrap_err("admit finality inspection block owner")
}

pub(super) fn inspect(
    writer: &mut dyn Write,
    block_store_path: &Path,
    chain_id: &ChainId,
    height: u64,
) -> Outcome {
    if !(1..=MAX_PREFIX_HEIGHT).contains(&height) {
        return Err(eyre!("finality height must be in 1..={MAX_PREFIX_HEIGHT}"));
    }
    let directory = resolve_block_store_dir(block_store_path)?;
    let mut store = BlockStore::open_read_only(&directory)
        .wrap_err("open canonical Kura journals read-only")?;
    if store.read_index_count()? < height {
        return Err(eyre!(
            "requested finality height exceeds the retained journal"
        ));
    }
    // One bounded offline inspection owns all retained block controls. This does not
    // authorize execution or claim that decoded nested allocations are already charged.
    let budget = AllocationBudget::new(MAX_OUTPUT_BYTES);
    let genesis = read_block(&mut store, 1, &budget)?;
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let epoch = authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .map_err(|error| eyre!(error))?;
    let mut committee = epoch.committee;
    let mut prefix = CertifiedPrefix::new(chain_id, network, genesis.clone())
        .wrap_err("authenticate the local signed genesis")?;
    let mut selected = genesis;
    for current in 2..=height {
        let block = read_block(&mut store, current, &budget)?;
        let (verified, _) = prefix
            .push(block.clone())
            .wrap_err_with(|| format!("invalid native finality successor at {current}"))?
            .into_parts();
        committee.clone_from(&verified.committed().commitment().schedule.current.committee);
        selected = block;
    }
    let proof = SumeragiFinalityProof {
        block_header: selected.header(),
        block_wire: selected.encode_wire()?,
        committee: committee
            .into_iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession,
            })
            .collect(),
    };
    // Local storage selects the genesis root; a genesis-only result has no successor QC.
    let report = norito::json!({
        "schema": "iroha.kura.finality-inspection.v1",
        "verified_prefix_start": 1_u64,
        "verified_prefix_end": height,
        "external_trust_anchor": false,
        "genesis_execution_authenticated": (height > 1),
        "local_network_id": (network.to_string()),
        "chain_id": (chain_id.to_string()),
        "finality_proof": proof
    });
    let encoded = norito::json::to_json_bounded(&report, MAX_OUTPUT_BYTES)
        .wrap_err("finality inspection exceeds output bound")?;
    writer.write_all(encoded.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_height_is_rejected_before_store_access() {
        for height in [0, MAX_PREFIX_HEIGHT + 1, u64::MAX] {
            let mut output = Vec::new();
            let error = inspect(
                &mut output,
                Path::new("/missing-finality-store"),
                &ChainId::from("test"),
                height,
            )
            .expect_err("invalid height must fail before opening a store");
            assert!(error.to_string().contains("finality height must be in"));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn empty_store_fails_without_output_or_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = BlockStore::new(directory.path());
        store.create_files_if_they_do_not_exist().unwrap();
        let names = ["blocks.index", "blocks.data", "blocks.hashes"];
        let before = names.map(|name| fs::read(directory.path().join(name)).unwrap());
        let mut output = Vec::new();
        let error = inspect(&mut output, directory.path(), &ChainId::from("test"), 1)
            .expect_err("empty store has no finality prefix");
        assert!(error.to_string().contains("exceeds the retained journal"));
        assert!(output.is_empty());
        for (name, expected) in names.into_iter().zip(before) {
            assert_eq!(fs::read(directory.path().join(name)).unwrap(), expected);
        }
    }

    #[test]
    fn block_read_rejects_oversized_frame_before_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = BlockStore::new(directory.path());
        store.create_files_if_they_do_not_exist().unwrap();
        let mut index = 0_u64.to_le_bytes().to_vec();
        index.extend_from_slice(&(MAX_EXECUTED_BLOCK_WIRE_BYTES + 1).to_le_bytes());
        fs::write(directory.path().join("blocks.index"), index).unwrap();
        let error = read_block(&mut store, 1, &AllocationBudget::new(0))
            .expect_err("oversized frame is inadmissible");
        assert!(error.to_string().contains("invalid wire length"));
    }

    #[test]
    fn block_read_retains_original_inspection_pool_until_last_reader_releases() {
        use iroha_core::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        use iroha_data_model::block::SharedBlockAdmissionError;

        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("execute signed inspection fixture genesis");
        let directory = tempfile::tempdir().unwrap();
        let mut store = BlockStore::new(directory.path());
        store.create_files_if_they_do_not_exist().unwrap();
        store
            .append_block_to_chain(chain.committed(1).block())
            .unwrap();
        let bytes = SharedSignedBlock::allocation_layout().size();
        let budget = AllocationBudget::new(bytes);
        let block = read_block(&mut store, 1, &budget).unwrap();
        let retained = block.clone();
        assert!(block.belongs_to(&budget));
        assert!(SharedSignedBlock::ptr_eq(&block, &retained));
        drop(block);
        let error = read_block(&mut store, 1, &budget)
            .expect_err("the original retained reader still owns the only control allocation");
        assert!(matches!(
            error.downcast_ref::<SharedBlockAdmissionError>(),
            Some(SharedBlockAdmissionError::Admission(_))
        ));
        assert_eq!(budget.reserved_bytes(), bytes);
        assert_eq!(
            retained.encode_wire().unwrap(),
            chain.genesis().encode_wire().unwrap()
        );
        drop(retained);
        assert_eq!(budget.reserved_bytes(), 0);
        let retry = read_block(&mut store, 1, &budget).expect("released capacity permits retry");
        assert_eq!(retry.hash(), chain.genesis().hash());
    }
}

#[cfg(test)]
#[path = "finality_native_fixture_tests.rs"]
mod native_fixture_tests;
