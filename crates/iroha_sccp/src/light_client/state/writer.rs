//! One output interface for shared verifier kernels and their actual delta owners.

use iroha_data_model::sccp::light_client::{SccpLcCheckpointV1, SccpLcConsensusSetV1};

use super::{
    SccpLcConsensusSetRefV1, SccpLcDeltaV1, SccpLcSupersessionV1,
    admitted::{SccpLcDeltaBuilderV1, SccpLcDeltaReadV1},
    same_checkpoint_block,
};
use crate::light_client::{SccpLcConflictV1, SccpLcError, prepared::SccpLcAttemptErrorV1};

/// Shared mutation interface. A failing attempt must discard its uncommitted output owner.
pub(in crate::light_client) trait DeltaWriter: SccpLcDeltaReadV1 {
    type Error: From<SccpLcError>;

    fn find_set(&self, id: u64) -> Option<SccpLcConsensusSetRefV1<'_>> {
        (0..self.set_count()).find_map(|index| self.set(index).filter(|set| set.set_id == id))
    }

    fn encode_set<T: norito::NoritoSerialize>(
        &mut self,
        id: u64,
        first_height: u64,
        superseded: Option<u64>,
        value: &T,
    ) -> Result<(), Self::Error>;
    fn supersede(&mut self, id: u64, at: u64) -> Result<(), Self::Error>;
    fn checkpoint(&mut self, value: SccpLcCheckpointV1) -> Result<(), Self::Error>;
}

impl DeltaWriter for SccpLcDeltaV1 {
    type Error = SccpLcError;

    fn encode_set<T: norito::NoritoSerialize>(
        &mut self,
        id: u64,
        first_height: u64,
        superseded: Option<u64>,
        value: &T,
    ) -> Result<(), Self::Error> {
        let position = self
            .new_sets
            .binary_search_by_key(&id, |set| set.set_id)
            .map_or_else(Ok, |_| {
                Err(SccpLcError::ConflictsWithStoredData(
                    SccpLcConflictV1::ConsensusSet { set_id: id },
                ))
            })?;
        let set_bytes = norito::encode_canonical(value)
            .map_err(|_| SccpLcError::MalformedFrame("consensus set"))?;
        self.new_sets.insert(
            position,
            SccpLcConsensusSetV1 {
                set_id: id,
                valid_from_source_height: first_height,
                superseded_at_source_ms: superseded,
                set_bytes,
            },
        );
        Ok(())
    }

    fn supersede(&mut self, id: u64, at: u64) -> Result<(), Self::Error> {
        let conflict =
            SccpLcError::ConflictsWithStoredData(SccpLcConflictV1::ConsensusSet { set_id: id });
        if let Some(set) = self.new_sets.iter_mut().find(|set| set.set_id == id) {
            if set.superseded_at_source_ms.is_some_and(|old| old != at) {
                return Err(conflict);
            }
            set.superseded_at_source_ms = Some(at);
            return Ok(());
        }
        match self
            .superseded_sets
            .binary_search_by_key(&id, |set| set.set_id)
        {
            Ok(index) if self.superseded_sets[index].superseded_at_source_ms == at => Ok(()),
            Ok(_) => Err(conflict),
            Err(position) => {
                self.superseded_sets.insert(
                    position,
                    SccpLcSupersessionV1 {
                        set_id: id,
                        superseded_at_source_ms: at,
                    },
                );
                Ok(())
            }
        }
    }

    fn checkpoint(&mut self, value: SccpLcCheckpointV1) -> Result<(), Self::Error> {
        match self
            .checkpoints
            .binary_search_by_key(&value.data.source_height, |row| row.data.source_height)
        {
            Ok(index) if same_checkpoint_block(&self.checkpoints[index].data, &value.data) => {
                Ok(())
            }
            Ok(_) => Err(SccpLcError::ConflictsWithStoredData(
                SccpLcConflictV1::Checkpoint {
                    source_height: value.data.source_height,
                },
            )),
            Err(position) => {
                self.checkpoints.insert(position, value);
                Ok(())
            }
        }
    }
}

impl SccpLcDeltaReadV1 for SccpLcDeltaBuilderV1 {
    fn set_count(&self) -> usize {
        self.delta().set_count()
    }
    fn set(&self, index: usize) -> Option<SccpLcConsensusSetRefV1<'_>> {
        self.delta().set(index)
    }
    fn superseded(&self) -> &[SccpLcSupersessionV1] {
        self.delta().superseded()
    }
    fn checkpoints(&self) -> &[SccpLcCheckpointV1] {
        self.delta().checkpoints()
    }
    fn head(&self) -> Option<iroha_data_model::sccp::light_client::SccpLcHeadV1> {
        None
    }
}

impl DeltaWriter for SccpLcDeltaBuilderV1 {
    type Error = SccpLcAttemptErrorV1;

    fn encode_set<T: norito::NoritoSerialize>(
        &mut self,
        id: u64,
        first_height: u64,
        superseded: Option<u64>,
        value: &T,
    ) -> Result<(), Self::Error> {
        Self::encode_set(self, id, first_height, superseded, value).map_err(Into::into)
    }
    fn supersede(&mut self, id: u64, at: u64) -> Result<(), Self::Error> {
        Self::supersede(self, id, at).map_err(Into::into)
    }
    fn checkpoint(&mut self, value: SccpLcCheckpointV1) -> Result<(), Self::Error> {
        Self::checkpoint(self, value).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ethereum_source::EthereumNativeSyncCommitteeV1,
        light_client::{
            ethereum::EthereumSyncCommitteeSetV1, proof::SccpLcSetDataV1,
            state::admitted::SccpLcDeltaCapacityV1,
        },
    };
    use iroha_allocation::AllocationBudget;
    use iroha_data_model::sccp::light_client::{SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1};

    fn checkpoint(height: u64) -> SccpLcCheckpointV1 {
        SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: height,
                block_hash: [1; 32],
                state_root: None,
                receipts_or_tx_root: [2; 32],
                source_time_ms: height,
            },
            origin: SccpLcCheckpointOriginV1::Advance,
            recorded_at_taira_ms: 9,
        }
    }

    fn write<D: DeltaWriter>(out: &mut D) -> Result<(), D::Error> {
        for id in [2, 1] {
            // This is codec DATA for output ownership, not an authenticated committee.
            let data = SccpLcSetDataV1::Ethereum(EthereumSyncCommitteeSetV1 {
                period: id,
                committee: EthereumNativeSyncCommitteeV1 {
                    public_keys: vec![vec![7; 48]; 4],
                    aggregate_public_key: vec![8; 48],
                },
            });
            out.encode_set(id, id * 8, None, &data)?;
            out.checkpoint(checkpoint(id))?;
        }
        out.supersede(1, 20)?;
        out.supersede(0, 10)?;
        out.supersede(0, 10)?;
        out.checkpoint(checkpoint(1))?;
        Ok(())
    }

    #[test]
    fn shared_writer_preserves_sorted_bytes_metadata_conflicts_and_original_output_custody() {
        let mut detached = SccpLcDeltaV1::default();
        write(&mut detached).unwrap();
        let pool = AllocationBudget::new(65536);
        let mut admitted = SccpLcDeltaBuilderV1::new(
            SccpLcDeltaCapacityV1 {
                new_sets: 2,
                superseded_sets: 1,
                checkpoints: 2,
                set_bytes: 4096,
            },
            &pool,
        )
        .unwrap();
        write(&mut admitted).unwrap();
        assert_eq!(detached.set_count(), admitted.set_count());
        for index in 0..detached.set_count() {
            assert_eq!(detached.set(index), admitted.set(index));
        }
        assert_eq!(detached.superseded(), admitted.superseded());
        assert_eq!(detached.checkpoints(), admitted.checkpoints());
        for id in [0, 1] {
            assert!(DeltaWriter::supersede(&mut detached, id, 99).is_err());
            assert!(DeltaWriter::supersede(&mut admitted, id, 99).is_err());
        }
        let mut conflict = checkpoint(1);
        conflict.data.block_hash = [3; 32];
        assert!(DeltaWriter::checkpoint(&mut detached, conflict).is_err());
        assert!(DeltaWriter::checkpoint(&mut admitted, conflict).is_err());
        let output = admitted.finish(None);
        assert!(pool.reserved_bytes() > 0);
        assert_eq!(output.set(0).unwrap().set_id, 1);
        drop(output);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
