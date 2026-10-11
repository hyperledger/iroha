//! Lane store authority from a certified test chain's committed State, never a supplied frame.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::{
    state::{State, StateReadOnly, WorldReadOnly},
    sumeragi::{
        availability_schedule::AvailabilitySchedule,
        crypto::BlsCrypto,
        lanes::{
            lane_height_config, lane_instance,
            registry::{LaneStoreAuthorities, LaneStoreAuthority},
        },
    },
};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::{Hash32, HeightConfig};
use std::{io, sync::Arc};

struct PinnedSchedule {
    instance: Hash32,
    config: HeightConfig,
}
impl AvailabilitySchedule for PinnedSchedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(self
            .config
            .epoch
            .contains(height)
            .then(|| self.config.clone()))
    }
}

/// Independent fixture authority read from a certified chain's committed lane record.
/// This test-support owner covers live records; runtime historical replay uses its authenticated
/// archive provider. A record absent from the fixture State remains unresolved.
pub struct TestLaneStoreAuthorities {
    state: Arc<State>,
    crypto: Arc<BlsCrypto>,
}
impl TestLaneStoreAuthorities {
    /// Bind the original certified State and the store's actual BLS verifier/PoP registry.
    #[must_use]
    pub fn new(state: Arc<State>, crypto: Arc<BlsCrypto>) -> Self {
        Self { state, crypto }
    }
}
impl LaneStoreAuthorities for TestLaneStoreAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<
        Option<LaneStoreAuthority>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        let view = self.state.view();
        let Some(record) = view.world().sumeragi_lanes().lane(lane).cloned() else {
            return Ok(None);
        };
        if record.incarnation != *incarnation {
            return Ok(None);
        }
        let network = *self.state.network_id_ref();
        if lane_instance(
            &*self.crypto,
            &network,
            &view.chain_id().to_string(),
            &record,
        ) != instance
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture lane authority has another instance",
            )
            .into());
        }
        self.crypto
            .admit_committee(
                record
                    .committee
                    .iter()
                    .map(|member| (member.peer.public_key(), member.pop.as_slice())),
            )
            .map_err(|(index, error)| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("fixture lane member {index}: {error}"),
                )
            })?;
        let config = lane_height_config(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Some(LaneStoreAuthority {
            schedule: Arc::new(PinnedSchedule { instance, config }),
        }))
    }
}
