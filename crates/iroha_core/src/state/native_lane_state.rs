//! Seal and witness the sole global lane lifecycle state after its native lane step.
use super::*;
use iroha_data_model::sumeragi_finality::{
    SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiLaneStateCommitment,
};

impl StateBlock<'_> {
    fn sumeragi_lane_state_commitment(&self) -> Result<SumeragiLaneStateCommitment, String> {
        SumeragiLaneStateCommitment::from_state(
            self.network_id,
            self._curr_block.height().get(),
            self.world.sumeragi_lanes(),
        )
    }

    /// Capture exactly one complete global lane state commitment in the original witness.
    pub(super) fn capture_sumeragi_lane_state(
        &mut self,
        witness: &mut ExecWitness,
    ) -> Result<(), String> {
        self.verify_sumeragi_lane_state_seal()?;
        let commitment = self.sumeragi_lane_state_commitment()?;
        let value = norito::encode_canonical(&commitment).map_err(|error| error.to_string())?;
        // The key is owned solely by this finalizer. An earlier supplied write is a collision,
        // never an instruction to silently replace untrusted witness contents.
        if witness
            .writes
            .iter()
            .any(|entry| entry.key == SUMERAGI_LANE_STATE_WITNESS_KEY)
        {
            return Err("duplicate global lane state witness key".into());
        }
        witness.writes.push(ExecKv {
            key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
            value,
        });
        self.fields
            .as_mut()
            .expect("original witness owner")
            .sumeragi_lane_state_seal = Some(commitment.state_hash());
        Ok(())
    }

    /// Reject any mutation after witness extraction while retaining the original overlay.
    pub(super) fn verify_sumeragi_lane_state_seal(&self) -> Result<(), String> {
        if let Some(seal) = self.sumeragi_lane_state_seal {
            if self.sumeragi_lane_state_commitment()?.state_hash() != seal {
                return Err("global lane state changed after witness capture".into());
            }
        }
        Ok(())
    }

    /// Match the single fixed witness write to the exact original poststate.
    pub(super) fn verify_sumeragi_lane_state_witness(
        &self,
        witness: &ExecWitness,
    ) -> Result<(), String> {
        self.verify_sumeragi_lane_state_seal()?;
        let expected = norito::encode_canonical(&self.sumeragi_lane_state_commitment()?)
            .map_err(|error| error.to_string())?;
        let mut entries = witness
            .writes
            .iter()
            .filter(|entry| entry.key == SUMERAGI_LANE_STATE_WITNESS_KEY);
        if entries.next().is_none_or(|entry| entry.value != expected) || entries.next().is_some() {
            return Err("execution witness does not contain the exact global lane state".into());
        }
        Ok(())
    }

    /// Publication cannot change any lane field committed by the retained execution.
    pub(super) fn verify_sumeragi_lane_state_publication(&self) -> Result<(), String> {
        self.verify_sumeragi_lane_state_seal()
    }
}

/// Validate a complete actual lane state at an authenticated current or predecessor cut.
/// This verifies structure and pinned credentials; the caller must independently authenticate
/// the global state root. No queue-plan, Decision or receipt-driven lifecycle is accepted.
pub(crate) fn validate_sumeragi_lane_state(
    network: iroha_data_model::NetworkId,
    height: u64,
    state: &iroha_data_model::sumeragi_lanes::SumeragiLaneState,
) -> Result<(), String> {
    if height == 0 {
        return if state == &iroha_data_model::sumeragi_lanes::SumeragiLaneState::default() {
            Ok(())
        } else {
            Err("height-zero predecessor has nonempty lane state".into())
        };
    }
    SumeragiLaneStateCommitment::from_state_encoding(network, height, state)
        .map_err(|error| error.to_string())?;
    if state.lanes.len() > iroha_data_model::nexus::MAX_ACTIVE_EXECUTION_LANES
        || state.incarnations < state.lanes.len() as u64
    {
        return Err("invalid lane state size or incarnation counter".into());
    }
    if state
        .samples
        .iter()
        .any(|sample| sample.height == 0 || sample.lanes == 0)
        || state
            .samples
            .windows(2)
            .any(|pair| pair[0].time_ms > pair[1].time_ms)
    {
        return Err("invalid lane load sample history".into());
    }
    for (index, lane) in state.lanes.iter().enumerate() {
        if lane.created_at == 0
            || lane.active_from != lane.created_at.saturating_add(2)
            || lane.anchor_freshness == 0
            || lane.incarnation == [0; 32]
            || state.lanes[..index]
                .iter()
                .any(|old| old.incarnation == lane.incarnation)
            || lane.closing.is_some_and(|closing| {
                closing < lane.created_at || closing > height.saturating_add(1)
            })
            || lane
                .retirement_height()
                .is_some_and(|retirement| retirement <= height)
        {
            return Err("invalid lane incarnation or lifecycle bounds".into());
        }
        if !iroha_data_model::block::consensus::is_valid_committee_size(lane.committee.len())
            || lane
                .committee
                .windows(2)
                .any(|pair| pair[0].peer >= pair[1].peer)
        {
            return Err("invalid pinned lane committee order or size".into());
        }
        for member in &lane.committee {
            if member.peer.public_key().algorithm() != iroha_crypto::Algorithm::BlsNormal
                || iroha_crypto::bls_normal_pop_verify(member.peer.public_key(), &member.pop)
                    .is_err()
            {
                return Err("invalid pinned lane BLS possession proof".into());
            }
        }
        crate::sumeragi::schedule::ChainParamsRecord::from_parameters(&lane.params)
            .validate()
            .map_err(|error| error.to_string())?;
        if lane.merged.height == 0 {
            if lane.merged_at != lane.active_from
                || lane.merged.block_hash
                    != crate::sumeragi::lanes::lane_genesis_hash(&network, lane).0
                || lane.merged.result != crate::sumeragi::lanes::lane_genesis_result(lane).0
            {
                return Err("lane frontier differs from its pinned genesis".into());
            }
        } else if lane.merged_at <= lane.active_from
            || lane.merged_at > height
            || lane.merged.block_hash == [0; 32]
            || lane.merged.result == [0; 32]
        {
            return Err("invalid merged lane frontier".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneState,
    };
    #[test]
    fn actual_lane_state_validation_binds_pinned_credentials_lifecycle_and_frontier() {
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"actual lane state validator")),
        );
        let mut committee = (1..=4)
            .map(|seed| {
                let key = iroha_crypto::KeyPair::from_seed(
                    vec![seed; 32],
                    iroha_crypto::Algorithm::BlsNormal,
                );
                SumeragiLaneMember {
                    peer: iroha_model_base::peer::PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                }
            })
            .collect::<Vec<_>>();
        committee.sort();
        let mut record = SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(1),
            dataspace: DataSpaceId::new(0),
            incarnation: [1; 32],
            params: iroha_data_model::parameter::system::SumeragiParameters::default(),
            committee,
            created_at: 1,
            active_from: 3,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 3,
            rescued: 0,
        };
        record.merged.block_hash = crate::sumeragi::lanes::lane_genesis_hash(&network, &record).0;
        record.merged.result = crate::sumeragi::lanes::lane_genesis_result(&record).0;
        let exact = SumeragiLaneState {
            lanes: vec![record],
            incarnations: 1,
            ..Default::default()
        };
        assert!(validate_sumeragi_lane_state(network, 0, &SumeragiLaneState::default()).is_ok());
        assert!(validate_sumeragi_lane_state(network, 0, &exact).is_err());
        let mut zero = SumeragiLaneState {
            incarnations: 1,
            ..Default::default()
        };
        assert!(validate_sumeragi_lane_state(network, 0, &zero).is_err());
        zero = SumeragiLaneState::default();
        zero.samples = vec![iroha_data_model::sumeragi_lanes::SumeragiLaneSample {
            height: 0,
            time_ms: 0,
            transactions: 0,
            lanes: 1,
        }]
        .try_into()
        .unwrap();
        assert!(validate_sumeragi_lane_state(network, 0, &zero).is_err());
        assert!(validate_sumeragi_lane_state(network, 1, &exact).is_ok());
        assert!(validate_sumeragi_lane_state(network, 4, &exact).is_ok());
        for mutation in 0..10 {
            let mut invalid = exact.clone();
            let lane = &mut invalid.lanes[0];
            match mutation {
                0 => lane.active_from = 2,
                1 => lane.committee.swap(0, 1),
                2 => lane.committee[0].pop[0] ^= 1,
                3 => lane.merged.block_hash[0] ^= 1,
                4 => lane.merged.result[0] ^= 1,
                5 => lane.merged_at = 4,
                6 => lane.anchor_freshness = 0,
                7 => lane.closing = Some(8),
                8 => invalid.incarnations = 0,
                _ => invalid.lanes.push(invalid.lanes[0].clone()),
            }
            assert!(
                validate_sumeragi_lane_state(network, 4, &invalid).is_err(),
                "mutation {mutation}"
            );
        }
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::sumeragi_lanes::SumeragiLaneSample;
    fn chain() -> CertifiedTestChain {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
        chain.commit_at(2000, Vec::new());
        chain
    }
    fn next(chain: &CertifiedTestChain) -> BlockHeader {
        BlockHeader::new(
            std::num::NonZeroU64::new(3).unwrap(),
            Some(chain.committed(2).block().hash()),
            None,
            3000,
            0,
        )
    }
    #[test]
    fn original_overlay_seal_matches_witness_and_refuses_every_postcapture_mutation() {
        let chain = chain();
        for mutation in 0..3 {
            let mut overlay = chain.state().block(next(&chain));
            let mut witness = ExecWitness::default();
            overlay.capture_sumeragi_lane_state(&mut witness).unwrap();
            assert!(overlay.verify_sumeragi_lane_state_witness(&witness).is_ok());
            assert!(overlay.verify_sumeragi_lane_state_publication().is_ok());
            let original = overlay.world.sumeragi_lanes.get().clone();
            match mutation {
                0 => overlay.world.sumeragi_lanes.get_mut().incarnations += 1,
                1 => overlay.world.sumeragi_lanes.get_mut().last_transition = 3,
                _ => {
                    let mut samples = overlay.world.sumeragi_lanes.get().samples.to_vec();
                    samples.push(SumeragiLaneSample {
                        height: 3,
                        time_ms: 3000,
                        transactions: 1,
                        lanes: 1,
                    });
                    overlay.world.sumeragi_lanes.get_mut().samples = samples.try_into().unwrap();
                }
            }
            assert!(overlay.verify_sumeragi_lane_state_seal().is_err());
            assert!(
                overlay
                    .verify_sumeragi_lane_state_witness(&witness)
                    .is_err()
            );
            assert!(overlay.verify_sumeragi_lane_state_publication().is_err());
            *overlay.world.sumeragi_lanes.get_mut() = original;
            assert!(overlay.verify_sumeragi_lane_state_publication().is_ok());
            drop(overlay);
        }
    }
    #[test]
    fn exact_fixed_write_cannot_be_substituted_removed_or_duplicated() {
        let chain = chain();
        let mut overlay = chain.state().block(next(&chain));
        let mut witness = ExecWitness::default();
        overlay.capture_sumeragi_lane_state(&mut witness).unwrap();
        for mutation in 0..3 {
            let mut changed = witness.clone();
            match mutation {
                0 => changed.writes.clear(),
                1 => changed.writes.push(changed.writes[0].clone()),
                _ => changed.writes[0].value.push(0),
            }
            assert!(
                overlay
                    .verify_sumeragi_lane_state_witness(&changed)
                    .is_err()
            );
        }
        let exact = witness.clone();
        assert!(overlay.capture_sumeragi_lane_state(&mut witness).is_err());
        assert_eq!(
            witness.writes, exact.writes,
            "duplicate capture preserves original bytes"
        );
        assert!(overlay.verify_sumeragi_lane_state_witness(&exact).is_ok());
    }
}
