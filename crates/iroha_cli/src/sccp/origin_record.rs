//! Original World authority used before creating an outbound transfer.

use super::*;
use iroha::data_model::sccp::{control::SccpControlRecordV1, registry::SccpRouteRevisionV1};

impl AuthenticatedOrigin {
    /// Identify the independently verified native cut that authenticated receipt checkpoints.
    pub(crate) fn receipt_authority_evidence(
        &self,
    ) -> Result<iroha_sccp_wallet::journal::SccpEvidenceItemV1> {
        crate::sccp::flows::evidence(
            "taira.evm_receipt_authority",
            &norito::json!({
                "network": (hex::encode(self.network)),
                "instance": (hex::encode(self.instance)),
                "height": (self.world.height()),
                "context_id": (self.world.context_id().to_string()),
                "world_root": (self.world.world_root().to_string()),
                "schema_hash": (self.world.schema_hash().to_string()),
            }),
        )
    }

    pub(crate) fn source_verification_time_ms(&self, wall_time_ms: u64) -> u64 {
        self.world.block_time_ms().max(wall_time_ms)
    }

    pub(crate) fn verify_light_client_set(
        &self,
        network: SccpNetworkV1,
        set: &iroha::data_model::sccp::light_client::SccpLcConsensusSetV1,
    ) -> Result<()> {
        self.world.verify_table_value(
            "world.sccp_light_client_sets",
            &(network, set.set_id),
            set,
        )?;
        Ok(())
    }

    pub(crate) fn verify_light_client(
        &self,
        network: SccpNetworkV1,
        client: &iroha::data_model::sccp::light_client::SccpLightClientV1,
    ) -> Result<()> {
        ensure!(
            client.params.network == network,
            "light client names a different network"
        );
        self.world
            .verify_table_value("world.sccp_light_clients", &network, client)?;
        Ok(())
    }

    pub(crate) fn verify_light_client_checkpoint(
        &self,
        network: SccpNetworkV1,
        checkpoint: &iroha::data_model::sccp::light_client::SccpLcCheckpointV1,
    ) -> Result<()> {
        self.world.verify_table_value(
            "world.sccp_light_client_checkpoints",
            &(network, checkpoint.data.source_height),
            checkpoint,
        )?;
        Ok(())
    }

    pub(crate) fn verify_burn_light_client(
        &self,
        network: SccpNetworkV1,
        client: &iroha::data_model::sccp::light_client::SccpLightClientV1,
        newest_set: &iroha::data_model::sccp::light_client::SccpLcConsensusSetV1,
    ) -> Result<u64> {
        ensure!(
            client.params.network == network && client.head.latest_set_id == newest_set.set_id,
            "burn light client and signing set name different original identities"
        );
        self.world
            .verify_table_value("world.sccp_light_clients", &network, client)?;
        self.world.verify_table_value(
            "world.sccp_light_client_sets",
            &(network, newest_set.set_id),
            newest_set,
        )?;
        Ok(self.world.block_time_ms())
    }

    pub(crate) fn record_margin(inclusion_ms: u64) -> Result<u64> {
        // CT4 bounds every committed current and future drift allowance, so the
        // record remains conservative even when a later block changes that cell.
        inclusion_ms
            .checked_add(2 * iroha::data_model::parameter::system::MAX_CLOCK_DRIFT_BOUND_MS)
            .ok_or_else(|| eyre!("record inclusion margin overflows"))
    }

    pub(crate) fn record_interval(&self, from: u64, current: u64) -> Result<()> {
        selected_interval(Some(from), current, self.element_count).map(|_| ())
    }

    pub(crate) fn verify_record_control(
        &self,
        network: SccpNetworkV1,
        revision: &SccpRouteRevisionV1,
        nonce: u64,
        control: &SccpControlRecordV1,
    ) -> Result<()> {
        ensure!(
            nonce.checked_add(1) == Some(revision.next_control_nonce) && control.has_valid_shape(),
            "control is not the selected revision's latest control"
        );
        self.world.verify_table_value(
            "world.sccp_control_messages",
            &(network, revision.revision, nonce),
            control,
        )?;
        ensure!(
            control.parliament_paused == revision.destination_paused,
            "latest control disagrees with the original revision pause"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::{
        sccp::deployment::{SccpCommitteePinV1, SccpDeploymentV1, SccpEvmDeploymentV1},
        sumeragi_finality::{
            WorldStateElementKindV1, WorldStateSnapshotEntryV1, world_state_value_hash_v1,
        },
        testing::native_finality::NativeFinalityFixture,
    };

    #[test]
    fn burn_guards_authenticate_exact_light_client_and_newest_set() {
        use iroha::data_model::sccp::light_client::{
            SccpLcConsensusSetV1, SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1,
            SccpLightClientV1,
        };
        let network = SccpNetworkV1::BscMainnet;
        let client = SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
            head: SccpLcHeadV1 {
                latest_set_id: 9,
                latest_finalized: SccpLcPointV1 {
                    source_height: 10,
                    block_hash: [1; 32],
                    source_time_ms: 20,
                },
                last_progress_taira_ms: 21,
            },
            frozen: None,
            state_hash: [2; 32],
        };
        let set = SccpLcConsensusSetV1 {
            set_id: 9,
            valid_from_source_height: 10,
            superseded_at_source_ms: None,
            set_bytes: vec![1, 2, 3],
        };
        let checkpoint = iroha::data_model::sccp::light_client::SccpLcCheckpointV1 {
            data: iroha::data_model::sccp::light_client::SccpLcCheckpointDataV1 {
                source_height: 10,
                block_hash: [3; 32],
                state_root: Some([4; 32]),
                receipts_or_tx_root: [5; 32],
                source_time_ms: 20,
            },
            recorded_at_taira_ms: 21,
            origin: iroha::data_model::sccp::light_client::SccpLcCheckpointOriginV1::Proof,
        };
        let mut snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"burn original sources"),
            entries: vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_client_checkpoints".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(
                        world_state_value_hash_v1(&(network, checkpoint.data.source_height))
                            .unwrap(),
                    ),
                    value_hash: world_state_value_hash_v1(&checkpoint).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_clients".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&network).unwrap()),
                    value_hash: world_state_value_hash_v1(&client).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_client_sets".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&(network, set.set_id)).unwrap()),
                    value_hash: world_state_value_hash_v1(&set).unwrap(),
                },
            ],
        };
        snapshot
            .entries
            .sort_by(|left, right| left.field_id.cmp(&right.field_id));
        let mut fixture = NativeFinalityFixture::new();
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = fixture.verifier().verify_retained_decision(&proof).unwrap();
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 3,
            verifier: fixture.verifier(),
        };
        let authority = original.receipt_authority_evidence().unwrap();
        assert_eq!(authority.label, "taira.evm_receipt_authority");
        let authority: norito::json::Value = norito::json::from_slice(&authority.bytes).unwrap();
        assert_eq!(
            authority
                .get("network")
                .and_then(norito::json::Value::as_str),
            Some(hex::encode(original.network).as_str())
        );
        assert_eq!(
            authority
                .get("height")
                .and_then(norito::json::Value::as_u64),
            Some(original.world.height())
        );
        assert_eq!(
            authority
                .get("world_root")
                .and_then(norito::json::Value::as_str),
            Some(original.world.world_root().to_string().as_str())
        );
        original.verify_light_client(network, &client).unwrap();
        original.verify_light_client_set(network, &set).unwrap();
        let later_time = original.world.block_time_ms() + 1_000_000;
        assert_eq!(
            original.source_verification_time_ms(0),
            original.world.block_time_ms()
        );
        assert_eq!(original.source_verification_time_ms(later_time), later_time);
        original
            .verify_light_client_checkpoint(network, &checkpoint)
            .unwrap();
        for field in 0..3 {
            let mut changed = checkpoint;
            match field {
                0 => changed.data.source_height += 1,
                1 => changed.data.state_root = Some([99; 32]),
                _ => changed.recorded_at_taira_ms += 1,
            }
            assert!(
                original
                    .verify_light_client_checkpoint(network, &changed)
                    .is_err()
            );
        }
        assert!(
            original
                .verify_light_client_checkpoint(SccpNetworkV1::EthereumMainnet, &checkpoint)
                .is_err()
        );
        assert_eq!(
            original
                .verify_burn_light_client(network, &client, &set)
                .unwrap(),
            original.world.block_time_ms()
        );
        let mut changed = client;
        changed.head.latest_finalized.source_time_ms += 1;
        assert!(original.verify_light_client(network, &changed).is_err());
        assert!(
            original
                .verify_light_client(SccpNetworkV1::EthereumMainnet, &client)
                .is_err()
        );
        assert!(
            original
                .verify_burn_light_client(network, &changed, &set)
                .is_err()
        );
        let mut changed_set = set.clone();
        changed_set.set_bytes.push(4);
        assert!(
            original
                .verify_light_client_set(network, &changed_set)
                .is_err()
        );
        assert!(
            original
                .verify_burn_light_client(network, &client, &changed_set)
                .is_err()
        );
        changed_set = set.clone();
        changed_set.set_id += 1;
        assert!(
            original
                .verify_burn_light_client(network, &client, &changed_set)
                .is_err()
        );
        assert!(
            original
                .verify_burn_light_client(SccpNetworkV1::EthereumMainnet, &client, &set)
                .is_err()
        );
    }

    #[test]
    fn record_guards_bind_full_control_preimage_and_checked_clock_margin() {
        let network = SccpNetworkV1::EthereumMainnet;
        let mut revision = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [1; 20],
                runtime_code_hash: [2; 32],
            }),
            SccpCommitteePinV1 {
                generation: 1,
                committee_root: [3; 32],
                start_height: 1,
                until_ms: 1000,
            },
            100,
            1,
        );
        revision.next_control_nonce = 3;
        let control = SccpControlRecordV1 {
            track: 2,
            parliament_paused: false,
            fast_pause_until_ms: 800,
            certificate_id: [1; 32],
            effect_hash: [2; 32],
            height: 2,
            commitment_index: 0,
            leaf: [3; 32],
        };
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"control"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.sccp_control_messages".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&(network, 1_u32, 2_u64)).unwrap()),
                value_hash: world_state_value_hash_v1(&control).unwrap(),
            }],
        };
        let mut fixture = NativeFinalityFixture::new();
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = fixture.verifier().verify_retained_decision(&proof).unwrap();
        let original = AuthenticatedOrigin {
            network: [1; 32],
            instance: [2; 32],
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 3,
            verifier: fixture.verifier(),
        };
        assert_eq!(AuthenticatedOrigin::record_margin(60_000).unwrap(), 180_000);
        assert!(AuthenticatedOrigin::record_margin(u64::MAX).is_err());
        assert!(original.record_interval(1, 3).is_ok());
        assert!(original.record_interval(1, 4).is_err());
        original
            .verify_record_control(network, &revision, 2, &control)
            .unwrap();
        for changed in [
            SccpControlRecordV1 {
                fast_pause_until_ms: 799,
                ..control
            },
            SccpControlRecordV1 {
                parliament_paused: true,
                ..control
            },
            SccpControlRecordV1 {
                leaf: [9; 32],
                ..control
            },
        ] {
            assert!(
                original
                    .verify_record_control(network, &revision, 2, &changed)
                    .is_err()
            );
        }
        assert!(
            original
                .verify_record_control(network, &revision, 1, &control)
                .is_err()
        );
        assert!(
            original
                .verify_record_control(SccpNetworkV1::BscMainnet, &revision, 2, &control)
                .is_err()
        );
    }

    #[test]
    fn receipt_authority_authenticates_exact_light_client_and_checkpoint_rows() {
        use iroha::data_model::sccp::light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        };
        let network = SccpNetworkV1::EthereumMainnet;
        let client = SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
            head: SccpLcHeadV1 {
                latest_set_id: 9,
                latest_finalized: SccpLcPointV1 {
                    source_height: 10,
                    block_hash: [1; 32],
                    source_time_ms: 20,
                },
                last_progress_taira_ms: 21,
            },
            frozen: None,
            state_hash: [2; 32],
        };
        let checkpoint = SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: 10,
                block_hash: [1; 32],
                state_root: Some([3; 32]),
                receipts_or_tx_root: [4; 32],
                source_time_ms: 20,
            },
            recorded_at_taira_ms: 21,
            origin: SccpLcCheckpointOriginV1::Advance,
        };
        let mut snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"receipt original sources"),
            entries: vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_clients".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&network).unwrap()),
                    value_hash: world_state_value_hash_v1(&client).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_client_checkpoints".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(
                        world_state_value_hash_v1(&(network, checkpoint.data.source_height))
                            .unwrap(),
                    ),
                    value_hash: world_state_value_hash_v1(&checkpoint).unwrap(),
                },
            ],
        };
        snapshot
            .entries
            .sort_by(|left, right| left.field_id.cmp(&right.field_id));
        let mut fixture = NativeFinalityFixture::new();
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = fixture.verifier().verify_retained_decision(&proof).unwrap();
        let original = AuthenticatedOrigin {
            network: *fixture.network_id().as_bytes(),
            instance: fixture.verifier().instance().0,
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: 2,
            verifier: fixture.verifier(),
        };
        original.verify_retained_block(&proof).unwrap();
        let evidence = original.receipt_authority_evidence().unwrap();
        assert_eq!(evidence.label, "taira.evm_receipt_authority");
        let metadata: norito::json::Value = norito::json::from_slice(&evidence.bytes).unwrap();
        assert_eq!(
            metadata,
            norito::json!({
                "network": (hex::encode(original.network)),
                "instance": (hex::encode(original.instance)),
                "height": (original.world.height()),
                "context_id": (original.world.context_id().to_string()),
                "world_root": (original.world.world_root().to_string()),
                "schema_hash": (original.world.schema_hash().to_string()),
            })
        );
        original.verify_light_client(network, &client).unwrap();
        original
            .verify_light_client_checkpoint(network, &checkpoint)
            .unwrap();
        let mut changed_client = client;
        changed_client.state_hash[0] ^= 1;
        assert!(
            original
                .verify_light_client(network, &changed_client)
                .is_err()
        );
        assert!(
            original
                .verify_light_client(SccpNetworkV1::BscMainnet, &client)
                .is_err()
        );
        assert!(
            original
                .verify_light_client_checkpoint(SccpNetworkV1::BscMainnet, &checkpoint)
                .is_err()
        );
        for changed in [
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    source_height: 11,
                    ..checkpoint.data
                },
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    block_hash: [5; 32],
                    ..checkpoint.data
                },
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    state_root: Some([6; 32]),
                    ..checkpoint.data
                },
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    receipts_or_tx_root: [7; 32],
                    ..checkpoint.data
                },
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    source_time_ms: 22,
                    ..checkpoint.data
                },
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                recorded_at_taira_ms: 22,
                ..checkpoint
            },
            SccpLcCheckpointV1 {
                origin: SccpLcCheckpointOriginV1::Parliament,
                ..checkpoint
            },
        ] {
            assert!(
                original
                    .verify_light_client_checkpoint(network, &changed)
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
#[path = "origin_record/receipt_adapter_tests.rs"]
mod receipt_adapter_tests;
