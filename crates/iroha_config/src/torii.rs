//! Node-owned conversions to the canonical Torii configuration records.
use crate::parameters::actual as base;
use iroha_data_model::soranet::vpn::VpnExitClassV1;
use iroha_torii_shared::configuration::*;
use iroha_torii_shared::status::{
    NexusRoutingMatcherStatus, NexusRoutingPolicyStatus, NexusRoutingRuleStatus, NexusStatus,
};
impl From<&base::Sumeragi> for Consensus {
    fn from(value: &base::Sumeragi) -> Self {
        let role = match value.role {
            base::NodeRole::Validator => "validator",
            base::NodeRole::Observer => "observer",
        };
        Self {
            protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
            role: role.to_owned(),
        }
    }
}

impl From<&'_ base::Root> for Configuration {
    fn from(value: &'_ base::Root) -> Self {
        Self {
            public_key: value.common.key_pair.public_key().clone(),
            logger: (&value.logger).into(),
            network: value.into(),
            queue: (&value.queue).into(),
            consensus: Consensus::from(&value.sumeragi),
            // The verification gas schedule is chain policy, not node
            // configuration: this is the protocol default, and the service that
            // owns State replaces it with the committed schedule before serving.
            confidential_gas: (&base::ConfidentialGas {
                proof_base: crate::parameters::defaults::confidential::gas::PROOF_BASE,
                per_public_input: crate::parameters::defaults::confidential::gas::PER_PUBLIC_INPUT,
                per_proof_byte: crate::parameters::defaults::confidential::gas::PER_PROOF_BYTE,
                per_nullifier: crate::parameters::defaults::confidential::gas::PER_NULLIFIER,
                per_commitment: crate::parameters::defaults::confidential::gas::PER_COMMITMENT,
            })
                .into(),
            transport: Transport::from(&value.torii.transport),
            nexus: Nexus::from(&value.nexus),
        }
    }
}

impl From<&'_ base::Nexus> for Nexus {
    fn from(value: &'_ base::Nexus) -> Self {
        Self {
            axt: Axt::from(&value.axt),
        }
    }
}

impl From<&'_ base::NexusAxt> for Axt {
    fn from(value: &'_ base::NexusAxt) -> Self {
        Self {
            slot_length_ms: value.slot_length_ms,
            max_clock_skew_ms: value.max_clock_skew_ms,
            proof_cache_ttl_slots: value.proof_cache_ttl_slots,
            replay_retention_slots: value.replay_retention_slots,
        }
    }
}

impl From<&'_ base::NoritoRpcTransport> for NoritoRpcSummary {
    fn from(value: &'_ base::NoritoRpcTransport) -> Self {
        Self {
            enabled: value.enabled,
            stage: value.stage.label().to_string(),
            require_mtls: value.require_mtls,
            canary_allowlist_size: value.allowed_clients.len(),
        }
    }
}

impl From<&'_ base::ConfidentialGas> for ConfidentialGas {
    fn from(value: &'_ base::ConfidentialGas) -> Self {
        Self {
            proof_base: value.proof_base,
            per_public_input: value.per_public_input,
            per_proof_byte: value.per_proof_byte,
            per_nullifier: value.per_nullifier,
            per_commitment: value.per_commitment,
        }
    }
}

impl From<&'_ base::Logger> for Logger {
    fn from(value: &'_ base::Logger) -> Self {
        Self {
            level: value.level,
            filter: value.filter.as_ref().map(ToString::to_string),
        }
    }
}

impl From<&'_ base::Queue> for Queue {
    fn from(value: &'_ base::Queue) -> Self {
        Self {
            capacity: value.capacity,
            max_retained_bytes: value.max_retained_bytes,
        }
    }
}

impl From<&'_ base::Root> for Network {
    fn from(value: &'_ base::Root) -> Self {
        let handshake = SoranetHandshakeSummary::from(&value.network.soranet_handshake);
        let privacy = SoranetPrivacySummary::from(&value.network.soranet_privacy);
        let vpn = SoranetVpnSummary::from(&value.network.soranet_vpn);
        Self {
            chain_discriminant: *value.common.chain_discriminant.value(),
            block_gossip_size: value.block_sync.gossip_size,
            block_gossip_period_ms: u32::try_from(value.block_sync.gossip_period.as_millis())
                .expect("block gossip period should fit into a u32"),
            peer_gossip_period_ms: u32::try_from(value.network.peer_gossip_period.as_millis())
                .expect("peer gossip period should fit into a u32"),
            relay_ttl: value.network.relay_ttl,
            trust_decay_half_life_ms: u32::try_from(
                value.network.trust_decay_half_life.as_millis(),
            )
            .expect("trust decay half-life should fit into a u32"),
            trust_penalty_bad_gossip: value.network.trust_penalty_bad_gossip,
            trust_penalty_unknown_peer: value.network.trust_penalty_unknown_peer,
            trust_min_score: value.network.trust_min_score,
            trust_gossip: value.network.trust_gossip,
            transaction_gossip_size: value.transaction_gossiper.gossip_size,
            transaction_gossip_period_ms: u32::try_from(
                value.transaction_gossiper.gossip_period.as_millis(),
            )
            .expect("transaction gossip period should fit into a u32"),
            transaction_gossip_resend_ticks: value.transaction_gossiper.gossip_resend_ticks,
            soranet_handshake: handshake,
            soranet_privacy: privacy,
            soranet_vpn: vpn,
            lane_profile: value.network.lane_profile.into(),
            require_sm_handshake_match: value.network.require_sm_handshake_match,
            require_sm_openssl_preview_match: value.network.require_sm_openssl_preview_match,
        }
    }
}

impl From<&'_ base::SoranetHandshake> for SoranetHandshakeSummary {
    fn from(value: &'_ base::SoranetHandshake) -> Self {
        Self {
            descriptor_commit_hex: hex::encode(value.descriptor_commit.value()),
            client_capabilities_hex: hex::encode(value.client_capabilities.value()),
            relay_capabilities_hex: hex::encode(value.relay_capabilities.value()),
            kem_id: value.kem_id,
            sig_id: value.sig_id,
            resume_hash_hex: value
                .resume_hash
                .as_ref()
                .map(|hash| hex::encode(hash.value())),
            pow: SoranetHandshakePowSummary::from(&value.pow),
        }
    }
}

impl From<&'_ base::SoranetPrivacy> for SoranetPrivacySummary {
    fn from(value: &'_ base::SoranetPrivacy) -> Self {
        Self {
            bucket_secs: value.bucket_secs,
            min_handshakes: value.min_handshakes,
            flush_delay_buckets: value.flush_delay_buckets,
            force_flush_buckets: value.force_flush_buckets,
            max_completed_buckets: value.max_completed_buckets,
            max_share_lag_buckets: value.max_share_lag_buckets,
            expected_shares: value.expected_shares,
            event_buffer_capacity: value.event_buffer_capacity,
        }
    }
}

impl From<&'_ base::SoranetVpn> for SoranetVpnSummary {
    fn from(value: &'_ base::SoranetVpn) -> Self {
        let lease_secs = u32::try_from(value.lease.as_secs())
            .expect("soranet_vpn.lease exceeds u32::MAX seconds");
        let exit_class = VpnExitClassV1::try_from_label(&value.exit_class)
            .expect("soranet_vpn.exit_class must be standard|low-latency|high-security");
        Self {
            enabled: value.enabled,
            cell_size_bytes: value.cell_size_bytes,
            flow_label_bits: value.flow_label_bits,
            cover_to_data_per_mille: value.cover_to_data_per_mille,
            max_cover_burst: value.max_cover_burst,
            heartbeat_ms: value.heartbeat_ms,
            jitter_ms: value.jitter_ms,
            padding_budget_ms: value.padding_budget_ms,
            guard_refresh_secs: value.guard_refresh.as_secs(),
            lease_secs: u64::from(lease_secs),
            dns_push_interval_secs: value.dns_push_interval.as_secs(),
            exit_class: exit_class.as_label().to_string(),
            meter_family: value.meter_family.clone(),
            operator_account_id: value.operator_account_id.to_string(),
            lease_fee: value.lease_fee.clone(),
            settlement_grace_secs: value.settlement_grace.as_secs(),
            route_pushes: value.route_pushes.clone(),
            excluded_routes: value.excluded_routes.clone(),
            dns_servers: value.dns_servers.clone(),
        }
    }
}

impl From<&'_ base::SoranetPow> for SoranetHandshakePowSummary {
    fn from(value: &'_ base::SoranetPow) -> Self {
        Self {
            difficulty: value.difficulty,
            max_future_skew_secs: value.max_future_skew.as_secs(),
            min_ticket_ttl_secs: value.min_ticket_ttl.as_secs(),
            ticket_ttl_secs: value.ticket_ttl.as_secs(),
            outbound_mint_capacity: value.outbound_mint_capacity.get(),
            inbound_verify_capacity: value.inbound_verify_capacity.get(),
            puzzle: SoranetHandshakePuzzleSummary::from(value.puzzle),
        }
    }
}

impl From<base::SoranetPuzzle> for SoranetHandshakePuzzleSummary {
    fn from(value: base::SoranetPuzzle) -> Self {
        Self {
            memory_kib: value.memory_kib.get(),
            time_cost: value.time_cost.get(),
            lanes: value.lanes.get(),
        }
    }
}

impl From<&'_ base::ToriiTransport> for Transport {
    fn from(transport: &'_ base::ToriiTransport) -> Self {
        Self {
            norito_rpc: NoritoRpcSummary::from(&transport.norito_rpc),
        }
    }
}

impl From<base::LaneProfile> for LaneProfile {
    fn from(profile: base::LaneProfile) -> Self {
        match profile {
            base::LaneProfile::Core => Self::Core,
            base::LaneProfile::Home => Self::Home,
        }
    }
}
impl From<LaneProfile> for base::LaneProfile {
    fn from(profile: LaneProfile) -> Self {
        match profile {
            LaneProfile::Core => Self::Core,
            LaneProfile::Home => Self::Home,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::defaults;
    use iroha_crypto::{
        KeyPair,
        soranet::handshake::{
            DEFAULT_CLIENT_CAPABILITIES, DEFAULT_DESCRIPTOR_COMMIT, DEFAULT_RELAY_CAPABILITIES,
        },
    };
    use iroha_data_model::Level;
    use nonzero_ext::nonzero;
    #[test]
    #[allow(clippy::too_many_lines)]
    fn snapshot_serialized_form() {
        let soranet_vpn = SoranetVpnSummary::from(&base::SoranetVpn::default());
        let value = Configuration {
            public_key: KeyPair::try_from_seed(vec![1, 2, 3], <_>::default())
                .expect("derive config snapshot fixture public key")
                .public_key()
                .clone(),
            logger: Logger {
                level: Level::TRACE,
                filter: None,
            },
            network: Network {
                chain_discriminant: defaults::common::chain_discriminant(),
                block_gossip_size: nonzero!(10u32),
                block_gossip_period_ms: 5000,
                peer_gossip_period_ms: 1_000,
                trust_decay_half_life_ms: u32::try_from(
                    defaults::network::TRUST_DECAY_HALF_LIFE.as_millis(),
                )
                .expect("trust decay half-life should fit into a u32"),
                trust_penalty_bad_gossip: defaults::network::TRUST_PENALTY_BAD_GOSSIP,
                trust_penalty_unknown_peer: defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
                trust_min_score: defaults::network::TRUST_MIN_SCORE,
                trust_gossip: defaults::network::TRUST_GOSSIP,
                relay_ttl: 8,
                transaction_gossip_size: nonzero!(512u32),
                transaction_gossip_period_ms: 1000,
                transaction_gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
                soranet_handshake: SoranetHandshakeSummary {
                    descriptor_commit_hex: hex::encode(DEFAULT_DESCRIPTOR_COMMIT),
                    client_capabilities_hex: hex::encode(DEFAULT_CLIENT_CAPABILITIES),
                    relay_capabilities_hex: hex::encode(DEFAULT_RELAY_CAPABILITIES),
                    kem_id: 1,
                    sig_id: 1,
                    resume_hash_hex: None,
                    pow: SoranetHandshakePowSummary {
                        difficulty: iroha_crypto::soranet::puzzle::DEFAULT_DIFFICULTY,
                        max_future_skew_secs: 300,
                        min_ticket_ttl_secs: 30,
                        ticket_ttl_secs: 300,
                        outbound_mint_capacity: 3,
                        inbound_verify_capacity: 3,
                        puzzle: SoranetHandshakePuzzleSummary {
                            memory_kib: 64 * 1024,
                            time_cost: 2,
                            lanes: 1,
                        },
                    },
                },
                soranet_privacy: SoranetPrivacySummary {
                    bucket_secs: 60,
                    min_handshakes: 12,
                    flush_delay_buckets: 1,
                    force_flush_buckets: 6,
                    max_completed_buckets: 120,
                    max_share_lag_buckets: 12,
                    expected_shares: 2,
                    event_buffer_capacity: 4_096,
                },
                soranet_vpn,
                lane_profile: LaneProfile::Core,
                require_sm_handshake_match: true,
                require_sm_openssl_preview_match: true,
            },
            queue: Queue {
                capacity: nonzero!(656_565_usize),
                max_retained_bytes: nonzero!(123_456_789_u64),
            },
            consensus: Consensus {
                protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
                role: "validator".to_string(),
            },
            confidential_gas: ConfidentialGas {
                proof_base: 777_777,
                per_public_input: 3_333,
                per_proof_byte: 42,
                per_nullifier: 123,
                per_commitment: 321,
            },
            transport: Transport {
                norito_rpc: NoritoRpcSummary {
                    enabled: true,
                    stage: "ga".to_string(),
                    require_mtls: true,
                    canary_allowlist_size: 2,
                },
            },
            nexus: Nexus {
                axt: Axt {
                    slot_length_ms: nonzero!(10_u64),
                    max_clock_skew_ms: 5,
                    proof_cache_ttl_slots: nonzero!(4_u64),
                    replay_retention_slots: nonzero!(256_u64),
                },
            },
        };
        let actual = norito::json::to_json_pretty(&value).expect("The value is a valid JSON");
        // NOTE: whenever this is updated, make sure to update the documentation accordingly:
        //       https://docs.iroha.tech/reference/torii-endpoints.html
        //       -> Configuration endpoints
        expect_test::expect_file!["../../../fixtures/torii/configuration.json"]
            .assert_eq(&format!("{actual}\n"));
        let parsed: Configuration =
            norito::json::from_json(&actual).expect("configuration snapshot should deserialize");
        assert_eq!(parsed.confidential_gas.proof_base, 777_777);
        assert_eq!(parsed.confidential_gas.per_public_input, 3_333);
        assert_eq!(parsed.confidential_gas.per_proof_byte, 42);
        assert_eq!(parsed.confidential_gas.per_nullifier, 123);
        assert_eq!(parsed.confidential_gas.per_commitment, 321);
    }
    #[test]
    fn mandatory_soranet_pow_is_exposed_in_client_summary() {
        let pow = base::SoranetPow::default();

        let summary = SoranetHandshakePowSummary::from(&pow);

        let puzzle = summary.puzzle;
        assert_eq!(puzzle.memory_kib, pow.puzzle.memory_kib.get());
        assert_eq!(puzzle.time_cost, pow.puzzle.time_cost.get());
        assert_eq!(puzzle.lanes, pow.puzzle.lanes.get());
    }
}

impl From<&base::LaneRoutingPolicy> for NexusRoutingPolicyStatus {
    fn from(policy: &base::LaneRoutingPolicy) -> Self {
        Self {
            default_lane: policy.default_lane.as_u32(),
            default_dataspace: policy.default_dataspace.as_u64(),
            rules: policy
                .rules
                .iter()
                .map(|rule| NexusRoutingRuleStatus {
                    lane: rule.lane.as_u32(),
                    dataspace_id: rule
                        .dataspace
                        .map(iroha_model_base::topology::DataSpaceId::as_u64),
                    matcher: NexusRoutingMatcherStatus {
                        account: rule.matcher.account.clone(),
                        instruction: rule.matcher.instruction.clone(),
                        description: rule.matcher.description.clone(),
                    },
                })
                .collect(),
        }
    }
}
impl From<&base::LaneRoutingPolicy> for NexusStatus {
    fn from(policy: &base::LaneRoutingPolicy) -> Self {
        Self {
            routing_policy: NexusRoutingPolicyStatus::from(policy),
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;
    #[test]
    fn nexus_status_exports_optional_rule_dataspace() {
        let policy = base::LaneRoutingPolicy {
            default_lane: iroha_model_base::topology::LaneId::new(2),
            default_dataspace: iroha_model_base::topology::DataSpaceId::new(10),
            rules: vec![
                base::LaneRoutingRule {
                    lane: iroha_model_base::topology::LaneId::new(3),
                    dataspace: Some(iroha_model_base::topology::DataSpaceId::new(11)),
                    matcher: base::LaneRoutingMatcher {
                        account: Some("alice".to_owned()),
                        instruction: Some("Register".to_owned()),
                        description: Some("explicit dataspace".to_owned()),
                    },
                },
                base::LaneRoutingRule {
                    lane: iroha_model_base::topology::LaneId::new(4),
                    dataspace: None,
                    matcher: base::LaneRoutingMatcher::default(),
                },
            ],
        };
        let status = NexusStatus::from(&policy);
        assert_eq!(status.routing_policy.default_lane, 2);
        assert_eq!(status.routing_policy.default_dataspace, 10);
        assert_eq!(status.routing_policy.rules[0].lane, 3);
        assert_eq!(status.routing_policy.rules[0].dataspace_id, Some(11));
        assert_eq!(
            status.routing_policy.rules[0]
                .matcher
                .description
                .as_deref(),
            Some("explicit dataspace")
        );
        assert_eq!(status.routing_policy.rules[1].lane, 4);
        assert_eq!(status.routing_policy.rules[1].dataspace_id, None);
    }
}
