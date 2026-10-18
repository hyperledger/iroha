//! Deterministic execution and fee policy from the State-owned pipeline.
//!
//! The projected fields are the pipeline contribution to
//! `execution_policy_digest_v1`. Worker counts, caches, tracing, GPU selection,
//! signature batching, and execution-memory caps are local resource choices;
//! their refusal must not change transaction validity or gas.

use iroha_config::parameters::actual::{GasLiquidity, GasVolatility, Pipeline};
use iroha_primitives::numeric::Numeric;
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:pipeline-gas-rate:v1")]
struct PipelineGasRateV1 {
    asset: String,
    units_per_gas: u64,
    twap_local_per_xor: Numeric,
    liquidity: u8,
    volatility: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:pipeline-gas:v1")]
struct PipelineGasPolicyV1 {
    tech_account_id: String,
    /// The configured allow-list is a set; its members use the same canonical
    /// Norito-byte ordering as `execution_policy_digest_v1`.
    accepted_assets: Vec<Vec<u8>>,
    /// The conversion list's order is retained because the fee policy digest
    /// and route consumers observe this vector in its configured order.
    units_per_gas: Vec<PipelineGasRateV1>,
}

/// Canonical first-release deterministic pipeline policy.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:pipeline:v1")]
pub(super) struct PipelineExecutionPolicyV1 {
    dynamic_prepass: bool,
    overlay_max_instructions: u64,
    overlay_max_bytes: u64,
    overlay_chunk_instructions: u64,
    gas: PipelineGasPolicyV1,
    ivm_max_cycles_upper_bound: u64,
    ivm_max_decoded_instructions: u64,
    ivm_max_decoded_bytes: u64,
    quarantine_max_txs_per_block: u64,
    quarantine_tx_max_cycles: u64,
    query_max_fetch_size: u64,
    query_stored_min_gas_units: u64,
    amx_per_dataspace_budget_ms: u64,
    amx_group_budget_ms: u64,
    amx_per_instruction_ns: u64,
    amx_per_memory_access_ns: u64,
    amx_per_syscall_ns: u64,
}

fn count(value: usize) -> u64 {
    u64::try_from(value)
        .expect("Iroha execution policy requires a pointer width of at most 64 bits")
}

fn liquidity_tag(value: GasLiquidity) -> u8 {
    match value {
        GasLiquidity::Tier1 => 1,
        GasLiquidity::Tier2 => 2,
        GasLiquidity::Tier3 => 3,
    }
}

fn volatility_tag(value: GasVolatility) -> u8 {
    match value {
        GasVolatility::Stable => 1,
        GasVolatility::Elevated => 2,
        GasVolatility::Dislocated => 3,
    }
}

impl PipelineExecutionPolicyV1 {
    /// Borrow precisely the execution-policy fields from the installed config.
    pub(super) fn from_actual(config: &Pipeline) -> Self {
        let mut accepted_assets = config
            .gas
            .accepted_assets
            .iter()
            .map(norito::codec::Encode::encode)
            .collect::<Vec<_>>();
        accepted_assets.sort_unstable();
        accepted_assets.dedup();
        let units_per_gas = config
            .gas
            .units_per_gas
            .iter()
            .map(|rate| PipelineGasRateV1 {
                asset: rate.asset.clone(),
                units_per_gas: rate.units_per_gas,
                twap_local_per_xor: rate.twap_local_per_xor.clone(),
                liquidity: liquidity_tag(rate.liquidity),
                volatility: volatility_tag(rate.volatility),
            })
            .collect();
        Self {
            dynamic_prepass: config.dynamic_prepass,
            overlay_max_instructions: count(config.overlay_max_instructions),
            overlay_max_bytes: config.overlay_max_bytes,
            overlay_chunk_instructions: count(config.overlay_chunk_instructions),
            gas: PipelineGasPolicyV1 {
                tech_account_id: config.gas.tech_account_id.clone(),
                accepted_assets,
                units_per_gas,
            },
            ivm_max_cycles_upper_bound: config.ivm_max_cycles_upper_bound.get(),
            ivm_max_decoded_instructions: config.ivm_max_decoded_instructions,
            ivm_max_decoded_bytes: config.ivm_max_decoded_bytes,
            quarantine_max_txs_per_block: count(config.quarantine_max_txs_per_block),
            quarantine_tx_max_cycles: config.quarantine_tx_max_cycles,
            query_max_fetch_size: config.query_max_fetch_size,
            query_stored_min_gas_units: config.query_stored_min_gas_units,
            amx_per_dataspace_budget_ms: config.amx_per_dataspace_budget_ms,
            amx_group_budget_ms: config.amx_group_budget_ms,
            amx_per_instruction_ns: config.amx_per_instruction_ns,
            amx_per_memory_access_ns: config.amx_per_memory_access_ns,
            amx_per_syscall_ns: config.amx_per_syscall_ns,
        }
    }
}

/// Borrow validated parameter projections and fund only canonical asset-set bytes.
pub(super) struct BorrowedPipelinePolicy<'a> {
    policy: &'a iroha_data_model::pipeline_validity_policy::PipelineValidityPolicyV1,
    gas: &'a iroha_config::parameters::actual::Gas,
    accepted: super::policy_borrowed::EncodedSet,
}
impl<'a> BorrowedPipelinePolicy<'a> {
    pub(super) fn new(
        policy: &'a iroha_data_model::pipeline_validity_policy::PipelineValidityPolicyV1,
        gas: &'a iroha_config::parameters::actual::Gas,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, super::policy_borrowed::OrderError> {
        let accepted = super::policy_borrowed::EncodedSet::new(&gas.accepted_assets, budget)?;
        Ok(Self {
            policy,
            gas,
            accepted,
        })
    }
}
impl norito::SerializePayload for BorrowedPipelinePolicy<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use super::policy_borrowed::{BareBytes, Ref, Seq, record};
        let policy = self.policy;
        let gas = self.gas;
        let gas_policy = record!(
            Ref(&gas.tech_account_id),
            Seq(self.accepted.unique().map(BareBytes)),
            Seq(gas.units_per_gas.iter().map(|rate| record!(
                Ref(&rate.asset),
                rate.units_per_gas,
                Ref(&rate.twap_local_per_xor),
                liquidity_tag(rate.liquidity),
                volatility_tag(rate.volatility)
            )))
        );
        record!(
            policy.dynamic_prepass,
            policy.overlay_max_instructions,
            policy.overlay_max_bytes,
            policy.overlay_chunk_instructions,
            gas_policy,
            policy.ivm_max_cycles_upper_bound,
            policy.ivm_max_decoded_instructions,
            policy.ivm_max_decoded_bytes,
            policy.quarantine_max_txs_per_block,
            policy.quarantine_tx_max_cycles,
            policy.query_max_fetch_size,
            policy.query_stored_min_gas_units,
            policy.amx_per_dataspace_budget_ms,
            policy.amx_group_budget_ms,
            policy.amx_per_instruction_ns,
            policy.amx_per_memory_access_ns,
            policy.amx_per_syscall_ns
        )
        .serialize(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::{GasRate, QueryCursorMode};
    use std::num::NonZeroU64;

    fn policy() -> Pipeline {
        let mut config = Pipeline::default();
        config.gas.tech_account_id = "tech@system".to_owned();
        config.gas.accepted_assets = vec!["gas-a".to_owned(), "gas-b".to_owned()];
        config.gas.units_per_gas = vec![GasRate {
            asset: "gas-a".to_owned(),
            units_per_gas: 17,
            twap_local_per_xor: Numeric::one(),
            liquidity: GasLiquidity::Tier1,
            volatility: GasVolatility::Stable,
        }];
        config
    }

    fn frame(config: &Pipeline) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &BorrowedPipelinePolicy::new(
                &crate::pipeline_validity_policy::policy_of(config),
                &config.gas,
                &iroha_allocation::AllocationBudget::new(1 << 20),
            )
            .unwrap(),
            &PipelineExecutionPolicyV1::from_actual(config),
        );
        norito::encode_canonical(&PipelineExecutionPolicyV1::from_actual(config)).unwrap()
    }

    fn assert_mutations_change_projection(mutations: &[(&str, fn(&mut Pipeline))]) {
        let baseline = policy();
        let expected = frame(&baseline);
        for &(name, mutate) in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(frame(&changed), expected, "{name}");
        }
    }

    #[test]
    fn pipeline_policy_has_canonical_v1_roundtrip() {
        let projected = PipelineExecutionPolicyV1::from_actual(&policy());
        assert_eq!(
            PipelineExecutionPolicyV1::nominal_name(),
            "iroha:state:pipeline:v1"
        );
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<PipelineExecutionPolicyV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    #[test]
    fn every_pipeline_execution_limit_changes_projection() {
        let mutations: &[(&str, fn(&mut Pipeline))] = &[
            ("dynamic prepass", |c| {
                c.dynamic_prepass = !c.dynamic_prepass
            }),
            ("overlay instructions", |c| c.overlay_max_instructions += 1),
            ("overlay bytes", |c| c.overlay_max_bytes += 1),
            ("overlay chunk", |c| c.overlay_chunk_instructions += 1),
            ("IVM cycles", |c| {
                c.ivm_max_cycles_upper_bound =
                    NonZeroU64::new(c.ivm_max_cycles_upper_bound.get() + 1).unwrap()
            }),
            ("decoded instructions", |c| {
                c.ivm_max_decoded_instructions += 1
            }),
            ("decoded bytes", |c| c.ivm_max_decoded_bytes += 1),
            ("quarantine count", |c| c.quarantine_max_txs_per_block += 1),
            ("quarantine cycles", |c| c.quarantine_tx_max_cycles += 1),
            ("query fetch", |c| c.query_max_fetch_size += 1),
            ("stored-query gas", |c| c.query_stored_min_gas_units += 1),
        ];
        assert_eq!(mutations.len(), 11);
        assert_mutations_change_projection(mutations);
    }

    #[test]
    fn every_pipeline_gas_input_changes_projection() {
        let mutations: &[(&str, fn(&mut Pipeline))] = &[
            ("fee account", |c| c.gas.tech_account_id.push('x')),
            ("accepted fee asset", |c| {
                c.gas.accepted_assets.push("gas-c".to_owned())
            }),
            ("rate asset", |c| c.gas.units_per_gas[0].asset.push('x')),
            ("rate units", |c| c.gas.units_per_gas[0].units_per_gas += 1),
            ("rate TWAP", |c| {
                c.gas.units_per_gas[0].twap_local_per_xor = Numeric::from(2_u32)
            }),
            ("rate liquidity", |c| {
                c.gas.units_per_gas[0].liquidity = GasLiquidity::Tier2
            }),
            ("rate volatility", |c| {
                c.gas.units_per_gas[0].volatility = GasVolatility::Elevated
            }),
        ];
        assert_eq!(mutations.len(), 7);
        assert_mutations_change_projection(mutations);
        let baseline = policy();
        let mut second_rate = baseline.gas.units_per_gas[0].clone();
        second_rate.asset = "gas-b".to_owned();
        let mut ordered = baseline.clone();
        ordered.gas.units_per_gas.push(second_rate);
        let mut reversed = ordered.clone();
        reversed.gas.units_per_gas.reverse();
        assert_ne!(frame(&ordered), frame(&reversed), "conversion order");
    }

    #[test]
    fn every_pipeline_amx_budget_changes_projection() {
        let mutations: &[(&str, fn(&mut Pipeline))] = &[
            ("dataspace budget", |c| c.amx_per_dataspace_budget_ms += 1),
            ("group budget", |c| c.amx_group_budget_ms += 1),
            ("instruction estimate", |c| c.amx_per_instruction_ns += 1),
            ("memory estimate", |c| c.amx_per_memory_access_ns += 1),
            ("syscall estimate", |c| c.amx_per_syscall_ns += 1),
        ];
        assert_eq!(mutations.len(), 5);
        assert_mutations_change_projection(mutations);
    }

    #[test]
    fn fee_asset_allow_list_is_a_set_and_local_resources_do_not_change_policy() {
        let baseline = policy();
        let expected = frame(&baseline);
        let mut reordered = baseline.clone();
        reordered.gas.accepted_assets.reverse();
        reordered.gas.accepted_assets.push("gas-a".to_owned());
        assert_eq!(frame(&reordered), expected);
        let mut local = baseline;
        local.access_set_cache_enabled = !local.access_set_cache_enabled;
        local.parallel_overlay = !local.parallel_overlay;
        local.workers += 1;
        local.stateless_cache_cap += 1;
        local.parallel_apply = !local.parallel_apply;
        local.ready_queue_heap = !local.ready_queue_heap;
        local.gpu_key_bucket = !local.gpu_key_bucket;
        local.debug_trace_scheduler_inputs = !local.debug_trace_scheduler_inputs;
        local.debug_trace_tx_eval = !local.debug_trace_tx_eval;
        local.signature_batch_max_ed25519 += 1;
        local.signature_batch_max_secp256k1 += 1;
        local.signature_batch_max_pqc += 1;
        local.signature_batch_max_bls += 1;
        local.cache_size += 1;
        local.ivm_cache_max_decoded_ops += 1;
        local.ivm_cache_max_bytes += 1;
        local.ivm_execution_max_bytes += 1;
        local.ivm_prover_threads += 1;
        local.query_default_cursor_mode = QueryCursorMode::Stored;
        assert_eq!(frame(&local), expected);
    }
}
