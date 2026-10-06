//! Core application of the committed execution-limit policy.
//!
//! The limits of the transaction pipeline that decide whether a transaction,
//! a contract program or a query is accepted are chain policy: overlay size,
//! IVM cycle and decoded-program bounds, the quarantine lane, stored-query
//! limits, the AMX budget model and the access-set derivation mode. Their
//! source is committed State: the typed custom parameter
//! [`PipelineValidityPolicyV1::PARAMETER_ID_STR`], defined with its protocol
//! default and canonical validation in
//! [`iroha_data_model::pipeline_validity_policy`]. An ordinary authorized
//! `SetParameter` installs or changes it, in genesis or later, and the change
//! governs every block after the one that commits it: block construction
//! freezes the policy of the predecessor's committed parameters for the whole
//! block. A chain that never installs the parameter uses the protocol default.
//! Executor data-model reconciliation never writes the parameter.
//!
//! A node's own `[pipeline]` configuration contributes local resource settings
//! only (workers, caches, tracing, accelerator selection, signature batching,
//! the default cursor mode of its query endpoints) and, until its committed
//! source exists, the fee policy `pipeline.gas`.
// TODO(F.4): `pipeline.gas` (fee collection account, accepted assets and
// conversion rates) is still read from node configuration and bound into State
// only through `execution_policy_digest_v1`. Move it to a committed fee policy
// with F.3; census entry `cfg.pipeline.policy`.

use std::{num::NonZeroU64, sync::RwLock};

use iroha_config::parameters::actual::Pipeline;
use iroha_data_model::parameter::{CustomParameter, Parameters};
pub use iroha_data_model::pipeline_validity_policy::{
    PipelineValidityPolicyError, PipelineValidityPolicyV1,
};
use iroha_primitives::json::Json;

fn count(value: usize) -> u64 {
    u64::try_from(value).expect("Iroha targets have a pointer width of at most 64 bits")
}

fn size(value: u64, field: &'static str) -> Result<usize, PipelineValidityPolicyError> {
    // `PipelineValidityPolicyV1::validate` bounds every count field by a fixed
    // protocol maximum that fits the narrowest supported pointer width, so a
    // validated policy never takes this error.
    usize::try_from(value).map_err(|_| PipelineValidityPolicyError::OutOfRange(field))
}

/// Project the validity-affecting values out of a pipeline settings value.
///
/// Every field of the settings value is named here: it is either read into
/// the policy or marked as a local resource. A field added to the settings
/// does not compile until it is classified.
#[must_use]
pub fn policy_of(pipeline: &Pipeline) -> PipelineValidityPolicyV1 {
    let Pipeline {
        dynamic_prepass,
        access_set_cache_enabled: _,     // local resource: advisory cache
        parallel_overlay: _,             // local resource
        workers: _,                      // local resource
        stateless_cache_cap: _,          // local resource
        parallel_apply: _,               // local resource
        ready_queue_heap: _,             // local resource: scheduler data structure
        gpu_key_bucket: _,               // local resource: accelerator with scalar fallback
        debug_trace_scheduler_inputs: _, // local resource: diagnostics
        debug_trace_tx_eval: _,          // local resource: diagnostics
        signature_batch_max_ed25519: _,  // local resource: batching of equivalent checks
        signature_batch_max_secp256k1: _, // local resource
        signature_batch_max_pqc: _,      // local resource
        signature_batch_max_bls: _,      // local resource
        cache_size: _,                   // local resource
        ivm_cache_max_decoded_ops: _,    // local resource
        ivm_cache_max_bytes: _,          // local resource
        ivm_execution_max_bytes: _,      // local resource: refusal defers, never rejects
        ivm_prover_threads: _,           // local resource
        overlay_max_instructions,
        overlay_max_bytes,
        overlay_chunk_instructions,
        gas: _, // fee policy: node-local until its committed source exists (module TODO)
        ivm_max_cycles_upper_bound,
        ivm_max_decoded_instructions,
        ivm_max_decoded_bytes,
        quarantine_max_txs_per_block,
        quarantine_tx_max_cycles,
        query_default_cursor_mode: _, // local resource: default of this node's endpoints
        query_max_fetch_size,
        query_stored_min_gas_units,
        amx_per_dataspace_budget_ms,
        amx_group_budget_ms,
        amx_per_instruction_ns,
        amx_per_memory_access_ns,
        amx_per_syscall_ns,
    } = pipeline;
    PipelineValidityPolicyV1 {
        dynamic_prepass: *dynamic_prepass,
        overlay_max_instructions: count(*overlay_max_instructions),
        overlay_max_bytes: *overlay_max_bytes,
        overlay_chunk_instructions: count(*overlay_chunk_instructions),
        ivm_max_cycles_upper_bound: ivm_max_cycles_upper_bound.get(),
        ivm_max_decoded_instructions: *ivm_max_decoded_instructions,
        ivm_max_decoded_bytes: *ivm_max_decoded_bytes,
        quarantine_max_txs_per_block: count(*quarantine_max_txs_per_block),
        quarantine_tx_max_cycles: *quarantine_tx_max_cycles,
        query_max_fetch_size: *query_max_fetch_size,
        query_stored_min_gas_units: *query_stored_min_gas_units,
        amx_per_dataspace_budget_ms: *amx_per_dataspace_budget_ms,
        amx_group_budget_ms: *amx_group_budget_ms,
        amx_per_instruction_ns: *amx_per_instruction_ns,
        amx_per_memory_access_ns: *amx_per_memory_access_ns,
        amx_per_syscall_ns: *amx_per_syscall_ns,
    }
}

/// Replace the validity-affecting values of `pipeline` with `policy`.
///
/// Local resource settings of `pipeline` and its fee policy are carried over.
/// `pipeline` is not modified when an error is returned. The new value is one
/// exhaustive literal: a field added to the settings does not compile until it
/// is given a source.
///
/// # Errors
///
/// Returns the first rule of [`PipelineValidityPolicyV1::validate`] that fails.
pub fn apply_policy(
    policy: &PipelineValidityPolicyV1,
    pipeline: &mut Pipeline,
) -> Result<(), PipelineValidityPolicyError> {
    policy.validate()?;
    let applied = Pipeline {
        dynamic_prepass: policy.dynamic_prepass,
        access_set_cache_enabled: pipeline.access_set_cache_enabled,
        parallel_overlay: pipeline.parallel_overlay,
        workers: pipeline.workers,
        stateless_cache_cap: pipeline.stateless_cache_cap,
        parallel_apply: pipeline.parallel_apply,
        ready_queue_heap: pipeline.ready_queue_heap,
        gpu_key_bucket: pipeline.gpu_key_bucket,
        debug_trace_scheduler_inputs: pipeline.debug_trace_scheduler_inputs,
        debug_trace_tx_eval: pipeline.debug_trace_tx_eval,
        signature_batch_max_ed25519: pipeline.signature_batch_max_ed25519,
        signature_batch_max_secp256k1: pipeline.signature_batch_max_secp256k1,
        signature_batch_max_pqc: pipeline.signature_batch_max_pqc,
        signature_batch_max_bls: pipeline.signature_batch_max_bls,
        cache_size: pipeline.cache_size,
        ivm_cache_max_decoded_ops: pipeline.ivm_cache_max_decoded_ops,
        ivm_cache_max_bytes: pipeline.ivm_cache_max_bytes,
        ivm_execution_max_bytes: pipeline.ivm_execution_max_bytes,
        ivm_prover_threads: pipeline.ivm_prover_threads,
        overlay_max_instructions: size(
            policy.overlay_max_instructions,
            "overlay_max_instructions",
        )?,
        overlay_max_bytes: policy.overlay_max_bytes,
        overlay_chunk_instructions: size(
            policy.overlay_chunk_instructions,
            "overlay_chunk_instructions",
        )?,
        gas: pipeline.gas.clone(),
        ivm_max_cycles_upper_bound: NonZeroU64::new(policy.ivm_max_cycles_upper_bound).ok_or(
            PipelineValidityPolicyError::Zero("ivm_max_cycles_upper_bound"),
        )?,
        ivm_max_decoded_instructions: policy.ivm_max_decoded_instructions,
        ivm_max_decoded_bytes: policy.ivm_max_decoded_bytes,
        quarantine_max_txs_per_block: size(
            policy.quarantine_max_txs_per_block,
            "quarantine_max_txs_per_block",
        )?,
        quarantine_tx_max_cycles: policy.quarantine_tx_max_cycles,
        query_default_cursor_mode: pipeline.query_default_cursor_mode,
        query_max_fetch_size: policy.query_max_fetch_size,
        query_stored_min_gas_units: policy.query_stored_min_gas_units,
        amx_per_dataspace_budget_ms: policy.amx_per_dataspace_budget_ms,
        amx_group_budget_ms: policy.amx_group_budget_ms,
        amx_per_instruction_ns: policy.amx_per_instruction_ns,
        amx_per_memory_access_ns: policy.amx_per_memory_access_ns,
        amx_per_syscall_ns: policy.amx_per_syscall_ns,
    };
    *pipeline = applied;
    Ok(())
}

/// The pipeline settings a node installs from its own configuration: its
/// local resource settings with every validity-affecting value replaced by
/// the protocol default. The committed policy, when the chain installs one,
/// is applied over this value by [`effective_pipeline`].
#[must_use]
pub fn node_local_resources(mut node: Pipeline) -> Pipeline {
    apply_policy(&PipelineValidityPolicyV1::protocol_default(), &mut node)
        .expect("the protocol default pipeline validity policy is valid");
    node
}

/// Names of the validity-affecting fields a settings value holds with a value
/// other than the protocol default. A node configuration cannot set them; a
/// tool or test that builds a settings value by hand learns which of its
/// values a node ignores.
#[must_use]
pub fn node_validity_overrides(node: &Pipeline) -> Vec<&'static str> {
    policy_of(node).differing_fields(&PipelineValidityPolicyV1::protocol_default())
}

/// The policy committed in `parameters`, or `None` when the chain uses the
/// protocol default.
///
/// # Errors
///
/// Returns an error when the committed payload is malformed. `SetParameter`
/// validates the payload before it is committed and nothing else writes the
/// parameter, so this indicates State that no valid transition produced.
pub fn committed(
    parameters: &Parameters,
) -> Result<Option<PipelineValidityPolicyV1>, PipelineValidityPolicyError> {
    parameters
        .custom()
        .get(&PipelineValidityPolicyV1::parameter_id())
        .map(|custom| from_committed_payload(custom.payload()))
        .transpose()
}

/// [`PipelineValidityPolicyV1::from_payload`] of a committed payload,
/// remembering the last valid one: every State view reads the policy and it
/// changes rarely. The memo is keyed by the exact canonical payload text, so
/// it returns exactly what decoding returns.
fn from_committed_payload(
    payload: &Json,
) -> Result<PipelineValidityPolicyV1, PipelineValidityPolicyError> {
    static LAST: RwLock<Option<(String, PipelineValidityPolicyV1)>> = RwLock::new(None);
    let text: &str = payload.as_ref();
    if let Ok(last) = LAST.read()
        && let Some((known, policy)) = last.as_ref()
        && known == text
    {
        return Ok(*policy);
    }
    let policy = PipelineValidityPolicyV1::from_payload(payload)?;
    if let Ok(mut last) = LAST.write() {
        *last = Some((text.to_owned(), policy));
    }
    Ok(policy)
}

/// The pipeline settings validation reads: `installed` with the committed
/// policy of `parameters`, when there is one, applied over it.
///
/// The function is pure: it reads its arguments and writes nothing. Block
/// construction calls it with the predecessor's committed parameters and
/// freezes the result for the block, so a policy committed in block `N`
/// governs block `N + 1` onwards and the genesis block runs under the
/// protocol default.
///
/// A malformed committed payload leaves `installed` unchanged. No valid
/// transition commits one;
/// [`crate::state::State::install_node_pipeline`] refuses to start on restored
/// State that holds one.
#[must_use]
pub fn effective_pipeline(installed: Pipeline, parameters: &Parameters) -> Pipeline {
    let mut effective = installed;
    if let Ok(Some(policy)) = committed(parameters) {
        apply_policy(&policy, &mut effective)
            .expect("a validated pipeline validity policy applies");
    }
    effective
}

/// Validate a `SetParameter` of the committed pipeline validity policy.
///
/// Returns `Ok(false)` when `custom` is another parameter and `Ok(true)` when
/// it is a policy that may be committed. The decision uses the instruction
/// bytes only, so every validator reaches it identically. A committed change
/// takes effect from the next block; a transaction is judged by the policy
/// frozen for the block that executes it, without grandfathering.
///
/// # Errors
///
/// Returns an error when the payload is malformed or violates a rule of
/// [`PipelineValidityPolicyV1::validate`].
pub fn validate_set_parameter(
    custom: &CustomParameter,
) -> Result<bool, PipelineValidityPolicyError> {
    match PipelineValidityPolicyV1::from_custom_parameter(custom) {
        None => Ok(false),
        Some(policy) => policy.map(|_| true),
    }
}

#[cfg(test)]
#[path = "pipeline_validity_policy_tests.rs"]
mod tests;
