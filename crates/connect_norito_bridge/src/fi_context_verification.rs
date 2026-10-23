//! Authenticate an execution-cut FI observation through a successful native assertion.
//! Neither decoding a capsule nor normalizing its original request conveys authority.

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{
        fi_context::{
            AssetFiContextSnapshotV1, AssetFiContextTargetV1, asset_fi_context_snapshot_hash_v1,
        },
        fi_evidence::AssetFiContextAssertionCapsuleV1,
        fi_request::{NormalizedAssetFiContextRequestV1, normalize_asset_fi_context_request_v1},
    },
    isi::asset_fi_context::AssertAssetFiContextV1,
    nexus::AxtAssetIncarnationV1,
    transaction::{Executable, SignedTransaction},
};

/// Independently admitted local state. Never populate these fields from the
/// capsule, its transport reference, or a response-supplied runtime/checkpoint.
pub(crate) struct FiContextAssertionExpectation<'a> {
    pub network_id: NetworkId,
    pub chain_id: &'a str,
    pub checkpoint_sha256: [u8; 32],
    pub checkpoint_height: u64,
    pub checkpoint_context_id: [u8; 32],
    pub asset_owner: &'a AccountId,
    pub asset_incarnation: AxtAssetIncarnationV1,
    pub uid: [u8; 32],
    pub target: &'a AssetFiContextTargetV1,
    pub runtime_manifest_sha256: [u8; 32],
    pub owner_key_identity: &'a str,
    pub fi_participant: &'a str,
    pub wallet_scope_canonical: &'a [u8],
}

/// Native authenticated facts only. This is not a signing capability, freshness
/// decision, physical route grant, nor proof of an earlier financial operation.
pub(crate) struct VerifiedFiContextAssertionV1 {
    pub snapshot: AssetFiContextSnapshotV1,
    pub request_sha256: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub block_creation_time_ms: u64,
}

pub(crate) fn bind_request(
    request: &NormalizedAssetFiContextRequestV1,
    expected: &FiContextAssertionExpectation<'_>,
) -> Result<(), String> {
    expected
        .asset_incarnation
        .validate()
        .map_err(|error| error.to_string())?;
    if request.network_id != expected.network_id
        || request.chain_id != expected.chain_id
        || request.minimum_height != expected.checkpoint_height
        || request.uid != expected.uid
        || request.target != *expected.target
        || request.runtime_manifest_sha256 != expected.runtime_manifest_sha256
        || request.owner_key_identity != expected.owner_key_identity
        || request.fi_participant != expected.fi_participant
        || request.wallet_scope_canonical != expected.wallet_scope_canonical
        || expected.uid == [0; 32]
        || expected.runtime_manifest_sha256 == [0; 32]
    {
        return Err("FI request differs from independently admitted owner/runtime/target".into());
    }
    Ok(())
}

/// Admit only a signed candidate's singleton native instruction and original
/// selectors. This authenticates neither its context hash nor ledger execution.
pub(crate) fn bind_assertion_original<'a>(
    transaction: &'a SignedTransaction,
    request: &NormalizedAssetFiContextRequestV1,
    expected: &FiContextAssertionExpectation<'_>,
    checkpoint_block_hash: [u8; 32],
) -> Result<&'a AssertAssetFiContextV1, String> {
    if transaction.network_id() != Some(&expected.network_id)
        || transaction.authority() != expected.asset_owner
        || !transaction.metadata().is_empty()
        || transaction.attachments().is_some()
    {
        return Err("FI assertion has a foreign authority/domain or extra signed content".into());
    }
    transaction
        .verify_signature()
        .map_err(|error| format!("invalid FI assertion authorization: {error}"))?;
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err("FI assertion must be one direct native instruction".into());
    };
    if instructions.len() != 1 {
        return Err("FI assertion must be one direct native instruction".into());
    }
    let assertion = instructions
        .iter()
        .next()
        .and_then(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<AssertAssetFiContextV1>()
        })
        .ok_or_else(|| "FI capsule contains a foreign native instruction".to_owned())?;
    if assertion.target != request.target
        || assertion.expected_incarnation != expected.asset_incarnation
        || assertion.expected_uid != request.uid
        || assertion.request_sha256 != request.original_sha256
        || assertion.challenge != request.challenge
        || assertion.minimum_height != expected.checkpoint_height
        || assertion.minimum_block_hash != checkpoint_block_hash
    {
        return Err("FI assertion differs from the exact original request or checkpoint".into());
    }
    Ok(assertion)
}

/// Bind a capsule snapshot to that same admitted signed assertion. Native finality
/// and exact successful committed wire are still required by the caller.
pub(crate) fn bind_assertion(
    transaction: &SignedTransaction,
    snapshot: &AssetFiContextSnapshotV1,
    request: &NormalizedAssetFiContextRequestV1,
    expected: &FiContextAssertionExpectation<'_>,
    checkpoint_block_hash: [u8; 32],
) -> Result<(), String> {
    let assertion = bind_assertion_original(transaction, request, expected, checkpoint_block_hash)?;
    if assertion.expected_context_hash
        != asset_fi_context_snapshot_hash_v1(snapshot)
            .map_err(|error| format!("invalid canonical FI snapshot: {error}"))?
        || snapshot.asset_definition_id != request.asset_id
        || snapshot.account_id != request.wallet
        || snapshot.asset_incarnation != expected.asset_incarnation
        || snapshot.uid != request.uid
    {
        return Err(
            "FI assertion/snapshot differs from the exact original request or native checkpoint"
                .into(),
        );
    }
    // Existing platform V1 schemas describe LinkApproval only. Do not infer a
    // transfer or invent capability fields absent from a retained transfer consent.
    let AssetFiContextTargetV1::LinkApproval(target) = &request.target else {
        return Err("FI transfer requires its own explicit retained request schema".into());
    };
    if snapshot.fi_account_id != target.link.fi_account_id
        || snapshot.reference_digest != target.link.reference_digest
    {
        return Err("FI snapshot differs from the exact selected relationship".into());
    }
    Ok(())
}

/// Authenticate the native assertion, not an HTTP status or projected World.
///
/// `original_request` is the exact locally retained platform request. The caller
/// must keep its challenge/checkpoint/idempotency key together across uncertain
/// submission and recheck owner/runtime plus monotonic <=120s lifetime before and
/// after this synchronous verification and each later use. A new challenge uses a
/// new idempotency key; it does not replace a pending original.
pub(crate) fn verify_fi_context_assertion_v1(
    capsule_bytes: &[u8],
    original_request: &[u8],
    trusted_checkpoint: &[u8],
    expected: &FiContextAssertionExpectation<'_>,
) -> Result<VerifiedFiContextAssertionV1, String> {
    let request = normalize_asset_fi_context_request_v1(original_request)?;
    bind_request(&request, expected)?;
    let checkpoint = super::fi_checkpoint_selection::verify_fi_checkpoint_selection(
        trusted_checkpoint,
        expected.network_id,
        expected.chain_id,
        expected.checkpoint_sha256,
        expected.checkpoint_height,
        expected.checkpoint_context_id,
    )?;
    let capsule = AssetFiContextAssertionCapsuleV1::decode_canonical(capsule_bytes)?;
    let assertion = super::decode_signed_transaction(&capsule.assertion_signed_transaction)
        .map_err(|error| format!("invalid canonical original FI assertion: {error}"))?;
    bind_assertion(
        &assertion,
        &capsule.snapshot,
        &request,
        expected,
        checkpoint.block_hash,
    )?;
    // Reuse the exact-original verifier: it checks the whole retained signed
    // transaction including signatures, authenticated full-block row, execution
    // output and successful result under the independently selected checkpoint.
    let chain_json = norito::json::to_vec(&capsule.finality_proof_chain)
        .map_err(|error| format!("invalid native FI finality chain: {error}"))?;
    let committed =
        super::committed_transaction_inclusion::verify_exact_successful_committed_transaction(
            &capsule.committed_transaction_response,
            &chain_json,
            expected.network_id,
            expected.chain_id,
            trusted_checkpoint,
            &capsule.assertion_signed_transaction,
        )?;
    if !committed.global_root
        || !committed.result_ok
        || committed.block_height <= checkpoint.height
        || committed.block_creation_time_ms == 0
    {
        return Err(
            "FI observation requires successful Global execution after the retained checkpoint"
                .into(),
        );
    }
    Ok(VerifiedFiContextAssertionV1 {
        snapshot: capsule.snapshot,
        request_sha256: request.original_sha256,
        block_hash: committed.block_hash,
        block_height: committed.block_height,
        block_creation_time_ms: committed.block_creation_time_ms,
    })
}

#[cfg(test)]
pub(super) mod tests;
