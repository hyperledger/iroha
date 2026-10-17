//! Test-owned policy-bound proposals for exercising strict genesis result handling.

use super::*;

/// Construct a valid signed policy binding, then discard only its execution result.
/// Pure wire-construction and deliberately invalid-input fixtures retain the raw builder.
pub(super) fn policy_bound_proposal(
    extra: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    entries: Vec<GenesisTopologyEntry>,
    key: KeyPair,
) -> (
    GenesisBlock,
    AccountId,
    Vec<PeerId>,
    KeyPair,
    RawGenesisTransaction,
) {
    let (proposal, account, topology, key, manifest) =
        build_minimal_genesis_unexecuted_with_post_topology(
            extra,
            Vec::new(),
            topology,
            entries,
            key,
            chain_id(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            None,
        );
    let (proposal, manifest) = bind_proposal(proposal, manifest, &account, &topology, &key, None)
        .expect("bind original fixture policy before testing result handling");
    (proposal, account, topology, key, manifest)
}

/// Bind only this locally owned fixture manifest; final strict execution remains mandatory.
pub(super) fn bind_proposal(
    proposal: GenesisBlock,
    manifest: RawGenesisTransaction,
    account: &AccountId,
    topology: &[PeerId],
    key: &KeyPair,
    nexus: Option<&ActualNexus>,
) -> Result<(GenesisBlock, RawGenesisTransaction), Report> {
    let (executed, _, manifest) =
        genesis_policy::execute_generated_genesis(proposal, manifest, key, true, |candidate| {
            preexecute_genesis_with_runtime_config(
                candidate, account, topology, key, None, nexus, None, None,
            )
        })?;
    Ok((
        GenesisBlock(executed.0.canonical_resultless_proposal()?),
        manifest,
    ))
}
