//! Fixture genesis signed with the policy commitments its original native execution derives.
//!
//! A signed genesis commits the execution-policy and Nexus/AMX context hashes, and native
//! genesis validation recomputes both from the staged State and rejects any mismatch. Like
//! kagami's signer, a fixture signs a provisional genesis, executes it over its exact configured
//! State, and signs again with the hashes that execution reports. The check is never bypassed:
//! the final genesis must pass it unchanged.

use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::SignedBlock,
    isi::InstructionBox,
    parameter::{
        Parameter,
        system::{ConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
};
use iroha_model_base::{chain::ChainId, peer::PeerId};
use iroha_primitives::time::TimeSource;

use super::{
    super::{network_topology::Topology, startup},
    build_genesis,
};
use crate::{
    block::{BlockValidationError, ValidBlock},
    state::State,
};

/// The signed genesis parameters of an optional `NPoS` policy.
pub(super) fn npos_genesis_parameters(npos: Option<SumeragiNposParameters>) -> Vec<Parameter> {
    npos.into_iter()
        .flat_map(|policy| {
            [
                Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                    policy.epoch_length_blocks,
                )),
                Parameter::Custom(policy.into_custom_parameter()),
            ]
        })
        .collect()
}

/// Execute `genesis` over the configured, still empty `state` through native genesis validation
/// and return the execution-policy and Nexus/AMX context hashes that execution derived when they
/// differ from the signed commitments. `None` means the signed commitments already match. The
/// staged overlay is discarded, so `state` stays empty either way.
///
/// # Errors
/// Any rejection other than the policy mismatch, with the failing execution outputs.
pub(crate) fn staged_genesis_policies(
    genesis: SignedBlock,
    topology: &Topology,
    genesis_account: &AccountId,
    state: &State,
    mode: ConsensusMode,
) -> Result<Option<(Hash, Hash)>, String> {
    let validation = {
        let selected_genesis = genesis;
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            topology,
            genesis_account,
            &TimeSource::new_system(),
            state,
            mode,
            selected_scope,
        )
    }
    .unpack(|_| {});
    match validation {
        Ok(staged) => {
            drop(staged);
            Ok(None)
        }
        Err((rejected, error)) => match *error {
            BlockValidationError::GenesisPolicyMismatch {
                actual_execution,
                actual_nexus,
                ..
            } => Ok(Some((actual_execution, actual_nexus))),
            error => {
                let failures = rejected
                    .execution_outputs()
                    .iter()
                    .enumerate()
                    .filter(|(_, output)| output.result().is_err())
                    .map(|(index, output)| (index, output.result()))
                    .collect::<Vec<_>>();
                Err(format!(
                    "original native genesis execution: {error}; failed outputs: {failures:?}"
                ))
            }
        },
    }
}

/// [`super::signed_genesis_fixture`] signed with the policy commitments that original native
/// execution derives over the State `configured` returns for the genesis network.
///
/// `configured` returns a fresh, fully configured State with no committed block for the given
/// network. The provisional State and its network identity are discarded; the returned State
/// belongs to the returned genesis, which [`startup::apply_genesis`] accepts unchanged. The
/// consensus mode is `NPoS` exactly when `npos` is supplied.
///
/// # Errors
/// The genesis cannot be built or signed, or original native execution rejects it.
pub(crate) fn signed_genesis_fixture_for_state(
    chain_id: &ChainId,
    genesis_key: &KeyPair,
    validators: &[(PeerId, Vec<u8>)],
    instructions: Vec<InstructionBox>,
    genesis_time_ms: u64,
    npos: Option<SumeragiNposParameters>,
    mut configured: impl FnMut(NetworkId) -> State,
) -> Result<(SignedBlock, State), String> {
    let mode = if npos.is_some() {
        ConsensusMode::Npos
    } else {
        ConsensusMode::Permissioned
    };
    let (provisional, manifest) = build_genesis(
        chain_id,
        genesis_key,
        validators,
        instructions,
        npos_genesis_parameters(npos),
        mode.into(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        genesis_time_ms,
        std::num::NonZeroU64::MIN,
    )?;
    let account = AccountId::new(genesis_key.public_key().clone());
    let topology = Topology::new(
        startup::genesis_committee_peers(&provisional).map_err(|error| error.to_string())?,
    );
    let state = configured(NetworkId::from_genesis_hash(provisional.hash()));
    let Some((execution, nexus)) =
        staged_genesis_policies(provisional.clone(), &topology, &account, &state, mode)?
    else {
        return Ok((provisional, state));
    };
    drop(state);
    let mut context = manifest.sumeragi_context_parameters();
    context.execution_policy_hash = execution.into();
    context.nexus_amx_context_hash = nexus.into();
    let genesis = manifest
        .with_sumeragi_context_parameters(context)
        .with_consensus_meta()
        .map_err(|error| format!("{error:#}"))?
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            genesis_key,
            None,
            Some(crate::state::default_genesis_confidential_policy_hash()),
            genesis_time_ms,
        )
        .map_err(|error| format!("sign derived native genesis policies: {error:#}"))?
        .0;
    let state = configured(NetworkId::from_genesis_hash(genesis.hash()));
    match staged_genesis_policies(genesis.clone(), &topology, &account, &state, mode)? {
        None => Ok((genesis, state)),
        Some((execution, nexus)) => Err(format!(
            "re-signed fixture genesis does not reproduce its policies: execution {execution}, \
             Nexus {nexus}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use iroha_crypto::Algorithm;
    use iroha_data_model::{Registrable as _, account::Account, domain::Domain};

    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{StateReadOnly, World},
    };

    #[test]
    fn state_bound_fixture_genesis_signs_the_policies_its_native_execution_derives() {
        iroha_genesis::init_instruction_registry();
        let chain_id = ChainId::from("genesis-policy-fixture");
        let key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let account = AccountId::new(key.public_key().clone());
        let validators = super::super::fixture_validators();
        // A non-default execution configuration: the recommended template cannot bind it.
        let configured = |network: NetworkId| {
            let world = World::with(
                [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
                [Account::new(account.clone()).build(&account)],
                [],
            );
            let mut state = State::new_with_chain_and_network_id_for_testing(
                world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
                chain_id.clone(),
                network,
            );
            let mut pipeline = state.pipeline_snapshot();
            pipeline.amx_group_budget_ms = pipeline.amx_group_budget_ms.saturating_add(1);
            state.set_pipeline(pipeline);
            state
        };
        let template = super::super::signed_genesis_fixture(
            &chain_id,
            &key,
            &validators,
            Vec::new(),
            1_000,
            ConsensusMode::Permissioned,
            None,
        )
        .unwrap();
        let state = configured(NetworkId::from_genesis_hash(template.hash()));
        let topology = Topology::new(startup::genesis_committee_peers(&template).unwrap());
        let (execution, nexus) = staged_genesis_policies(
            template.clone(),
            &topology,
            &account,
            &state,
            ConsensusMode::Permissioned,
        )
        .unwrap()
        .expect("the template does not commit this configured execution");
        assert_eq!(
            state.view().height(),
            0,
            "provisional execution publishes nothing"
        );
        assert!(matches!(
            startup::apply_genesis(
                &state,
                template,
                &account,
                ConsensusMode::Permissioned,
                None
            ),
            Err(startup::StartupError::InvalidGenesis(error))
                if matches!(*error, BlockValidationError::GenesisPolicyMismatch { .. })
        ));

        let (genesis, state) = signed_genesis_fixture_for_state(
            &chain_id,
            &key,
            &validators,
            Vec::new(),
            1_000,
            None,
            configured,
        )
        .unwrap();
        let signed =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(&genesis)
                .unwrap()
                .sumeragi_context;
        assert_eq!(Hash::prehashed(signed.execution_policy_hash), execution);
        assert_eq!(Hash::prehashed(signed.nexus_amx_context_hash), nexus);
        assert_eq!(
            state.view().network_id(),
            &NetworkId::from_genesis_hash(genesis.hash())
        );
        startup::apply_genesis(&state, genesis, &account, ConsensusMode::Permissioned, None)
            .expect("the signed policies are the ones original execution derives");
        assert_eq!(state.view().height(), 1);
    }

    #[test]
    fn staged_genesis_policies_report_other_rejections_as_errors() {
        use iroha_data_model::isi::Register;
        use iroha_model_base::domain::DomainId;

        iroha_genesis::init_instruction_registry();
        let chain_id = ChainId::from("genesis-policy-fixture");
        let key = KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519);
        let account = AccountId::new(key.public_key().clone());
        let duplicate = DomainId::try_new("duplicate", "universal").unwrap();
        // The second registration fails, so original execution rejects the genesis output
        // before its policy commitments are compared.
        let genesis = super::super::signed_genesis_fixture(
            &chain_id,
            &key,
            &super::super::fixture_validators(),
            vec![
                Register::domain(Domain::new(duplicate.clone())).into(),
                Register::domain(Domain::new(duplicate)).into(),
            ],
            1_000,
            ConsensusMode::Permissioned,
            None,
        )
        .unwrap();
        let state = State::new_with_chain_and_network_id_for_testing(
            World::with(
                [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
                [Account::new(account.clone()).build(&account)],
                [],
            ),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain_id,
            NetworkId::from_genesis_hash(genesis.hash()),
        );
        let topology = Topology::new(startup::genesis_committee_peers(&genesis).unwrap());
        let error = staged_genesis_policies(
            genesis,
            &topology,
            &account,
            &state,
            ConsensusMode::Permissioned,
        )
        .unwrap_err();
        assert!(
            error.starts_with("original native genesis execution: "),
            "{error}"
        );
        assert!(!error.contains("policy mismatch"), "{error}");
        assert_eq!(state.view().height(), 0);
    }
}
