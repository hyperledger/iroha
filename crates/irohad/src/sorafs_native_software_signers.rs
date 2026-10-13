//! Daemon-owned, role-separated software signing for the native SoraFS forwarders.
//!
//! Credentials are resolved only after State construction. The private adapter has no queue or
//! outbox capability: the existing native forwarders retain permission/operation eligibility
//! checks before claiming work. Every signature additionally requires exact current durable
//! same-State finality, a live account, and the configured network, role and authority.

use crate::{IrohaRuntimeDeps, runtime_credential::load_bound_software_key_v1};
use iroha_config::parameters::actual::{
    SorafsNativeTransactionSignerBinding as ConfiguredBinding,
    SorafsNativeTransactionSignerBindings,
};
use iroha_core::{
    query::signer_finality::verify_signer_finality_v1,
    state::{State, WorldReadOnly},
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    account::AccountId,
    transaction::{SignedTransaction, TransactionBuilder, TransactionPayload},
};
use iroha_torii::{
    SorafsNativeTransactionSignerBindingV1 as Binding,
    SorafsNativeTransactionSignerProbeErrorV1 as ProbeError,
    SorafsNativeTransactionSignerProviderV1,
    SorafsNativeTransactionSignerQualificationV1 as Qualification,
    SorafsNativeTransactionSignerRoleV1 as Role,
};
use mv::storage::StorageReadOnly;
use std::sync::Arc;

struct NativeSoftwareSigner {
    binding: Binding,
    state: Arc<State>,
    key: KeyPair,
}

impl NativeSoftwareSigner {
    fn load(
        config: &ConfiguredBinding,
        role: Role,
        state: Arc<State>,
    ) -> Result<Self, &'static str> {
        if !config.handle.starts_with("software://")
            || config.public_key.try_algorithm().ok() != Some(config.algorithm)
        {
            return Err("native signer public binding is invalid");
        }
        let binding = Binding::try_new(
            role,
            config.handle.clone(),
            config.authority.clone(),
            config.public_key.clone(),
            Qualification::new(config.revision, config.policy_digest),
        )
        .map_err(|_| "native signer public binding is invalid")?;
        let path = config
            .software_credential
            .as_ref()
            .ok_or("native signer credential is absent")?;
        let key = load_bound_software_key_v1(path, binding.public_key())
            .map_err(|_| "native signer credential is unavailable, unsafe or mismatched")?;
        Ok(Self {
            binding,
            state,
            key,
        })
    }

    fn sign_exact(
        &self,
        role: Role,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SignError> {
        if payload.authority() != self.binding.authority() {
            return Err(SignError::Authority);
        }
        if role != self.binding.role()
            || payload.network_id() != Some(self.state.network_id_ref())
            || !iroha_torii::sorafs::native_transaction_signer::sorafs_native_transaction_payload_matches_role_v1(role, &payload)
        {
            return Err(SignError::Refused);
        }
        let view = self.state.view();
        let height = u64::try_from(view.height()).map_err(|_| SignError::Unavailable)?;
        let hash = view.latest_block_hash().ok_or(SignError::Unavailable)?;
        verify_signer_finality_v1(&view, height, *hash.as_ref())
            .map_err(|_| SignError::Unavailable)?;
        if view
            .world()
            .accounts()
            .get(self.binding.authority())
            .is_none()
        {
            return Err(SignError::Refused);
        }
        TransactionBuilder::from_payload(payload)
            .map_err(|_| SignError::Refused)?
            .try_sign(self.key.private_key())
            .map_err(|_| SignError::Unavailable)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SignError {
    Authority,
    Refused,
    Unavailable,
}

impl SorafsNativeTransactionSignerProviderV1 for NativeSoftwareSigner {
    fn role(&self) -> Role {
        self.binding.role()
    }
    fn handle(&self) -> &str {
        self.binding.handle()
    }
    fn authority(&self) -> AccountId {
        self.binding.authority().clone()
    }
    fn public_key(&self) -> Result<PublicKey, ProbeError> {
        Ok(self.key.public_key().clone())
    }
    fn qualification(&self) -> Result<Qualification, ProbeError> {
        Ok(self.binding.qualification())
    }
}

macro_rules! implement_role {
    ($trait:ident, $error:ident, $role:ident) => {
        impl iroha_torii::$trait for NativeSoftwareSigner {
            fn sign(
                &self,
                payload: TransactionPayload,
            ) -> Result<SignedTransaction, iroha_torii::$error> {
                self.sign_exact(Role::$role, payload)
                    .map_err(|error| match error {
                        SignError::Authority => iroha_torii::$error::InputAuthorityMismatch,
                        SignError::Refused => iroha_torii::$error::Refused,
                        SignError::Unavailable => iroha_torii::$error::Unavailable,
                    })
            }
        }
    };
}
implement_role!(
    SoraFsProofOutcomeTransactionSigner,
    SoraFsProofOutcomeSigningError,
    ProofOutcome
);
implement_role!(
    SoraFsRepairTransactionSigner,
    SoraFsRepairTransactionSigningError,
    Repair
);
implement_role!(
    SoraFsReserveTransactionSigner,
    SoraFsReserveTransactionSigningError,
    Reserve
);
implement_role!(
    SoraFsOrderbookTransactionSigner,
    SoraFsOrderbookTransactionSigningError,
    Orderbook
);

/// Install explicit local custody, preserving qualified facade checks and external-role isolation.
/// Keys are never inferred from the validator, account identity or another role.
pub fn install_native_software_signers(
    configured: &SorafsNativeTransactionSignerBindings,
    state: &Arc<State>,
    validator_key: &PublicKey,
    dependencies: &mut IrohaRuntimeDeps,
) -> Result<(), &'static str> {
    let bindings = [
        configured.proof_outcome.as_ref(),
        configured.repair.as_ref(),
        configured.reserve.as_ref(),
        configured.orderbook.as_ref(),
    ];
    for (index, binding) in bindings
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.map(|b| (i, b)))
    {
        if binding.software_credential.is_some() && &binding.public_key == validator_key {
            return Err("native SoraFS signer must not use the validator key");
        }
        if bindings[..index].iter().flatten().any(|other| {
            other.public_key == binding.public_key
                || other.authority == binding.authority
                || other.handle == binding.handle
        }) {
            return Err("native SoraFS roles require distinct keys, authorities and handles");
        }
    }
    macro_rules! install {
        ($field:ident, $dependency:ident, $role:ident, $qualify:ident) => {
            if let Some(config) = configured
                .$field
                .as_ref()
                .filter(|config| config.software_credential.is_some())
            {
                if dependencies.$dependency.is_some() {
                    return Err(
                        "native SoraFS software custody conflicts with an external adapter",
                    );
                }
                let signer = NativeSoftwareSigner::load(config, Role::$role, Arc::clone(state))?;
                let binding = signer.binding.clone();
                dependencies.$dependency = Some(
                    iroha_torii::$qualify(*state.network_id_ref(), binding, Arc::new(signer))
                        .map_err(|_| "native SoraFS software signer qualification failed")?,
                );
            }
        };
    }
    install!(
        proof_outcome,
        sorafs_proof_outcome_signer,
        ProofOutcome,
        qualify_sorafs_proof_outcome_transaction_signer_v1
    );
    install!(
        repair,
        sorafs_repair_transaction_signer,
        Repair,
        qualify_sorafs_repair_transaction_signer_v1
    );
    install!(
        reserve,
        sorafs_reserve_transaction_signer,
        Reserve,
        qualify_sorafs_reserve_transaction_signer_v1
    );
    install!(
        orderbook,
        sorafs_orderbook_transaction_signer,
        Orderbook,
        qualify_sorafs_orderbook_transaction_signer_v1
    );
    Ok(())
}

#[cfg(test)]
mod tests;
