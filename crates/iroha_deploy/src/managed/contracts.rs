//! Managed contract reads and finite, durable native mutable calls on the selected root.

use super::*;
use iroha::blocking::Client;
use iroha_contract_deploy::{
    CompletedContract,
    call::{
        CallAuthorization, ContractCallDisposition, ContractCallReceipt, ContractCallRequest,
        ContractCallService, trusted_contract_intent,
    },
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    smart_contract::{ContractAddress, ContractAlias},
    transaction::FeePaymentIntent,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_primitives::numeric::Quantity;
use norito::json::Value;
use std::{collections::BTreeMap, num::NonZeroU64, path::Path};

/// Exact explicitly selected read-only entrypoint and canonical named JSON arguments.
#[derive(Clone, Debug)]
pub struct ManagedContractViewRequest {
    /// Public view selector from the verified deployed interface.
    pub entrypoint: String,
    /// Named JSON arguments; an empty object denotes a zero-parameter view.
    pub arguments: Value,
    /// Positive bounded read execution gas.
    pub gas_limit: NonZeroU64,
}

/// Authenticated selected-root view result, without any mutation or parent inclusion claim.
#[derive(Debug, JsonSerialize)]
pub struct ManagedContractView {
    /// Immutable selected ledger and root ownership.
    pub execution: ManagedDeploymentExecution,
    /// Exact retained deployed alias.
    pub contract_alias: ContractAlias,
    /// Exact retained deployed address.
    pub contract_address: ContractAddress,
    /// Exact verified artifact identity.
    pub code_hash: iroha_crypto::Hash,
    /// Requested view selector.
    pub entrypoint: String,
    /// Canonical SDK view response.
    pub result: Value,
}

/// Original finite authorization and optional explicit post-call value readback.
pub struct ManagedContractCallOptions {
    /// Positive aggregate maximum in the immutable generated root's native fee asset.
    pub max_fee: Quantity,
    /// Fixed original Unix millisecond deadline for all new signing in this operation.
    pub signing_deadline_unix_ms: u64,
    /// Signature-bound execution gas maximum.
    pub gas_limit: NonZeroU64,
    /// Persist the complete original operation without dispatching either stage.
    pub prepare_only: bool,
    /// Explicit view selector for checking the resulting value; never inferred from a mutation.
    pub readback: Option<ManagedContractViewRequest>,
}

/// Exact local call disposition and separate optional value/parent observations.
#[derive(Debug, JsonSerialize)]
pub struct ManagedContractCallReport {
    /// `prepared` means no dispatch; `applied` means exact state-resolved native completion.
    pub status: String,
    /// Original selected context.
    pub context: String,
    /// Immutable local execution root.
    pub execution: ManagedDeploymentExecution,
    /// Exact native Applied receipt, absent for a prepared-only operation.
    pub receipt: Option<ContractCallReceipt>,
    /// Original owner-private recovery journal.
    pub journal: PathBuf,
    /// Explicit view readback, independently observed after Applied.
    pub readback: Option<ManagedContractView>,
    /// Independent bounded readback failure; exact Applied remains successful.
    pub readback_failure: Option<String>,
    /// Separate historical parent observation; this is not proof of the call's parent inclusion.
    pub parent: Option<ManagedParentReport>,
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

fn journal_failure(journal: &Path, source: impl Into<color_eyre::eyre::Report>) -> Error {
    Error::ContractCall {
        journal: journal.to_owned(),
        source: source.into(),
    }
}

fn call_slot(root: &Path, selected: &ManagedContext, address: &ContractAddress) -> PathBuf {
    let identity = format!(
        "iroha.managed-contract-call-slot.v1\n{}\n{}\n{}",
        selected.network_id, selected.account_id, address
    );
    root.join("calls")
        .join(&selected.name)
        .join(blake3::hash(identity.as_bytes()).to_hex().as_str())
}

fn journal_id(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "call journal must name one canonical operation hash",
        ));
    }
    Ok(())
}

fn check_deployment(selected: &ManagedContext, contract: &CompletedContract) -> Result<()> {
    let receipt = contract.receipt();
    let _profile = ChainDiscriminantGuard::enter(receipt.chain_discriminant);
    if receipt.network_id.to_string() != selected.network_id
        || receipt.chain_id != selected.chain_id
        || receipt.authority.to_string() != selected.account_id
        || receipt.dataspace_id.as_u64() != selected.dataspace_id
        || receipt.contract_alias.dataspace_segment() != selected.dataspace_alias
        || receipt.contract_address.dataspace_id().ok() != Some(receipt.dataspace_id)
    {
        return Err(invalid(
            "contract deployment differs from the selected managed root",
        ));
    }
    Ok(())
}

fn view_exact(
    config: &iroha::config::Config,
    execution: ManagedDeploymentExecution,
    alias: &ContractAlias,
    artifact: &[u8],
    address: &ContractAddress,
    request: ManagedContractViewRequest,
) -> Result<ManagedContractView> {
    let (intent, payload) = trusted_contract_intent(
        artifact,
        address.clone(),
        &request.entrypoint,
        request.arguments,
        true,
    )
    .map_err(invalid)?;
    let result = Client::new(config.clone())
        .map_err(invalid)?
        .client()
        .post_contract_view_json(
            &config.account,
            Some(address),
            None,
            &request.entrypoint,
            payload.as_ref(),
            request.gas_limit.get(),
        )
        .map_err(invalid)?;
    validate_view_response(
        &result,
        address,
        intent.invocation.expected_code_hash,
        &request.entrypoint,
    )?;
    Ok(ManagedContractView {
        execution,
        contract_alias: alias.clone(),
        contract_address: address.clone(),
        code_hash: intent.invocation.expected_code_hash,
        entrypoint: request.entrypoint,
        result,
    })
}

fn validate_view_response(
    result: &Value,
    address: &ContractAddress,
    code_hash: iroha_crypto::Hash,
    entrypoint: &str,
) -> Result<()> {
    if result.get("ok").and_then(Value::as_bool) != Some(true)
        || result.get("contract_address")
            != Some(&norito::json::to_value(address).map_err(invalid)?)
        || result.get("code_hash_hex").and_then(Value::as_str)
            != Some(hex::encode(code_hash.as_ref()).as_str())
        || result.get("entrypoint").and_then(Value::as_str) != Some(entrypoint)
    {
        return Err(invalid(
            "contract view response differs from the verified local deployment and selector",
        ));
    }
    Ok(())
}

impl ManagedStore {
    /// Query an exact view using the native current-completed deployment's retained artifact.
    ///
    /// # Errors
    /// Rejects changed selection, wrong root, wrong-kind selector, malformed arguments or SDK reads.
    pub fn view_contract(
        &self,
        selected: &ManagedContext,
        contract: &CompletedContract,
        request: ManagedContractViewRequest,
    ) -> Result<ManagedContractView> {
        let target = self.capture_deployment(selected)?;
        check_deployment(selected, contract)?;
        let config = selected.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let result = view_exact(
            &config,
            target.execution,
            &contract.receipt().contract_alias,
            contract.artifact(),
            &contract.receipt().contract_address,
            request,
        )?;
        target.revalidate_generation(self)?;
        Ok(result)
    }

    /// Prepare and optionally execute one bounded mutable call through the native service.
    ///
    /// The same address slot refuses fresh work while an original operation remains ambiguous.
    /// Fixed deadline and aggregate maxima are signed and published before any dispatch.
    ///
    /// # Errors
    /// Rejects custody, changed deployment, unbounded terms, pending prior work, or native errors.
    pub fn call_contract(
        &self,
        selected: &ManagedContext,
        contract: &CompletedContract,
        entrypoint: &str,
        arguments: Value,
        options: ManagedContractCallOptions,
    ) -> Result<ManagedContractCallReport> {
        let target = self.capture_deployment(selected)?;
        check_deployment(selected, contract)?;
        if options.max_fee.is_zero() {
            return Err(invalid("--max-fee must be positive"));
        }
        let config = selected.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let service = ContractCallService::new(config.clone()).map_err(invalid)?;
        let slot = call_slot(self.root(), selected, &contract.receipt().contract_address);
        let root = PrivateDirectory::open(self.root())?
            .ensure_child("calls")?
            .ensure_child(&selected.name)?;
        let name = slot
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid call slot"))?;
        let directory = root.ensure_child(name)?;
        let lock = directory.open_lock("call.lock")?;
        lock.try_lock()
            .map_err(|_| Error::Busy(selected.name.clone()))?;
        match directory.read_optional("active-journal", 64)? {
            Some(bytes) => {
                let id = std::str::from_utf8(&bytes).map_err(invalid)?;
                journal_id(id)?;
                if matches!(
                    service
                        .inspect(&directory.path().join(id))
                        .map_err(invalid)?,
                    ContractCallDisposition::Pending
                ) {
                    return Err(invalid(format!(
                        "an original call is unresolved; resume its exact journal: {}",
                        directory.path().join(id).display()
                    )));
                }
            }
            None => {}
        }
        let (intent, payload) = trusted_contract_intent(
            contract.artifact(),
            contract.receipt().contract_address.clone(),
            entrypoint,
            arguments,
            false,
        )
        .map_err(invalid)?;
        if let Some(request) = &options.readback {
            iroha_contract_deploy::call::admit_arguments(&request.arguments).map_err(invalid)?;
            trusted_contract_intent(
                contract.artifact(),
                contract.receipt().contract_address.clone(),
                &request.entrypoint,
                request.arguments.clone(),
                true,
            )
            .map_err(invalid)?;
        }
        let prepared = service
            .prepare(ContractCallRequest {
                artifact: contract.artifact().to_vec(),
                alias: contract.receipt().contract_alias.clone(),
                payload,
                intent,
                fee_payment: FeePaymentIntent::authority(Vec::new(), Some(options.gas_limit)),
                authorization: CallAuthorization {
                    signing_deadline_unix_ms: options.signing_deadline_unix_ms,
                    max_total_fees: BTreeMap::from([(target.fee_asset()?, options.max_fee)]),
                },
            })
            .map_err(invalid)?;
        target.revalidate_generation(self)?;
        let id = prepared.operation_id().map_err(invalid)?;
        journal_id(&id)?;
        let journal = directory.path().join(&id);
        service
            .persist(&prepared, &journal)
            .map_err(|error| journal_failure(&journal, error))?;
        directory
            .write_atomic("active-journal", id.as_bytes(), PublishMode::Replace)
            .map_err(|error| journal_failure(&journal, error))?;
        if options.prepare_only {
            return Ok(ManagedContractCallReport {
                status: "prepared".into(),
                context: selected.name.clone(),
                execution: target.execution,
                receipt: None,
                journal,
                readback: None,
                readback_failure: None,
                parent: None,
            });
        }
        drop(lock);
        self.resume_contract_call(selected, &journal, options.readback)
    }

    /// Resume the exact original call without rebuilding or renewing signed terms.
    ///
    /// # Errors
    /// Rejects an escaped journal, replaced root, substituted signed terms or native failure.
    pub fn resume_contract_call(
        &self,
        selected: &ManagedContext,
        journal: &Path,
        readback: Option<ManagedContractViewRequest>,
    ) -> Result<ManagedContractCallReport> {
        let target = self.capture_deployment(selected)?;
        let config = selected.load_client_config()?;
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        let service = ContractCallService::new(config.clone()).map_err(invalid)?;
        let prepared = service.retained_call(journal).map_err(invalid)?;
        if prepared
            .contract_address()
            .dataspace_id()
            .map_err(invalid)?
            .as_u64()
            != selected.dataspace_id
            || prepared.contract_alias().dataspace_segment() != selected.dataspace_alias
        {
            return Err(invalid("call journal differs from the selected dataspace"));
        }
        let id = prepared.operation_id().map_err(invalid)?;
        let slot = call_slot(self.root(), selected, prepared.contract_address());
        if journal != slot.join(&id) {
            return Err(invalid(
                "call journal is outside its original managed address slot",
            ));
        }
        let directory = PrivateDirectory::open(&slot)?;
        let lock = directory.open_read("call.lock")?;
        lock.try_lock()
            .map_err(|_| Error::Busy(selected.name.clone()))?;
        directory.revalidate()?;
        let receipt = service
            .resume(journal)
            .map_err(|error| journal_failure(journal, error))?;
        let observation = readback.map(|request| {
            view_exact(
                &config,
                target.execution,
                prepared.contract_alias(),
                &prepared.artifact().map_err(invalid)?,
                prepared.contract_address(),
                request,
            )
        });
        let (readback, readback_failure) = match observation {
            Some(Ok(view)) => (Some(view), None),
            Some(Err(_)) => (
                None,
                Some("explicit selected-root view readback is unavailable".into()),
            ),
            None => (None, None),
        };
        Ok(ManagedContractCallReport {
            status: "applied".into(),
            context: selected.name.clone(),
            execution: target.execution,
            receipt: Some(receipt),
            journal: journal.into(),
            readback,
            readback_failure,
            parent: target.parent_report(self),
        })
    }
}

#[cfg(test)]
mod tests;
