//! Native wallet adapters; public orchestration retains the original intent before dispatch.

use super::*;

pub(super) struct LeaseRead<'a> {
    pub alias: &'a str,
    pub owner: &'a AccountId,
    pub native_schema: Hash,
    pub block: &'a VerifiedSumeragiBlock,
    pub deadline: Instant,
}

pub(super) trait ProvisioningOperations {
    fn fund(
        &self,
        config: &Config,
        request: &FaucetRequest,
        journal: &Path,
        deadline: Instant,
    ) -> Result<OperationStatus>;
    fn namespace_request(
        &self,
        config: &Config,
        alias: &str,
        account_alias: &str,
        deadline: Instant,
    ) -> Result<AliasSetupPlanRequestV1>;
    fn reserve(
        &self,
        config: &Config,
        request: &AliasSetupPlanRequestV1,
        options: &BoundedTransactionOptions,
        journal: &Path,
    ) -> Result<OperationStatus>;
    fn lease(&self, config: &Config, request: &LeaseRead<'_>) -> Result<VerifiedSnsLeaseV1>;
}

#[derive(Default)]
pub(super) struct NativeOperations {
    pub(super) cancellation: Option<Arc<AtomicBool>>,
}

impl NativeOperations {
    fn require_active(&self) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            return Err(ProvisioningError::Cancelled);
        }
        Ok(())
    }
}

impl ProvisioningOperations for NativeOperations {
    fn fund(
        &self,
        config: &Config,
        request: &FaucetRequest,
        journal: &Path,
        deadline: Instant,
    ) -> Result<OperationStatus> {
        let service = OnboardingService::new(config.clone())
            .and_then(|service| match &self.cancellation {
                Some(signal) => service.with_cancellation(Arc::clone(signal)),
                None => Ok(service),
            })
            .and_then(|service| service.with_deadline(deadline))
            .map_err(|_| ProvisioningError::Invalid("cannot construct exact faucet context"))?;
        if !path_exists(journal)? {
            service
                .prepare_faucet(
                    request,
                    &PreparationOptions {
                        timeout_secs: 60,
                        ..PreparationOptions::default()
                    },
                    journal,
                )
                .map_err(|_| ProvisioningError::FaucetPreparation)?;
        }
        Ok(service
            .submit_faucet_with_request(journal, request, 60)
            .map_err(|_| ProvisioningError::FaucetRecovery)?
            .status)
    }

    fn namespace_request(
        &self,
        config: &Config,
        alias: &str,
        account_alias: &str,
        deadline: Instant,
    ) -> Result<AliasSetupPlanRequestV1> {
        self.require_active()?;
        let request = prepare_private_dataspace_request(config, alias, account_alias, deadline)
            .map_err(|_| ProvisioningError::NamespaceQuote)?
            .request;
        self.require_active()?;
        Ok(request)
    }

    fn reserve(
        &self,
        config: &Config,
        request: &AliasSetupPlanRequestV1,
        options: &BoundedTransactionOptions,
        journal: &Path,
    ) -> Result<OperationStatus> {
        let service = AccountService::new(config.clone())
            .and_then(|service| match &self.cancellation {
                Some(signal) => service.with_cancellation(Arc::clone(signal)),
                None => Ok(service),
            })
            .and_then(|service| service.with_deadline(options.deadline))
            .map_err(|_| ProvisioningError::Invalid("cannot construct exact namespace context"))?;
        let preparation = service
            .inspect_alias_bounded_preparation(journal, request, options)
            .map_err(|_| ProvisioningError::NamespaceRecovery)?;
        let needs_prepare = match preparation.phase() {
            iroha_wallet::operations::NativePreparationPhase::Missing
            | iroha_wallet::operations::NativePreparationPhase::RequestOnly
            | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => true,
            iroha_wallet::operations::NativePreparationPhase::Signed => false,
            iroha_wallet::operations::NativePreparationPhase::Retired => {
                return Err(ProvisioningError::NamespaceRecovery);
            }
        };
        if needs_prepare {
            let report = service
                .prepare_alias_bounded(request, options, journal)
                .map_err(|_| ProvisioningError::NamespacePreparation)?;
            if report.status == OperationStatus::AlreadyPresent {
                return Ok(report.status);
            }
        }
        Ok(service
            .submit_alias_bounded(journal, request, options)
            .map_err(|_| ProvisioningError::NamespaceRecovery)?
            .status)
    }

    fn lease(&self, config: &Config, request: &LeaseRead<'_>) -> Result<VerifiedSnsLeaseV1> {
        let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
        if Instant::now() >= request.deadline {
            return Err(ProvisioningError::Deadline);
        }
        let client = Client::builder(config.clone())
            .build()
            .map_err(|_| ProvisioningError::Invalid("namespace observation client"))?
            .with_request_deadline(request.deadline);
        let lease = client
            .get_dataspace_lease(
                request.alias,
                request.owner,
                request.native_schema,
                request.block,
                unix_ms()?,
            )
            .map_err(|_| ProvisioningError::NamespaceObservation)?;
        if Instant::now() >= request.deadline {
            return Err(ProvisioningError::Deadline);
        }
        Ok(lease)
    }
}
