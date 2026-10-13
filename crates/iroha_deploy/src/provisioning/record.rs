//! Exact public parent terms retained independently of the resettable private generation.

use super::*;

impl Binding {
    pub(super) fn new(
        bootstrap: &AuthenticatedBootstrap,
        child: &Config,
        alias: String,
        account_alias: String,
        registration: PrivateDataspaceRegistration,
    ) -> Result<Self> {
        let release = bootstrap.release();
        let faucet = release.faucet.clone().ok_or(ProvisioningError::Invalid(
            "installed network has no signed developer funding allowance",
        ))?;
        let result = Self {
            parent_name: release.network_name.clone(),
            parent_generation: release.generation,
            parent_network_id: release.network_id,
            parent_chain_id: release.chain_id.clone(),
            parent_profile: release.account_chain_discriminant,
            parent_torii_root: release.torii_roots[0].clone(),
            alias,
            account_alias,
            owner: child.account.clone(),
            registration,
            faucet,
        };
        result.validate_parent(bootstrap)?;
        let identity = result.attachment_identity(bootstrap, 1)?;
        // This performs the same exact owner, loopback and credential checks as the relay,
        // without making an HTTP request or granting the placeholder generation any authority.
        LocalPrivateRootSource::new(
            child.clone(),
            &identity,
            Instant::now() + Duration::from_secs(1),
        )?;
        Ok(result)
    }

    pub(super) fn validate_parent(&self, bootstrap: &AuthenticatedBootstrap) -> Result<()> {
        self.owner_alias()?;
        let release = bootstrap.release();
        if self.parent_name != release.network_name
            || self.parent_generation != release.generation
            || self.parent_network_id != release.network_id
            || self.parent_chain_id != release.chain_id
            || self.parent_profile != release.account_chain_discriminant
            || !release.torii_roots.contains(&self.parent_torii_root)
            || release.faucet.as_ref() != Some(&self.faucet)
        {
            return Err(ProvisioningError::Invalid(
                "signed parent identity or retained funding terms changed",
            ));
        }
        self.attachment_identity(bootstrap, 1)?;
        Ok(())
    }

    pub(super) fn wallet_network(&self) -> Result<WalletNetwork> {
        WalletNetwork::new(
            self.parent_network_id,
            self.parent_chain_id
                .parse()
                .map_err(|_| ProvisioningError::Invalid("retained parent chain"))?,
            self.parent_torii_root
                .parse()
                .map_err(|_| ProvisioningError::Invalid("retained parent endpoint"))?,
            self.parent_profile,
        )
        .map_err(|_| ProvisioningError::Invalid("retained public wallet context"))
    }

    pub(super) fn validate_config(&self, config: &Config) -> Result<()> {
        if config.network_id != self.parent_network_id
            || config.chain.to_string() != self.parent_chain_id
            || config.account_chain_discriminant != self.parent_profile
            || config.account != self.owner
            || config.torii_api_url.as_str() != self.parent_torii_root
            || config.http_transport_policy != iroha::config::HttpTransportPolicy::Ordinary
            || config.api_token.is_some()
            || config.basic_auth.is_some()
        {
            return Err(ProvisioningError::Invalid(
                "parent wallet differs from retained public identity",
            ));
        }
        Ok(())
    }

    pub(super) fn attachment_identity(
        &self,
        bootstrap: &AuthenticatedBootstrap,
        generation: u64,
    ) -> Result<AttachmentIdentity> {
        Ok(AttachmentIdentity::new(
            bootstrap,
            self.alias.clone(),
            self.owner.clone(),
            generation,
            self.registration.clone(),
        )?)
    }

    pub(super) fn options(&self, deadline: Instant) -> BoundedTransactionOptions {
        BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(vec![], None),
            max_total_fees: [(
                self.faucet.asset_definition_id.clone(),
                self.faucet.max_operation_fee.clone(),
            )]
            .into_iter()
            .collect(),
            deadline,
        }
    }

    pub(super) fn faucet_request(&self) -> FaucetRequest {
        // The native faucet envelope contains only account registration and asset transfer.
        // Its issuer pays the Nexus component; an added IVM/PipelineGas component is forbidden.
        FaucetRequest {
            issuer: self.faucet.issuer.clone(),
            asset_definition: self.faucet.asset_definition_id.clone(),
            amount: self.faucet.amount.clone(),
            fee_payment: FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    self.faucet.asset_definition_id.clone(),
                    self.faucet.max_operation_fee.clone(),
                )],
                None,
            ),
        }
    }

    pub(super) fn validate_namespace(&self, request: &AliasSetupPlanRequestV1) -> Result<()> {
        let [intent, account_intent] = request.intents.as_slice() else {
            return Err(ProvisioningError::Invalid(
                "namespace request must contain the ordered dataspace and owner alias intents",
            ));
        };
        let AliasIntentV1::Dataspace(desired) = &intent.intent else {
            return Err(ProvisioningError::Invalid(
                "namespace request substituted another resource",
            ));
        };
        let AliasIntentV1::AccountAlias(account) = &account_intent.intent else {
            return Err(ProvisioningError::Invalid(
                "namespace request substituted the owner alias",
            ));
        };
        let rent = intent
            .quote_guard
            .max_amount
            .checked_add(&account_intent.quote_guard.max_amount)
            .map_err(|_| ProvisioningError::Invalid("namespace rent overflow"))?;
        if request.schema_version != AliasSetupPlanRequestV1::VERSION
            || desired.dataspace.canonical_name.as_ref() != self.alias
            || desired.dataspace.dataspace_id != self.registration.scope.dataspace_id()
            || desired.owner != self.owner
            || account.alias != self.owner_alias()?
            || account.target_account != self.owner
            || account.provision != iroha_data_model::alias_setup::AccountProvisionV1::Existing
            || account.role != iroha_data_model::alias_setup::AccountAliasRoleV1::Additional
            || intent.acquisition.term_years != 1
            || account_intent.acquisition.term_years != 1
            || intent.quote_guard.expected_payment_asset != self.faucet.asset_definition_id
            || account_intent.quote_guard.expected_payment_asset != self.faucet.asset_definition_id
            || rent > self.faucet.max_namespace_rent
            || intent.quote_guard.valid_until_ms == 0
            || account_intent.quote_guard.valid_until_ms != intent.quote_guard.valid_until_ms
        {
            return Err(ProvisioningError::Invalid(
                "namespace quote exceeds original owner, identity, term or spending allowance",
            ));
        }
        Ok(())
    }

    fn owner_alias(&self) -> Result<iroha_data_model::alias_setup::ResolvedAccountAliasV1> {
        iroha_wallet::namespace::resolve_private_owner_alias(&self.alias, &self.account_alias)
            .map_err(|_| ProvisioningError::Invalid("invalid retained private owner alias"))
    }

    pub(super) fn lease_generation(
        &self,
        record: &NameRecordV1,
        observed_at_ms: u64,
    ) -> Result<u64> {
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, &self.alias)
            .map_err(|_| ProvisioningError::Invalid("retained namespace selector"))?;
        if observed_at_ms == 0
            || record.selector != selector
            || record.name_hash != selector.name_hash()
            || record.owner != self.owner
            || record.ownership_generation == 0
            || !matches!(record.status, NameStatus::Active)
            || record.registered_at_ms > observed_at_ms
            || record.expires_at_ms <= observed_at_ms
        {
            return Err(ProvisioningError::Invalid(
                "namespace observation differs from the exact active owner lease",
            ));
        }
        if let Some(mapping) = record.metadata.get("sns.dataspace_id") {
            let id: u64 = norito::json::from_str(mapping.get())
                .map_err(|_| ProvisioningError::Invalid("invalid namespace numeric mapping"))?;
            if id != self.registration.scope.dataspace_id().as_u64() {
                return Err(ProvisioningError::Invalid(
                    "namespace observation substituted a physical parent mapping",
                ));
            }
        }
        // The caller authenticates this row at its independently selected current parent cut.
        // RegisterPrivateDataspace rechecks owner/generation in committed state before applying;
        // an attachment is confirmed only by the resulting native parent receipt.
        Ok(record.ownership_generation)
    }
}

impl Record {
    pub(super) fn validate(&self) -> Result<()> {
        self.binding.owner_alias()?;
        self.binding
            .registration
            .validate()
            .map_err(|_| ProvisioningError::Invalid("invalid retained compact registration"))?;
        if let Some(request) = &self.namespace {
            self.binding.validate_namespace(request)?;
        }
        if self.lease_generation == Some(0)
            || (self.namespace.is_some() && !self.faucet_observed)
            || (self.lease_generation.is_some() && self.namespace.is_none())
        {
            return Err(ProvisioningError::Invalid(
                "inconsistent retained provisioning progress",
            ));
        }
        Ok(())
    }
}
