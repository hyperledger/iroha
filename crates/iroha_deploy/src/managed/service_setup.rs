//! Purpose-closed managed gateway, recorder and provider-ingest setup through the original wallet journal.
//!
//! Successful exact execution is historical evidence only. Native identical-policy replay can
//! retain an earlier policy origin. Fresh daemon qualification, reconciliation and serving remain
//! separate; this owner neither proves current policy nor enables a service.

use super::{
    PreparedLocalnet, Result,
    native_operation::{
        ManagedTransactionFinality, Terms, checkpoint_bytes, encode, invalid, now_ms,
        require_deadline, require_empty,
    },
    service_authority::{CheckpointImportScope, NetworkPurpose, ProviderPurpose, ServiceAuthority},
};
use crate::localnet::service_authorities::StreamTokenAuthorityRole;
use iroha_data_model::{
    sorafs::{
        capacity::ProviderId,
        pin_registry::ProviderIngestCompletionAuthorityV1,
        reputation::{ReputationJournalAuthorityPolicyV1, derive_stream_token_gateway_id_v1},
        stream_token_gateway::native::StreamTokenGatewayPolicyV1,
    },
    transaction::SignedTransaction,
};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, InitialGatewaySetupRequest,
    InitialGatewaySetupSelection, InitialProviderIngestAuthorityRequest,
    InitialReputationPolicyRequest, InitialReputationPolicySelection, OperationReport,
    OperationStatus,
};
use std::{path::Path, time::Instant};

#[path = "service_setup/journal.rs"]
mod journal;
use super::{
    native_operation::{
        Fees,
        attempts::{self, Observation, Purpose, Selected},
    },
    service_bootstrap::authorization::BootstrapChildAuthorization,
};
use journal::{Intent, Original};

/// Wallet observation and independently authenticated execution of the exact original envelope.
/// Neither field proves current policy, first-created origin, funding or daemon readiness.
#[derive(Clone, Copy, Debug)]
pub struct ManagedInitialServiceSetupProgress {
    /// Replaceable wallet/node observation; `Applied` alone is not authenticated inclusion.
    pub transaction_status: OperationStatus,
    /// Exact successful carrier, retained even when current peers are unavailable.
    pub finalized: Option<ManagedTransactionFinality>,
}

/// Initial native gateway Configure followed by the exact generated Operate and Check grants.
pub struct ManagedInitialGatewaySetup {
    inner: Setup,
}
impl ManagedInitialGatewaySetup {
    /// Authenticate the complete original profile and exclusively hold its gateway setup intent.
    /// # Errors
    /// Rejects changed profile/genesis/custody or a concurrent owner. Performs no HTTP or signing.
    pub fn open(prepared: &PreparedLocalnet, provider: ProviderId) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_provider(prepared, provider, Kind::Gateway)?,
        })
    }

    /// Admit the fixed setup purpose from immutable original intent with its own native lock.
    /// Active decode admission and owned parents retain the full standalone producer.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_provider_from_original(parent, provider, Kind::Gateway)?,
        })
    }
    /// Retain a complete revision-one policy and bounded authorization, then advance it.
    /// # Errors
    /// Rejects substituted generated roles, changed retained intent, unavailable original
    /// finality, or unsafe journal custody. Native Configure/Grant owns CAS and permissions.
    pub fn configure(
        &mut self,
        policy: &StreamTokenGatewayPolicyV1,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::gateway(&self.inner.authority, policy)?;
        self.inner.retain(intent, deadline_unix_ms, options)
    }
    /// Advance only the original bounded wallet envelope, with at most one dispatch.
    /// # Errors
    /// Rejects changed original/journal/evidence. A new I/O deadline never renews authorization.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::SubmitOriginal)
    }
    /// Observe the original without preparing, signing, quoting or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or corrupt evidence; retained carrier survives outage.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::ObserveOnly)
    }
    /// Recover only the parent's complete retained initial policy and original authorization.
    pub(super) fn recover_selected_if_present(
        &mut self,
        policy: &StreamTokenGatewayPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::gateway(&self.inner.authority, policy)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        policy: &StreamTokenGatewayPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::gateway(&self.inner.authority, policy)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveLocal)
    }
    pub(super) fn advance_selected(
        &mut self,
        policy: &StreamTokenGatewayPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::gateway(&self.inner.authority, policy)?;
        self.inner.advance_selected(intent, authorization, deadline)
    }
    // The real standalone producer remains the test baseline for physical admission parity.
    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
    ) -> Result<Option<Self>> {
        Setup::open_provider_existing(prepared, provider, Kind::Gateway)
            .map(|inner| inner.map(|inner| Self { inner }))
    }

    /// Retain the fixed setup purpose from the immutable original read-only parent profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Setup::open_provider_existing_from_original(parent, provider, Kind::Gateway, scope)
            .map(|inner| inner.map(|inner| Self { inner }))
    }
}

/// Initial sole native recorder Set for the exact generated recorder and all three selected gateways.
pub struct ManagedInitialReputationPolicy {
    inner: Setup,
}
impl ManagedInitialReputationPolicy {
    /// Authenticate the complete original profile and exclusively hold its recorder intent.
    /// # Errors
    /// Rejects changed profile/genesis/custody or a concurrent owner. Performs no HTTP or signing.
    pub fn open(prepared: &PreparedLocalnet) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_reputation(prepared)?,
        })
    }

    /// Admit the fixed network recorder purpose from immutable original intent.
    /// This grants no signing authority and retains the child's independent native lock.
    pub(super) fn open_from_original(parent: &ServiceAuthority) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_reputation_from_original(parent)?,
        })
    }
    /// Retain a full revision-one recorder policy and its complete original gateway list.
    /// All three policy recorder roles bind to the generated ReputationRecorder account.
    /// # Errors
    /// Rejects substituted roles/gateway, changed retained intent, unavailable original finality
    /// or unsafe journal custody. Native Set owns authorization and identical-policy replay.
    pub fn set_initial(
        &mut self,
        compliance_gateway_ids: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::reputation(&self.inner.authority, compliance_gateway_ids, policy)?;
        self.inner.retain(intent, deadline_unix_ms, options)
    }
    /// Advance only the original bounded wallet envelope, with at most one dispatch.
    /// # Errors
    /// Rejects changed original/journal/evidence. A new I/O deadline never renews authorization.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::SubmitOriginal)
    }
    /// Observe the original without preparing, signing, quoting or dispatching.
    /// # Errors
    /// Rejects missing/changed originals or corrupt evidence; retained carrier survives outage.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::ObserveOnly)
    }
    /// Recover only the parent's complete retained initial policy and original authorization.
    pub(super) fn recover_selected_if_present(
        &mut self,
        compliance_gateway_ids: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::reputation(&self.inner.authority, compliance_gateway_ids, policy)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        compliance_gateway_ids: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::reputation(&self.inner.authority, compliance_gateway_ids, policy)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveLocal)
    }
    pub(super) fn advance_selected(
        &mut self,
        compliance_gateway_ids: &[String],
        policy: &ReputationJournalAuthorityPolicyV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::reputation(&self.inner.authority, compliance_gateway_ids, policy)?;
        self.inner.advance_selected(intent, authorization, deadline)
    }
    // The real standalone producer remains the test baseline for physical admission parity.
    #[cfg(test)]
    pub(super) fn open_existing(prepared: &PreparedLocalnet) -> Result<Option<Self>> {
        Setup::open_reputation_existing(prepared).map(|inner| inner.map(|inner| Self { inner }))
    }

    /// Retain the fixed setup purpose from the immutable original read-only parent profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Setup::open_reputation_existing_from_original(parent, scope)
            .map(|inner| inner.map(|inner| Self { inner }))
    }
}

/// Initial owner-signed native authority Set for the exact generated dedicated completion role.
/// Historical execution does not prove current authority, source eligibility or serving.
pub struct ManagedInitialProviderIngestAuthority {
    inner: Setup,
}
impl ManagedInitialProviderIngestAuthority {
    /// Authenticate the complete original generated profile and exclusively retain its setup.
    /// # Errors
    /// Rejects changed original profile or concurrent custody, without HTTP or signing.
    pub fn open(prepared: &PreparedLocalnet, provider: ProviderId) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_provider(prepared, provider, Kind::ProviderIngest)?,
        })
    }

    /// Admit the fixed setup purpose from immutable original intent with its own native lock.
    /// Active decode admission and owned parents retain the full standalone producer.
    pub(super) fn open_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
    ) -> Result<Self> {
        Ok(Self {
            inner: Setup::open_provider_from_original(parent, provider, Kind::ProviderIngest)?,
        })
    }
    /// Retain one exact initial authority and finite fee/UTC authorization, then advance it.
    /// # Errors
    /// Rejects substituted generated roles, original intent, native finality or private custody.
    pub fn set_initial(
        &mut self,
        authority: &ProviderIngestCompletionAuthorityV1,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::provider_ingest(&self.inner.authority, authority)?;
        self.inner.retain(intent, deadline_unix_ms, options)
    }
    /// Advance only the original wallet envelope with at most one dispatch.
    /// # Errors
    /// Rejects changed original/evidence; fresh I/O time never renews authorization.
    pub fn advance(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::SubmitOriginal)
    }
    /// Observe the original without quoting, signing or dispatching.
    /// # Errors
    /// Rejects missing or changed originals; retained exact finality survives peer outage.
    pub fn recover(&mut self, deadline: Instant) -> Result<ManagedInitialServiceSetupProgress> {
        self.inner.advance(deadline, Mode::ObserveOnly)
    }
    pub(super) fn recover_selected_if_present(
        &mut self,
        authority: &ProviderIngestCompletionAuthorityV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::provider_ingest(&self.inner.authority, authority)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveOnly)
    }
    pub(super) fn recover_local_selected_if_present(
        &mut self,
        authority: &ProviderIngestCompletionAuthorityV1,
        fees: &Fees,
        deadline: Instant,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        let intent = Intent::provider_ingest(&self.inner.authority, authority)?;
        self.inner
            .recover_selected_if_present(&intent, fees, deadline, Mode::ObserveLocal)
    }
    pub(super) fn advance_selected(
        &mut self,
        authority: &ProviderIngestCompletionAuthorityV1,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let intent = Intent::provider_ingest(&self.inner.authority, authority)?;
        self.inner.advance_selected(intent, authorization, deadline)
    }
    // The real standalone producer remains the test baseline for physical admission parity.
    #[cfg(test)]
    pub(super) fn open_existing(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
    ) -> Result<Option<Self>> {
        Setup::open_provider_existing(prepared, provider, Kind::ProviderIngest)
            .map(|inner| inner.map(|inner| Self { inner }))
    }

    /// Retain the fixed setup purpose from the immutable original read-only parent profile.
    /// Optional lexical import work supplies no source, transaction or current-state verdict.
    pub(super) fn open_existing_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        Setup::open_provider_existing_from_original(parent, provider, Kind::ProviderIngest, scope)
            .map(|inner| inner.map(|inner| Self { inner }))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    ProviderIngest,
    Gateway,
    Reputation,
}
#[derive(Clone, Copy)]
enum Mode<'a> {
    ObserveLocal,
    SubmitOriginal,
    SubmitAuthorized(&'a BootstrapChildAuthorization<'a>),
    ObserveOnly,
}
impl Mode<'_> {
    fn bind_account(self, account: AccountService) -> Result<AccountService> {
        match self {
            Self::SubmitAuthorized(authorization) => authorization.bind_account(account),
            _ => Ok(account),
        }
    }

    fn submits(self) -> bool {
        matches!(self, Self::SubmitOriginal | Self::SubmitAuthorized(_))
    }
    fn check_dispatch(self, purpose: Purpose, deadline: Instant) -> Result<()> {
        if let Self::SubmitAuthorized(authorization) = self {
            authorization.check(purpose, deadline)?;
        }
        Ok(())
    }
}
struct Setup {
    authority: ServiceAuthority,
    kind: Kind,
}
impl Setup {
    fn open_provider(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        kind: Kind,
    ) -> Result<Self> {
        let purpose = match kind {
            Kind::ProviderIngest => ProviderPurpose::InitialProviderIngestAuthority,
            Kind::Gateway => ProviderPurpose::InitialGatewaySetup,
            Kind::Reputation => return Err(invalid("recorder setup requires network scope")),
        };
        Ok(Self {
            authority: ServiceAuthority::open_provider(prepared, provider, purpose)?,
            kind,
        })
    }
    fn open_reputation(prepared: &PreparedLocalnet) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network(
                prepared,
                NetworkPurpose::InitialReputationPolicy,
            )?,
            kind: Kind::Reputation,
        })
    }
    fn open_provider_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
        kind: Kind,
    ) -> Result<Self> {
        let purpose = Self::provider_purpose(kind)?;
        Ok(Self {
            authority: ServiceAuthority::open_provider_from_original(parent, provider, purpose)?,
            kind,
        })
    }
    fn open_reputation_from_original(parent: &ServiceAuthority) -> Result<Self> {
        Ok(Self {
            authority: ServiceAuthority::open_network_from_original(
                parent,
                NetworkPurpose::InitialReputationPolicy,
            )?,
            kind: Kind::Reputation,
        })
    }
    // Used only by the standalone constructor baseline above.
    #[cfg(test)]
    fn open_provider_existing(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        kind: Kind,
    ) -> Result<Option<Self>> {
        let purpose = Self::provider_purpose(kind)?;
        ServiceAuthority::open_provider_existing(prepared, provider, purpose)
            .map(|authority| authority.map(|authority| Self { authority, kind }))
    }
    fn open_provider_existing_from_original(
        parent: &ServiceAuthority,
        provider: ProviderId,
        kind: Kind,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        let purpose = Self::provider_purpose(kind)?;
        ServiceAuthority::open_provider_existing_from_original(parent, provider, purpose, scope)
            .map(|authority| authority.map(|authority| Self { authority, kind }))
    }
    fn provider_purpose(kind: Kind) -> Result<ProviderPurpose> {
        Ok(match kind {
            Kind::ProviderIngest => ProviderPurpose::InitialProviderIngestAuthority,
            Kind::Gateway => ProviderPurpose::InitialGatewaySetup,
            Kind::Reputation => return Err(invalid("recorder setup requires network scope")),
        })
    }
    // Used only by the standalone constructor baseline above.
    #[cfg(test)]
    fn open_reputation_existing(prepared: &PreparedLocalnet) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing(prepared, NetworkPurpose::InitialReputationPolicy)
            .map(|authority| {
                authority.map(|authority| Self {
                    authority,
                    kind: Kind::Reputation,
                })
            })
    }
    fn open_reputation_existing_from_original(
        parent: &ServiceAuthority,
        scope: Option<&CheckpointImportScope>,
    ) -> Result<Option<Self>> {
        ServiceAuthority::open_network_existing_from_original(
            parent,
            NetworkPurpose::InitialReputationPolicy,
            scope,
        )
        .map(|authority| {
            authority.map(|authority| Self {
                authority,
                kind: Kind::Reputation,
            })
        })
    }
    fn purpose(&self) -> Result<Purpose> {
        Ok(match self.kind {
            Kind::ProviderIngest => Purpose::ProviderIngest(self.authority.provider_id()?),
            Kind::Gateway => Purpose::Gateway(self.authority.provider_id()?),
            Kind::Reputation => Purpose::Reputation,
        })
    }
    fn retain(
        &mut self,
        intent: Intent,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        self.authority.validate_profile()?;
        self.validate_intent(&intent)?;
        let directory = self.authority.directory.ensure_child("setup")?;
        let original = self.select_intent(&directory, intent, options.deadline)?;
        journal::explicit(
            &directory,
            self.purpose()?,
            &original,
            utc,
            options,
            &self.wallet()?,
        )?;
        self.advance(options.deadline, Mode::SubmitOriginal)
    }
    fn select_intent(
        &mut self,
        directory: &PrivateDirectory,
        intent: Intent,
        deadline: Instant,
    ) -> Result<Original> {
        if let Some(original) = journal::read_intent(directory)? {
            original.matches_intent(&intent)?;
            self.validate_original(&original)?;
            return Ok(original);
        }
        require_empty(directory)?;
        let verifier = self.authority.observe_finality(deadline)?;
        let original = Original {
            intent,
            checkpoint: checkpoint_bytes(&verifier)?,
        };
        self.validate_original(&original)?;
        journal::publish_intent(directory, &original)?;
        Ok(original)
    }
    fn advance_selected(
        &mut self,
        intent: Intent,
        authorization: &BootstrapChildAuthorization<'_>,
        deadline: Instant,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        let purpose = self.purpose()?;
        let deadline = authorization.validate(&self.authority, purpose, deadline)?;
        let expected = match self.kind {
            Kind::ProviderIngest => Intent::provider_ingest(
                &self.authority,
                &authorization
                    .policies()
                    .provider(self.authority.provider_id()?)?
                    .provider_ingest,
            )?,
            Kind::Gateway => Intent::gateway(
                &self.authority,
                &authorization
                    .policies()
                    .provider(self.authority.provider_id()?)?
                    .gateway,
            )?,
            Kind::Reputation => Intent::reputation(
                &self.authority,
                &authorization.policies().gateway_labels(),
                &authorization.policies().network.reputation,
            )?,
        };
        self.validate_intent(&intent)?;
        if encode(&intent, journal::MAX_INTENT_BYTES)?
            != encode(&expected, journal::MAX_INTENT_BYTES)?
        {
            return Err(invalid(
                "service setup differs from original authorized policies",
            ));
        }
        let directory = self.authority.directory.ensure_child("setup")?;
        let original = self.select_intent(&directory, intent, deadline)?;
        let account = self.wallet()?;
        let account = authorization.bind_account(account)?;
        attempts::generated(
            &directory,
            purpose,
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
            authorization,
            deadline,
            None,
            |attempt| {
                original
                    .request(attempt.terms(), deadline)
                    .inspect_in_parent(&account, attempt.directory())
            },
            |attempt| {
                original
                    .request(attempt.terms(), deadline)
                    .retire(&account, &attempt.wallet_path())
            },
            |attempt, _, deadline| {
                original
                    .request(attempt.terms(), deadline)
                    .retain(&account, &attempt.wallet_path())
            },
            |_, deadline| {
                self.authority.observe_finality(deadline)?;
                Ok(Observation::ordinary())
            },
            |_| Ok(true),
        )?;
        authorization.validate(&self.authority, purpose, deadline)?;
        self.advance(deadline, Mode::SubmitAuthorized(authorization))
    }
    fn recover_selected_if_present(
        &mut self,
        intent: &Intent,
        fees: &Fees,
        deadline: Instant,
        mode: Mode<'_>,
    ) -> Result<Option<ManagedInitialServiceSetupProgress>> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        self.validate_intent(intent)?;
        let Some(directory) = self.authority.directory.open_child_optional("setup")? else {
            return Ok(None);
        };
        let Some(original) = journal::read_intent(&directory)? else {
            return Ok(None);
        };
        self.validate_original(&original)?;
        original.matches_intent(intent)?;
        let history = attempts::History::read(
            &directory,
            self.purpose()?,
            original.digest()?,
            &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
        )?;
        history.require_fees(fees)?;
        self.advance(deadline, mode).map(Some)
    }
    fn validate_intent(&self, intent: &Intent) -> Result<()> {
        intent.validate()?;
        if intent.kind() != self.kind {
            return Err(invalid("service setup original changed purpose"));
        }
        let expected = match intent {
            Intent::ProviderIngest { authority, .. } => {
                Intent::provider_ingest(&self.authority, authority)?
            }
            Intent::Gateway { policy, .. } => Intent::gateway(&self.authority, policy)?,
            Intent::Reputation { selection, policy } => {
                Intent::reputation(&self.authority, &selection.compliance_gateway_ids, policy)?
            }
        };
        if encode(intent, journal::MAX_INTENT_BYTES)?
            != encode(&expected, journal::MAX_INTENT_BYTES)?
        {
            return Err(invalid(
                "service setup differs from the original generated roles",
            ));
        }
        Ok(())
    }
    fn validate_original(&self, original: &Original) -> Result<()> {
        original.validate()?;
        self.validate_intent(&original.intent)?;
        self.authority
            .decode_checkpoint(&original.checkpoint)?
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original service setup checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("service setup checkpoint is not the selected Global root"))?;
        Ok(())
    }
    fn validate_carrier(
        &self,
        original: &Original,
        finalized: &ManagedTransactionFinality,
    ) -> Result<()> {
        if finalized.height
            <= self
                .authority
                .decode_checkpoint(&original.checkpoint)?
                .checkpoint()
                .height()
        {
            return Err(invalid("service setup carrier predates original intent"));
        }
        Ok(())
    }
    fn wallet_config(&self) -> Result<iroha::config::Config> {
        match self.kind {
            Kind::ProviderIngest => self.authority.issuer_operator_config(),
            Kind::Gateway | Kind::Reputation => Ok(self.authority.config.clone()),
        }
    }
    fn wallet(&self) -> Result<AccountService> {
        AccountService::new(self.wallet_config()?)
            .map_err(|_| invalid("cannot open service setup wallet"))
    }
    fn verify_wallet(
        &self,
        directory: &PrivateDirectory,
        original: &Selected<Original>,
        deadline: Instant,
    ) -> Result<SignedTransaction> {
        original
            .request(deadline)
            .verify(&self.wallet()?, &directory.path().join("transaction"))
    }
    fn advance(
        &mut self,
        deadline: Instant,
        mode: Mode<'_>,
    ) -> Result<ManagedInitialServiceSetupProgress> {
        require_deadline(deadline)?;
        self.authority.validate_profile()?;
        let operation = self.authority.directory.open_child("setup")?;
        let original = journal::required_original(&operation, self.purpose()?)?;
        self.validate_original(&original)?;
        let directory = original.directory();
        let path = directory.path().join("transaction");
        let account = mode.bind_account(self.wallet()?)?;
        let verify_custody = || {
            original.verify_wallets(|intent, attempt| {
                intent
                    .request(attempt.terms(), deadline)
                    .inspect_in_parent(&account, attempt.directory())
            })
        };
        verify_custody()?;
        let preparation = original
            .request(deadline)
            .inspect_in_parent(&account, directory)?;
        let unprepared_expired = preparation.unprepared_status() == Some(OperationStatus::Expired);
        let retained = match preparation.phase() {
            iroha_wallet::operations::NativePreparationPhase::Missing
            | iroha_wallet::operations::NativePreparationPhase::RequestOnly
            | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => None,
            iroha_wallet::operations::NativePreparationPhase::Signed => {
                Some(preparation.into_signed_transaction().map_err(|_| {
                    invalid("retained service preparation has no signed transaction")
                })?)
            }
            iroha_wallet::operations::NativePreparationPhase::Retired => {
                return Err(invalid("original service wallet request was retired"));
            }
        };
        let needs_prepare = retained.is_none();
        if let Some(transaction) = &retained
            && let Some(finalized) = self.authority.retained_finality(&directory, transaction)?
        {
            self.validate_carrier(&original, &finalized)?;
            // Historical successful execution is sufficient for this report. Do not turn a
            // current outage into loss of the original result or imply current policy/serving.
            verify_custody()?;
            return Ok(progress(OperationStatus::Applied, Some(finalized)));
        }
        if matches!(mode, Mode::ObserveLocal) {
            return Ok(progress(
                if needs_prepare {
                    if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                        OperationStatus::Expired
                    } else {
                        OperationStatus::Absent
                    }
                } else {
                    OperationStatus::Pending
                },
                None,
            ));
        }
        if needs_prepare
            && (matches!(mode, Mode::ObserveOnly)
                || (now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired))
        {
            return Ok(progress(
                if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                    OperationStatus::Expired
                } else {
                    OperationStatus::Absent
                },
                None,
            ));
        }
        let observed = self.authority.observe_finality(deadline).ok();
        if needs_prepare {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                return Ok(progress(OperationStatus::Expired, None));
            }
            if observed.is_none() {
                return Err(invalid(
                    "fresh selected service finality unavailable; retain original intent",
                ));
            }
            // This checks a current certified network source only, never current policy/absence.
            verify_custody()?;
            mode.check_dispatch(self.purpose()?, deadline)?;
            original
                .request(original.terms.signing_deadline(deadline)?)
                .prepare(&account, &path)?;
        }
        verify_custody()?;
        let transaction = match retained {
            Some(transaction) => transaction,
            None => self.verify_wallet(&directory, &original, deadline)?,
        };
        let request = original.request(deadline);
        let mut report = request.resume(&account, &path)?;
        if mode.submits() && report.status == OperationStatus::Absent {
            if now_ms()? >= original.terms.signing_deadline_unix_ms || unprepared_expired {
                report.status = OperationStatus::Expired;
            } else if observed.is_some() {
                verify_custody()?;
                mode.check_dispatch(self.purpose()?, deadline)?;
                report = request.submit(&account, &path)?;
            }
        }
        if matches!(mode, Mode::SubmitAuthorized(_)) && report.status == OperationStatus::Expired {
            return Err(super::ManagedBootstrapFailure::SignedUnresolved.into());
        }
        verify_custody()?;
        let finalized = if report.status == OperationStatus::Applied {
            if let Ok(observed) = self.authority.observe_finality(deadline) {
                self.authority.advance_carrier(
                    &directory,
                    &original.checkpoint,
                    &transaction,
                    &report,
                    &observed,
                    deadline,
                )?
            } else {
                None
            }
        } else {
            None
        };
        if let Some(finalized) = &finalized {
            self.validate_carrier(&original, finalized)?;
        }
        verify_custody()?;
        Ok(progress(report.status, finalized))
    }
}
fn progress(
    transaction_status: OperationStatus,
    finalized: Option<ManagedTransactionFinality>,
) -> ManagedInitialServiceSetupProgress {
    ManagedInitialServiceSetupProgress {
        transaction_status,
        finalized,
    }
}

enum Request {
    ProviderIngest(InitialProviderIngestAuthorityRequest),
    Gateway(InitialGatewaySetupRequest),
    Reputation(InitialReputationPolicyRequest),
}
impl Request {
    #[cfg(test)]
    fn inspect(
        &self,
        account: &AccountService,
        path: &Path,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        match self {
            Self::ProviderIngest(request) => {
                account.inspect_initial_provider_ingest_authority_preparation(path, request)
            }
            Self::Gateway(request) => {
                account.inspect_initial_gateway_setup_preparation(path, request)
            }
            Self::Reputation(request) => {
                account.inspect_initial_reputation_policy_preparation(path, request)
            }
        }
        .map_err(Self::inspection_error)
    }
    fn inspect_in_parent(
        &self,
        account: &AccountService,
        parent: &PrivateDirectory,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        match self {
            Self::ProviderIngest(request) => account
                .inspect_initial_provider_ingest_authority_preparation_in_parent(
                    parent,
                    std::ffi::OsStr::new("transaction"),
                    request,
                ),
            Self::Gateway(request) => account.inspect_initial_gateway_setup_preparation_in_parent(
                parent,
                std::ffi::OsStr::new("transaction"),
                request,
            ),
            Self::Reputation(request) => account
                .inspect_initial_reputation_policy_preparation_in_parent(
                    parent,
                    std::ffi::OsStr::new("transaction"),
                    request,
                ),
        }
        .map_err(Self::inspection_error)
    }
    fn inspection_error(_: color_eyre::eyre::Report) -> crate::managed::Error {
        invalid("service wallet preparation differs from exact original request")
    }
    fn retain(
        &self,
        account: &AccountService,
        path: &Path,
    ) -> Result<iroha_wallet::operations::VerifiedNativePreparation> {
        match self {
            Self::ProviderIngest(request) => {
                account.retain_initial_provider_ingest_authority_request(request, path)
            }
            Self::Gateway(request) => account.retain_initial_gateway_setup_request(request, path),
            Self::Reputation(request) => {
                account.retain_initial_reputation_policy_request(request, path)
            }
        }
        .map_err(|_| invalid("cannot retain exact unsigned service setup request"))
    }
    fn retire(
        &self,
        account: &AccountService,
        path: &Path,
    ) -> Result<iroha_wallet::operations::RetiredNativeRequest> {
        match self {
            Self::ProviderIngest(request) => {
                account.retire_initial_provider_ingest_authority_unprepared(path, request)
            }
            Self::Gateway(request) => {
                account.retire_initial_gateway_setup_unprepared(path, request)
            }
            Self::Reputation(request) => {
                account.retire_initial_reputation_policy_unprepared(path, request)
            }
        }
        .map_err(|_| invalid("service setup unsigned request could not retire"))
    }
    fn prepare(&self, account: &AccountService, path: &Path) -> Result<OperationReport> {
        match self {
            Self::ProviderIngest(request) => {
                account.prepare_initial_provider_ingest_authority(request, path)
            }
            Self::Gateway(request) => account.prepare_initial_gateway_setup(request, path),
            Self::Reputation(request) => account.prepare_initial_reputation_policy(request, path),
        }
        .map_err(|_| {
            invalid("service setup preparation failed; retain original intent and wallet journal")
        })
    }
    fn verify(&self, account: &AccountService, path: &Path) -> Result<SignedTransaction> {
        match self {
            Self::ProviderIngest(request) => {
                account.verify_initial_provider_ingest_authority_journal(path, request)
            }
            Self::Gateway(request) => account.verify_initial_gateway_setup_journal(path, request),
            Self::Reputation(request) => {
                account.verify_initial_reputation_policy_journal(path, request)
            }
        }
        .map_err(|_| invalid("service setup wallet differs from exact original request"))
    }
    fn resume(&self, account: &AccountService, path: &Path) -> Result<OperationReport> {
        match self {
            Self::ProviderIngest(request) => {
                account.resume_initial_provider_ingest_authority(path, request)
            }
            Self::Gateway(request) => account.resume_initial_gateway_setup(path, request),
            Self::Reputation(request) => account.resume_initial_reputation_policy(path, request),
        }
        .map_err(|_| invalid("service setup unresolved; recover the original wallet journal"))
    }
    fn submit(&self, account: &AccountService, path: &Path) -> Result<OperationReport> {
        match self {
            Self::ProviderIngest(request) => {
                account.submit_initial_provider_ingest_authority(path, request)
            }
            Self::Gateway(request) => account.submit_initial_gateway_setup(path, request),
            Self::Reputation(request) => account.submit_initial_reputation_policy(path, request),
        }
        .map_err(|_| invalid("service setup unresolved; recover the original wallet journal"))
    }
}

#[cfg(test)]
#[path = "service_setup/native_tests.rs"]
mod native_tests;
#[cfg(test)]
#[path = "service_setup/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "service_setup/transport_tests.rs"]
mod transport_tests;

#[cfg(test)]
#[path = "service_setup/bootstrap_test_support.rs"]
mod bootstrap_test_support;

#[cfg(test)]
#[path = "service_setup/provider_ingest_native_tests.rs"]
mod provider_ingest_native_tests;
