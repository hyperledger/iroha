//! Shared operation budgets and typed parent registration over the native journal.

use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::private_dataspace::{AnchorPrivateDataspace, RegisterPrivateDataspace},
    private_dataspace::{
        PrivateDataspaceAnchor, PrivateDataspaceAnchorState, PrivateDataspaceRegistration,
    },
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
};
use iroha_model_base::topology::DataSpaceId;
use std::time::Instant;

/// Explicit aggregate fee ceilings and one total operation deadline.
#[derive(Clone, Debug)]
pub struct BoundedTransactionOptions {
    /// Selected payer and gas bound; supplied per-component limits are also enforced.
    pub fee_payment: FeePaymentIntent,
    /// Maximum combined fee for each allowed asset; unlisted assets are forbidden.
    pub max_total_fees: BTreeMap<AssetDefinitionId, Quantity>,
    /// One deadline shared by validation, probes, quotes, funding reads, signing and dispatch.
    /// Recovery uses this for new I/O while preserving the original signed transaction deadline.
    pub deadline: Instant,
}

/// Compact registration independently selected and authenticated by the attachment owner.
#[derive(Clone, Debug)]
pub struct PrivateRootRegistrationRequest {
    /// Exact canonical parent SNS dataspace alias.
    pub alias: String,
    /// Current nonzero parent ownership generation for compare-and-swap admission.
    pub expected_ownership_generation: u64,
    /// Exact public child context; contains no private genesis body or listener credential.
    pub registration: PrivateDataspaceRegistration,
    /// Caller-selected spending limits and deadline.
    pub options: BoundedTransactionOptions,
}

/// One compact child certificate extending independently authenticated parent cursor state.
#[derive(Clone, Debug)]
pub struct PrivateRootAnchorRequest {
    /// Exact state from the attachment store's independently confirmed parent record.
    pub state: PrivateDataspaceAnchorState,
    /// The next native quorum-certified child decision, without its body.
    pub anchor: PrivateDataspaceAnchor,
    /// Caller-selected spending limits and deadline.
    pub options: BoundedTransactionOptions,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct BoundedTerms {
    max_total_fees: Vec<AssetFeeMaximum>,
    pub(super) deadline_ms: u64,
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AssetFeeMaximum {
    asset_definition_id: AssetDefinitionId,
    max_amount: Quantity,
}

impl BoundedTerms {
    pub(super) fn new(options: &BoundedTransactionOptions) -> Result<Self> {
        eyre::ensure!(
            options.max_total_fees.len() <= 16 && options.fee_payment.charge_limits().len() <= 16,
            "operation fee authorization exceeds sixteen entries"
        );
        options.fee_payment.validate()?;
        let remaining = options
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| eyre!("bounded operation deadline elapsed"))?;
        let remaining_ms = u64::try_from(remaining.as_millis())?;
        let deadline_ms = current_unix_ms()?
            .checked_add(remaining_ms)
            .ok_or_else(|| eyre!("bounded operation deadline overflow"))?;
        let terms = Self {
            max_total_fees: options
                .max_total_fees
                .iter()
                .map(|(asset, maximum)| AssetFeeMaximum {
                    asset_definition_id: asset.clone(),
                    max_amount: maximum.clone(),
                })
                .collect(),
            deadline_ms,
        };
        terms.validate()?;
        Ok(terms)
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.deadline_ms == 0
            || self.max_total_fees.len() > 16
            || self
                .max_total_fees
                .iter()
                .any(|maximum| maximum.max_amount.is_zero())
            || self
                .max_total_fees
                .windows(2)
                .any(|pair| pair[0].asset_definition_id >= pair[1].asset_definition_id)
        {
            eyre::bail!("operation fee maxima must be positive, bounded and canonically ordered");
        }
        Ok(())
    }

    pub(super) fn verify_quote(&self, quote: &FeeQuoteResponse) -> Result<()> {
        self.validate()?;
        let mut totals = BTreeMap::new();
        for limit in quote.intent.charge_limits() {
            add_quantity(&mut totals, limit.asset_definition_id(), limit.max_amount())?;
        }
        for (asset, total) in totals {
            let maximum = self
                .max_total_fees
                .iter()
                .find(|maximum| maximum.asset_definition_id == asset)
                .ok_or_else(|| {
                    eyre!("operation quote charges an asset outside the explicit total fee budget")
                })?;
            if total > maximum.max_amount {
                eyre::bail!("operation quote exceeds the explicit total fee budget");
            }
        }
        Ok(())
    }

    pub(super) fn matches_options(&self, options: &BoundedTransactionOptions) -> Result<bool> {
        self.validate()?;
        options.fee_payment.validate()?;
        Ok(self.max_total_fees.len() == options.max_total_fees.len()
            && self.max_total_fees.iter().zip(&options.max_total_fees).all(
                |(saved, (asset, maximum))| {
                    &saved.asset_definition_id == asset && &saved.max_amount == maximum
                },
            ))
    }
}

impl AccountService {
    /// Inspect exact private-root preparation without network I/O or signing.
    /// # Errors
    /// Rejects changed child, certificate, fees or unsafe journal custody.
    pub fn inspect_private_root_anchor_preparation(
        &self,
        journal: &Path,
        expected: &PrivateRootAnchorRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::PrivateRootAnchor,
            Some(OperationExpectation::PrivateRoot(
                BoundedOperationExpectation::Anchor(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_private_root_anchor_unprepared(
        &self,
        journal: &Path,
        expected: &PrivateRootAnchorRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::PrivateRootAnchor,
            OperationExpectation::PrivateRoot(BoundedOperationExpectation::Anchor(expected)),
        )
    }

    /// Inspect exact private-root preparation without network I/O or signing.
    /// # Errors
    /// Rejects changed child, certificate, fees or unsafe journal custody.
    pub fn inspect_private_root_registration_preparation(
        &self,
        journal: &Path,
        expected: &PrivateRootRegistrationRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::PrivateRootRegistration,
            Some(OperationExpectation::PrivateRoot(
                BoundedOperationExpectation::Registration(expected),
            )),
        )
    }
    /// Retire only this exact retained request before any payload or dispatch evidence exists.
    /// # Errors
    /// Refuses missing, changed, malformed, payload-retained or signed histories and unsafe custody.
    pub fn retire_private_root_registration_unprepared(
        &self,
        journal: &Path,
        expected: &PrivateRootRegistrationRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::PrivateRootRegistration,
            OperationExpectation::PrivateRoot(BoundedOperationExpectation::Registration(expected)),
        )
    }

    /// Clone this exact account context with a deadline shared by every subsequent HTTP request.
    ///
    /// Use the clone for prepare, submit or read-only recovery within one attachment deadline.
    /// Applying another deadline can only shorten an existing one. The clone retains the original
    /// blocking runtime and connection pools, so either view may outlive the other.
    ///
    /// # Errors
    /// Rejects an elapsed deadline or invalid bounded account authority binding.
    pub fn with_deadline(&self, deadline: Instant) -> Result<Self> {
        let deadline = self
            .deadline
            .map_or(deadline, |retained| retained.min(deadline));
        if deadline <= Instant::now() {
            eyre::bail!("wallet operation deadline elapsed");
        }
        Ok(Self {
            config: self.config.clone(),
            client: self.client.with_request_deadline(deadline)?,
            deadline: Some(deadline),
            cancellation: self.cancellation.clone(),
        })
    }

    /// Validate, quote and retain one exact compact parent registration without submitting it.
    ///
    /// The caller authenticates parent admission and SNS ownership independently. This method
    /// rechecks the exact parent, canonical alias-derived id and nonzero ownership generation.
    /// A later `Applied` report describes exact transport evidence, not independent parent finality.
    ///
    /// # Errors
    /// Rejects changed scope, invalid child credentials, fee-budget increases, elapsed deadlines
    /// and unsafe or existing journals before any transaction submission.
    pub fn prepare_private_root_registration(
        &self,
        request: &PrivateRootRegistrationRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::PrivateRootRegistration,
                Some(OperationExpectation::PrivateRoot(
                    BoundedOperationExpectation::Registration(request),
                )),
            )?
        {
            return Ok(report);
        }
        let operation = NativeOperation::PrivateRootRegistration {
            alias: request.alias.clone(),
            expected_ownership_generation: request.expected_ownership_generation,
            registration: Box::new(request.registration.clone()),
            terms: BoundedTerms::new(&request.options)?,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .prepare_native(operation, request.options.fee_payment.clone(), journal)
    }

    /// Validate and retain the next compact certificate against the exact confirmed registration.
    ///
    /// Native `PrivateDataspaceAnchorState::apply` verifies the certificate and contiguous cursor
    /// locally before quoting. The caller must independently authenticate the supplied parent state
    /// and later confirm parent inclusion; `Applied` alone does not advance that trust boundary.
    ///
    /// # Errors
    /// Rejects substituted parent/child/cursor, invalid quorum, gaps, fee-budget increases,
    /// elapsed deadlines and unsafe journals before transaction submission.
    pub fn prepare_private_root_anchor(
        &self,
        request: &PrivateRootAnchorRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self
            .with_deadline(request.options.deadline)?
            .finish_existing_preparation(
                journal,
                NativeOperationKind::PrivateRootAnchor,
                Some(OperationExpectation::PrivateRoot(
                    BoundedOperationExpectation::Anchor(request),
                )),
            )?
        {
            return Ok(report);
        }
        let operation = NativeOperation::PrivateRootAnchor {
            state: Box::new(request.state.clone()),
            anchor: Box::new(request.anchor.clone()),
            terms: BoundedTerms::new(&request.options)?,
        };
        operation.instructions(&self.config)?;
        self.with_deadline(request.options.deadline)?
            .prepare_native(operation, request.options.fee_payment.clone(), journal)
    }
}

pub(super) fn registration_instruction(
    config: &Config,
    alias: &str,
    expected_ownership_generation: u64,
    registration: &PrivateDataspaceRegistration,
) -> Result<InstructionBox> {
    registration.validate()?;
    let dataspace = require_parent(config, registration)?;
    let name = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)?;
    if name.normalized_label() != alias
        || alias == "universal"
        || DataSpaceId::from_hash(&name.name_hash()) != dataspace
        || expected_ownership_generation == 0
    {
        eyre::bail!("private-root registration differs from the exact canonical SNS ownership");
    }
    let bytes = norito::encode_canonical(registration)?;
    PrivateDataspaceRegistration::decode(&bytes)?;
    Ok(RegisterPrivateDataspace {
        alias: alias.to_owned(),
        expected_ownership_generation,
        registration: bytes,
    }
    .into())
}

pub(super) fn anchor_instruction(
    config: &Config,
    state: &PrivateDataspaceAnchorState,
    anchor: &PrivateDataspaceAnchor,
) -> Result<InstructionBox> {
    state.validate()?;
    let dataspace_id = require_parent(config, state.registration())?;
    let bytes = norito::encode_canonical(anchor)?;
    PrivateDataspaceAnchor::decode(&bytes)?;
    let mut next = state.clone();
    next.apply(anchor)?;
    Ok(AnchorPrivateDataspace {
        dataspace_id,
        anchor: bytes,
    }
    .into())
}

fn require_parent(
    config: &Config,
    registration: &PrivateDataspaceRegistration,
) -> Result<DataSpaceId> {
    let SumeragiRootScope::Dataspace {
        parent_network_id,
        dataspace_id,
    } = registration.scope
    else {
        eyre::bail!("private-root operation requires a private dataspace registration");
    };
    if parent_network_id != config.network_id {
        eyre::bail!("private-root operation differs from the exact configured parent network");
    }
    Ok(dataspace_id)
}

pub(super) enum BoundedOperationExpectation<'a> {
    Alias(&'a AliasSetupPlanRequestV1, &'a BoundedTransactionOptions),
    Registration(&'a PrivateRootRegistrationRequest),
    Anchor(&'a PrivateRootAnchorRequest),
}
impl BoundedOperationExpectation<'_> {
    pub(super) fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        let options = match (self, record.operation) {
            (Self::Alias(expected, options), NativeOperation::AliasSetup { request, .. })
                if *expected == request =>
            {
                *options
            }
            (
                Self::Registration(request),
                NativeOperation::PrivateRootRegistration {
                    alias,
                    expected_ownership_generation,
                    registration,
                    ..
                },
            ) if alias == &request.alias
                && *expected_ownership_generation == request.expected_ownership_generation
                && registration.as_ref() == &request.registration =>
            {
                &request.options
            }
            (Self::Anchor(request), NativeOperation::PrivateRootAnchor { state, anchor, .. })
                if state.as_ref() == &request.state && anchor.as_ref() == &request.anchor =>
            {
                &request.options
            }
            _ => eyre::bail!(
                "saved bounded journal differs from the exact selected operation request"
            ),
        };
        options.fee_payment.validate()?;
        let terms = record
            .operation
            .bounded_terms()
            .ok_or_else(|| eyre!("saved journal does not retain explicit operation bounds"))?;
        terms.validate()?;
        if *record.requested_fee != options.fee_payment
            || !terms.matches_options(options)?
            || record.deadline_ms > terms.deadline_ms
        {
            eyre::bail!("saved bounded fee authorization differs from the exact retained limits");
        }
        // The fresh monotonic deadline controls new HTTP work only. Recovery never re-signs
        // or extends the original absolute transaction lifetime retained in this journal.
        Ok(())
    }
}

impl AccountService {
    /// Check one retained registration against the exact selected child and original fee limits.
    ///
    /// # Errors
    /// Rejects unsafe custody, substituted signed bytes, another child or changed authorization.
    pub fn verify_private_root_registration_journal(
        &self,
        journal: &Path,
        expected: &PrivateRootRegistrationRequest,
    ) -> Result<()> {
        self.inspect_private_root_registration_preparation(journal, expected)?
            .into_signed_transaction()?;
        Ok(())
    }

    /// Check one retained anchor against the exact confirmed state, child certificate and fee limits.
    ///
    /// # Errors
    /// Rejects unsafe custody, substituted signed bytes, another state/certificate or changed limits.
    pub fn verify_private_root_anchor_journal(
        &self,
        journal: &Path,
        expected: &PrivateRootAnchorRequest,
    ) -> Result<()> {
        self.inspect_private_root_anchor_preparation(journal, expected)?
            .into_signed_transaction()?;
        Ok(())
    }

    /// Submit once only after binding the held journal to the exact selected private child.
    ///
    /// # Errors
    /// Rejects changed child/fees or unsafe evidence before observation or dispatch.
    pub fn submit_private_root_registration(
        &self,
        journal: &Path,
        expected: &PrivateRootRegistrationRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction(
                journal,
                NativeOperationKind::PrivateRootRegistration,
                true,
                Some(BoundedOperationExpectation::Registration(expected)),
            )
    }

    /// Recover the exact selected private registration without another submission or signature.
    ///
    /// # Errors
    /// Rejects changed child/fees, elapsed read budget, unsafe evidence or untrusted observations.
    pub fn resume_private_root_registration(
        &self,
        journal: &Path,
        expected: &PrivateRootRegistrationRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction(
                journal,
                NativeOperationKind::PrivateRootRegistration,
                false,
                Some(BoundedOperationExpectation::Registration(expected)),
            )
    }

    /// Submit the selected next child certificate once, comparing request and held journal atomically.
    ///
    /// # Errors
    /// Rejects changed cursor/certificate/fees or unsafe evidence before observation or dispatch.
    pub fn submit_private_root_anchor(
        &self,
        journal: &Path,
        expected: &PrivateRootAnchorRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction(
                journal,
                NativeOperationKind::PrivateRootAnchor,
                true,
                Some(BoundedOperationExpectation::Anchor(expected)),
            )
    }

    /// Read-only recovery for the exact selected certificate and original confirmed parent cursor.
    ///
    /// # Errors
    /// Rejects changed cursor/certificate/fees, elapsed read budget, unsafe or untrusted evidence.
    pub fn resume_private_root_anchor(
        &self,
        journal: &Path,
        expected: &PrivateRootAnchorRequest,
    ) -> Result<OperationReport> {
        self.with_deadline(expected.options.deadline)?
            .run_transaction(
                journal,
                NativeOperationKind::PrivateRootAnchor,
                false,
                Some(BoundedOperationExpectation::Anchor(expected)),
            )
    }
}
