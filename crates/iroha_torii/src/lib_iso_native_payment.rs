// Canonical ISO business recovery. World receipts are locators; only the original
// authenticated successful input/output can authorize the monetary projection.
#[derive(Debug)]
struct CanonicalIsoBusinessOutcome {
    settlement: Option<iso20022_bridge::IsoNativeBusinessSettlement>,
    conflicting_intent: bool,
    successful_hash: HashOf<SignedTransaction>,
}

fn canonical_iso_business_locator(
    state: &CoreState,
    request: &iso20022_bridge::IsoNativePaymentRequest,
) -> Result<Option<iroha_data_model::isi::SettlementReceipt>, Error> {
    if request.intent.network_id != *state.network_id_ref() {
        return Err(pipeline_status_projection_error(
            "ISO native intent differs from this committed network",
        ));
    }
    let view = state.view();
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(view.world())
        != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    {
        return Err(pipeline_status_projection_error(
            "ISO shared-asset settlement requires the authenticated Global root",
        ));
    }
    let Some(receipt) = view
        .world
        .settlement_receipts()
        .get(&request.intent.settlement_id)
    else {
        return Ok(None);
    };
    let index = usize::try_from(receipt.block_height)
        .ok()
        .filter(|height| *height >= 2)
        .ok_or_else(|| pipeline_status_projection_error("ISO native receipt has invalid height"))?;
    if view.block_hashes().get(index - 1) != Some(&receipt.block_hash) {
        return Err(pipeline_status_projection_error(
            "ISO native receipt differs from the canonical block journal",
        ));
    }
    Ok(Some(receipt.clone()))
}

fn canonical_iso_business_from_carrier(
    request: &iso20022_bridge::IsoNativePaymentRequest,
    locator: &iroha_data_model::isi::SettlementReceipt,
    carrier: &iroha_core::smartcontracts::isi::tx::FinalizedExecutionCarrier,
) -> Result<CanonicalIsoBusinessOutcome, Error> {
    use iroha_data_model::isi::{
        SettleAtomic, SettlementInstructionBox, project_atomic_payment_receipt_unverified,
    };
    let header = carrier.block().header();
    let mut found = None;
    let mut duplicate = false;
    carrier
        .visit_network_transactions(locator.block_hash, |entrypoint, result| {
            let TransactionEntrypoint::External(transaction) = entrypoint else {
                return;
            };
            let iroha_data_model::transaction::Executable::Instructions(instructions) =
                transaction.instructions()
            else {
                return;
            };
            let [instruction] = instructions.as_ref() else {
                return;
            };
            let instruction = instruction.as_any();
            let Some(actual) =
                instruction
                    .downcast_ref::<SettleAtomic>()
                    .or_else(
                        || match instruction.downcast_ref::<SettlementInstructionBox>() {
                            Some(SettlementInstructionBox::Atomic(intent)) => Some(intent),
                            _ => None,
                        },
                    )
            else {
                return;
            };
            // A rejected retry in the original block is not the successful business source.
            if actual.settlement_id != request.intent.settlement_id || result.as_ref().is_err() {
                return;
            }
            let projected = (|| {
                let receipt = project_atomic_payment_receipt_unverified(
                    request.intent.network_id,
                    actual,
                    &header,
                    entrypoint,
                    result,
                )
                .map_err(|error| {
                    pipeline_status_projection_error(format!(
                        "invalid original ISO native payment: {error}"
                    ))
                })?;
                if &receipt != locator {
                    return Err(pipeline_status_projection_error(
                        "ISO receipt locator differs from its original successful source",
                    ));
                }
                let conflicting_intent = actual != &request.intent;
                let settlement = if conflicting_intent {
                    None
                } else {
                    Some(
                        iso20022_bridge::IsoNativeBusinessSettlement::from_canonical_projection(
                            transaction.hash().to_string(),
                            &receipt,
                            result.nexus_fee_receipt(),
                        )
                        .map_err(|error| {
                            pipeline_status_projection_error(format!(
                                "invalid ISO native projection: {error}"
                            ))
                        })?,
                    )
                };
                Ok(CanonicalIsoBusinessOutcome {
                    settlement,
                    conflicting_intent,
                    successful_hash: transaction.hash(),
                })
            })();
            duplicate |= found.replace(projected).is_some();
        })
        .map_err(|error| crate::canonical_history::query_attempt_error(error.into()))?;
    if duplicate {
        return Err(pipeline_status_projection_error(
            "multiple successful sources for one ISO native settlement identity",
        ));
    }
    found.ok_or_else(|| {
        pipeline_status_projection_error(
            "ISO native receipt lacks its original successful direct payment source",
        )
    })?
}

fn canonical_iso_business_with_reader<T>(
    state: &CoreState,
    request: &iso20022_bridge::IsoNativePaymentRequest,
    read: impl FnOnce(NonZeroUsize) -> Result<T, Error>,
    project: impl FnOnce(
        &T,
        &iroha_data_model::isi::SettlementReceipt,
    ) -> Result<CanonicalIsoBusinessOutcome, Error>,
) -> Result<Option<CanonicalIsoBusinessOutcome>, Error> {
    let Some(locator) = canonical_iso_business_locator(state, request)? else {
        return Ok(None);
    };
    let height = usize::try_from(locator.block_height)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            pipeline_status_projection_error("ISO native receipt height exceeds platform index")
        })?;
    let original = read(height)?;
    let outcome = project(&original, &locator)?;
    // Keep the authenticated original owner alive through both final namespace joins.
    if canonical_iso_business_locator(state, request)?.as_ref() != Some(&locator)
        || canonical_transaction_anchor(state, &outcome.successful_hash)?
            .is_none_or(|anchor| anchor.height != height || anchor.block_hash != locator.block_hash)
    {
        return Err(pipeline_status_projection_error(
            "ISO native business binding changed during original source authentication",
        ));
    }
    drop(original);
    Ok(Some(outcome))
}

fn canonical_iso_business(
    state: &CoreState,
    request: &iso20022_bridge::IsoNativePaymentRequest,
) -> Result<Option<CanonicalIsoBusinessOutcome>, Error> {
    let work = routing::app_query_limits().max_fetch_size;
    canonical_iso_business_with_reader(
        state,
        request,
        |height| {
            state
                .read_finalized_execution_carrier(
                    height,
                    work,
                    iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
                )
                .map_err(crate::canonical_history::query_attempt_error)
        },
        |carrier, locator| canonical_iso_business_from_carrier(request, locator, carrier),
    )
}

fn canonical_iso_business_for_request(
    app: &SharedAppState,
    request: &iso20022_bridge::IsoNativePaymentRequest,
) -> Result<Option<CanonicalIsoBusinessOutcome>, Error> {
    canonical_iso_business_with_reader(
        &app.state,
        request,
        |height| read_pipeline_execution_carrier(app, height),
        |original, locator| {
            original
                .owner
                .scope(|| canonical_iso_business_from_carrier(request, locator, &original.carrier))
        },
    )
}

fn iso_native_carrier_projection(
    outcome: CanonicalTransactionOutcome,
) -> iso20022_bridge::IsoNativeCarrierOutcome {
    match outcome {
        CanonicalTransactionOutcome::Applied { height, .. } => {
            iso20022_bridge::IsoNativeCarrierOutcome {
                height: height.get(),
                applied: true,
                rejection: None,
            }
        }
        CanonicalTransactionOutcome::Rejected { height, reason } => {
            iso20022_bridge::IsoNativeCarrierOutcome {
                height: height.get(),
                applied: false,
                rejection: Some(reason.to_string()),
            }
        }
    }
}

fn publish_iso_native_outcomes(
    runtime: &Iso20022BridgeRuntime,
    request: &iso20022_bridge::IsoNativePaymentRequest,
    attempted: Option<CanonicalTransactionOutcome>,
    business: Option<CanonicalIsoBusinessOutcome>,
) -> Result<(), Error> {
    let (settlement, conflict) = business.map_or((None, false), |outcome| {
        (outcome.settlement, outcome.conflicting_intent)
    });
    runtime
        .publish_native_payment_projection(
            request,
            attempted.map(iso_native_carrier_projection),
            settlement,
            conflict,
        )
        .map_err(|error| {
            pipeline_status_projection_error(format!(
                "ISO native projection could not be durably published: {error:?}"
            ))
        })?;
    runtime
        .resolve_native_payment_return_reports(&request.message_id)
        .map_err(|error| {
            pipeline_status_projection_error(format!(
                "ISO native return report could not be durably resolved: {error:?}"
            ))
        })
}
