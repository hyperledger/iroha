//! Finality-bound public observations for frozen validator committee preparation.

use super::*;
use iroha_core::{
    beacon::{
        GlobalThresholdBeaconError, GlobalThresholdBeaconSessionBindingV1,
        global_threshold_beacon_roster_hash_iter_v1,
    },
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::certified_chain::CertifiedChain,
    validator_committee_evidence::validate_validator_committee_selection_binding_v1,
};
#[cfg(test)]
use iroha_data_model::Registrable as _;
use iroha_data_model::{
    nexus::{ValidatorCommitteeSelectionStatusV1, ValidatorCommitteeStatusV1},
    sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_BLOCK_COUNT,
        NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityArtifact, NativeFinalityArtifactError,
        NativeFinalityLimits,
    },
};
use mv::storage::StorageReadOnly;

/// Optional exact target epoch; omission selects the next scheduling epoch.
#[derive(Debug, Default, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct CommitteeStatusQuery {
    pub(super) target_epoch: Option<u64>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Query(iroha_data_model::ValidationFail::InternalError(
        message.into(),
    ))
}

fn unavailable() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::NotFound,
    ))
}

fn capacity() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded,
    ))
}

fn codec_error(error: norito::Error) -> Error {
    if error.is_decode_resource_limit() {
        capacity()
    } else {
        invalid(error.to_string())
    }
}

fn artifact_error(error: NativeFinalityArtifactError) -> Error {
    match error {
        NativeFinalityArtifactError::Resource(_) => capacity(),
        NativeFinalityArtifactError::Invalid(message) => invalid(message),
    }
}

fn beacon_binding_error(error: GlobalThresholdBeaconError) -> Error {
    invalid(format!("invalid prepared committee beacon: {error}"))
}

fn response_error(error: crate::utils::BoundedResponseEncodeError) -> Error {
    match error {
        crate::utils::BoundedResponseEncodeError::BodyTooLarge { .. }
        | crate::utils::BoundedResponseEncodeError::JsonBodyTooLarge { .. } => capacity(),
        crate::utils::BoundedResponseEncodeError::Serialization => {
            invalid("committee response canonical serialization failed")
        }
    }
}

// Copy a borrowed World graph through a counted canonical buffer and the caller's
// unchanged cumulative decoder. The encoder charges its physical frame once; the decoded
// graph is charged separately before allocation. Refusal preserves the original row.
fn admitted_copy<T>(value: &T, max_frame_bytes: usize) -> Result<T, Error>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    let length = norito::canonical_frame_len(value).map_err(codec_error)?;
    if length > max_frame_bytes {
        return Err(capacity());
    }
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes = norito::core::to_bytes_bounded(value, length).map_err(|error| match error {
        norito::core::BoundedEncodeError::Serialization(error) => codec_error(error),
        _ => capacity(),
    })?;
    norito::decode_canonical(&bytes).map_err(codec_error)
}

fn load(
    state: &impl StateReadOnly,
    target_epoch: Option<u64>,
    limits: NativeFinalityLimits,
) -> Result<ValidatorCommitteeStatusV1, Error> {
    let height = u64::try_from(state.height()).map_err(|_| invalid("committee height overflow"))?;
    limits.validate().map_err(invalid)?;
    if height < 2 {
        return Err(unavailable());
    }
    // The independently captured original execution tip authenticates recent
    // ancestry. Rechecking the entire genesis prefix for every status read makes
    // valid boundaries eventually exhaust even an otherwise idle request pool.
    // Keep one cumulative decode scope and source allowance for both attachments.
    let mut source_blocks_left = limits.block_count as u64;
    let mut source_bytes_left = limits.journal_bytes as u64;
    use iroha_data_model::query::error::QueryExecutionFail;
    let query_error = crate::canonical_history::query_attempt_error;
    let mut admit = |work, bytes| {
        if bytes > limits.block_bytes as u64 {
            return Err(
                iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            );
        }
        let remaining_blocks = source_blocks_left.checked_sub(work).ok_or(
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ),
        )?;
        let remaining_bytes = source_bytes_left.checked_sub(bytes).ok_or(
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ),
        )?;
        source_blocks_left = remaining_blocks;
        source_bytes_left = remaining_bytes;
        Ok(())
    };
    let reader =
        CertifiedChain::new_with_source_admission(state, &mut admit).map_err(query_error)?;
    let index = usize::try_from(height)
        .ok()
        .and_then(std::num::NonZeroUsize::new)
        .ok_or_else(unavailable)?;
    let mut resolved_epoch = None;
    let mut transition = None;
    let (latest, historical) = reader
        .certified_with_ancestor_from_execution(index, &mut admit, |latest| {
            let outcome = &latest.commitment().schedule;
            let current = outcome
                .boundary
                .as_ref()
                .map_or(&outcome.current, |boundary| &boundary.next);
            let epoch = target_epoch.map_or_else(
                || {
                    current.authorization.epoch.checked_add(1).ok_or_else(|| {
                        QueryExecutionFail::Conversion("committee epoch overflow".into())
                    })
                },
                Ok,
            )?;
            resolved_epoch = Some(epoch);
            transition = state.world().validator_committee_transitions().get(&epoch);
            transition
                .filter(|row| row.preparation.selection_height != height)
                .map(|row| {
                    usize::try_from(row.preparation.selection_height)
                        .ok()
                        .and_then(std::num::NonZeroUsize::new)
                        .ok_or(QueryExecutionFail::NotFound)
                })
                .transpose()
        })
        .map_err(query_error)?;
    let target_epoch = resolved_epoch.ok_or_else(unavailable)?;
    let latest_finality =
        NativeFinalityArtifact::from_block(latest.block(), limits).map_err(artifact_error)?;
    let outcome = &latest.commitment().schedule;
    let selected = transition
        .map(|transition| {
            let selecting = historical.as_ref().unwrap_or(&latest);
            validate_validator_committee_selection_binding_v1(
                transition,
                selecting,
                &latest,
                target_epoch,
            )
            .map_err(invalid)?;
            let selecting_finality = NativeFinalityArtifact::from_block(selecting.block(), limits)
                .map_err(artifact_error)?;
            let selection = ValidatorCommitteeSelectionStatusV1 {
                transition: admitted_copy(transition, limits.block_bytes)?,
                selecting_finality,
            };
            Ok::<_, Error>(selection)
        })
        .transpose()?;
    if selected.is_none()
        && outcome
            .boundary
            .as_ref()
            .and_then(|boundary| boundary.preparation.as_ref())
            .is_some_and(|preparation| preparation.target_epoch == target_epoch)
    {
        return Err(invalid(
            "certified committee preparation is absent from committed State",
        ));
    }
    let network_id = *state.network_id();
    let pending_beacon_session =
        selected
            .as_ref()
            .map(|selection| {
                let preparation = &selection.transition.preparation;
                let session_id = preparation.beacon_session_id().map_err(invalid)?;
                state
                .world()
                .global_beacon_key_sessions()
                .get(&session_id)
                .map(|record| {
                    if usize::from(record.session.committee_size) != preparation.committee.len()
                        || record.session.adaptive_dkg.session.start_height
                            <= preparation.selection_height
                        || record.session.adaptive_dkg.finalized_at_height
                            >= preparation.first_height - 1
                    {
                        return Err(invalid(
                            "prepared committee beacon differs from the frozen roster or interval",
                        ));
                    }
                    let binding = GlobalThresholdBeaconSessionBindingV1 {
                        network_id,
                        session_id,
                        roster_hash: global_threshold_beacon_roster_hash_iter_v1(
                            preparation.committee.iter().map(|seat| &seat.validator),
                        ),
                        transcript_hash: record.session.transcript_hash,
                    };
                    record.session.check_binding(&binding).map_err(beacon_binding_error)?;
                    if selection
                        .transition
                        .credentials
                        .as_ref()
                        .is_some_and(|credentials| {
                            credentials.beacon.session_id != session_id
                                || credentials.beacon.transcript_hash
                                    != record.session.transcript_hash
                        })
                    {
                        return Err(invalid(
                            "prepared committee beacon differs from fixed credentials",
                        ));
                    }
                    admitted_copy(record.session.record(), limits.block_bytes)
                })
                .transpose()
            })
            .transpose()?
            .flatten();
    if pending_beacon_session.is_none()
        && selected
            .as_ref()
            .is_some_and(|selection| selection.transition.credentials.is_some())
    {
        return Err(invalid(
            "fixed committee credentials lack their committed beacon transcript",
        ));
    }
    Ok(ValidatorCommitteeStatusV1 {
        network_id,
        target_epoch,
        latest_finality,
        selected,
        pending_beacon_session,
    })
}

/// One reservation, specialized for two certificates and their shared native ancestry.
/// Four units cover cumulative admitted decode/owned projection/scratch; one covers
/// the currently read canonical frame; one the final response and one its encoder.
/// The existing fixed allowance remains reserved throughout. This phase split does
/// not by itself qualify the remaining native crypto/cache and decoded-graph owners.
/// No per-frame budget is reset or enlarged.
#[derive(Clone, Copy, Debug)]
struct CommitteeMemoryEnvelope {
    limits: NativeFinalityLimits,
    response_bytes: usize,
}

impl CommitteeMemoryEnvelope {
    fn new(working_set_bytes: usize) -> Result<Self, Response> {
        let phases = QueryFanoutMemoryEnvelope::new(working_set_bytes, 0)?;
        let unit = phases.route_body_bytes;
        // QueryFanoutMemoryEnvelope already checked the fixed allowance plus seven
        // units against the acquired reservation, so these smaller products fit.
        let limits = NativeFinalityLimits {
            block_bytes: unit.min(NATIVE_FINALITY_MAX_BLOCK_BYTES),
            journal_bytes: phases
                .final_body_bytes
                .min(NATIVE_FINALITY_MAX_JOURNAL_BYTES),
            block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
            allocated_bytes: unit * 4,
        };
        Ok(Self {
            limits,
            response_bytes: unit,
        })
    }
}

/// Serve the exact selected preparation and its immutable finality attachments.
pub(super) async fn handler_validator_committee_status(
    State(app): State<SharedAppState>,
    crate::NoritoQuery(query): crate::NoritoQuery<CommitteeStatusQuery>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Response, Error> {
    validate_api_token(app.as_ref(), &headers)?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(
        &headers,
        Some(remote.ip()),
        iroha_torii_shared::route_catalog::core::NEXUS_VALIDATOR_COMMITTEE_GET.path(),
        app.authenticated_api_token_principal(&headers),
    );
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let reservation = match try_acquire_query_fanout_memory(&app) {
        Ok(reservation) => reservation,
        Err(response) => return Ok(response),
    };
    // Committee evidence reads complete certified blocks. The ordinary name/ID
    // query source bound is only 1 KiB and cannot describe this workload. Reserve
    // a complete working set before reading State and retain it through egress.
    let envelope = match CommitteeMemoryEnvelope::new(app.query_fanout_working_set_bytes) {
        Ok(envelope) => envelope,
        Err(response) => {
            return Ok(hold_query_fanout_memory_in_response_body(
                response,
                reservation,
            ));
        }
    };
    let response_limit = envelope.response_bytes;
    let limits = envelope.limits;
    limits.validate().map_err(invalid)?;
    let state = app.state.clone();
    let worker_reservation = reservation.clone();
    let response =
        routing::run_admitted_blocking(admission, "committee status worker failed", move || {
            // A dropped HTTP future does not cancel a running blocking worker.
            let _reservation = worker_reservation;
            let view = state.view();
            let payload = norito::core::with_decode_limits_scope(
                limits.decode_limits().map_err(invalid)?,
                || load(&view, query.target_epoch, limits),
            )?;
            crate::utils::respond_with_format_bounded(payload, format, response_limit)
                .map_err(response_error)
        })
        .await?;
    let response = proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        "v1/nexus/validator-committee",
        response,
        true,
    )
    .await?;
    Ok(hold_query_fanout_memory_in_response_body(
        response,
        reservation,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::query::error::QueryExecutionFail;

    #[test]
    fn beacon_read_resource_refusal_remains_distinct_from_invalid_evidence() {
        let resource = norito::with_decode_limits(norito::DecodeLimits::new(1, 1, 1, 0, 1), || {
            norito::core::reserve_decode_allocation(1)
        })
        .expect_err("original zero allocation owner refuses its first byte");
        assert!(resource.is_decode_resource_limit());
        assert!(matches!(
            codec_error(resource),
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
        assert!(matches!(
            beacon_binding_error(GlobalThresholdBeaconError::TranscriptMismatch),
            Error::Query(iroha_data_model::ValidationFail::InternalError(message))
                if message.contains("invalid prepared committee beacon")
        ));
    }

    #[test]
    fn committee_envelope_preserves_one_working_set_and_original_fixed_allowance() {
        let fixed = query_fanout_fixed_overhead_bytes().unwrap();
        for reserved in [48 * 1024 * 1024, 64 * 1024 * 1024, 128 * 1024 * 1024] {
            let envelope = CommitteeMemoryEnvelope::new(reserved).unwrap();
            let phase = QueryFanoutMemoryEnvelope::new(reserved, 0)
                .unwrap()
                .route_body_bytes;
            assert_eq!(envelope.limits.allocated_bytes, phase * 4);
            assert_eq!(envelope.response_bytes, phase);
            assert_eq!(
                envelope.limits.block_bytes,
                phase.min(NATIVE_FINALITY_MAX_BLOCK_BYTES)
            );
            assert!(
                fixed + envelope.limits.allocated_bytes + phase + 2 * envelope.response_bytes
                    <= reserved
            );
            envelope.limits.validate().unwrap();
        }
        assert!(CommitteeMemoryEnvelope::new(fixed).is_err());
    }

    #[test]
    fn committee_world_copy_charges_encoding_and_decoded_graph_before_retry() {
        let source = vec![vec![0x37_u8; 512], vec![0x51_u8; 128]];
        let encoded = norito::canonical_frame_len(&source).unwrap();
        let copy = |budget, bound| {
            norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(65536, 65536, 65536, budget, 128),
                || {
                    let result = admitted_copy(&source, bound);
                    let norito::Error::TotalAllocationExceeded { attempted, .. } =
                        norito::core::reserve_decode_allocation(budget + 1).unwrap_err()
                    else {
                        panic!("allocation usage probe must refuse without charging");
                    };
                    (result, attempted as usize - budget - 1)
                },
            )
        };
        let (result, charged) = copy(65536, encoded);
        assert_eq!(result.unwrap(), source);
        assert!(charged >= encoded + 640 + 2 * size_of::<Vec<u8>>());
        assert_eq!(copy(charged, encoded).0.unwrap(), source);
        assert!(matches!(
            copy(charged - 1, encoded).0,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                QueryExecutionFail::GasBudgetExceeded
            )))
        ));
        let (refused, used) = copy(65536, encoded - 1);
        assert!(matches!(
            refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                QueryExecutionFail::GasBudgetExceeded
            )))
        ));
        assert_eq!(
            used, 0,
            "oversized source must refuse before its first allocation"
        );
        assert_eq!(source, [vec![0x37; 512], vec![0x51; 128]]);
        assert!(matches!(
            codec_error(norito::Error::LengthMismatch),
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
    }

    fn committee_source_with_logs(log_bytes: usize) -> CertifiedTestChain {
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::{
            isi::{InstructionBox, Log},
            level::Level,
        };
        let author = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let account_id = iroha_data_model::account::AccountId::new(author.public_key().clone());
        let account =
            iroha_data_model::account::Account::new(account_id.clone()).build(&account_id);
        let world = iroha_core::state::World::with([], [account], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        for height in 2..=3 {
            let tx = chain.sign(
                &author,
                [InstructionBox::from(Log::new(
                    Level::TRACE,
                    "q".repeat(log_bytes),
                ))],
                height * 1_000 - 1,
            );
            assert_eq!(chain.commit_at(height * 1_000, vec![tx]), [true]);
        }
        chain
    }

    #[test]
    fn validator_committee_status_large_signed_source_fits_its_reserved_envelope() {
        // This genuine source exceeds one generic decode unit while leaving room
        // for both complete source decodes, RS16 scratch and the final artifact.
        let chain = committee_source_with_logs(256 * 1024);
        let envelope = CommitteeMemoryEnvelope::new(48 * 1024 * 1024).unwrap();
        let legacy = QueryFanoutMemoryEnvelope::new(48 * 1024 * 1024, 0).unwrap();
        let view = chain.state().view();
        let read = |limits: NativeFinalityLimits| {
            norito::core::with_decode_limits_scope(limits.decode_limits().unwrap(), || {
                load(&view, None, limits)
            })
        };
        let refused = NativeFinalityLimits {
            allocated_bytes: legacy.decode_allocated_bytes,
            ..envelope.limits
        };
        assert!(
            matches!(
                read(refused),
                Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    QueryExecutionFail::CapacityLimit
                )))
            ),
            "the former generic decode unit cannot admit this genuine finalized source"
        );
        let observed = read(envelope.limits)
            .expect("same source fits the complete acquired committee envelope");
        assert_eq!(
            observed.latest_finality.block_wire,
            chain.committed(3).block().encode_wire().unwrap()
        );
        for format in [ResponseFormat::Json, ResponseFormat::Norito] {
            let observed = read(envelope.limits).unwrap();
            let response = crate::utils::respond_with_format_bounded(
                observed,
                format,
                envelope.response_bytes,
            )
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let observed = read(envelope.limits).unwrap();
            let refused = crate::utils::respond_with_format_bounded(observed, format, 1)
                .map_err(response_error);
            assert!(matches!(
                refused,
                Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    QueryExecutionFail::GasBudgetExceeded
                )))
            ));
        }
        assert!(matches!(
            response_error(crate::utils::BoundedResponseEncodeError::Serialization),
            Error::Query(iroha_data_model::ValidationFail::InternalError(_))
        ));
        let insufficient_source = NativeFinalityLimits {
            block_count: 2,
            ..envelope.limits
        };
        assert!(matches!(
            read(insufficient_source),
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            )))
        ));
        assert!(
            read(envelope.limits).is_ok(),
            "refusal must not poison canonical source storage"
        );
    }

    #[test]
    fn validator_committee_status_oversized_signed_source_refuses_without_poisoning() {
        // Measured independently with one diagnostic cumulative scope: this
        // source needs over 48 MiB of admitted work, so it must never be admitted
        // by reallocating phases within the 48 MiB total request reservation.
        let chain = committee_source_with_logs(1024 * 1024);
        let envelope = CommitteeMemoryEnvelope::new(48 * 1024 * 1024).unwrap();
        let view = chain.state().view();
        for _ in 0..2 {
            let refused = norito::core::with_decode_limits_scope(
                envelope.limits.decode_limits().unwrap(),
                || load(&view, None, envelope.limits),
            );
            assert!(matches!(
                refused,
                Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    QueryExecutionFail::CapacityLimit
                )))
            ));
        }
        assert_eq!(view.height(), 3);
        assert_eq!(chain.kura().blocks_count(), 3);
        // A bounded source refusal remains independent of disk validity. A
        // fresh native certificate read authenticates the same original tip.
        let reader = CertifiedChain::new(&view).unwrap();
        let tip = reader
            .certified_from_execution(std::num::NonZeroUsize::new(3).unwrap(), |_, _| Ok(()))
            .unwrap();
        assert_eq!(tip.block().hash(), chain.committed(3).block().hash());
    }

    #[test]
    fn validator_committee_status_charges_genesis_to_the_shared_source_limits() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(iroha_core::state::World::new(), 1_000))
                .unwrap();
        while chain.height() < 4 {
            chain.commit(Vec::new());
        }
        let lengths =
            [1, 3, 4].map(|height| chain.committed(height).block().encode_wire().unwrap().len());
        let limits = NativeFinalityLimits {
            block_bytes: *lengths.iter().max().unwrap(),
            journal_bytes: lengths.iter().sum(),
            block_count: 3,
            allocated_bytes: 128 * 1024 * 1024,
        };
        let view = chain.state().view();
        assert!(load(&view, None, limits).is_ok());
        for refused in [
            NativeFinalityLimits {
                block_count: 2,
                ..limits
            },
            NativeFinalityLimits {
                journal_bytes: limits.journal_bytes - 1,
                ..limits
            },
        ] {
            assert!(matches!(
                load(&view, None, refused),
                Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    QueryExecutionFail::CapacityLimit
                )))
            ));
        }
        assert!(
            load(&view, None, limits).is_ok(),
            "capacity refusal must preserve canonical storage for retry"
        );
    }
    #[test]
    fn committee_copy_charges_one_frame_and_its_independently_measured_decoded_graph() {
        let source = vec![0x37_u8; 64];
        let frame = norito::encode_canonical(&source).unwrap();
        let budget = 65536;
        let limits = norito::DecodeLimits::new(65536, 65536, 65536, budget, 128);
        let decoded_bytes = norito::with_decode_limits_scope(limits, || {
            assert_eq!(norito::decode_canonical::<Vec<u8>>(&frame).unwrap(), source);
            let norito::Error::TotalAllocationExceeded { attempted, .. } =
                norito::core::reserve_decode_allocation(budget + 1).unwrap_err()
            else {
                panic!("allocation usage probe must refuse without charging");
            };
            attempted as usize - budget - 1
        });
        let exact = frame.len() + decoded_bytes;
        let limits = norito::DecodeLimits::new(65536, 65536, 65536, exact, 128);
        norito::with_decode_limits_scope(limits, || {
            assert_eq!(admitted_copy(&source, frame.len()).unwrap(), source);
            assert!(
                admitted_copy(&source, frame.len()).is_err(),
                "committee copy cannot renew its inherited allowance"
            );
        });
    }
}
