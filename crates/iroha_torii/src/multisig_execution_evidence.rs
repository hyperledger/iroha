//! Bounded data-only publication of immutable multisig records from a certified pre-tail cut.
use super::*;
use iroha_core::{
    smartcontracts::isi::multisig::{
        multisig_approval_outcome_state_key, multisig_proposal_terminal_execution_state_key,
    },
    state::AllocationBudget,
    sumeragi::certified_chain::{CertifiedChain, QcVerification},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{account::AccountId, isi::InstructionBox};
use iroha_executor_data_model::isi::multisig::MultisigProposalId;
use iroha_torii_shared::multisig_execution_evidence::{
    MULTISIG_EXECUTION_EVIDENCE_MAX_BYTES_V1, MultisigExecutionEvidenceRefV1,
};
use norito::json::{BoundedJsonError, JsonSerialize as _, JsonWriteSink};
use std::str::FromStr;
const ROUTE: &str =
    iroha_torii_shared::multisig_execution_evidence::MULTISIG_EXECUTION_EVIDENCE_PATH_V1;

pub(super) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((account, entrypoint, proposal, instructions)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let (account, entrypoint, proposal, instructions) =
        selectors(&account, &entrypoint, &proposal, &instructions)?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([u64::try_from(bytes).map_err(|_| capacity())?])
        .ok_or_else(capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let max_response = app
        .torii_proxy_max_response_bytes
        .min(MULTISIG_EXECUTION_EVIDENCE_MAX_BYTES_V1);
    let state = app.state.clone();
    let response = routing::run_admitted_blocking(
        admission,
        "multisig execution evidence worker failed",
        move || {
            let memory = memory;
            let view = state.view();
            let height = u64::try_from(view.height()).map_err(|_| unavailable())?;
            if height < 2 {
                return Err(unavailable());
            }
            let chain = CertifiedChain::new(&view).map_err(|_| unavailable())?;
            let certified = chain.certified(height).map_err(|_| unavailable())?;
            if certified.verification() != QcVerification::Verified {
                return Err(unavailable());
            }
            let tip = certified.into_committed();
            let context_id = Hash::prehashed(*tip.id().0.as_ref());
            drop(chain);
            drop(view);
            let keys = [
                multisig_approval_outcome_state_key(entrypoint, &account, &proposal),
                multisig_proposal_terminal_execution_state_key(entrypoint, &account, &proposal),
            ];
            let mut body = state
                .with_native_multisig_execution_snapshot_v1(
                    &tip,
                    &keys,
                    &budget,
                    |snapshot, outcome, terminal, target| {
                        let payload = MultisigExecutionEvidenceRefV1::new(
                            &height,
                            &context_id,
                            &account,
                            &entrypoint,
                            &proposal,
                            &instructions,
                            snapshot,
                            outcome,
                            terminal,
                            target,
                        );
                        encode(&payload, format, max_response, &budget)
                            .map_err(|_| "multisig execution evidence serialization refused".into())
                    },
                )
                .map_err(|_| unavailable())?;
            body.memory = Some(memory);
            let mut response = AxResponse::new(Body::from(Bytes::from_owner(body)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(match format {
                    ResponseFormat::Norito => "application/x-norito",
                    ResponseFormat::Json => "application/json",
                }),
            );
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            Ok(response)
        },
    )
    .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await
}
fn selectors(
    account: &str,
    entrypoint: &str,
    proposal: &str,
    instructions: &str,
) -> Result<
    (
        AccountId,
        [u8; 32],
        MultisigProposalId,
        HashOf<Vec<InstructionBox>>,
    ),
    Error,
> {
    if account.is_empty()
        || account.len() > 1024
        || [entrypoint, proposal, instructions].iter().any(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(conversion_error(
            "multisig execution selectors must be exact bounded native identities".into(),
        ));
    }
    let native = AccountId::parse_encoded(account)
        .map_err(|_| conversion_error("invalid canonical multisig account".into()))?;
    if native.to_string() != account {
        return Err(conversion_error(
            "multisig account must be canonical".into(),
        ));
    }
    let entrypoint = Hash::from_str(entrypoint)
        .map_err(|_| conversion_error("invalid native entrypoint hash".into()))?;
    let instructions = HashOf::<Vec<InstructionBox>>::from_str(instructions)
        .map_err(|_| conversion_error("invalid native instructions hash".into()))?;
    let proposal = proposal
        .parse()
        .map_err(|_| conversion_error("invalid proposal occurrence".into()))?;
    Ok((native, *entrypoint.as_ref(), proposal, instructions))
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {code: "multisig_execution_evidence_unavailable", message: "Both immutable execution records are not yet available in the current certified native cut.".into()}
}
fn capacity() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
    ))
}
struct EncodedBody {
    bytes: iroha_allocation::ChargedBuffer<u8>,
    memory: Option<QueryFanoutMemoryReservation>,
}
impl AsRef<[u8]> for EncodedBody {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
struct ChargedWriter(iroha_allocation::ChargedBuffer<u8>);
impl std::io::Write for ChargedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity().saturating_sub(self.0.as_slice().len()) {
            return Err(std::io::Error::other("native response length changed"));
        }
        for byte in bytes {
            self.0.push_reserved(*byte);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl JsonWriteSink for ChargedWriter {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        std::io::Write::write_all(self, value.as_bytes())
            .map_err(|_| BoundedJsonError::LengthMismatch)
    }
}
struct CountJson {
    length: usize,
    limit: usize,
    depth: usize,
}
impl JsonWriteSink for CountJson {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        let next = self
            .length
            .checked_add(value.len())
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if next > self.limit {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.length = next;
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if next >= norito::json::MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}
fn encode(
    payload: &MultisigExecutionEvidenceRefV1<'_>,
    format: ResponseFormat,
    limit: usize,
    budget: &AllocationBudget,
) -> Result<EncodedBody, Error> {
    let length = match format {
        ResponseFormat::Norito => {
            norito::canonical_frame_len(payload).map_err(|_| unavailable())?
        }
        ResponseFormat::Json => {
            let mut count = CountJson {
                length: 0,
                limit,
                depth: 0,
            };
            payload
                .json_serialize_to(&mut count)
                .map_err(|_| capacity())?;
            count.length
        }
    };
    if length > limit {
        return Err(capacity());
    }
    let bytes = iroha_allocation::ChargedBuffer::new(length, budget).map_err(|_| capacity())?;
    let mut writer = ChargedWriter(bytes);
    match format {
        ResponseFormat::Norito => norito::core::write_canonical_to_writer(payload, &mut writer)
            .map_err(|_| unavailable())?,
        ResponseFormat::Json => payload
            .json_serialize_to(&mut writer)
            .map_err(|_| unavailable())?,
    }
    if writer.0.as_slice().len() != length {
        return Err(unavailable());
    }
    Ok(EncodedBody {
        bytes: writer.0,
        memory: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_selectors_admit_exact_native_identities_and_refuse_alternate_spellings() {
        let account = iroha_test_samples::ALICE_ID.to_string();
        let entrypoint = Hash::new(b"actual selector encoding")
            .to_string()
            .to_ascii_lowercase();
        let instructions = HashOf::new(&Vec::<InstructionBox>::new())
            .to_string()
            .to_ascii_lowercase();
        let occurrence = "11".repeat(32);
        let (selected, hash, id, proposal) =
            selectors(&account, &entrypoint, &occurrence, &instructions).unwrap();
        assert_eq!(id.to_string(), occurrence);
        assert_eq!(selected.to_string(), account);
        assert_eq!(hash, *Hash::from_str(&entrypoint).unwrap().as_ref());
        assert_eq!(proposal.to_string().to_ascii_lowercase(), instructions);
        for wrong in [
            entrypoint.to_ascii_uppercase(),
            format!(" {entrypoint}"),
            format!("{entrypoint}00"),
        ] {
            assert!(selectors(&account, &wrong, &occurrence, &instructions).is_err());
        }
        assert!(
            selectors(
                &format!(" {account}"),
                &entrypoint,
                &occurrence,
                &instructions
            )
            .is_err()
        );
        assert!(selectors(&account, &entrypoint, &occurrence, "1").is_err());
    }
    #[test]
    fn bounded_native_body_never_allocates_a_replacement_pool_on_growth() {
        use std::io::Write as _;
        let budget = AllocationBudget::new(3);
        let mut writer = ChargedWriter(iroha_allocation::ChargedBuffer::new(3, &budget).unwrap());
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        let body = Bytes::from_owner(EncodedBody {
            bytes: writer.0,
            memory: None,
        });
        assert!(budget.reserved_bytes() > 0);
        drop(body);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
