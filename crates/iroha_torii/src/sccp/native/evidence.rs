//! Evidence reads share the original admitted metadata worker, pool and deadline.

use super::*;
use iroha_core::{
    smartcontracts::isi::sccp::read::native::evidence as source, state::StateReadOnly,
};

#[derive(Debug, Clone, Copy)]
pub(super) enum Selection {
    Detail([u8; 32]),
    Page {
        after: Option<[u8; 32]>,
        limit: usize,
    },
}
impl Selection {
    pub(super) fn route(self) -> RouteDescriptor {
        match self {
            Self::Detail(_) => sccp::EVIDENCE,
            Self::Page { .. } => sccp::EVIDENCE_PAGE,
        }
    }
}
/// Strict textual cursor and bound, without JSON scalar coercion.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceQuery {
    /// Exclusive original evidence-id cursor.
    #[norito(default)]
    pub after: Option<String>,
    /// Number of rows in 1..=64, default 64.
    #[norito(default)]
    pub limit: Option<String>,
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn selection(query: &EvidenceQuery) -> Result<Selection, Response> {
    let after = query
        .after
        .as_deref()
        .map(crate::sccp::parse_word)
        .transpose()?;
    let limit = query
        .limit
        .as_deref()
        .map(decimal)
        .transpose()?
        .unwrap_or(iroha_sccp::api::MAX_EVIDENCE_PAGE as u64);
    let limit =
        usize::try_from(limit).map_err(|_| invalid("evidence limit exceeds local extent"))?;
    if !(1..=iroha_sccp::api::MAX_EVIDENCE_PAGE).contains(&limit) {
        return Err(invalid("evidence limit must be in 1..=64"));
    }
    Ok(Selection::Page { after, limit })
}
pub(super) fn produce(
    selection: Selection,
    view: &impl StateReadOnly,
    budget: &iroha_allocation::AllocationBudget,
    control: SccpNativeReadControl<'_>,
    owner: &HistoryProducerOwner,
    (format, maximum): (ResponseFormat, usize),
    headers: &HeaderMap,
) -> Result<Result<PreparedResponse, Error>, SccpNativeReadError> {
    Ok(match selection {
        Selection::Detail(id) => encode(
            source::detail(view, id, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Page { after, limit } => encode(
            source::page(view, after, limit, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
    })
}
/// Read one original SCCP evidence status through the funded source owner.
pub async fn handler_evidence(
    State(app): State<SharedAppState>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    if query.as_deref().is_some_and(|query| !query.is_empty()) {
        return Ok(invalid("evidence detail accepts no query parameters"));
    }
    match crate::sccp::parse_word(&id) {
        Ok(id) => {
            serve(
                app,
                super::Selection::Evidence(Selection::Detail(id)),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}
/// Read a bounded page of original SCCP evidence status rows.
pub async fn handler_evidence_page(
    State(app): State<SharedAppState>,
    NoritoStringQuery(query): NoritoStringQuery<EvidenceQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match selection(&query) {
        Ok(selection) => {
            serve(
                app,
                super::Selection::Evidence(selection),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_selectors_preserve_exact_cursor_and_reject_unbounded_queries() {
        assert!(matches!(
            selection(&EvidenceQuery::default()),
            Ok(Selection::Page {
                after: None,
                limit: 64
            })
        ));
        for limit in ["0", "65", "-1", "1.0", "18446744073709551616"] {
            assert!(
                selection(&EvidenceQuery {
                    limit: Some(limit.into()),
                    ..Default::default()
                })
                .is_err()
            );
        }
        assert!(
            selection(&EvidenceQuery {
                after: Some("bad".into()),
                ..Default::default()
            })
            .is_err()
        );
        assert!(matches!(
            selection(&EvidenceQuery {
                after: Some("12".repeat(32)),
                limit: Some("1".into())
            }),
            Ok(Selection::Page {
                after: Some(after),
                limit: 1
            }) if after == [0x12; 32]
        ));
    }
}
