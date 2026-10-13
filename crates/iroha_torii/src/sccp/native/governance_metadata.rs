//! Governance metadata through the original admitted worker and response transport owner.

use super::*;
use iroha_core::{
    smartcontracts::isi::sccp::read::native::governance_metadata as source, state::StateView,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Selection {
    Registry,
    Revisions,
    Readiness,
    Proposals,
    Proposal([u8; 32]),
}
impl Selection {
    pub(super) fn route(self) -> RouteDescriptor {
        match self {
            Self::Registry => sccp::REGISTRY,
            Self::Revisions => sccp::GOVERNANCE,
            Self::Readiness => sccp::GOVERNANCE_READINESS,
            Self::Proposals => sccp::GOVERNANCE_PROPOSALS,
            Self::Proposal(_) => sccp::GOVERNANCE_PROPOSAL,
        }
    }
}

pub(super) fn produce(
    selection: Selection,
    view: &StateView<'_>,
    budget: &iroha_allocation::AllocationBudget,
    control: SccpNativeReadControl<'_>,
    owner: &HistoryProducerOwner,
    (format, maximum): (ResponseFormat, usize),
    headers: &HeaderMap,
) -> Result<Result<PreparedResponse, Error>, SccpNativeReadError> {
    Ok(match selection {
        Selection::Registry => encode(
            source::registry(view, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Revisions => encode(
            source::revisions(view, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Readiness => encode(
            source::readiness(view, &view.gov, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Proposals => encode(
            source::proposals(view, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Proposal(id) => encode(
            source::proposal(view, id, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
    })
}

pub async fn handler_registry(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(
        app,
        super::Selection::Governance(Selection::Registry),
        deadline,
        headers,
        remote,
    )
    .await
}

pub async fn handler_governance(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(
        app,
        super::Selection::Governance(Selection::Revisions),
        deadline,
        headers,
        remote,
    )
    .await
}

pub async fn handler_governance_proposals(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(
        app,
        super::Selection::Governance(Selection::Proposals),
        deadline,
        headers,
        remote,
    )
    .await
}

pub async fn handler_governance_proposal(
    State(app): State<SharedAppState>,
    Path(id): Path<String>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let id = match crate::sccp::parse_word(&id) {
        Ok(id) => id,
        Err(response) => return Ok(response),
    };
    serve(
        app,
        super::Selection::Governance(Selection::Proposal(id)),
        deadline,
        headers,
        remote,
    )
    .await
}

/// Read governance readiness through the admitted original-view response owner.
pub async fn handler_governance_readiness(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(
        app,
        super::Selection::Governance(Selection::Readiness),
        deadline,
        headers,
        remote,
    )
    .await
}
