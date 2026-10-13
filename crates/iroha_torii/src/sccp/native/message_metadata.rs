//! Message metadata through the original admitted native worker and response owner.

use super::*;
use crate::sccp::{ControlsQuery, OutboundQuery, RecentQuery};
use iroha_core::{
    smartcontracts::isi::sccp::read::{SccpDirectionV1, native::message_metadata as source},
    state::StateReadOnly,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Selection {
    Message([u8; 32]),
    Recent {
        direction: SccpDirectionV1,
        network: Option<SccpNetworkV1>,
        before: Option<source::RecentCursor>,
        limit: usize,
    },
    Outbound {
        network: SccpNetworkV1,
        revision: u32,
        from: u64,
        limit: usize,
    },
    Controls {
        network: SccpNetworkV1,
        revision: u32,
        after: u64,
        limit: usize,
    },
}
impl Selection {
    pub(super) fn route(self) -> RouteDescriptor {
        match self {
            Self::Message(_) => sccp::MESSAGE,
            Self::Recent { .. } => sccp::MESSAGES_RECENT,
            Self::Outbound { .. } => sccp::OUTBOUND_BY_NONCE,
            Self::Controls { .. } => sccp::CONTROLS,
        }
    }
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
        Selection::Message(id) => {
            let data = source::message(view, id, budget, control)?;
            let immutable = data.data().is_final();
            encode(data, owner, format, maximum, immutable, headers)
        }
        Selection::Recent {
            direction,
            network,
            before,
            limit,
        } => encode(
            source::recent(view, direction, network, before, limit, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Outbound {
            network,
            revision,
            from,
            limit,
        } => encode(
            source::outbound_page(view, network, revision, from, limit, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
        Selection::Controls {
            network,
            revision,
            after,
            limit,
        } => encode(
            source::controls_page(view, network, revision, after, limit, budget, control)?,
            owner,
            format,
            maximum,
            false,
            headers,
        ),
    })
}

pub async fn handler_message(
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
        super::Selection::Metadata(Selection::Message(id)),
        deadline,
        headers,
        remote,
    )
    .await
}

pub async fn handler_messages_recent(
    State(app): State<SharedAppState>,
    NoritoStringQuery(query): NoritoStringQuery<RecentQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let selection = (|| {
        let direction = crate::sccp::parse_direction(query.direction.as_deref())?;
        let network = query
            .network
            .as_deref()
            .map(crate::sccp::parse_network)
            .transpose()?;
        let limit = crate::sccp::parse_number(
            query.limit.as_deref(),
            iroha_sccp::api::MAX_RECENT_MESSAGES,
        )?;
        let before = query
            .before
            .as_deref()
            .map(|text| source::recent_cursor(direction, text))
            .transpose()
            .map_err(source_error)?;
        Ok::<_, Response>(Selection::Recent {
            direction,
            network,
            before,
            limit,
        })
    })();
    match selection {
        Ok(selection) => {
            serve(
                app,
                super::Selection::Metadata(selection),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}

pub async fn handler_outbound(
    State(app): State<SharedAppState>,
    Path((network, revision)): Path<(String, u32)>,
    NoritoStringQuery(query): NoritoStringQuery<OutboundQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let selection = (|| {
        Ok::<_, Response>(Selection::Outbound {
            network: crate::sccp::parse_network(&network)?,
            revision,
            from: crate::sccp::parse_number(query.from_nonce.as_deref(), 0_u64)?,
            limit: crate::sccp::parse_number(
                query.limit.as_deref(),
                iroha_sccp::api::MAX_OUTBOUND_PAGE,
            )?,
        })
    })();
    match selection {
        Ok(selection) => {
            serve(
                app,
                super::Selection::Metadata(selection),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}

pub async fn handler_controls(
    State(app): State<SharedAppState>,
    Path((network, revision)): Path<(String, u32)>,
    NoritoStringQuery(query): NoritoStringQuery<ControlsQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let selection = (|| {
        Ok::<_, Response>(Selection::Controls {
            network: crate::sccp::parse_network(&network)?,
            revision,
            after: crate::sccp::parse_number(query.after_nonce.as_deref(), 0_u64)?,
            limit: crate::sccp::parse_number(
                query.limit.as_deref(),
                iroha_sccp::api::MAX_CONTROLS_PAGE,
            )?,
        })
    })();
    match selection {
        Ok(selection) => {
            serve(
                app,
                super::Selection::Metadata(selection),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}
