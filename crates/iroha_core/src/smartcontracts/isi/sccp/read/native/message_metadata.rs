//! Funded message pages borrowing original account and payload graphs through encoding.

use super::*;
use crate::smartcontracts::isi::sccp::read::{SccpDirectionV1, views};
use iroha_data_model::sccp::{inbound::SccpInboundRecordV1, outbound::SccpOutboundMessageRecordV1};
use iroha_sccp::api::{self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES};
use norito::core::{Encoder, PayloadRef, SerializePayload};
use norito::json::{BoundedJsonError, JsonSerialize, JsonWriteSink};
use std::{fmt::Write as _, ops::Bound};

macro_rules! schema {
    ($view:ty, $wire:ty) => {
        impl norito::NoritoSchema for $view {
            fn nominal_name() -> String {
                <$wire as norito::NoritoSchema>::nominal_name()
            }
            fn frame_name() -> String {
                <$wire as norito::NoritoSchema>::frame_name()
            }
        }
    };
}

/// One original outbound record and its committed status scalars.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct Outbound<'a> {
    message_id: [u8; 32],
    record: PayloadRef<'a, SccpOutboundMessageRecordV1>,
    state: api::SccpOutboundStateV1,
}
/// One original inbound record, without copying its account graph.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct Inbound<'a> {
    message_id: [u8; 32],
    record: PayloadRef<'a, SccpInboundRecordV1>,
}
/// Canonical status payload retaining only original borrowed graphs.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
#[norito(tag = "direction", content = "detail")]
enum MessageDetail<'a> {
    /// Original outbound record.
    #[codec(index = 0)]
    #[norito(rename = "outbound")]
    Outbound(Outbound<'a>),
    /// Original inbound record.
    #[codec(index = 1)]
    #[norito(rename = "inbound")]
    Inbound(Inbound<'a>),
    /// No original record exists.
    #[codec(index = 2)]
    #[norito(rename = "unknown")]
    Unknown,
}
/// Canonical status frame with the owned wire type's alignment and borrowed payload.
#[repr(C)]
pub struct Message<'a> {
    detail: MessageDetail<'a>,
    // A reference loses the original record's u128 alignment. Preserve frame padding
    // without constructing or copying the canonical owned graph.
    _alignment: [api::SccpMessageStatusV1; 0],
}
schema!(Message<'_>, api::SccpMessageStatusV1);
impl SerializePayload for Message<'_> {
    fn serialize(&self, encoder: &mut Encoder<'_>) -> std::result::Result<(), norito::Error> {
        self.detail.serialize(encoder)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        self.detail.encoded_len_hint()
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        self.detail.encoded_len_exact()
    }
}
impl JsonSerialize for Message<'_> {
    fn json_serialize(&self, out: &mut String) {
        self.detail.json_serialize(out);
    }

    fn json_serialize_to(
        &self,
        out: &mut dyn JsonWriteSink,
    ) -> std::result::Result<(), BoundedJsonError> {
        self.detail.json_serialize_to(out)
    }
}
impl<'a> From<MessageDetail<'a>> for Message<'a> {
    fn from(detail: MessageDetail<'a>) -> Self {
        Self {
            detail,
            _alignment: [],
        }
    }
}
impl Message<'_> {
    /// Whether the original stored status is terminal.
    pub fn is_final(&self) -> bool {
        match &self.detail {
            MessageDetail::Outbound(row) => row.state.is_final(),
            MessageDetail::Inbound(row) => !row.record.0.status.is_pending(),
            MessageDetail::Unknown => false,
        }
    }
}

fn outbound(
    id: [u8; 32],
    record: &SccpOutboundMessageRecordV1,
    committed: Option<u64>,
) -> Outbound<'_> {
    Outbound {
        message_id: id,
        record: PayloadRef(record),
        state: views::outbound_state(record, committed),
    }
}

/// Borrow one message from the original captured view.
/// # Errors
/// Preserves original budget, cancellation and deadline refusal.
pub fn message<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    id: [u8; 32],
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Message<'a>>> {
    deadline_check(control)?;
    let charge = budget.try_reserve_bytes(size_of::<Message<'_>>())?;
    let world = view.world();
    let data = if let Some(row) = store::outbound_messages::get(world, &id) {
        MessageDetail::Outbound(outbound(id, row, views::committed_height(view)))
    } else if let Some(row) = store::inbound_messages::get(world, &id) {
        MessageDetail::Inbound(Inbound {
            message_id: id,
            record: PayloadRef(row),
        })
    } else {
        MessageDetail::Unknown
    };
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: data.into(),
        _charge: charge,
    })
}

/// Funded outbound page with original borrowed record graphs.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct OutboundPage<'a> {
    network: SccpNetworkV1,
    revision: u32,
    next_outbound_nonce: u64,
    records: Vec<Outbound<'a>>,
    next_from_nonce: Option<u64>,
}
schema!(OutboundPage<'_>, api::SccpOutboundPageV1);

fn rows<T>(limit: usize) -> Result<Vec<T>> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(limit)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    Ok(rows)
}

/// Read bounded outbound records under one caller-pool admission.
/// # Errors
/// Preserves missing source, budget, cancellation and deadline refusal.
pub fn outbound_page<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    from_nonce: u64,
    limit: usize,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<OutboundPage<'a>>> {
    deadline_check(control)?;
    let world = view.world();
    let next_outbound_nonce = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .ok_or(SccpNativeReadError::NotFound("route revision"))?
        .next_outbound_nonce;
    let limit = limit.clamp(1, MAX_OUTBOUND_PAGE);
    let charge = budget
        .try_reserve_bytes(size_of::<OutboundPage<'_>>() + limit * size_of::<Outbound<'_>>())?;
    let mut data = OutboundPage {
        network,
        revision,
        next_outbound_nonce,
        records: rows(limit)?,
        next_from_nonce: None,
    };
    let committed = views::committed_height(view);
    for ((_, _, nonce), id) in store::outbound_by_nonce::range(
        world,
        (network, revision, from_nonce)..=(network, revision, u64::MAX),
    ) {
        deadline_check(control)?;
        if data.records.len() == limit {
            data.next_from_nonce = Some(*nonce);
            break;
        }
        let record = store::outbound_messages::get(world, id).ok_or(
            SccpNativeReadError::Unavailable("indexed outbound record absent"),
        )?;
        data.records.push(outbound(*id, record, committed));
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// Read scalar controls under one caller-pool admission.
/// # Errors
/// Preserves missing source, budget, cancellation and deadline refusal.
pub fn controls_page(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    after_nonce: u64,
    limit: usize,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<api::SccpControlPageV1>> {
    deadline_check(control)?;
    let world = view.world();
    let next_control_nonce = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .ok_or(SccpNativeReadError::NotFound("route revision"))?
        .next_control_nonce;
    let limit = limit.clamp(1, MAX_CONTROLS_PAGE);
    let charge = budget.try_reserve_bytes(
        size_of::<api::SccpControlPageV1>() + limit * size_of::<api::SccpControlViewV1>(),
    )?;
    let mut data = api::SccpControlPageV1 {
        network,
        revision,
        next_control_nonce,
        controls: rows(limit)?,
        next_after_nonce: None,
    };
    let committed = views::committed_height(view);
    for ((_, _, nonce), record) in store::control_messages::range(
        world,
        (
            Bound::Excluded((network, revision, after_nonce)),
            Bound::Included((network, revision, u64::MAX)),
        ),
    ) {
        deadline_check(control)?;
        if data.controls.len() == limit {
            data.next_after_nonce = data.controls.last().map(|row| row.control_nonce);
            break;
        }
        data.controls.push(api::SccpControlViewV1 {
            control_nonce: *nonce,
            record: *record,
            provable: committed.is_some_and(|tip| record.height != 0 && record.height <= tip),
        });
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

/// One typed, fixed-size recent-message cursor, held inline for either direction.
#[derive(Debug, Clone, Copy)]
pub struct RecentCursor {
    direction: SccpDirectionV1,
    height: u64,
    index: u32,
    message_id: [u8; 32],
}
/// Parse the canonical cursor without allocating a decoded byte vector.
/// # Errors
/// Refuses malformed text or a direction mismatch.
pub fn recent_cursor(direction: SccpDirectionV1, text: &str) -> Result<RecentCursor> {
    let (height, rest) = text
        .split_once(':')
        .ok_or(SccpNativeReadError::Request("recent cursor"))?;
    let height = height
        .parse()
        .map_err(|_| SccpNativeReadError::Request("recent cursor height"))?;
    match direction {
        SccpDirectionV1::Outbound => Ok(RecentCursor {
            direction,
            height,
            index: rest
                .parse()
                .map_err(|_| SccpNativeReadError::Request("recent cursor index"))?,
            message_id: [0; 32],
        }),
        SccpDirectionV1::Inbound => {
            let mut id = [0; 32];
            hex::decode_to_slice(rest, &mut id)
                .map_err(|_| SccpNativeReadError::Request("recent cursor message id"))?;
            Ok(RecentCursor {
                direction,
                height,
                index: 0,
                message_id: id,
            })
        }
    }
}

/// Funded bounded recent page borrowing each original record.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct RecentPage<'a> {
    messages: Vec<Message<'a>>,
    next_before: Option<String>,
}
schema!(RecentPage<'_>, api::SccpRecentMessagesV1);

fn cursor_text(height: u64, index: Option<u32>, id: Option<[u8; 32]>) -> Result<String> {
    let mut text = String::new();
    text.try_reserve_exact(85)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    write!(&mut text, "{height}:").map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    if let Some(index) = index {
        write!(&mut text, "{index}").map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    }
    if let Some(id) = id {
        let mut encoded = [0; 64];
        hex::encode_to_slice(id, &mut encoded)
            .map_err(|_| SccpNativeReadError::Invalid("cursor width"))?;
        text.push_str(
            std::str::from_utf8(&encoded)
                .map_err(|_| SccpNativeReadError::Invalid("cursor encoding"))?,
        );
    }
    Ok(text)
}

/// Scan original indices with bounded inline selection and funded borrowed row backing.
/// # Errors
/// Preserves cursor, budget, cancellation and source deadline refusal.
pub fn recent<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    direction: SccpDirectionV1,
    network: Option<SccpNetworkV1>,
    before: Option<RecentCursor>,
    limit: usize,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<RecentPage<'a>>> {
    deadline_check(control)?;
    let limit = limit.clamp(1, MAX_RECENT_MESSAGES);
    let charge = budget
        .try_reserve_bytes(size_of::<RecentPage<'_>>() + limit * size_of::<Message<'_>>() + 85)?;
    let mut data = RecentPage {
        messages: rows(limit)?,
        next_before: None,
    };
    let world = view.world();
    match direction {
        SccpDirectionV1::Outbound => {
            let upper = match before {
                None => Bound::Unbounded,
                Some(cursor) if cursor.direction == SccpDirectionV1::Outbound => {
                    Bound::Excluded((cursor.height, cursor.index))
                }
                _ => return Err(SccpNativeReadError::Request("recent cursor direction")),
            };
            let committed = views::committed_height(view);
            for (scanned, ((height, index), leaf)) in
                store::block_leaves::range(world, (Bound::Unbounded, upper))
                    .rev()
                    .enumerate()
            {
                deadline_check(control)?;
                if data.messages.len() == limit || scanned == views::MAX_RECENT_SCAN {
                    data.next_before =
                        Some(cursor_text(*height, Some(index.saturating_add(1)), None)?);
                    break;
                }
                let iroha_data_model::sccp::control::SccpLeafRefV1::Transfer(leaf) = leaf else {
                    continue;
                };
                let Some(record) = store::outbound_messages::get(world, &leaf.message_id) else {
                    continue;
                };
                if network.is_some_and(|network| network != record.network) {
                    continue;
                }
                data.messages.push(
                    MessageDetail::Outbound(outbound(leaf.message_id, record, committed)).into(),
                );
            }
        }
        SccpDirectionV1::Inbound => {
            let before = match before {
                None => None,
                Some(cursor) if cursor.direction == SccpDirectionV1::Inbound => {
                    Some((cursor.height, cursor.message_id))
                }
                _ => return Err(SccpNativeReadError::Request("recent cursor direction")),
            };
            let mut selected = [(0_u64, [0_u8; 32]); MAX_RECENT_MESSAGES];
            let mut len = 0;
            let mut more = false;
            for (id, record) in store::inbound_messages::iter(world) {
                deadline_check(control)?;
                let key = (record.proven_at_height, *id);
                if network.is_some_and(|network| network != record.network)
                    || before.is_some_and(|before| key >= before)
                {
                    continue;
                }
                let insertion = selected[..len].partition_point(|old| *old > key);
                if len == limit {
                    more = true;
                    if insertion == limit {
                        continue;
                    }
                }
                let end = len.min(limit - 1);
                selected.copy_within(insertion..end, insertion + 1);
                selected[insertion] = key;
                len = (len + 1).min(limit);
            }
            for (height, id) in &selected[..len] {
                deadline_check(control)?;
                let record = store::inbound_messages::get(world, id).ok_or(
                    SccpNativeReadError::Unavailable("selected inbound record absent"),
                )?;
                data.messages.push(
                    MessageDetail::Inbound(Inbound {
                        message_id: *id,
                        record: PayloadRef(record),
                    })
                    .into(),
                );
                if more && data.messages.len() == len {
                    data.next_before = Some(cursor_text(*height, None, Some(*id))?);
                }
            }
        }
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}
