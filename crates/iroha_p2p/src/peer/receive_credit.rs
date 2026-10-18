//! Receiver-issued reservations for one-message authenticated transport records.
//!
//! A grant owns source bytes, alignment scratch, dispatch bytes and one exact
//! occurrence before its header may be written. No capacity acquisition remains
//! between a granted data header and its payload. The unique reader owns every
//! unspent grant; delivered guards retain the `PeerId` registry owner after reconnect.
//!
//! Production peer startup requires authenticated geometry and the grant stream.
//! TODO: compile and qualify the composed actor/post/subscriber/consumer owners
//! with the native retention, malformed-frame and real peer lifecycle controls.

pub(super) mod negotiation;
pub(super) mod record;
pub(super) mod stream;
#[cfg(test)]
mod tests;

use super::*;
use crate::{TransportAdmissionClass as Class, network::message::ClassifyTopic};
use message::{AuthenticatedSourceCreditGuard, AuthenticatedSourceCredits};
use record::{Header, Kind};

/// Maximum fixed native parser, request, grant and writer cells per tenure.
/// This is charged once against the existing per-PeerId progress reserve.
const CONTROL_BYTES: usize = 64 * 1024;
/// Conservative per-message envelope allowance, including the bounded header.
pub(super) const ENVELOPE_BYTES: usize = record::HEADER_CAP + 4 + 64;
const CLASS_COUNT: usize = Class::ALL.len();

/// The per-source partitions are shared by current and draining tenures.
#[derive(Debug)]
pub(super) struct SourcePartition {
    pub(super) geometry: [u8; 32],
    counts: [Arc<SharedByteBudget>; CLASS_COUNT],
    control_cells: Arc<SharedByteBudget>,
    _cells: SharedByteLease,
    fallback: [Arc<SharedByteBudget>; CLASS_COUNT],
}

/// Shared class sublimits over the existing physical byte pools.
#[derive(Debug)]
pub struct Pool {
    frames: InboundFrameByteBudgets,
    dispatch: InboundDispatchByteBudgets,
    geometry: [u8; 32],
    max_plaintext: [usize; CLASS_COUNT],
    class_bytes: [Arc<SharedByteBudget>; CLASS_COUNT],
    counts: [usize; CLASS_COUNT],
    fallback: [usize; CLASS_COUNT],
    changed: Notify,
    /// Streams currently waiting for released capacity to grant a request.
    ///
    /// Releases wake `changed` only while this is non-zero, so ordinary
    /// traffic never wakes every peer task on every delivered message.
    blocked: AtomicUsize,
}

fn partition(total: usize, index: usize, shares: usize) -> usize {
    total / shares + usize::from(index < total % shares)
}

impl Pool {
    /// Partition the configured pools without increasing any aggregate ceiling.
    /// Six nonzero ordinary-high count shares require `per_lane_count >= 6`.
    /// Every primary byte share must admit its declared maximum frame. Private
    /// fallback funds source, scratch and dispatch together from P; its maximum
    /// is `(private_class_bytes / 3) - ENVELOPE_BYTES`, never the global maximum. Configuration owners must invoke this before opening listeners.
    pub(crate) fn new(
        frames: InboundFrameByteBudgets,
        dispatch: InboundDispatchByteBudgets,
        per_lane_count: usize,
        max_plaintext: [usize; CLASS_COUNT],
    ) -> Result<Arc<Self>, Error> {
        if per_lane_count > Semaphore::MAX_PERMITS
            || per_lane_count
                .checked_mul(3)
                .and_then(|n| n.checked_mul(frames.source_geometry.max_sources))
                .is_none()
        {
            return Err(Error::Format);
        }
        if per_lane_count < Class::ORDINARY_HIGH.len()
            || frames.progress_reserve_bytes_per_peer <= CONTROL_BYTES
        {
            return Err(Error::Format);
        }
        let mut counts = [0; CLASS_COUNT];
        let mut byte_caps = [0; CLASS_COUNT];
        let mut fallback = [0; CLASS_COUNT];
        for class in Class::ALL {
            let i = class.index();
            let bytes = max_plaintext[i]
                .checked_add(ENVELOPE_BYTES)
                .ok_or(Error::FrameTooLarge)?;
            if max_plaintext[i] == 0 {
                return Err(Error::Format);
            }
            counts[i] = match class {
                Class::Safety => per_lane_count,
                class if class.is_low() => {
                    partition(per_lane_count, i - Class::HIGH.len(), Class::LOW.len())
                }
                _ => partition(per_lane_count, i - 1, Class::ORDINARY_HIGH.len()),
            };
            byte_caps[i] = if class.is_low() {
                partition(
                    frames.low.max_bytes,
                    i - Class::HIGH.len(),
                    Class::LOW.len(),
                )
                .min(partition(
                    frames.low_decode_scratch.max_bytes,
                    i - Class::HIGH.len(),
                    Class::LOW.len(),
                ))
                .min(partition(
                    dispatch.low.max_bytes,
                    i - Class::HIGH.len(),
                    Class::LOW.len(),
                ))
            } else {
                partition(frames.high.max_bytes, i, Class::HIGH.len())
                    .min(partition(
                        frames.high_decode_scratch.max_bytes,
                        i,
                        Class::HIGH.len(),
                    ))
                    .min(partition(dispatch.high.max_bytes, i, Class::HIGH.len()))
            };
            if bytes > byte_caps[i] {
                return Err(Error::FrameTooLarge);
            }
        }
        // Fund the protected Safety maximum completely first. All other high
        // classes retain a positive minimal private rank. Distribute only the
        // checked residual.
        let available = frames
            .progress_reserve_bytes_per_peer
            .checked_sub(CONTROL_BYTES)
            .ok_or(Error::Format)?;
        let mut required = 0usize;
        for class in Class::HIGH {
            let payload = if class == Class::Safety {
                max_plaintext[class.index()]
            } else {
                1
            };
            let minimum = payload
                .checked_add(ENVELOPE_BYTES)
                .and_then(|n| n.checked_mul(3))
                .ok_or(Error::FrameTooLarge)?;
            fallback[class.index()] = minimum;
            required = required.checked_add(minimum).ok_or(Error::FrameTooLarge)?;
        }
        let residual = available
            .checked_sub(required)
            .ok_or(Error::FrameTooLarge)?;
        for (i, value) in fallback[..Class::HIGH.len()].iter_mut().enumerate() {
            *value = value
                .checked_add(partition(residual, i, Class::HIGH.len()))
                .ok_or(Error::FrameTooLarge)?;
        }
        // The Safety maximum must fit its private corridor.
        let safety_private_maximum = (fallback[Class::Safety.index()] / 3)
            .checked_sub(ENVELOPE_BYTES)
            .ok_or(Error::FrameTooLarge)?;
        if max_plaintext[Class::Safety.index()] > safety_private_maximum {
            return Err(Error::FrameTooLarge);
        }
        // The existing dispatch safety reserve is part of its total, not extra
        // capacity. The ordinary-high shares must fit its ordinary ceiling.
        let ordinary = byte_caps[1..Class::HIGH.len()]
            .iter()
            .try_fold(0usize, |a, b| a.checked_add(*b))
            .ok_or(Error::Format)?;
        if ordinary > dispatch.high.class_max_bytes(false) {
            return Err(Error::Format);
        }
        let encoded = norito::core::to_bytes(&(
            1u8,
            counts.map(|n| n as u64),
            byte_caps.map(|n| n as u64),
            fallback.map(|n| n as u64),
            max_plaintext.map(|n| n as u64),
        ))
        .map_err(Error::NoritoCodec)?;
        let geometry = iroha_crypto::Hash::new(&encoded).into();
        let cache = Arc::clone(&frames.receive_credit_pool);
        let mut existing = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pool) = existing.upgrade() {
            if pool.geometry != geometry
                || !Arc::ptr_eq(&pool.dispatch.high, &dispatch.high)
                || !Arc::ptr_eq(&pool.dispatch.low, &dispatch.low)
            {
                return Err(Error::Format);
            }
            return Ok(pool);
        }
        let class_bytes =
            byte_caps.map(|n| SharedByteBudget::new(n, 0).expect("validated nonzero sublimit"));
        let pool = Arc::new(Self {
            frames,
            dispatch,
            geometry,
            max_plaintext,
            class_bytes,
            counts,
            fallback,
            changed: Notify::new(),
            blocked: AtomicUsize::new(0),
        });
        *existing = Arc::downgrade(&pool);
        Ok(pool)
    }

    /// Largest complete canonical frame guaranteed by this class's private P
    /// partition when its own byte/count owners are available. All three byte
    /// allocations are charged; this is never a maximum-Topic-size promise.
    #[cfg(test)]
    pub(super) fn private_maximum(&self, class: Class) -> Option<usize> {
        if class.is_low() {
            return None;
        }
        (self.fallback[class.index()] / 3).checked_sub(ENVELOPE_BYTES)
    }

    /// Bind one authenticated source to the existing strong `PeerId` count owner.
    /// Control cells are reserved before constructing a reader or writer.
    pub(super) fn bind(self: &Arc<Self>, peer: &PeerId) -> Result<BoundSource, Error> {
        let credits = self
            .frames
            .source_credits(peer, self.counts[0])
            .ok_or(Error::Format)?;
        if credits.receive_capacity() < Class::ORDINARY_HIGH.len()
            || self.counts[0] != credits.receive_capacity()
        {
            return Err(Error::Format);
        }
        let source = self.frames.high(peer).ok_or(Error::Format)?;
        let reserve = source.peer_reserve.ok_or(Error::Format)?;
        let partition = credits.receive_partition(self.geometry, || {
            let cells = reserve
                .try_reserve(CONTROL_BYTES, false)
                .ok_or(Error::Format)?;
            Ok(SourcePartition {
                geometry: self.geometry,
                counts: self
                    .counts
                    .map(|n| SharedByteBudget::new(n, 0).expect("nonzero count partition")),
                control_cells: SharedByteBudget::new(CONTROL_BYTES, 0)
                    .expect("fixed control partition"),
                _cells: cells,
                // Zero Low fallback is inert and never selected.
                fallback: self.fallback.map(|n| {
                    SharedByteBudget::new(n.max(1), 0).expect("bounded fallback partition")
                }),
            })
        })?;
        // One active reader per PeerId; the base cell lease lives as long as
        // any delivered source guard, including the shared source metadata.
        let control_limit = partition
            .control_cells
            .try_reserve(CONTROL_BYTES, false)
            .ok_or(Error::Format)?;
        Ok(BoundSource {
            peer: peer.clone(),
            pool: Arc::clone(self),
            credits,
            partition,
            reserve,
            _control_limit: control_limit,
        })
    }
}

/// One control-cell lease per connection tenure; not cloneable.
#[derive(Debug)]
pub(super) struct BoundSource {
    peer: PeerId,
    pool: Arc<Pool>,
    credits: AuthenticatedSourceCredits,
    partition: Arc<SourcePartition>,
    reserve: Arc<SharedByteBudget>,
    _control_limit: SharedByteLease,
}

impl BoundSource {
    fn reserve(&self, class: Class, plaintext: usize) -> Option<Reservation> {
        let i = class.index();
        if plaintext == 0 || plaintext > self.pool.max_plaintext[i] {
            return None;
        }
        let bytes = plaintext.checked_add(ENVELOPE_BYTES)?;
        let count = self.partition.counts[i].try_reserve(1, false)?;
        let credit = self.credits.try_receive_count(class)?;
        let high = !class.is_low();
        let (primary, scratch, dispatch) = if high {
            (
                &self.pool.frames.high,
                &self.pool.frames.high_decode_scratch,
                &self.pool.dispatch.high,
            )
        } else {
            (
                &self.pool.frames.low,
                &self.pool.frames.low_decode_scratch,
                &self.pool.dispatch.low,
            )
        };
        // Every failed primary attempt drops its partial leases before trying
        // the separate PeerId corridor. No global class or scratch prerequisite
        // is retained by the fallback path.
        let primary = (|| {
            let class_bytes = self.pool.class_bytes[i].try_reserve(bytes, false)?;
            Some((
                class_bytes,
                primary.try_reserve(bytes, false)?,
                scratch.try_reserve(bytes, false)?,
                dispatch.try_reserve(bytes, class == Class::Safety)?,
            ))
        })();
        let (class_bytes, source, scratch, dispatch, private) = match primary {
            Some((class_bytes, source, scratch, dispatch)) => {
                (Some(class_bytes), source, scratch, dispatch, None)
            }
            None if high => {
                // P already belongs to the configured total physical envelope.
                // Its private class share funds all three allocations, so an
                // unrelated peer's global source/scratch/dispatch cannot block
                // a request within this smaller admitted fallback maximum.
                let total = bytes.checked_mul(3)?;
                if total > self.pool.fallback[i] {
                    return None;
                }
                let private = self.partition.fallback[i].try_reserve(total, false)?;
                (
                    None,
                    self.reserve.try_reserve(bytes, false)?,
                    self.reserve.try_reserve(bytes, false)?,
                    self.reserve.try_reserve(bytes, false)?,
                    Some(private),
                )
            }
            None => return None,
        };
        Some(Reservation {
            class,
            plaintext,
            scratch: Some(scratch),
            retention: GrantRetention {
                class,
                _pool: Arc::clone(&self.pool),
                _credits: self.credits.clone(), // strong registry owner survives all tenures
                _partition: Arc::clone(&self.partition),
                _credit: credit,
                _count: count,
                class_bytes,
                _source: source,
                _private: private,
                _dispatch: dispatch,
                _released: ReleaseNotify(Arc::clone(&self.pool)),
            },
        })
    }
}

/// A grant's permanent leases move through `PeerMessage` into its final consumer.
#[derive(Debug)]
pub(super) struct GrantRetention {
    pub(super) class: Class,
    _pool: Arc<Pool>,
    _credits: AuthenticatedSourceCredits,
    _partition: Arc<SourcePartition>,
    _credit: AuthenticatedSourceCreditGuard,
    _count: SharedByteLease,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "class custody is released only when the retained grant drops"
        )
    )]
    class_bytes: Option<SharedByteLease>,
    _source: SharedByteLease,
    _private: Option<SharedByteLease>,
    _dispatch: SharedByteLease,
    _released: ReleaseNotify,
}
#[derive(Debug)]
struct ReleaseNotify(Arc<Pool>);
impl Drop for ReleaseNotify {
    fn drop(&mut self) {
        // This is the final field: all byte/count subleases are already
        // released. A waiter registers in `blocked` before it retries its
        // reservation, so either that retry observes this release or this
        // load observes the registration (both are `SeqCst` and the budgets
        // are mutex-ordered between them); no wake-up can be lost.
        if self.0.blocked.load(Ordering::SeqCst) > 0 {
            self.0.changed.notify_waiters();
        }
    }
}
/// Registration of one stream that waits for released receive capacity.
///
/// Create it, then enable the `changed` notification, then retry the
/// reservation; drop it once the stream stops waiting.
pub(super) struct BlockedOnRelease<'a>(&'a Pool);
impl<'a> BlockedOnRelease<'a> {
    pub(super) fn register(pool: &'a Pool) -> Self {
        pool.blocked.fetch_add(1, Ordering::SeqCst);
        Self(pool)
    }
}
impl Drop for BlockedOnRelease<'_> {
    fn drop(&mut self) {
        self.0.blocked.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Single-use exact byte/count ownership; cannot be cloned or reconstructed.
struct Reservation {
    class: Class,
    plaintext: usize,
    scratch: Option<SharedByteLease>,
    retention: GrantRetention,
}
impl Reservation {
    fn delivered<T: Pload>(
        mut self,
        peer: iroha_data_model::peer::Peer,
        payload: T,
        connection: ConnectionId,
    ) -> message::PeerMessage<T> {
        // Canonical decoding finished. Source and dispatch leases remain held.
        self.scratch.take();
        message::PeerMessage::from_receive_grant(
            peer,
            payload,
            self.plaintext,
            connection,
            self.retention,
        )
    }
}

struct PendingGrant {
    header: Header,
    reservation: Reservation,
}

/// The unique stream reader owns unspent grants. Dropping it first closes the
/// reader, then releases the ledger; no clone or standalone revoke can reclaim
/// a grant while a reader still has authority to consume its data record.
struct Ledger {
    // Source/control cells drop last, after all unspent grants are reclaimed.
    requests: [Option<Header>; CLASS_COUNT],
    grants: [Option<PendingGrant>; CLASS_COUNT],
    next: [u64; CLASS_COUNT],
    cursor: usize,
    source: BoundSource,
}
impl Ledger {
    fn new(source: BoundSource) -> Self {
        Self {
            source,
            requests: [None; CLASS_COUNT],
            grants: std::array::from_fn(|_| None),
            next: [1; CLASS_COUNT],
            cursor: 0,
        }
    }
    /// Whether a received request still waits for its grant.
    fn has_ungranted_request(&self) -> bool {
        self.requests.iter().any(Option::is_some)
    }
    fn request(&mut self, header: Header) -> Result<(), Error> {
        let i = header.class()?.index();
        if header.kind()? != Kind::Request
            || header.sequence != self.next[i]
            || self.requests[i].is_some()
            || self.grants[i].is_some()
        {
            return Err(Error::Format);
        }
        if usize::try_from(header.plaintext).map_err(|_| Error::Format)?
            > self.source.pool.max_plaintext[i]
        {
            return Err(Error::FrameTooLarge);
        }
        self.requests[i] = Some(header);
        Ok(())
    }
    fn next_grant(&mut self) -> Result<Option<Header>, Error> {
        // Every class has one bounded pending request and one round-robin rank.
        // A blocked request of one class does not block another, and a continuous
        // source of one class cannot skip a ready request of another indefinitely.
        for offset in 0..Class::SCHEDULE.len() {
            let rank = (self.cursor + offset) % Class::SCHEDULE.len();
            let i = Class::SCHEDULE[rank].index();
            let Some(request) = self.requests[i] else {
                continue;
            };
            let size = usize::try_from(request.plaintext).map_err(|_| Error::Format)?;
            let Some(reservation) = self.source.reserve(request.class()?, size) else {
                continue;
            };
            let grant = request.with_kind(Kind::Grant);
            self.grants[i] = Some(PendingGrant {
                header: grant,
                reservation,
            });
            self.requests[i] = None;
            self.cursor = (rank + 1) % Class::SCHEDULE.len();
            return Ok(Some(grant));
        }
        Ok(None)
    }
    fn consume(&mut self, data: &Header) -> Result<Reservation, Error> {
        let i = data.class()?.index();
        let grant = self.grants[i].as_ref().ok_or(Error::Format)?;
        if data.kind()? != Kind::Data || grant.header.with_kind(Kind::Data) != *data {
            return Err(Error::Format);
        }
        let next = self.next[i].checked_add(1).ok_or(Error::Format)?;
        let grant = self.grants[i].take().expect("exact grant just compared");
        self.next[i] = next;
        Ok(grant.reservation)
    }
}

/// Fixed writer partitions replace the previous connection-local frame pools.
/// Network startup checks local maxima; negotiation can only reduce them.
pub fn writer_partitions(
    maximum: [usize; CLASS_COUNT],
    limits: OutboundFrameQueueLimits,
) -> Result<[usize; CLASS_COUNT], Error> {
    // These replace the old per-connection plaintext/encrypted queue pools.
    // At most one post per class plus its encryption copy is resident.
    let mut bytes = [0; CLASS_COUNT];
    for (i, maximum) in maximum.iter().enumerate() {
        if *maximum == 0 {
            return Err(Error::Format);
        }
        bytes[i] = maximum
            .checked_mul(2)
            .and_then(|n| n.checked_add(ENVELOPE_BYTES))
            .ok_or(Error::FrameTooLarge)?;
    }
    let high = bytes[..Class::HIGH.len()]
        .iter()
        .try_fold(CONTROL_BYTES, |a, b| a.checked_add(*b))
        .ok_or(Error::FrameTooLarge)?;
    let low = Class::LOW
        .into_iter()
        .try_fold(0usize, |sum, class| sum.checked_add(bytes[class.index()]))
        .ok_or(Error::FrameTooLarge)?;
    if high > limits.high_max_bytes
        || low > limits.low_max_bytes
        || limits.high_max_frames < Class::HIGH.len()
        || limits.low_max_frames < Class::LOW.len()
    {
        return Err(Error::FrameTooLarge);
    }
    Ok(bytes)
}
