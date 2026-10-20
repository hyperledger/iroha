//! One-record sender/reader service over the authenticated ordered connection.
//! Control records use the tenure's precharged cells, never data grants.
use super::*;
use record::Binding;
use tokio::time::Instant;

#[cfg(feature = "bench")]
#[path = "benchmark.rs"]
pub mod benchmark;

struct Queued {
    header: Header,
    /// Canonical encoded payload. It is sealed into its single wire buffer
    /// only when the grant arrives, so encoding and sealing a large post never
    /// block this peer task back to back: the Request record (and any due
    /// Ping/Pong) leaves in between, keeping the remote idle timer fed.
    plaintext: Vec<u8>,
    ownership: OutboundPostOwnership,
    bytes: SharedByteLease,
    requested: bool,
    granted: bool,
}
/// One complete record being written: `u32 header length || header || sealed body`.
struct Writing {
    record: Vec<u8>,
    offset: usize,
    class: Option<Class>,
    ownership: Option<OutboundPostOwnership>,
    _bytes: Option<SharedByteLease>,
}
impl Writing {
    /// A transport-control record with an authenticated empty body.
    fn control<E: Enc>(
        crypto: &cryptographer::Cryptographer<E>,
        header: Header,
    ) -> Result<Self, Error> {
        Ok(Self {
            record: record::seal_record(crypto, &header, &[])?,
            offset: 0,
            class: None,
            ownership: None,
            _bytes: None,
        })
    }
    /// A granted Data record, sealed now into one wire buffer. The send charge
    /// covers the plaintext and this sealed copy while both briefly coexist.
    fn data<E: Enc>(
        crypto: &cryptographer::Cryptographer<E>,
        queued: Queued,
        class: Class,
    ) -> Result<Self, Error> {
        let record = record::seal_record(
            crypto,
            &queued.header.with_kind(Kind::Data),
            &queued.plaintext,
        )?;
        Ok(Self {
            record,
            offset: 0,
            class: Some(class),
            ownership: Some(queued.ownership),
            _bytes: Some(queued.bytes),
        })
    }
    async fn advance(
        &mut self,
        write: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<bool, Error> {
        if self.offset < self.record.len() {
            // One contiguous buffer: the transport sees the whole record at
            // once instead of separate prefix, header and body writes.
            let written = write.write(&self.record[self.offset..]).await?;
            if written == 0 {
                return Err(Error::Io(
                    std::io::Error::from(std::io::ErrorKind::WriteZero).into(),
                ));
            }
            self.offset += written;
        }
        if self.offset != self.record.len() {
            return Ok(false);
        }
        // Cancellation after the final write resumes this flush, never rewrites
        // the record or acknowledges an unflushed post.
        write.flush().await?;
        if let Some(owner) = self.ownership.take() {
            owner.acknowledge_flush();
        }
        Ok(true)
    }
}

/// Largest receive buffer kept between records. It is part of the fixed
/// per-tenure parser cells charged by `CONTROL_BYTES`; larger records use a
/// fresh buffer that is released after decoding.
const RETAINED_RECEIVE_BYTES: usize = 16 * 1024;

/// Incremental reader of one record. Every completed offset is committed
/// before another await, so a cancelled read resumes exactly.
struct Reading {
    prefix: [u8; 4],
    prefix_read: usize,
    header: [u8; record::HEADER_CAP],
    header_len: usize,
    header_read: usize,
    parsed: Option<Header>,
    /// Sealed body storage, positioned so the decrypted payload is aligned
    /// for zero-copy canonical decoding.
    body: Vec<u8>,
    body_start: usize,
    body_len: usize,
    body_read: usize,
    reservation: Option<Reservation>,
}
/// Position of a sealed body inside `buffer` whose plaintext, `nonce` bytes
/// after its start, begins at a multiple of `align` (a power of two).
pub(super) fn aligned_body_start(buffer: &[u8], nonce: usize, align: usize) -> usize {
    let misalignment = (buffer.as_ptr() as usize).wrapping_add(nonce) % align;
    (align - misalignment) % align
}
impl Reading {
    fn new() -> Self {
        Self {
            prefix: [0; 4],
            prefix_read: 0,
            header: [0; record::HEADER_CAP],
            header_len: 0,
            header_read: 0,
            parsed: None,
            body: Vec::new(),
            body_start: 0,
            body_len: 0,
            body_read: 0,
            reservation: None,
        }
    }
    /// Read toward one complete record; `Ok(true)` once it is complete.
    async fn advance<E: Enc>(
        &mut self,
        read: &mut (dyn AsyncRead + Send + Unpin),
        ledger: &mut Ledger,
        binding: &Binding,
        align: usize,
    ) -> Result<bool, Error> {
        // Each await performs one cancellation-safe `read`. Every completed
        // offset is committed before another await or return.
        if self.prefix_read < 4 {
            let n = read.read(&mut self.prefix[self.prefix_read..]).await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.prefix_read += n;
            if self.prefix_read != 4 {
                return Ok(false);
            }
            let length = u32::from_be_bytes(self.prefix) as usize;
            if length == 0 || length > record::HEADER_CAP {
                return Err(Error::Format);
            }
            self.header_len = length;
            self.header_read = 0;
            return Ok(false);
        }
        if self.parsed.is_none() {
            let n = read
                .read(&mut self.header[self.header_read..self.header_len])
                .await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.header_read += n;
            if self.header_read != self.header_len {
                return Ok(false);
            }
            let header = Header::decode(&self.header[..self.header_len])?;
            let expected = if matches!(header.kind()?, Kind::Grant | Kind::Pong) {
                &binding.outgoing
            } else {
                &binding.incoming
            };
            header.check(expected)?;
            let plaintext = if header.kind()? == Kind::Data {
                // This exact existing reservation is consumed before allocating
                // any variable-size payload. No semaphore or byte wait follows.
                self.reservation = Some(ledger.consume(&header)?);
                usize::try_from(header.plaintext).map_err(|_| Error::Format)?
            } else {
                0
            };
            let encrypted = record::encrypted_len::<E>(plaintext)?;
            let needed = encrypted.checked_add(align).ok_or(Error::FrameTooLarge)?;
            if needed > self.body.capacity().max(RETAINED_RECEIVE_BYTES) {
                // A large granted body gets its own zeroed allocation (lazily
                // zeroed by the allocator), released after decoding.
                self.body = vec![0; needed];
            } else {
                self.body.clear();
                self.body.resize(needed, 0);
            }
            self.body_start =
                aligned_body_start(&self.body, core::mem::size_of::<aead::Nonce<E>>(), align);
            self.body_len = encrypted;
            self.body_read = 0;
            self.parsed = Some(header);
            if encrypted != 0 {
                return Ok(false);
            }
        }
        if self.body_read < self.body_len {
            let from = self.body_start + self.body_read;
            let to = self.body_start + self.body_len;
            let n = read.read(&mut self.body[from..to]).await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.body_read += n;
            if self.body_read != self.body_len {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Release the completed record's state, keeping a small buffer.
    fn reset(&mut self) {
        self.prefix_read = 0;
        self.header_len = 0;
        self.header_read = 0;
        self.parsed = None;
        self.body_start = 0;
        self.body_len = 0;
        self.body_read = 0;
        self.reservation = None;
        self.body.clear();
        if self.body.capacity() > RETAINED_RECEIVE_BYTES {
            self.body = Vec::new();
        }
    }
}

/// Full concrete stream framing component. The parent run-loop integration must
/// replace both old `MessageSender` and `MessageReader`; it must not wrap only one.
/// There is no legacy frame parser or optional protocol switch in this owner.
///
/// Readiness is defined per semantic class, so an ungranted Payload post does not
/// prevent enqueuing another class or emitting the bounded grant-control path.
pub(in crate::peer) struct CreditStream<E: Enc, T: Pload + ClassifyTopic> {
    // Field order matters: the read half is dropped before the unspent ledger.
    read: Box<dyn AsyncRead + Send + Unpin>,
    write: Box<dyn AsyncWrite + Send + Unpin>,
    reading: Reading,
    writing: Option<Writing>,
    ledger: Ledger,
    queued: [Option<Queued>; CLASS_COUNT],
    send_bytes: [Arc<SharedByteBudget>; CLASS_COUNT],
    maximum: [usize; CLASS_COUNT],
    next: [u64; CLASS_COUNT],
    cursor: usize,
    binding: Binding,
    crypto: cryptographer::Cryptographer<E>,
    peer: iroha_data_model::peer::Peer,
    connection: ConnectionId,
    caps: crate::network::TopicFrameCaps,
    failed: bool,
    ping: Option<(Header, bool)>,
    pong: Option<Header>,
    next_ping: u64,
    next_peer_ping: u64,
    authenticated_records: u64,
    remote_pings: run::InboundPingLimiter,
    _type: std::marker::PhantomData<T>,
}
/// Negotiated frame limits and liveness policy installed on one credit stream.
pub(in crate::peer) struct CreditStreamConfig {
    pub(in crate::peer) caps: crate::network::TopicFrameCaps,
    pub(in crate::peer) maximum: [usize; CLASS_COUNT],
    pub(in crate::peer) limits: OutboundFrameQueueLimits,
    pub(in crate::peer) idle_timeout: Duration,
}

impl<E: Enc, T: Pload + ClassifyTopic> CreditStream<E, T> {
    /// Construct only after verifying the signed mandatory record/geometry
    /// handshake. Local/remote class maxima are independent admissions.
    pub(in crate::peer) fn new(
        transport: negotiation::OwnedTransport,
        binding: Binding,
        crypto: cryptographer::Cryptographer<E>,
        peer: iroha_data_model::peer::Peer,
        connection: ConnectionId,
        CreditStreamConfig {
            caps,
            maximum,
            limits,
            idle_timeout,
        }: CreditStreamConfig,
    ) -> Result<Self, Error> {
        // NET1 restores the rejected constructor's premature source release.
        #[cfg(all(test, sumeragi_p2p_mutation = "NET1"))]
        let negotiation::OwnedTransport {
            read,
            write,
            source,
        } = transport;
        #[cfg(all(test, sumeragi_p2p_mutation = "NET1"))]
        let peer_matches = source.peer == *peer.id();
        #[cfg(not(all(test, sumeragi_p2p_mutation = "NET1")))]
        let peer_matches = transport.source.peer == *peer.id();
        if !peer_matches {
            return Err(Error::Format);
        }
        if record::encrypted_len::<E>(0)? > 64 {
            return Err(Error::Format);
        }
        let bytes = super::writer_partitions(maximum, limits)?;
        // Keep read/write/source in their ordered owner until every fallible
        // admission has passed. Rejection must close I/O before source reuse.
        #[cfg(not(all(test, sumeragi_p2p_mutation = "NET1")))]
        let negotiation::OwnedTransport {
            read,
            write,
            source,
        } = transport;
        Ok(Self {
            read,
            write,
            reading: Reading::new(),
            writing: None,
            ledger: Ledger::new(source),
            queued: std::array::from_fn(|_| None),
            send_bytes: bytes
                .map(|n| SharedByteBudget::new(n, 0).expect("validated send partition")),
            maximum,
            next: [1; CLASS_COUNT],
            cursor: 0,
            binding,
            crypto,
            peer,
            connection,
            caps,
            failed: false,
            ping: None,
            pong: None,
            next_ping: 1,
            next_peer_ping: 1,
            authenticated_records: 0,
            remote_pings: run::InboundPingLimiter::new(Instant::now(), idle_timeout),
            _type: std::marker::PhantomData,
        })
    }
    /// Only fully authenticated, structurally valid inbound records refresh idle time.
    pub(in crate::peer) fn authenticated_records(&self) -> u64 {
        self.authenticated_records
    }
    #[cfg(test)]
    pub(super) fn probe_pending(&self) -> bool {
        self.ping.is_some()
    }

    /// One bounded probe at a time. Probes never borrow application grants.
    pub(in crate::peer) fn request_ping(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Format);
        }
        if self.ping.is_none() {
            self.ping = Some((Header::ping(self.binding.outgoing, self.next_ping)?, false));
        }
        Ok(())
    }
    pub(in crate::peer) fn can_enqueue(&self, class: Class) -> bool {
        !self.failed
            && self.queued[class.index()].is_none()
            && self.writing.as_ref().and_then(|w| w.class) != Some(class)
    }
    /// A blocked post is returned intact. Invalid encoding also returns its
    /// actual owner; the caller must preserve/report failure, never retry with
    /// a synthesized ownership token or drop an accepted upstream occurrence.
    #[expect(
        clippy::result_large_err,
        reason = "capacity refusal returns the original retained post without a new allocation or loss of upstream custody"
    )]
    pub(in crate::peer) fn enqueue(
        &mut self,
        post: RetainedPost<T>,
    ) -> Result<(), (Error, RetainedPost<T>)> {
        let payload = post.message.as_ref().expect("unconsumed post");
        let class = payload.admission_class();
        let i = class.index();
        if !self.can_enqueue(class) {
            return Err((Error::Format, post));
        }
        let length = match run::receive_credit_encoded_len::<T, E>(payload, self.maximum[i]) {
            Ok(n) => n,
            Err(e) => return Err((e, post)),
        };
        if length > self.caps.for_topic(payload.topic()) {
            return Err((Error::InboundTopicCapExceeded, post));
        }
        let charge = match length
            .checked_mul(2)
            .and_then(|n| n.checked_add(ENVELOPE_BYTES))
        {
            Some(n) => n,
            None => return Err((Error::FrameTooLarge, post)),
        };
        let Some(bytes) = self.send_bytes[i].try_reserve(charge, false) else {
            return Err((Error::Format, post));
        };
        let mut plaintext = Vec::with_capacity(length);
        if let Err(e) = run::receive_credit_encode(payload, &mut plaintext) {
            return Err((e, post));
        }
        if plaintext.len() != length {
            return Err((Error::Format, post));
        }
        let header = match Header::request(self.binding.outgoing, class, self.next[i], length) {
            Ok(h) => h,
            Err(e) => return Err((e, post)),
        };
        // Sealing waits for the grant (`Writing::data`): the Request leaves
        // between the two CPU-heavy steps, so a large post never stalls the
        // remote's liveness view for their combined duration.
        let (_, ownership) = post.into_parts();
        self.queued[i] = Some(Queued {
            header,
            plaintext,
            ownership,
            bytes,
            requested: false,
            granted: false,
        });
        Ok(())
    }
    fn schedule(&mut self) -> Result<(), Error> {
        // Weighted fixed ranks include bounded Ping/Pong. Control chatter cannot
        // exclude an eligible application rank on an honest completing stream.
        const RANKS: usize = Class::SCHEDULE.len() * 3 + 2;
        if self.writing.is_some() {
            return Ok(());
        }
        for offset in 0..RANKS {
            let rank = (self.cursor + offset) % RANKS;
            let i = if rank < Class::SCHEDULE.len() * 3 {
                Class::SCHEDULE[rank / 3].index()
            } else {
                0
            };
            let writing = if rank == Class::SCHEDULE.len() * 3 {
                let Some((header, sent)) = self.ping.as_mut().filter(|(_, sent)| !*sent) else {
                    continue;
                };
                let writing = Writing::control(&self.crypto, *header)?;
                *sent = true;
                writing
            } else if rank == Class::SCHEDULE.len() * 3 + 1 {
                let Some(header) = self.pong.take() else {
                    continue;
                };
                Writing::control(&self.crypto, header)?
            } else {
                match rank % 3 {
                    0 => {
                        let Some(post) = self.queued[i].as_mut().filter(|p| !p.requested) else {
                            continue;
                        };
                        let record = Writing::control(&self.crypto, post.header)?;
                        post.requested = true;
                        record
                    }
                    1 => {
                        if !self.queued[i].as_ref().is_some_and(|p| p.granted) {
                            continue;
                        }
                        let post = self.queued[i].take().expect("checked granted post");
                        let class = post.header.class()?;
                        Writing::data(&self.crypto, post, class)?
                    }
                    _ => {
                        let Some(header) = self.ledger.next_grant()? else {
                            continue;
                        };
                        Writing::control(&self.crypto, header)?
                    }
                }
            };
            self.writing = Some(writing);
            self.cursor = (rank + 1) % RANKS;
            return Ok(());
        }
        Ok(())
    }
    /// Authenticate and apply the record completed by `self.reading`.
    fn receive(&mut self) -> Result<Option<PeerMessage<T>>, Error> {
        let header = self.reading.parsed.take().ok_or(Error::Format)?;
        let reservation = self.reading.reservation.take();
        let header_bytes = self.reading.header;
        let header_len = self.reading.header_len;
        let (start, len) = (self.reading.body_start, self.reading.body_len);
        let mut body = core::mem::take(&mut self.reading.body);
        let outcome = self.receive_sealed(
            header,
            reservation,
            &header_bytes[..header_len],
            &mut body[start..start + len],
        );
        self.reading.body = body;
        self.reading.reset();
        outcome
    }
    fn receive_sealed(
        &mut self,
        header: Header,
        mut reservation: Option<Reservation>,
        header_bytes: &[u8],
        sealed: &mut [u8],
    ) -> Result<Option<PeerMessage<T>>, Error> {
        let plaintext = record::open(&self.crypto, header_bytes, sealed)?;
        let outcome = match header.kind()? {
            Kind::Ping => {
                if !plaintext.is_empty()
                    || self.pong.is_some()
                    || header.sequence != self.next_peer_ping
                    || !self.remote_pings.admit_at(Instant::now())
                {
                    return Err(Error::Format);
                }
                self.next_peer_ping = self.next_peer_ping.checked_add(1).ok_or(Error::Format)?;
                self.pong = Some(header.with_kind(Kind::Pong));
                None
            }
            Kind::Pong => {
                if !plaintext.is_empty()
                    || !self
                        .ping
                        .as_ref()
                        .is_some_and(|(ping, sent)| *sent && ping.with_kind(Kind::Pong) == header)
                {
                    return Err(Error::Format);
                }
                // This exact authenticated response retires the sole local probe.
                // It does not spend or replenish the remote Ping request budget.
                self.next_ping = self.next_ping.checked_add(1).ok_or(Error::Format)?;
                self.ping = None;
                None
            }
            Kind::Request => {
                if !plaintext.is_empty() {
                    return Err(Error::Format);
                }
                self.ledger.request(header)?;
                None
            }
            Kind::Grant => {
                if !plaintext.is_empty() {
                    return Err(Error::Format);
                }
                let post = self.queued[header.class()?.index()]
                    .as_mut()
                    .ok_or(Error::Format)?;
                if !post.requested || post.granted || post.header.with_kind(Kind::Grant) != header {
                    return Err(Error::Format);
                }
                post.granted = true;
                None
            }
            Kind::Data => {
                let reservation = reservation.take().ok_or(Error::Format)?;
                if plaintext.len() != reservation.plaintext {
                    return Err(Error::Format);
                }
                let decoded =
                    run::receive_credit_decode::<T>(plaintext, reservation.class, self.caps)?;
                Some(reservation.delivered(self.peer.clone(), decoded, self.connection))
            }
        };
        self.authenticated_records = self
            .authenticated_records
            .checked_add(1)
            .ok_or(Error::Format)?;
        Ok(outcome)
    }
    /// Service real read/write halves and local released-credit wakeups. Every
    /// error fences this tenure. A caller may drop it only after retaining its
    /// failure outcome; resuming its partially consumed ledger is forbidden.
    pub(in crate::peer) async fn step(&mut self) -> Result<Option<PeerMessage<T>>, Error> {
        if self.failed {
            return Err(Error::Format);
        }
        let result = self.step_inner().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn step_inner(&mut self) -> Result<Option<PeerMessage<T>>, Error> {
        // Only a received request that may still lack a grant can be unblocked
        // by capacity released elsewhere. Such a stream registers and enables
        // its wake-up before examining reservations; the shared pool wakes
        // registered waiters only after actual leases are released
        // (ReleaseNotify). Streams with nothing to grant never register, so a
        // release does not wake every peer task.
        let pool = Arc::clone(&self.ledger.source.pool);
        let changed = pool.changed.notified();
        tokio::pin!(changed);
        let awaiting_capacity = self.ledger.has_ungranted_request();
        let _registration =
            awaiting_capacity.then(|| super::BlockedOnRelease::register(pool.as_ref()));
        if awaiting_capacity {
            changed.as_mut().enable();
        }
        self.schedule()?;
        let align = ncore::archived_payload_align::<T>().max(1);
        tokio::select! {
            complete = self.reading.advance::<E>(&mut *self.read, &mut self.ledger, &self.binding, align) => {
                if complete? { self.receive() } else { Ok(None) }
            }
            done = async {
                match &mut self.writing { Some(w) => w.advance(&mut *self.write).await, None => std::future::pending().await }
            } => {
                if done? {
                    let completed = self.writing.take().expect("completed writer");
                    if let Some(class) = completed.class {
                        self.next[class.index()] = self.next[class.index()].checked_add(1).ok_or(Error::Format)?;
                    }
                }
                Ok(None)
            }
            () = &mut changed, if awaiting_capacity => Ok(None),
        }
    }
}

#[cfg(test)]
#[tokio::test]
async fn malformed_tag_fences_reader_without_delivery_or_unspent_grant_reuse() {
    use super::tests::{crypto, peer, pool, used};
    use crate::network::admission_class_tests::AdmissionFixture as Fixture;
    use iroha_crypto::encryption::ChaCha20Poly1305;
    let p = pool(3);
    let remote = peer(31);
    let local = peer(32);
    let cipher = crypto();
    let binding = Binding::verified(
        &test_network_id("malformed grant data"),
        local.id(),
        remote.id(),
        cipher.session_binding,
        [71; 32],
        p.geometry,
        p.geometry,
    )
    .unwrap();
    let incoming = binding.incoming;
    let (mut raw, receiver) = tokio::io::duplex(7);
    let (read, write) = tokio::io::split(receiver);
    let mut stream = CreditStream::<ChaCha20Poly1305, Fixture>::new(
        negotiation::OwnedTransport {
            read: Box::new(read),
            write: Box::new(write),
            source: p.bind(remote.id()).unwrap(),
        },
        binding,
        cipher.clone(),
        remote.clone(),
        99,
        CreditStreamConfig {
            caps: crate::network::TopicFrameCaps::uniform(1024),
            maximum: [1024; CLASS_COUNT],
            limits: OutboundFrameQueueLimits::new_with_progress_reserve(
                256 * 1024,
                128 * 1024,
                256 * 1024,
                32,
                32,
            ),
            idle_timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let mut plaintext = Vec::new();
    run::receive_credit_encode(&Fixture::Payload(1), &mut plaintext).unwrap();
    let request = Header::request(incoming, Class::Payload, 1, plaintext.len()).unwrap();
    stream.ledger.request(request).unwrap();
    let grant = stream.ledger.next_grant().unwrap().unwrap();
    stream
        .ledger
        .request(Header::request(incoming, Class::Lane, 1, 200).unwrap())
        .unwrap();
    stream.ledger.next_grant().unwrap().unwrap();
    let (header, mut ciphertext) =
        record::seal(&cipher, &grant.with_kind(Kind::Data), &plaintext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    let send = async {
        raw.write_all(&u32::try_from(header.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        raw.write_all(&header).await.unwrap();
        raw.write_all(&ciphertext).await.unwrap();
    };
    let receive = async {
        loop {
            match stream.step().await {
                Ok(None) => {}
                Ok(Some(_)) => panic!("forged AEAD data reached the application"),
                Err(_) => break,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(send, receive);
    })
    .await
    .unwrap();
    assert!(stream.failed);
    assert_eq!(
        stream.authenticated_records(),
        0,
        "unauthenticated partial bytes never refresh idle liveness"
    );
    assert!(stream.step().await.is_err());
    assert!(
        p.bind(remote.id()).is_err(),
        "failed but unclosed reader still owns its control tenure"
    );
    assert_eq!(
        used(&stream.ledger.source.partition.counts[Class::Lane.index()]),
        1,
        "unspent grant remains owned until reader close"
    );
    drop(stream);
    let next = p.bind(remote.id()).unwrap();
    assert!(next.reserve(Class::Lane, 200).is_some());
}

#[cfg(test)]
#[tokio::test]
async fn data_record_is_sealed_when_granted_not_when_enqueued() {
    use super::tests::{crypto, peer, pool};
    use crate::network::admission_class_tests::AdmissionFixture as Fixture;
    use iroha_crypto::encryption::ChaCha20Poly1305;
    let p = pool(3);
    let remote = peer(35);
    let local = peer(36);
    let cipher = crypto();
    let binding = Binding::verified(
        &test_network_id("grant-time data sealing"),
        local.id(),
        remote.id(),
        cipher.session_binding,
        [73; 32],
        p.geometry,
        p.geometry,
    )
    .unwrap();
    let outgoing = binding.outgoing;
    let (_raw, transport) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(transport);
    let mut stream = CreditStream::<ChaCha20Poly1305, Fixture>::new(
        negotiation::OwnedTransport {
            read: Box::new(read),
            write: Box::new(write),
            source: p.bind(remote.id()).unwrap(),
        },
        binding,
        cipher.clone(),
        remote.clone(),
        102,
        CreditStreamConfig {
            caps: crate::network::TopicFrameCaps::uniform(1024),
            maximum: [1024; CLASS_COUNT],
            limits: OutboundFrameQueueLimits::new_with_progress_reserve(
                256 * 1024,
                128 * 1024,
                256 * 1024,
                32,
                32,
            ),
            idle_timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let mut expected = Vec::new();
    run::receive_credit_encode(&Fixture::Payload(7), &mut expected).unwrap();
    let (post, _flush_ack) = super::tests::post(Fixture::Payload(7));
    assert!(stream.enqueue(post).is_ok());
    let queued = stream.queued[Class::Payload.index()]
        .as_mut()
        .expect("enqueued post");
    assert_eq!(
        queued.plaintext, expected,
        "enqueue keeps the canonical plaintext; sealing waits for the grant"
    );
    queued.requested = true;
    queued.granted = true;
    stream.schedule().unwrap();
    let writing = stream.writing.as_ref().expect("granted data is scheduled");
    assert_eq!(writing.class, Some(Class::Payload));
    let record = &writing.record;
    let header_len = u32::from_be_bytes(record[..4].try_into().unwrap()) as usize;
    let header_bytes = &record[4..4 + header_len];
    assert_eq!(
        Header::decode(header_bytes).unwrap(),
        Header::request(outgoing, Class::Payload, 1, expected.len())
            .unwrap()
            .with_kind(Kind::Data)
    );
    let mut sealed = record[4 + header_len..].to_vec();
    assert_eq!(
        &*record::open(&cipher, header_bytes, &mut sealed).unwrap(),
        expected.as_slice(),
        "the grant-time record carries exactly the enqueued plaintext"
    );
}

#[cfg(test)]
#[tokio::test]
async fn authenticated_health_burst_keeps_original_limit_and_cannot_refresh_idle_forever() {
    use super::tests::{crypto, peer, pool};
    use crate::network::admission_class_tests::AdmissionFixture as Fixture;
    use iroha_crypto::encryption::ChaCha20Poly1305;
    let p = pool(3);
    let remote = peer(33);
    let local = peer(34);
    let cipher = crypto();
    let binding = Binding::verified(
        &test_network_id("bounded native health controls"),
        local.id(),
        remote.id(),
        cipher.session_binding,
        [72; 32],
        p.geometry,
        p.geometry,
    )
    .unwrap();
    let incoming = binding.incoming;
    let (mut raw, receiver) = tokio::io::duplex(7);
    let (read, write) = tokio::io::split(receiver);
    let mut stream = CreditStream::<ChaCha20Poly1305, Fixture>::new(
        negotiation::OwnedTransport {
            read: Box::new(read),
            write: Box::new(write),
            source: p.bind(remote.id()).unwrap(),
        },
        binding,
        cipher.clone(),
        remote.clone(),
        100,
        CreditStreamConfig {
            caps: crate::network::TopicFrameCaps::uniform(1024),
            maximum: [1024; CLASS_COUNT],
            limits: OutboundFrameQueueLimits::new_with_progress_reserve(
                256 * 1024,
                128 * 1024,
                256 * 1024,
                32,
                32,
            ),
            idle_timeout: Duration::from_secs(20),
        },
    )
    .unwrap();
    let sender = async {
        for sequence in 1..=3 {
            let (header, ciphertext) =
                record::seal(&cipher, &Header::ping(incoming, sequence).unwrap(), &[]).unwrap();
            raw.write_all(&u32::try_from(header.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            raw.write_all(&header).await.unwrap();
            raw.write_all(&ciphertext).await.unwrap();
            if sequence < 3 {
                let length = raw.read_u32().await.unwrap() as usize;
                assert!(length <= record::HEADER_CAP);
                let mut reply_header = vec![0; length];
                raw.read_exact(&mut reply_header).await.unwrap();
                let mut reply = vec![0; record::encrypted_len::<ChaCha20Poly1305>(0).unwrap()];
                raw.read_exact(&mut reply).await.unwrap();
                assert!(
                    record::open(&cipher, &reply_header, &mut reply)
                        .unwrap()
                        .is_empty()
                );
            }
        }
    };
    let receiver = async {
        loop {
            match stream.step().await {
                Ok(None) => {}
                Ok(Some(_)) => panic!("transport health is not application data"),
                Err(_) => break,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
    assert!(stream.failed);
    assert_eq!(
        stream.authenticated_records(),
        2,
        "excess authenticated health must not refresh idle liveness"
    );
    drop(stream);
    assert!(p.bind(remote.id()).is_ok());
}

#[cfg(test)]
mod health_tests;

#[cfg(test)]
mod constructor_tests {
    use super::super::tests::{crypto, peer, pool};
    use super::*;
    use crate::network::admission_class_tests::AdmissionFixture as Fixture;
    use iroha_crypto::encryption::ChaCha20Poly1305;
    use std::{
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    #[derive(Default)]
    struct ClosureObservation {
        order: Mutex<Vec<&'static str>>,
        reclaimed_before_io_closed: AtomicBool,
    }
    struct ObservedIo<I> {
        io: I,
        pool: Arc<Pool>,
        peer: PeerId,
        label: &'static str,
        observation: Arc<ClosureObservation>,
    }
    impl<I: AsyncRead + Unpin> AsyncRead for ObservedIo<I> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buffer)
        }
    }
    impl<I: AsyncWrite + Unpin> AsyncWrite for ObservedIo<I> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, bytes)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
    impl<I> Drop for ObservedIo<I> {
        fn drop(&mut self) {
            if self.pool.bind(&self.peer).is_ok() {
                self.observation
                    .reclaimed_before_io_closed
                    .store(true, Ordering::SeqCst);
            }
            self.observation.order.lock().unwrap().push(self.label);
        }
    }
    #[derive(Clone, Copy)]
    enum Construction {
        Accepted,
        WrongPeer,
        UnfundedWriter,
    }
    fn assert_constructor_tenure(outcome: Construction) {
        let p = pool(3);
        let local = peer(81);
        let remote = peer(82);
        let cipher = crypto();
        let binding = Binding::verified(
            &test_network_id("credit constructor custody"),
            local.id(),
            remote.id(),
            cipher.session_binding,
            [83; 32],
            p.geometry,
            p.geometry,
        )
        .unwrap();
        let observation = Arc::new(ClosureObservation::default());
        let transport = negotiation::OwnedTransport {
            read: Box::new(ObservedIo {
                io: tokio::io::empty(),
                pool: Arc::clone(&p),
                peer: remote.id().clone(),
                label: "read",
                observation: Arc::clone(&observation),
            }),
            write: Box::new(ObservedIo {
                io: tokio::io::sink(),
                pool: Arc::clone(&p),
                peer: remote.id().clone(),
                label: "write",
                observation: Arc::clone(&observation),
            }),
            source: p.bind(remote.id()).unwrap(),
        };
        let configured_peer = if matches!(outcome, Construction::WrongPeer) {
            peer(84)
        } else {
            remote.clone()
        };
        let high_bytes = if matches!(outcome, Construction::UnfundedWriter) {
            1
        } else {
            256 * 1024
        };
        let result = CreditStream::<ChaCha20Poly1305, Fixture>::new(
            transport,
            binding,
            cipher,
            configured_peer,
            85,
            CreditStreamConfig {
                caps: crate::network::TopicFrameCaps::uniform(1024),
                maximum: [1024; CLASS_COUNT],
                limits: OutboundFrameQueueLimits::new_with_progress_reserve(
                    high_bytes,
                    128 * 1024,
                    256 * 1024,
                    32,
                    32,
                ),
                idle_timeout: Duration::from_secs(20),
            },
        );
        match outcome {
            Construction::Accepted => {
                let stream = result.unwrap();
                assert!(observation.order.lock().unwrap().is_empty());
                assert!(
                    p.bind(remote.id()).is_err(),
                    "live stream must retain its exact source"
                );
                drop(stream);
            }
            Construction::WrongPeer => assert!(matches!(result, Err(Error::Format))),
            Construction::UnfundedWriter => assert!(matches!(result, Err(Error::FrameTooLarge))),
        }
        assert!(
            !observation
                .reclaimed_before_io_closed
                .load(Ordering::SeqCst),
            "source cannot be rebound while either I/O half remains alive"
        );
        assert_eq!(*observation.order.lock().unwrap(), ["read", "write"]);
        assert!(
            p.bind(remote.id()).is_ok(),
            "closed transport releases its source exactly once"
        );
    }
    #[test]
    fn constructor_peer_mismatch_closes_io_before_source_reuse() {
        assert_constructor_tenure(Construction::WrongPeer);
    }
    #[test]
    fn constructor_writer_refusal_closes_io_before_source_reuse() {
        assert_constructor_tenure(Construction::UnfundedWriter);
    }
    #[test]
    fn constructor_success_transfers_original_io_and_source_until_drop() {
        assert_constructor_tenure(Construction::Accepted);
    }
}
