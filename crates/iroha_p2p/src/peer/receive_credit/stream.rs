//! One-record sender/reader service over the authenticated ordered connection.
//! Control records use the tenure's precharged cells, never data grants.
use super::*;
use record::Binding;
use tokio::time::Instant;

struct Queued {
    header: Header,
    plaintext: Vec<u8>,
    ownership: OutboundPostOwnership,
    bytes: SharedByteLease,
    requested: bool,
    granted: bool,
}
struct Writing {
    prefix: [u8; 4],
    header: Vec<u8>,
    ciphertext: Vec<u8>,
    offset: usize,
    class: Option<Class>,
    ownership: Option<OutboundPostOwnership>,
    _bytes: Option<SharedByteLease>,
}
impl Writing {
    fn new<E: Enc>(
        crypto: &cryptographer::Cryptographer<E>,
        header: Header,
        payload: &[u8],
        ownership: Option<OutboundPostOwnership>,
        bytes: Option<SharedByteLease>,
    ) -> Result<Self, Error> {
        let (encoded, ciphertext) = record::seal(crypto, &header, payload)?;
        let prefix = u32::try_from(encoded.len())
            .map_err(|_| Error::Format)?
            .to_be_bytes();
        Ok(Self {
            prefix,
            header: encoded,
            ciphertext,
            offset: 0,
            class: (header.kind()? == Kind::Data)
                .then(|| header.class())
                .transpose()?,
            ownership,
            _bytes: bytes,
        })
    }
    async fn advance(
        &mut self,
        write: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<bool, Error> {
        let total = 4 + self.header.len() + self.ciphertext.len();
        if self.offset < total {
            let slice = if self.offset < 4 {
                &self.prefix[self.offset..]
            } else if self.offset < 4 + self.header.len() {
                &self.header[self.offset - 4..]
            } else {
                &self.ciphertext[self.offset - 4 - self.header.len()..]
            };
            let written = write.write(slice).await?;
            if written == 0 {
                return Err(Error::Io(
                    std::io::Error::from(std::io::ErrorKind::WriteZero).into(),
                ));
            }
            self.offset += written;
        }
        if self.offset != total {
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

#[derive(Default)]
struct Reading {
    prefix: [u8; 4],
    prefix_read: usize,
    header: Vec<u8>,
    header_read: usize,
    parsed: Option<Header>,
    ciphertext: Vec<u8>,
    ciphertext_read: usize,
    reservation: Option<Reservation>,
}
struct ReadRecord {
    header: Header,
    encoded: Vec<u8>,
    ciphertext: Vec<u8>,
    reservation: Option<Reservation>,
}
impl Reading {
    async fn advance<E: Enc>(
        &mut self,
        read: &mut (dyn AsyncRead + Send + Unpin),
        ledger: &mut Ledger,
        binding: &Binding,
    ) -> Result<Option<ReadRecord>, Error> {
        // Each await performs one cancellation-safe `read`. Every completed
        // offset is committed before another await or return.
        if self.prefix_read < 4 {
            let n = read.read(&mut self.prefix[self.prefix_read..]).await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.prefix_read += n;
            if self.prefix_read != 4 {
                return Ok(None);
            }
            let length = u32::from_be_bytes(self.prefix) as usize;
            if length == 0 || length > record::HEADER_CAP {
                return Err(Error::Format);
            }
            self.header = vec![0; length];
            return Ok(None);
        }
        if self.header_read < self.header.len() {
            let n = read.read(&mut self.header[self.header_read..]).await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.header_read += n;
            if self.header_read != self.header.len() {
                return Ok(None);
            }
            let header = Header::decode(&self.header)?;
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
            self.ciphertext = vec![0; encrypted];
            self.parsed = Some(header);
            return Ok(None);
        }
        if self.ciphertext_read < self.ciphertext.len() {
            let n = read
                .read(&mut self.ciphertext[self.ciphertext_read..])
                .await?;
            if n == 0 {
                return Err(Error::ConnectionResetByPeer);
            }
            self.ciphertext_read += n;
            if self.ciphertext_read != self.ciphertext.len() {
                return Ok(None);
            }
        }
        let prior = std::mem::take(self);
        Ok(Some(ReadRecord {
            header: prior.parsed.ok_or(Error::Format)?,
            encoded: prior.header,
            ciphertext: prior.ciphertext,
            reservation: prior.reservation,
        }))
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
impl<E: Enc, T: Pload + ClassifyTopic> CreditStream<E, T> {
    /// Construct only after verifying the signed mandatory record/geometry
    /// handshake. Local/remote class maxima are independent admissions.
    pub(in crate::peer) fn new(
        read: Box<dyn AsyncRead + Send + Unpin>,
        write: Box<dyn AsyncWrite + Send + Unpin>,
        source: BoundSource,
        binding: Binding,
        crypto: cryptographer::Cryptographer<E>,
        peer: iroha_data_model::peer::Peer,
        connection: ConnectionId,
        caps: crate::network::TopicFrameCaps,
        maximum: [usize; CLASS_COUNT],
        limits: OutboundFrameQueueLimits,
        idle_timeout: Duration,
    ) -> Result<Self, Error> {
        if source.peer != *peer.id() {
            return Err(Error::Format);
        }
        if record::encrypted_len::<E>(0)? > 64 {
            return Err(Error::Format);
        }
        let bytes = super::writer_partitions(maximum, limits)?;
        Ok(Self {
            read,
            write,
            reading: Reading::default(),
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
                let writing = Writing::new(&self.crypto, *header, &[], None, None)?;
                *sent = true;
                writing
            } else if rank == Class::SCHEDULE.len() * 3 + 1 {
                let Some(header) = self.pong.take() else {
                    continue;
                };
                Writing::new(&self.crypto, header, &[], None, None)?
            } else {
                match rank % 3 {
                    0 => {
                        let Some(post) = self.queued[i].as_mut().filter(|p| !p.requested) else {
                            continue;
                        };
                        let record = Writing::new(&self.crypto, post.header, &[], None, None)?;
                        post.requested = true;
                        record
                    }
                    1 => {
                        if !self.queued[i].as_ref().is_some_and(|p| p.granted) {
                            continue;
                        }
                        let post = self.queued[i].take().expect("checked granted post");
                        Writing::new(
                            &self.crypto,
                            post.header.with_kind(Kind::Data),
                            &post.plaintext,
                            Some(post.ownership),
                            Some(post.bytes),
                        )?
                    }
                    _ => {
                        let Some(header) = self.ledger.next_grant()? else {
                            continue;
                        };
                        Writing::new(&self.crypto, header, &[], None, None)?
                    }
                }
            };
            self.writing = Some(writing);
            self.cursor = (rank + 1) % RANKS;
            return Ok(());
        }
        Ok(())
    }
    fn receive(&mut self, mut record: ReadRecord) -> Result<Option<PeerMessage<T>>, Error> {
        let plaintext = record::open(&self.crypto, &record.encoded, &mut record.ciphertext)?;
        let outcome = match record.header.kind()? {
            Kind::Ping => {
                if !plaintext.is_empty()
                    || self.pong.is_some()
                    || record.header.sequence != self.next_peer_ping
                    || !self.remote_pings.admit_at(Instant::now())
                {
                    return Err(Error::Format);
                }
                self.next_peer_ping = self.next_peer_ping.checked_add(1).ok_or(Error::Format)?;
                self.pong = Some(record.header.with_kind(Kind::Pong));
                None
            }
            Kind::Pong => {
                if !plaintext.is_empty()
                    || !self.ping.as_ref().is_some_and(|(ping, sent)| {
                        *sent && ping.with_kind(Kind::Pong) == record.header
                    })
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
                self.ledger.request(record.header)?;
                None
            }
            Kind::Grant => {
                if !plaintext.is_empty() {
                    return Err(Error::Format);
                }
                let post = self.queued[record.header.class()?.index()]
                    .as_mut()
                    .ok_or(Error::Format)?;
                if !post.requested
                    || post.granted
                    || post.header.with_kind(Kind::Grant) != record.header
                {
                    return Err(Error::Format);
                }
                post.granted = true;
                None
            }
            Kind::Data => {
                let reservation = record.reservation.take().ok_or(Error::Format)?;
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
        // Register before examining reservations. The shared pool wakes every
        // enabled waiter only after actual leases are released (ReleaseNotify).
        let pool = Arc::clone(&self.ledger.source.pool);
        let changed = pool.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        self.schedule()?;
        tokio::select! {
            record = self.reading.advance::<E>(&mut *self.read, &mut self.ledger, &self.binding) => {
                record?.map_or_else(|| Ok(None), |record| self.receive(record))
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
            () = &mut changed => Ok(None),
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
        Box::new(read),
        Box::new(write),
        p.bind(remote.id()).unwrap(),
        binding,
        cipher.clone(),
        remote.clone(),
        99,
        crate::network::TopicFrameCaps::uniform(1024),
        [1024; CLASS_COUNT],
        OutboundFrameQueueLimits::new_with_progress_reserve(
            256 * 1024,
            128 * 1024,
            256 * 1024,
            32,
            32,
        ),
        Duration::from_secs(20),
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
        Box::new(read),
        Box::new(write),
        p.bind(remote.id()).unwrap(),
        binding,
        cipher.clone(),
        remote.clone(),
        100,
        crate::network::TopicFrameCaps::uniform(1024),
        [1024; CLASS_COUNT],
        OutboundFrameQueueLimits::new_with_progress_reserve(
            256 * 1024,
            128 * 1024,
            256 * 1024,
            32,
            32,
        ),
        Duration::from_secs(20),
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
