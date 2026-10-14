//! Mandatory bounded receiver-geometry exchange after authenticated identity.
//! The caller owns the original authentication deadline. The stream owner drops
//! both I/O halves before its source reservation on failure or cancellation.
use super::*;

const OFFER_CAP: usize = 4096;
const DOMAIN: &[u8] = b"iroha:p2p:receive-credit-geometry:v1|";

/// Canonical first-release geometry; all declared classes are mandatory.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_p2p::peer::receive_credit::GeometryOfferV1")]
struct Offer {
    version: u8,
    writer_flags: u8,
    classes: [u8; CLASS_COUNT],
    counts: [u64; CLASS_COUNT],
    primary_bytes: [u64; CLASS_COUNT],
    private_bytes: [u64; CLASS_COUNT],
    maximum: [u64; CLASS_COUNT],
    pool_identity: [u8; 32],
}
impl Offer {
    fn from_pool(pool: &Pool) -> Self {
        Self {
            version: 1,
            writer_flags: ncore::default_encode_flags(),
            classes: Class::ALL.map(Class::wire_code),
            counts: pool.counts.map(|n| n as u64),
            primary_bytes: std::array::from_fn(|i| pool.class_bytes[i].max_bytes as u64),
            private_bytes: pool.fallback.map(|n| n as u64),
            maximum: pool.max_plaintext.map(|n| n as u64),
            pool_identity: pool.geometry,
        }
    }
    fn bytes(&self) -> Result<Vec<u8>, Error> {
        let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        let bytes = ncore::to_bytes(self).map_err(Error::NoritoCodec)?;
        if bytes.len() > OFFER_CAP {
            return Err(Error::FrameTooLarge);
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > OFFER_CAP {
            return Err(Error::Format);
        }
        let offer: Self = ncore::decode_from_bytes_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(Error::NoritoCodec)?;
        if offer.bytes()? != bytes
            || offer.version != 1
            || offer.writer_flags != ncore::default_encode_flags()
            || offer.classes != Class::ALL.map(Class::wire_code)
        {
            return Err(Error::Format);
        }
        for class in Class::ALL {
            let i = class.index();
            let maximum = usize::try_from(offer.maximum[i]).map_err(|_| Error::FrameTooLarge)?;
            let charged = maximum
                .checked_add(ENVELOPE_BYTES)
                .ok_or(Error::FrameTooLarge)?;
            if maximum == 0
                || maximum > crate::MAX_ENCRYPTED_FRAME_BYTES
                || offer.counts[i] == 0
                || offer.counts[i] > Semaphore::MAX_PERMITS as u64
                || offer.primary_bytes[i] < charged as u64
            {
                return Err(Error::Format);
            }
            if class == Class::Safety
                && offer.private_bytes[i]
                    < charged.checked_mul(3).ok_or(Error::FrameTooLarge)? as u64
            {
                return Err(Error::Format);
            }
            if class.is_low() && offer.private_bytes[i] != 0 {
                return Err(Error::Format);
            }
        }
        Ok(offer)
    }
    fn commitment(&self) -> Result<[u8; 32], Error> {
        Ok(iroha_crypto::Hash::new(&self.bytes()?).into())
    }
}

fn authority(
    network: &iroha_data_model::NetworkId,
    sender: &PeerId,
    receiver: &PeerId,
    session: [u8; 32],
    transport: TransportBinding,
) -> Result<Vec<u8>, Error> {
    if sender == receiver {
        return Err(Error::Format);
    }
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    ncore::to_bytes(&(
        DOMAIN.to_vec(),
        *network,
        sender.clone(),
        receiver.clone(),
        session,
        transport,
    ))
    .map_err(Error::NoritoCodec)
}

async fn write_offer<E: Enc>(
    write: &mut (dyn AsyncWrite + Send + Unpin),
    crypto: &cryptographer::Cryptographer<E>,
    aad: &[u8],
    local: &Offer,
) -> Result<(), Error> {
    let bytes = local.bytes()?;
    let encrypted = crypto.encryptor.encrypt_easy(aad, &bytes)?;
    if encrypted.len() > OFFER_CAP + 64 {
        return Err(Error::FrameTooLarge);
    }
    let length = u32::try_from(encrypted.len()).map_err(|_| Error::FrameTooLarge)?;
    write.write_all(&length.to_be_bytes()).await?;
    write.write_all(&encrypted).await?;
    write.flush().await?;
    Ok(())
}
async fn read_offer<E: Enc>(
    read: &mut (dyn AsyncRead + Send + Unpin),
    crypto: &cryptographer::Cryptographer<E>,
    aad: &[u8],
) -> Result<Offer, Error> {
    let mut prefix = [0; 4];
    read.read_exact(&mut prefix).await?;
    let bytes = u32::from_be_bytes(prefix) as usize;
    if bytes == 0 || bytes > OFFER_CAP + 64 {
        return Err(Error::Format);
    }
    // Both directions and codec scratch fit the already precharged 64 KiB
    // source control cells. No application credit can block this exchange.
    let mut encrypted = vec![0; bytes];
    read.read_exact(&mut encrypted).await?;
    let plaintext = crypto
        .encryptor
        .decrypt_easy_in_place(aad, &mut encrypted)?;
    Offer::parse(plaintext)
}

/// Verified exchange result is consumed by the one mandatory `CreditStream`.
/// This does not clone the reader-tenure/source owner or authorize a fallback.
pub(in crate::peer) struct Negotiated {
    pub(in crate::peer) transport: OwnedTransport,
    pub(in crate::peer) binding: record::Binding,
    pub(in crate::peer) outbound_maximum: [usize; CLASS_COUNT],
}

/// Exact transport tenure; declaration order fences I/O before reclaiming credit.
pub(in crate::peer) struct OwnedTransport {
    pub(in crate::peer) read: Box<dyn AsyncRead + Send + Unpin>,
    pub(in crate::peer) write: Box<dyn AsyncWrite + Send + Unpin>,
    pub(in crate::peer) source: BoundSource,
}

/// Exchange geometry on the authenticated, ordered stream before application
/// registration. Both sends and reads are polled together, including tiny TLS
/// buffers. The caller must use its original preauthentication deadline.
/// All authority inputs must come from Ready after full identity verification.
#[allow(clippy::too_many_arguments)]
pub(in crate::peer) async fn exchange<E: Enc>(
    mut owner: OwnedTransport,
    crypto: &cryptographer::Cryptographer<E>,
    network: &iroha_data_model::NetworkId,
    local: &PeerId,
    remote: &PeerId,
    transport: TransportBinding,
) -> Result<Negotiated, Error> {
    if &owner.source.peer != remote || record::encrypted_len::<E>(0)? > 64 {
        return Err(Error::Format);
    }
    let local_offer = Offer::from_pool(&owner.source.pool);
    let outgoing_aad = authority(network, local, remote, crypto.session_binding, transport)?;
    let incoming_aad = authority(network, remote, local, crypto.session_binding, transport)?;
    let ((), remote_offer) = tokio::try_join!(
        write_offer(owner.write.as_mut(), crypto, &outgoing_aad, &local_offer),
        read_offer(owner.read.as_mut(), crypto, &incoming_aad),
    )?;
    let binding = record::Binding::verified(
        network,
        local,
        remote,
        crypto.session_binding,
        transport,
        local_offer.commitment()?,
        remote_offer.commitment()?,
    )?;
    let mut outbound_maximum = [0; CLASS_COUNT];
    for class in Class::ALL {
        let i = class.index();
        outbound_maximum[i] = owner.source.pool.max_plaintext[i]
            .min(usize::try_from(remote_offer.maximum[i]).map_err(|_| Error::FrameTooLarge)?);
    }
    Ok(Negotiated {
        transport: owner,
        binding,
        outbound_maximum,
    })
}

#[cfg(test)]
mod tests {
    include!("arbitration_tests.rs");
    use super::*;
    use crate::peer::receive_credit::tests::{crypto, peer, pool};
    #[test]
    fn canonical_geometry_rejects_missing_classes_and_unfunded_protected_maximum() {
        let offer = Offer::from_pool(&pool(3));
        assert_eq!(Offer::parse(&offer.bytes().unwrap()).unwrap(), offer);
        for index in 0..CLASS_COUNT {
            let mut bad = offer.clone();
            bad.classes[index] = 255;
            assert!(Offer::parse(&bad.bytes().unwrap()).is_err());
            let mut bad = offer.clone();
            bad.counts[index] = 0;
            assert!(Offer::parse(&bad.bytes().unwrap()).is_err());
        }
        let mut bad = offer.clone();
        bad.private_bytes[Class::Safety.index()] = 0;
        assert!(Offer::parse(&bad.bytes().unwrap()).is_err());
    }
    #[tokio::test]
    async fn tiny_duplex_geometry_exchange_binds_both_directions_and_holds_tenure() {
        let a = peer(41);
        let b = peer(42);
        let pa = pool(3);
        let pb = pool(3);
        let crypto = crypto();
        let network = test_network_id("credit geometry exchange");
        let (left, right) = tokio::io::duplex(7);
        let (ar, aw) = tokio::io::split(left);
        let (br, bw) = tokio::io::split(right);
        let a_transport = OwnedTransport {
            read: Box::new(ar),
            write: Box::new(aw),
            source: pa.bind(b.id()).unwrap(),
        };
        let b_transport = OwnedTransport {
            read: Box::new(br),
            write: Box::new(bw),
            source: pb.bind(a.id()).unwrap(),
        };
        let (a_result, b_result) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(
                exchange(a_transport, &crypto, &network, a.id(), b.id(), [4; 32]),
                exchange(b_transport, &crypto, &network, b.id(), a.id(), [4; 32])
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(a_result.binding.outgoing, b_result.binding.incoming);
        assert_eq!(a_result.binding.incoming, b_result.binding.outgoing);
        assert!(
            pa.bind(b.id()).is_err(),
            "unspent grants and parser retain exact tenure"
        );
        drop(a_result);
        assert!(pa.bind(b.id()).is_ok());
    }
    #[tokio::test]
    async fn asymmetric_native_offer_refuses_oversize_with_exact_post_and_uncompleted_ack() {
        use crate::network::admission_class_tests::AdmissionFixture as Fixture;
        use crate::peer::receive_credit::{stream::CreditStream, tests::post};
        use iroha_crypto::encryption::ChaCha20Poly1305;
        let a = peer(45);
        let b = peer(46);
        let pa = pool(3);
        let frames = InboundFrameByteBudgets::new(256 * 1024, 128 * 1024, 256 * 1024, 2).unwrap();
        assert!(frames.install_protected_sources(HashSet::new()));
        let pb = Pool::new(
            frames,
            InboundDispatchByteBudgets::new(256 * 1024, 128 * 1024, 4096).unwrap(),
            6,
            [1; CLASS_COUNT],
        )
        .unwrap();
        let crypto = crypto();
        let network = test_network_id("asymmetric mandatory credit maxima");
        let (left, right) = tokio::io::duplex(7);
        let (ar, aw) = tokio::io::split(left);
        let (br, bw) = tokio::io::split(right);
        let (local, remote) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(
                exchange(
                    OwnedTransport {
                        read: Box::new(ar),
                        write: Box::new(aw),
                        source: pa.bind(b.id()).unwrap()
                    },
                    &crypto,
                    &network,
                    a.id(),
                    b.id(),
                    [6; 32]
                ),
                exchange(
                    OwnedTransport {
                        read: Box::new(br),
                        write: Box::new(bw),
                        source: pb.bind(a.id()).unwrap()
                    },
                    &crypto,
                    &network,
                    b.id(),
                    a.id(),
                    [6; 32]
                )
            )
        })
        .await
        .unwrap()
        .unwrap();
        assert_ne!(pa.geometry, pb.geometry);
        assert_eq!(local.binding.outgoing, remote.binding.incoming);
        assert_eq!(local.outbound_maximum, [1; CLASS_COUNT]);
        let mut stream = CreditStream::<ChaCha20Poly1305, Fixture>::new(
            local.transport.read,
            local.transport.write,
            local.transport.source,
            local.binding,
            crypto,
            b,
            101,
            crate::network::TopicFrameCaps::uniform(1024),
            local.outbound_maximum,
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
        let (post, mut ack) = post(Fixture::Payload(99));
        let (error, retained) = stream
            .enqueue(post)
            .expect_err("negotiated one-byte maximum cannot encode this native payload");
        assert!(matches!(error, Error::FrameTooLarge));
        assert!(
            matches!(
                ack.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "refusal must return the owner without completing or dropping its ACK"
        );
        assert!(matches!(
            retained.message.as_ref(),
            Some(Fixture::Payload(99))
        ));
        assert!(stream.can_enqueue(Class::Payload));
        drop(retained);
        assert!(
            matches!(
                ack.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ),
            "the actual refused owner, never a synthetic success, closes ACK on drop"
        );
        drop((stream, remote));
        assert!(pa.bind(peer(46).id()).is_ok());
    }
    struct ClosingReader {
        inner: Box<dyn AsyncRead + Send + Unpin>,
        pool: Arc<Pool>,
        peer: PeerId,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }
    impl AsyncRead for ClosingReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(self.inner.as_mut()).poll_read(cx, buffer)
        }
    }
    impl Drop for ClosingReader {
        fn drop(&mut self) {
            assert!(
                self.pool.bind(&self.peer).is_err(),
                "reader must close before its source can be rebound"
            );
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[tokio::test]
    async fn cancelled_geometry_exchange_closes_reader_before_reclaiming_tenure() {
        let a = peer(45);
        let b = peer(46);
        let pa = pool(3);
        let cipher = crypto();
        let network = test_network_id("cancelled geometry exchange");
        let (left, _unserviced_remote) = tokio::io::duplex(7);
        let (read, write) = tokio::io::split(left);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = OwnedTransport {
            read: Box::new(ClosingReader {
                inner: Box::new(read),
                pool: pa.clone(),
                peer: b.id().clone(),
                closed: closed.clone(),
            }),
            write: Box::new(write),
            source: pa.bind(b.id()).unwrap(),
        };
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                exchange(transport, &cipher, &network, a.id(), b.id(), [4; 32])
            )
            .await
            .is_err()
        );
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(pa.bind(b.id()).is_ok());
    }
    #[tokio::test]
    async fn geometry_tag_rejects_foreign_transport_before_app_registration() {
        let a = peer(43);
        let b = peer(44);
        let cipher = crypto();
        let network = test_network_id("foreign geometry transport");
        let correct = authority(&network, a.id(), b.id(), cipher.session_binding, [4; 32]).unwrap();
        let foreign = authority(&network, a.id(), b.id(), cipher.session_binding, [5; 32]).unwrap();
        let offer = Offer::from_pool(&pool(3));
        let (mut read, mut write) = tokio::io::duplex(7);
        let (sent, received) = tokio::join!(
            write_offer(&mut write, &cipher, &correct, &offer),
            read_offer(&mut read, &cipher, &foreign)
        );
        assert!(sent.is_ok());
        assert!(received.is_err());
    }
}
