//! Authenticated heartbeat request budgets and locally owned response retirement.
use super::super::tests::{crypto, peer, pool};
use super::*;
use crate::network::admission_class_tests::AdmissionFixture;
use iroha_crypto::encryption::ChaCha20Poly1305;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

type HealthStream = CreditStream<ChaCha20Poly1305, AdmissionFixture>;
const IDLE: Duration = Duration::from_secs(20);

struct Fixture {
    stream: HealthStream,
    remote: DuplexStream,
}
impl Fixture {
    fn new() -> Self {
        let pool = pool(3);
        let local = peer(80);
        let remote = peer(81);
        let cipher = crypto();
        let binding = Binding::verified(
            &test_network_id("heartbeat probe ownership"),
            local.id(),
            remote.id(),
            cipher.session_binding,
            [83; 32],
            pool.geometry,
            pool.geometry,
        )
        .unwrap();
        // Only fixed health records are written here. The existing seven-byte
        // duplex test separately exercises cancellation and partial I/O.
        let (wire, socket) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(socket);
        let stream = HealthStream::new(
            negotiation::OwnedTransport {
                read: Box::new(read),
                write: Box::new(write),
                source: pool.bind(remote.id()).unwrap(),
            },
            binding,
            cipher,
            remote,
            200,
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
                idle_timeout: IDLE,
            },
        )
        .unwrap();
        Self {
            stream,
            remote: wire,
        }
    }

    async fn deliver(&mut self, header: Header) -> Result<(), Error> {
        let (encoded, ciphertext) = record::seal(&self.stream.crypto, &header, &[]).unwrap();
        self.remote
            .write_all(&(u32::try_from(encoded.len()).unwrap()).to_be_bytes())
            .await
            .unwrap();
        self.remote.write_all(&encoded).await.unwrap();
        self.remote.write_all(&ciphertext).await.unwrap();
        let before = self.stream.authenticated_records();
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.stream.authenticated_records() == before {
                assert!(
                    self.stream.step().await?.is_none(),
                    "health is never application data"
                );
            }
            Ok(())
        })
        .await
        .expect("fixed authenticated record must complete")
    }

    async fn flush_health(&mut self) -> Header {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.stream.writing.is_some()
                || self.stream.pong.is_some()
                || self.stream.ping.as_ref().is_some_and(|(_, sent)| !*sent)
            {
                assert!(self.stream.step().await.unwrap().is_none());
            }
        })
        .await
        .expect("one fixed health writer must flush");
        let length = usize::try_from(self.remote.read_u32().await.unwrap()).unwrap();
        assert!(length <= record::HEADER_CAP);
        let mut encoded = vec![0; length];
        self.remote.read_exact(&mut encoded).await.unwrap();
        let mut ciphertext = vec![0; record::encrypted_len::<ChaCha20Poly1305>(0).unwrap()];
        self.remote.read_exact(&mut ciphertext).await.unwrap();
        assert!(
            record::open(&self.stream.crypto, &encoded, &mut ciphertext)
                .unwrap()
                .is_empty()
        );
        Header::decode(&encoded).unwrap()
    }

    async fn local_probe(&mut self) -> Header {
        self.stream.request_ping().unwrap();
        let header = self.flush_health().await;
        assert_eq!(header.kind().unwrap(), Kind::Ping);
        assert!(self.stream.probe_pending());
        header
    }
}

#[tokio::test(start_paused = true)]
async fn correlated_pong_retires_local_probe_with_empty_remote_ping_budget() {
    let mut fixture = Fixture::new();
    for sequence in 1..=2 {
        let ping = Header::ping(fixture.stream.binding.incoming, sequence).unwrap();
        fixture.deliver(ping).await.unwrap();
        assert_eq!(fixture.flush_health().await, ping.with_kind(Kind::Pong));
    }
    let ping = fixture.local_probe().await;
    fixture.deliver(ping.with_kind(Kind::Pong)).await.unwrap();
    assert!(!fixture.stream.probe_pending());
    assert_eq!(fixture.stream.next_ping, 2);
    assert_eq!(fixture.stream.authenticated_records(), 3);
    // Retiring a local response never mints remote request credit either.
    let excess = Header::ping(fixture.stream.binding.incoming, 3).unwrap();
    assert!(fixture.deliver(excess).await.is_err());
    assert!(fixture.stream.failed);
    assert_eq!(fixture.stream.authenticated_records(), 3);
}

#[tokio::test(start_paused = true)]
async fn delayed_pong_keeps_one_outstanding_local_probe() {
    let mut fixture = Fixture::new();
    let ping = fixture.local_probe().await;
    for _ in 0..4 {
        tokio::time::advance(IDLE / 2).await;
        fixture.stream.request_ping().unwrap();
        fixture.stream.schedule().unwrap();
        assert_eq!(fixture.stream.ping, Some((ping, true)));
        assert!(fixture.stream.writing.is_none(), "no second probe writer");
        assert_eq!(fixture.stream.next_ping, 1);
    }
    fixture.deliver(ping.with_kind(Kind::Pong)).await.unwrap();
    assert!(!fixture.stream.probe_pending());
    assert_eq!(fixture.stream.next_ping, 2);
    let next = fixture.local_probe().await;
    assert_eq!(next.sequence, 2);
}

#[tokio::test(start_paused = true)]
async fn unsolicited_and_duplicate_pongs_fail_without_refreshing_liveness() {
    let mut unsolicited = Fixture::new();
    let header = Header::ping(unsolicited.stream.binding.outgoing, 1)
        .unwrap()
        .with_kind(Kind::Pong);
    assert!(unsolicited.deliver(header).await.is_err());
    assert!(unsolicited.stream.failed);
    assert_eq!(unsolicited.stream.authenticated_records(), 0);
    assert_eq!(unsolicited.stream.next_ping, 1);

    let mut duplicate = Fixture::new();
    let pong = duplicate.local_probe().await.with_kind(Kind::Pong);
    duplicate.deliver(pong).await.unwrap();
    assert!(!duplicate.stream.probe_pending());
    assert!(duplicate.deliver(pong).await.is_err());
    assert!(duplicate.stream.failed);
    assert_eq!(duplicate.stream.authenticated_records(), 1);
    assert_eq!(duplicate.stream.next_ping, 2);
}

#[tokio::test(start_paused = true)]
async fn substituted_pongs_cannot_retire_the_locally_owned_probe() {
    for variant in 0..3 {
        let mut fixture = Fixture::new();
        let ping = fixture.local_probe().await;
        let altered = match variant {
            0 => Header::ping(fixture.stream.binding.outgoing, ping.sequence + 1).unwrap(),
            1 => Header::ping(fixture.stream.binding.incoming, ping.sequence).unwrap(),
            2 => Header::request(
                fixture.stream.binding.outgoing,
                Class::Lane,
                ping.sequence,
                1,
            )
            .unwrap(),
            _ => unreachable!(),
        }
        .with_kind(Kind::Pong);
        assert!(fixture.deliver(altered).await.is_err());
        assert!(fixture.stream.failed);
        assert_eq!(fixture.stream.authenticated_records(), 0);
        assert_eq!(fixture.stream.ping, Some((ping, true)));
        assert_eq!(fixture.stream.next_ping, 1);
    }
}
