//! Non-shipping fixtures for the production record writer and credit-release path.

use super::{super::*, Writing};
use iroha_crypto::{Algorithm, KeyPair, encryption::ChaCha20Poly1305};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Wake, Waker},
};
use tokio::sync::futures::Notified;

/// A fixed plaintext and authenticated record header, prepared outside timing.
pub struct RecordFixture {
    crypto: cryptographer::Cryptographer<ChaCha20Poly1305>,
    header: Header,
    plaintext: Vec<u8>,
}

impl RecordFixture {
    /// Prepare a nonempty Data record of the requested plaintext length.
    pub fn new(bytes: usize) -> Self {
        Self {
            crypto: cryptographer::Cryptographer::new(&iroha_crypto::SessionKey::new(vec![19; 32]))
                .expect("benchmark cipher"),
            header: Header::request([7; 32], Class::Lane, 1, bytes)
                .expect("nonempty benchmark record")
                .with_kind(Kind::Data),
            plaintext: vec![0xA5; bytes],
        }
    }

    /// Seal through the same single-buffer implementation used by live sessions.
    pub fn seal(&self) -> Vec<u8> {
        record::seal_record(&self.crypto, &self.header, &self.plaintext)
            .expect("seal benchmark record")
    }

    /// Prepare a sealed write outside timing, with a bounded in-memory transport.
    pub fn prepare_write(&self, max_write: usize) -> RecordWrite {
        assert!(max_write > 0);
        RecordWrite {
            writing: Writing {
                record: self.seal(),
                offset: 0,
                class: None,
                ownership: None,
                _bytes: None,
            },
            sink: CountingWriter {
                max_write,
                bytes: 0,
                writes: 0,
                flushes: 0,
            },
        }
    }
}

/// A prepared record advanced by the actual production partial-write loop.
pub struct RecordWrite {
    writing: Writing,
    sink: CountingWriter,
}

impl RecordWrite {
    /// Drain the record and return `(bytes, write calls, flush calls)`.
    pub async fn finish(mut self) -> (usize, usize, usize) {
        while !self
            .writing
            .advance(&mut self.sink)
            .await
            .expect("write benchmark record")
        {}
        (self.sink.bytes, self.sink.writes, self.sink.flushes)
    }
}

struct CountingWriter {
    max_write: usize,
    bytes: usize,
    writes: usize,
    flushes: usize,
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = std::hint::black_box(bytes).len().min(self.max_write);
        self.bytes += written;
        self.writes += 1;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// One authenticated source with real byte/count reservation owners.
pub struct ReleaseFixture {
    source: BoundSource,
}

impl Default for ReleaseFixture {
    fn default() -> Self {
        let frames = InboundFrameByteBudgets::new(256 * 1024, 128 * 1024, 256 * 1024, 2)
            .expect("benchmark frame budgets");
        assert!(frames.install_protected_sources(HashSet::new()));
        let pool = Pool::new(
            frames,
            InboundDispatchByteBudgets::new(256 * 1024, 128 * 1024, 4096)
                .expect("benchmark dispatch budgets"),
            Class::ORDINARY_HIGH.len(),
            [1024; CLASS_COUNT],
        )
        .expect("benchmark receive geometry");
        let key = KeyPair::try_from_seed(vec![31; 32], Algorithm::BlsNormal)
            .expect("benchmark source key");
        Self {
            source: pool
                .bind(&PeerId::new(key.public_key().clone()))
                .expect("bind benchmark source"),
        }
    }
}

impl ReleaseFixture {
    /// Reserve the only Lane count slot and register blocked notifications.
    /// Allocation, waiter registration and their first poll happen outside timing.
    pub fn prepare(&self, waiters: usize) -> ReleaseCase<'_> {
        let reservation = self.source.reserve(Class::Lane, 200).expect("free slot");
        let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut notifications = Vec::with_capacity(waiters);
        let mut registrations = Vec::with_capacity(waiters);
        for _ in 0..waiters {
            registrations.push(BlockedOnRelease::register(&self.source.pool));
            let mut notification = Box::pin(self.source.pool.changed.notified());
            notification.as_mut().enable();
            assert!(self.source.reserve(Class::Lane, 200).is_none());
            assert!(
                notification
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            notifications.push(notification);
        }
        ReleaseCase {
            reservation,
            notifications,
            _registrations: registrations,
            wake_count,
            waker,
        }
    }
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// An outstanding real reservation and enabled, polled release notifications.
pub struct ReleaseCase<'a> {
    reservation: Reservation,
    notifications: Vec<Pin<Box<Notified<'a>>>>,
    _registrations: Vec<BlockedOnRelease<'a>>,
    wake_count: Arc<WakeCount>,
    waker: Waker,
}

impl ReleaseCase<'_> {
    /// Release all grant leases, wake blocked streams and observe their readiness.
    pub fn release(self) -> usize {
        let Self {
            reservation,
            mut notifications,
            _registrations,
            wake_count,
            waker,
        } = self;
        drop(reservation);
        for notification in &mut notifications {
            assert!(
                notification
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
        }
        wake_count.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_fixture_authenticates_and_drains_complete_and_partial_writes() {
        let fixture = RecordFixture::new(4096);
        let record = fixture.seal();
        let header_len = u32::from_be_bytes(record[..4].try_into().unwrap()) as usize;
        let mut ciphertext = record[4 + header_len..].to_vec();
        assert_eq!(
            record::open(&fixture.crypto, &record[4..4 + header_len], &mut ciphertext).unwrap(),
            fixture.plaintext
        );
        for max_write in [usize::MAX, 1024] {
            assert_eq!(
                fixture.prepare_write(max_write).finish().await,
                (record.len(), record.len().div_ceil(max_write), 1)
            );
        }
    }

    #[test]
    fn release_fixture_wakes_exactly_registered_waiters_and_reuses_capacity() {
        let fixture = ReleaseFixture::default();
        for waiters in [0, 1, 8, 64, 0] {
            assert_eq!(fixture.prepare(waiters).release(), waiters);
            assert_eq!(fixture.source.pool.blocked.load(Ordering::SeqCst), 0);
        }
    }
}
