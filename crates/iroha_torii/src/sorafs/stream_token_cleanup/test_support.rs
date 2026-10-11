//! Bounded blocking probes around the existing durable admission/callback fixture.
use super::*;
use crate::sorafs::{
    StreamTokenGatewayAdmissionProviderV1, stream_token_admission::tests::ServingAdmissionFixture,
};
use iroha_data_model::sorafs::stream_token_gateway::{
    StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1,
    StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionReadbackV1,
    StreamTokenGatewayAdmissionRequestV1, StreamTokenGatewayAdmissionResultV1,
    StreamTokenGatewayQuotaRequestV1,
};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    reputation::{
        StreamTokenRequestRouteV1, StreamTokenValidationRequestContextV1,
        StreamTokenValidationStatusV1,
    },
};
use std::{
    sync::{Condvar, atomic::AtomicU8},
    time::{Duration, Instant},
};

/// A failure-safe gate: a bounded wait and a separately retained release guard.
#[derive(Debug, Default)]
pub(crate) struct BlockingGate {
    open: Mutex<bool>,
    wake: Condvar,
    pub(crate) entered: AtomicUsize,
}
impl BlockingGate {
    fn block(&self) {
        self.entered.fetch_add(1, Ordering::AcqRel);
        let open = self.open.lock().unwrap();
        let (open, timeout) = self
            .wake
            .wait_timeout_while(open, Duration::from_secs(5), |v| !*v)
            .unwrap();
        assert!(
            *open && !timeout.timed_out(),
            "bounded provider gate was not released"
        );
    }
    /// Release on success or during test unwinding so no physical provider worker is stranded.
    pub(crate) fn release(&self) {
        *self.open.lock().unwrap_or_else(|error| error.into_inner()) = true;
        self.wake.notify_all();
    }
}
/// Releases an intentionally blocked provider even when an assertion unwinds.
pub(crate) struct GateRelease(pub(crate) Arc<BlockingGate>);
impl Drop for GateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Delegates real quota/outbox semantics; only the selected call is delayed or fails.
pub(crate) struct ProbeProvider {
    inner: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
    pub(crate) gate: Arc<BlockingGate>,
    /// Zero disables gating; one gates release, two gates admit, three gates qualification.
    pub(crate) gate_point: AtomicU8,
    /// Zero delegates; one returns an ambiguous release; two panics at release.
    pub(crate) release_fault: AtomicU8,
    pub(crate) release_calls: Mutex<Vec<StreamTokenGatewayAdmissionRecordV1>>,
    pub(crate) admission_calls: AtomicUsize,
    pub(crate) qualification_calls: AtomicUsize,
}
impl fmt::Debug for ProbeProvider {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ProbeProvider").finish_non_exhaustive()
    }
}
impl ProbeProvider {
    /// Wrap the durable owner without replacing its qualification or acknowledgements.
    pub(crate) fn new(inner: Arc<dyn StreamTokenGatewayAdmissionProviderV1>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            gate: Arc::default(),
            gate_point: AtomicU8::new(0),
            release_fault: AtomicU8::new(0),
            release_calls: Mutex::default(),
            admission_calls: AtomicUsize::new(0),
            qualification_calls: AtomicUsize::new(0),
        })
    }
}
impl StreamTokenGatewayAdmissionProviderV1 for ProbeProvider {
    fn handle(&self) -> &str {
        self.inner.handle()
    }
    fn configured_qualification(&self) -> StreamTokenGatewayAdmissionQualificationV1 {
        self.inner.configured_qualification()
    }
    fn qualification(
        &self,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionErrorV1>
    {
        self.qualification_calls.fetch_add(1, Ordering::AcqRel);
        if self.gate_point.load(Ordering::Acquire) == 3 {
            self.gate.block();
        }
        self.inner.qualification(deadline)
    }
    fn admit(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionResultV1, StreamTokenGatewayAdmissionErrorV1> {
        self.admission_calls.fetch_add(1, Ordering::AcqRel);
        if self.gate_point.load(Ordering::Acquire) == 2 {
            self.gate.block();
        }
        self.inner.admit(request, deadline)
    }
    fn pending(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionReadbackV1, StreamTokenGatewayAdmissionErrorV1> {
        self.inner.pending(max_items, deadline)
    }
    fn pending_for_background(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<
        crate::sorafs::StreamTokenGatewayReconciliationReadV1,
        StreamTokenGatewayAdmissionErrorV1,
    > {
        self.inner.pending_for_background(max_items, deadline)
    }
    fn acknowledge(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1> {
        self.inner.acknowledge(record, deadline)
    }
    fn release_lease(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1> {
        self.release_calls.lock().unwrap().push(record);
        if self.gate_point.load(Ordering::Acquire) == 1 {
            self.gate.block();
        }
        match self.release_fault.load(Ordering::Acquire) {
            1 => Err(StreamTokenGatewayAdmissionErrorV1::Ambiguous),
            2 => panic!("injected bounded release failure"),
            _ => self.inner.release_lease(record, deadline),
        }
    }
    fn confirm_serving(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionRecordV1, StreamTokenGatewayAdmissionErrorV1> {
        self.inner.confirm_serving(request, record, deadline)
    }
}

/// A canonical body-independent quota request for cleanup-owner tests, not a hardware token.
pub(crate) fn request(nonce: &str) -> StreamTokenGatewayAdmissionRequestV1 {
    const NOW: u64 = 1_800_000_000_000;
    StreamTokenGatewayAdmissionRequestV1 {
        serving_attempt_id: [0x61; 32],
        context: StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x41; 32]),
            [0x42; 32],
            sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
            "sorafs.sf1@1.0.0".to_owned(),
            nonce,
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::car_range(64, 1_023).unwrap(),
        )
        .unwrap(),
        token_body_digest: Some([0x44; 32]),
        token_key_version: Some(3),
        validated_at_unix_ms: NOW,
        status: StreamTokenValidationStatusV1::Accepted,
        quota: Some(StreamTokenGatewayQuotaRequestV1 {
            token_id: "11".repeat(16),
            max_streams: 8,
            requests_per_minute: 120,
            rate_limit_bytes: 1_048_576,
            requested_bytes: 960,
            expires_at_epoch: NOW / 1_000 + 600,
            observed_at_epoch: NOW / 1_000,
        }),
    }
}

/// Wait a bounded duration for an actual physical call/state transition.
pub(crate) async fn wait_until(ready: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("bounded worker transition");
}

/// Construct the real durable fixture and an independently configured probed capture.
pub(crate) fn fixture() -> (
    ServingAdmissionFixture,
    Arc<ProbeProvider>,
    Arc<StreamTokenAdmissionCaptureV1>,
) {
    let fixture = ServingAdmissionFixture::new();
    let provider = ProbeProvider::new(fixture.provider());
    let capture = fixture.capture_with_provider(provider.clone());
    (fixture, provider, capture)
}
