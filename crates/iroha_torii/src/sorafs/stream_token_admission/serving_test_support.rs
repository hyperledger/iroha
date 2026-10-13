// Route tests share the durable admission and reputation fixtures, never the local quota fallback.

pub struct ServingAdmissionFixture {
    pub(crate) capture: Arc<StreamTokenAdmissionCaptureV1>,
    provider: Arc<DurableProvider>,
    reputation: Arc<ReputationProbe>,
}
impl ServingAdmissionFixture {
    pub(crate) fn new() -> Self {
        let provider = Arc::new(DurableProvider::new());
        let reputation = Arc::new(ReputationProbe::default());
        Self {
            capture: Arc::new(capture(provider.clone(), reputation.clone(), 8)),
            provider,
            reputation,
        }
    }
    /// Reuse the real durable quota/outbox owner behind a test-only blocking or failure probe.
    pub(crate) fn provider(&self) -> Arc<dyn StreamTokenGatewayAdmissionProviderV1> {
        self.provider.clone()
    }
    /// Preserve the independently configured qualification and committed callback fixture.
    pub(crate) fn capture_with_provider(
        &self,
        provider: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
    ) -> Arc<StreamTokenAdmissionCaptureV1> {
        self.capture_with_provider_timeout(provider, Duration::from_secs(60))
    }
    /// Configure the real operation bound for queue-expiry tests without replacing the clock.
    pub(crate) fn capture_with_provider_timeout(
        &self,
        provider: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
        operation_timeout: Duration,
    ) -> Arc<StreamTokenAdmissionCaptureV1> {
        Arc::new(
            StreamTokenAdmissionCaptureV1::try_new(
                HANDLE,
                qualification(),
                8,
                operation_timeout,
                provider,
                self.reputation.clone(),
            )
            .expect("qualified probed capture"),
        )
    }
    pub(crate) fn requests(&self) -> Vec<StreamTokenGatewayAdmissionRequestV1> {
        self.provider
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }
    pub(crate) fn outcomes(&self) -> Vec<StreamTokenValidationOutcomeV1> {
        self.reputation
            .calls()
            .into_iter()
            .map(|(record, _)| record.outcome)
            .collect()
    }
    pub(crate) fn active_leases(&self) -> usize {
        self.provider.state.lock().unwrap().active_leases.len()
    }
    pub(crate) fn unavailable(&self) {
        self.provider.state.lock().unwrap().admission_unavailable = true;
    }
}
#[test]
fn signer_authority_exclusion_retains_material_without_quota_lease_or_reputation_penalty() {
    let fixture = ServingAdmissionFixture::new();
    let mut request = request(
        "authority-unavailable",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        1,
    );
    request.status = StreamTokenValidationStatusV1::Excluded(
        StreamTokenExcludedKindV1::SignerAuthorityUnavailable,
    );
    request.validate().unwrap();
    let bytes = norito::encode_canonical(&request).unwrap();
    assert_eq!(
        norito::decode_canonical::<StreamTokenGatewayAdmissionRequestV1>(&bytes).unwrap(),
        request
    );
    let record = fixture
        .capture
        .admit(
            &request,
            crate::sorafs::stream_token_admission::tests::test_deadline(),
        )
        .unwrap();
    record.validate_shape(qualification()).unwrap();
    let bytes = norito::encode_canonical(&record).unwrap();
    assert_eq!(
        norito::decode_canonical::<StreamTokenGatewayAdmissionRecordV1>(&bytes).unwrap(),
        record
    );
    assert_eq!(record.outcome.status, request.status);
    assert_eq!(record.outcome.token_body_digest, request.token_body_digest);
    assert_eq!(record.outcome.token_key_version, request.token_key_version);
    assert_eq!(fixture.active_leases(), 0);
    assert_eq!(fixture.outcomes(), [record.outcome]);
    assert!(!record.outcome.status.counts_for_provider());
    assert!(!record.outcome.status.is_violation());
    let mut missing_material = request.clone();
    missing_material.token_body_digest = None;
    assert_eq!(
        missing_material.validate(),
        Err(StreamTokenGatewayAdmissionErrorV1::InvalidRequest)
    );
    let mut missing_material = record;
    missing_material.outcome.token_body_digest = None;
    assert_eq!(
        missing_material.validate_shape(qualification()),
        Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
    );
}
