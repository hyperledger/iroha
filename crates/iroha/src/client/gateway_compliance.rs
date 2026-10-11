//! Exact bounded account-signed compliance control through the sole SDK HTTP transport.
use super::*;
use iroha_torii_shared::{
    route_catalog::contracts_and_verification_keys as routes,
    sorafs_gateway_compliance_api::{
        GATEWAY_COMPLIANCE_IDEMPOTENCY_KEY_HEADER, GATEWAY_COMPLIANCE_RESPONSE_MAX_BYTES_V1,
        GatewayComplianceActionResponseV1, GatewayCompliancePromoteExpectationV1,
        GatewayComplianceStatusResponseV1, decode_lower_hex_32, request_idempotency_binding,
    },
};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogV1, GatewayComplianceTrustPolicyV1,
    MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1,
};

#[derive(Clone, Copy)]
enum ControlAction {
    Stage,
    Acknowledge,
    Promote,
}

impl Client {
    /// Read one bounded runtime controller status with canonical account authentication.
    ///
    /// This performs one request under the existing request deadline, without probing or retry.
    /// The returned fields, including `serving_ready`, are runtime node observations; they do not
    /// establish native eligibility, current authority or a successful package read.
    /// # Errors
    /// Refuses elapsed deadline, transport/HTTP failure, invalid JSON schema or malformed fields.
    pub fn get_sorafs_gateway_compliance_status(
        &self,
    ) -> Result<GatewayComplianceStatusResponseV1> {
        self.ensure_activation_evidence_deadline()?;
        let url = join_torii_url(
            &self.torii_url,
            routes::SORAFS_GATEWAY_COMPLIANCE_STATUS_GET
                .path()
                .trim_start_matches('/'),
        );
        let response = self.send_builder(
            self.account_signed_request(HttpMethod::GET, url, Vec::new())?
                .replace_header(http::header::ACCEPT, APPLICATION_JSON)
                .max_response_bytes(GATEWAY_COMPLIANCE_RESPONSE_MAX_BYTES_V1),
        )?;
        let status: GatewayComplianceStatusResponseV1 =
            decode_response(response, StatusCode::OK, "gateway_compliance_status")?;
        status.validate()?;
        if let Some(latest) = &status.latest_action {
            sorafs_manifest::gateway_compliance::validate_token(
                &latest.reason_code,
                "reason_code",
            )?;
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(status)
    }
    /// Stage one exact threshold-signed catalog, using independently caller-selected trust.
    ///
    /// The trust argument is not network authentication. Its signatures and freshness are checked
    /// locally; the controller independently checks its configured trust and current durable state.
    /// One POST uses canonical bounded JSON and the exact deterministic request idempotency key.
    /// A returned action is a runtime observation, not serving or native admission authority.
    /// # Errors
    /// Refuses invalid/expired signed material, elapsed deadline, transport/HTTP or response mismatch.
    pub fn stage_sorafs_gateway_compliance_catalog(
        &self,
        catalog: &GatewayComplianceCatalogV1,
        trust: &GatewayComplianceTrustPolicyV1,
    ) -> Result<GatewayComplianceActionResponseV1> {
        self.ensure_activation_evidence_deadline()?;
        let body = canonical_body(catalog)?;
        let digest = catalog.verify(trust, now()?, clock_skew())?;
        self.compliance_mutation(ControlAction::Stage, None, body, digest)
    }
    /// Submit one already signed acknowledgement for an independently selected exact catalog.
    ///
    /// Caller-selected trust does not authenticate the network. This method verifies the original
    /// ACK and sends it once; it neither observes a gateway reload nor signs or renews the ACK.
    /// A stale original requires read-only status/recovery through its owning publisher.
    /// # Errors
    /// Refuses a wrong catalog, invalid/stale signature, deadline, transport/HTTP or response mismatch.
    pub fn acknowledge_sorafs_gateway_compliance_catalog(
        &self,
        acknowledgement: &GatewayComplianceAcknowledgementV1,
        trust: &GatewayComplianceTrustPolicyV1,
        expected_catalog_digest: [u8; 32],
    ) -> Result<GatewayComplianceActionResponseV1> {
        self.ensure_activation_evidence_deadline()?;
        let body = canonical_body(acknowledgement)?;
        acknowledgement.verify(trust, expected_catalog_digest, now()?, clock_skew())?;
        self.compliance_mutation(
            ControlAction::Acknowledge,
            None,
            body,
            expected_catalog_digest,
        )
    }
    /// Request exact-candidate promotion once with its canonical signed query and empty body.
    ///
    /// The controller owns current candidate lineage and genuine acknowledgement quorum checks.
    /// This method grants no approval from a caller-constructed expectation or returned report.
    /// # Errors
    /// Refuses a noncanonical expectation, deadline, transport/HTTP or mismatching action report.
    pub fn promote_sorafs_gateway_compliance_catalog(
        &self,
        expectation: GatewayCompliancePromoteExpectationV1,
    ) -> Result<GatewayComplianceActionResponseV1> {
        self.ensure_activation_evidence_deadline()?;
        let query = expectation.canonical_query()?;
        self.compliance_mutation(
            ControlAction::Promote,
            Some(&query),
            Vec::new(),
            expectation.catalog_digest,
        )
    }
    fn compliance_mutation(
        &self,
        selected: ControlAction,
        query: Option<&str>,
        body: Vec<u8>,
        expected_catalog_digest: [u8; 32],
    ) -> Result<GatewayComplianceActionResponseV1> {
        self.ensure_activation_evidence_deadline()?;
        let (path, action, expected_status) = match selected {
            ControlAction::Stage => (
                routes::SORAFS_GATEWAY_COMPLIANCE_STAGE_POST.path(),
                "stage",
                StatusCode::ACCEPTED,
            ),
            ControlAction::Acknowledge => (
                routes::SORAFS_GATEWAY_COMPLIANCE_ACKNOWLEDGE_POST.path(),
                "acknowledge",
                StatusCode::ACCEPTED,
            ),
            ControlAction::Promote => (
                routes::SORAFS_GATEWAY_COMPLIANCE_PROMOTE_POST.path(),
                "promote",
                StatusCode::OK,
            ),
        };
        let mut url = join_torii_url(&self.torii_url, path.trim_start_matches('/'));
        url.set_query(query);
        let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let key = request_idempotency_binding(action, target, &body);
        let response = self.send_builder(
            self.account_signed_request(HttpMethod::POST, url, body)?
                .replace_header(http::header::ACCEPT, APPLICATION_JSON)
                .replace_header(http::header::CONTENT_TYPE, APPLICATION_JSON)
                .replace_header(GATEWAY_COMPLIANCE_IDEMPOTENCY_KEY_HEADER, &hex::encode(key))
                .max_response_bytes(GATEWAY_COMPLIANCE_RESPONSE_MAX_BYTES_V1),
        )?;
        let report: GatewayComplianceActionResponseV1 =
            decode_response(response, expected_status, action)?;
        report.validate()?;
        if report.action != action
            || decode_lower_hex_32(&report.catalog_digest_hex) != Some(expected_catalog_digest)
            || decode_lower_hex_32(&report.idempotency_key) != Some(key)
        {
            return Err(eyre!(
                "gateway-compliance action response differs from exact original request"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(report)
    }
}
fn clock_skew() -> u64 {
    sorafs_manifest::gateway_compliance::DEFAULT_GATEWAY_COMPLIANCE_MAX_CLOCK_SKEW_SECS
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn canonical_body<T: norito::json::JsonSerialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    Ok(norito::json::to_json_bounded(value, MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1)?.into_bytes())
}
fn decode_response<T: norito::json::JsonDeserialize>(
    response: Response<Vec<u8>>,
    expected: StatusCode,
    operation: &'static str,
) -> Result<T> {
    // The transport is the sole admission owner; this also fences explicitly supplied mock bodies.
    if response.body().len() > GATEWAY_COMPLIANCE_RESPONSE_MAX_BYTES_V1 {
        return Err(eyre!("gateway-compliance response exceeds byte bound"));
    }
    if response.status() != expected {
        return Err(crate::Error::Http {
            operation,
            status: response.status().as_u16(),
            retry_after: crate::error::retry_after(response.headers()),
            body: response.into_body(),
        }
        .into());
    }
    let mut types = response
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter();
    let content_type = types.next().and_then(|v| v.to_str().ok());
    if types.next().is_some() || !content_type.is_some_and(Client::is_exact_json_content_type) {
        return Err(eyre!(
            "gateway-compliance response requires exactly one application/json content type"
        ));
    }
    norito::json::from_slice(response.body()).map_err(Into::into)
}
#[cfg(test)]
#[path = "gateway_compliance_tests.rs"]
mod tests;
