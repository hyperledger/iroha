//! One-shot enrollment transport; signed originals are admitted by the native wallet owner.

use super::{
    Client, EnrollmentServiceActionV1 as Action, EnrollmentServiceRequestV1,
    EnrollmentServiceResponseV1 as Response, Kagemusha,
};
use crate::{
    Error, Result,
    client::{dispatch, join_torii_url},
    http::{Method, StatusCode},
};
use iroha_torii_shared::kagemusha_enrollment::{
    ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1, ENROLLMENT_SERVICE_ROUTE_V1,
    EnrollmentServiceOutcomeV1,
};

const OP: &str = "kagemusha.wallet.enrollment";
const MIME: &str = "application/x-norito";

impl Kagemusha<'_> {
    /// Send one enrollment operation under this account's exact network signature.
    ///
    /// Supply the original dispatch and, for Evidence, the original account-signed E5 from
    /// the native enrollment owner. This signs the complete canonical envelope, including its
    /// action. It performs one asynchronous POST with bounded input/output and no automatic
    /// retry. Recovery resubmits the same native originals with fresh HTTP authentication;
    /// a timeout never permits a new platform attempt.
    ///
    /// A response is transport data: pass Permit/E6 originals to the native owner for their
    /// full signature, scope, deadline and durable-state checks before reporting completion.
    /// The service independently checks current provider eligibility at each boundary.
    ///
    /// # Errors
    /// [`Error::EnrollmentOutcome`] for a closed refusal, withheld delivery or unknown outcome
    /// (identical statuses carry different outcomes); rejects invalid envelopes, witness-based
    /// signing, elapsed deadlines, HTTP/transport failures, malformed outcome headers, invalid
    /// canonical responses or a response for a different action.
    pub async fn enrollment(&self, request: &EnrollmentServiceRequestV1) -> Result<Response> {
        let client = &self.account.context;
        if client.account.controller.single_signatory() != Some(client.key_pair.public_key())
            || client
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("X-Iroha-Witness"))
        {
            return Err(Error::InvalidRequest {
                operation: OP,
                details: "enrollment requires the direct account signer without witness headers"
                    .to_owned(),
            });
        }
        ensure_deadline(client)?;
        let original = request
            .canonical_wire()
            .map_err(|error| Error::InvalidRequest {
                operation: OP,
                details: error.to_string(),
            })?;
        let url = join_torii_url(&client.torii_url, ENROLLMENT_SERVICE_ROUTE_V1);
        let builder = client
            .account_signed_request(Method::POST, url, original)
            .map_err(|error| Error::RequestSigning {
                operation: OP,
                details: error.to_string(),
            })?
            .replace_header(http::header::CONTENT_TYPE, MIME)
            .max_response_bytes(ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1);
        let response = dispatch::send(client, OP, builder, MIME).await?;
        // Outcome headers are read on every response: a success carrying one, a malformed one
        // or one whose status differs is a decode failure, never success or generic HTTP.
        let outcome = EnrollmentServiceOutcomeV1::from_headers(
            response.status().as_u16(),
            response
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
        )
        .map_err(|error| Error::Decode {
            operation: OP,
            details: error.to_string(),
        })?;
        if let Some(outcome) = outcome {
            return Err(Error::EnrollmentOutcome {
                operation: OP,
                outcome,
            });
        }
        if response.status() != StatusCode::OK {
            return Err(Error::Http {
                operation: OP,
                status: response.status().as_u16(),
                retry_after: crate::error::retry_after(response.headers()),
                body: response.into_body(),
            });
        }
        let result: Response = Client::decode_canonical_norito_response(
            &response,
            ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1,
            OP,
        )?;
        // The canonical codec checks bytes, while the shared response validator also checks
        // nonempty native originals and their individual caps before exposing any result.
        result.canonical_wire().map_err(|error| Error::Decode {
            operation: OP,
            details: error.to_string(),
        })?;
        if !matches!(
            (request.action, &result),
            (Action::PreKey, Response::Permit(_))
                | (
                    Action::Evidence,
                    Response::EvidenceReady | Response::Pending
                )
                | (Action::Issue, Response::CredentialReady)
                | (Action::Deliver, Response::Credential(_))
        ) {
            return Err(Error::ResponseBinding {
                operation: OP,
                field: "enrollment action",
            });
        }
        ensure_deadline(client)?;
        Ok(result)
    }
}

fn ensure_deadline(client: &Client) -> Result<()> {
    if client
        .http_transport
        .deadline()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(Error::Timeout { operation: OP });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
