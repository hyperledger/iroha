//! Bounded public reads of committee preparation and exact finality attachments.

use super::*;
use iroha_data_model::{
    nexus::ValidatorCommitteeStatusV1, sumeragi::finality::NativeFinalityLimits,
};

const COMMITTEE_STATUS_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;

impl super::Nexus<'_> {
    /// Fetch one committee attempt as canonical Norito under the normal request deadline.
    ///
    /// Omit `target_epoch` to inspect the next scheduling epoch. These are progress
    /// observations; the caller must authenticate both finality attachments from an
    /// independently configured native chain and signed genesis before provisioning or signing.
    /// An omitted target is a server-selected, untrusted observation; this transport reader
    /// does not infer epoch authority from decoded result bytes or authenticate a QC.
    ///
    /// # Errors
    /// Rejects transport, HTTP status, media type, body bound, codec, network and target mismatches.
    pub async fn validator_committee(
        &self,
        target_epoch: Option<u64>,
    ) -> crate::Result<ValidatorCommitteeStatusV1> {
        let operation = "nexus.validator_committee.read";
        if target_epoch == Some(0) {
            return Err(crate::Error::InvalidRequest {
                operation,
                details: "target epoch must be positive".to_owned(),
            });
        }
        let route = iroha_torii_shared::route_catalog::core::NEXUS_VALIDATOR_COMMITTEE_GET.path();
        let path = target_epoch.map_or_else(
            || route.to_owned(),
            |epoch| format!("{route}?target_epoch={epoch}"),
        );
        let request = self
            .client
            .canonical_norito_get_request(
                &path,
                COMMITTEE_STATUS_RESPONSE_MAX_BYTES,
                ActivationEvidenceReadAuth::Public,
            )
            .map_err(|error| crate::Error::InvalidRequest {
                operation,
                details: error.to_string(),
            })?;
        let response = dispatch::send(self.client, operation, request, APPLICATION_NORITO).await?;
        if response.status() != StatusCode::OK {
            return Err(crate::Error::Http {
                operation,
                status: response.status().as_u16(),
                retry_after: crate::error::retry_after(response.headers()),
                body: response.into_body(),
            });
        }
        let status: ValidatorCommitteeStatusV1 = Client::decode_canonical_norito_response(
            &response,
            COMMITTEE_STATUS_RESPONSE_MAX_BYTES,
            operation,
        )?;
        let source = status
            .latest_finality
            .decode_block(NativeFinalityLimits {
                block_bytes: COMMITTEE_STATUS_RESPONSE_MAX_BYTES,
                journal_bytes: COMMITTEE_STATUS_RESPONSE_MAX_BYTES,
                block_count: 256,
                allocated_bytes: 64 * 1024 * 1024,
            })
            .map_err(|source| {
                crate::Error::NativeFinalityDecode(Box::new(crate::NativeFinalityDecodeFailure {
                    operation,
                    source,
                }))
            })?;
        if status.network_id != self.client.network_id
            || target_epoch.is_some_and(|epoch| status.target_epoch != epoch)
            || status.target_epoch == 0
            || source.header().height().get() < 2
            || source
                .external_transactions()
                .any(|transaction| transaction.network_id() != Some(&self.client.network_id))
        {
            return Err(crate::Error::ResponseBinding {
                operation,
                field: "network, target epoch or native source",
            });
        }
        if self
            .client
            .http_transport
            .deadline()
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(crate::Error::Timeout { operation });
        }
        Ok(status)
    }
}
