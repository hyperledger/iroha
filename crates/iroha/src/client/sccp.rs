//! Public asynchronous SCCP v1 reads on one immutable client context (`specs/sccp.md` §6).
//!
//! Every response is data from one Taira peer; nothing here is trusted. Wallets verify proof
//! bundles locally before using them.
//! Proofs select a committed certificate height; readers independently verify its authority.

use super::{Client, dispatch, join_torii_url};
use crate::{Error, Result, http::Method};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, bridge::SccpNetworkV1, sccp::registry::SccpRouteV1,
};
use iroha_sccp::api::{
    SccpCapabilitiesV1, SccpControlPageV1, SccpControlProofBundleV1, SccpGenerationV1,
    SccpGovernanceProposalDetailV1, SccpHistoryPathViewV1, SccpLcCheckpointCoverV1,
    SccpLightClientDetailV1, SccpMessageProofBundleV1, SccpMessageStatusV1, SccpOutboundPageV1,
    SccpRecentMessagesV1, SccpRotationV1,
};
use iroha_torii_shared::route_catalog::{RouteDescriptor, sccp};
use norito::json::JsonDeserialize;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Select the committed certificate height of a proof bundle (`?at=`).
pub use iroha_sccp::api::SccpProofHeightV1;

/// Direction filter of [`Sccp::recent_messages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpDirection {
    /// Taira → external records.
    Outbound,
    /// External → Taira records.
    Inbound,
}

impl SccpDirection {
    const fn query(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

/// Public SCCP read routes.
///
/// Committee reads carry native BLS generation metadata; attestation roster reads are absent:
///
/// ```compile_fail,E0599
/// fn removed_current_roster(api: &iroha::client::sccp::Sccp<'_>) {
///     let _ = api.current_roster();
/// }
/// ```
///
/// ```compile_fail,E0599
/// fn removed_roster(api: &iroha::client::sccp::Sccp<'_>) {
///     let _ = api.roster(1);
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Sccp<'a> {
    client: &'a Client,
}

impl Client {
    /// Access the public SCCP read API through the context's asynchronous transport.
    #[must_use]
    pub const fn sccp(&self) -> Sccp<'_> {
        Sccp { client: self }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Fill the `{name}` placeholders of `route`'s path in order.
fn path(route: RouteDescriptor, values: &[&str]) -> String {
    let mut path = route.path().to_owned();
    for value in values {
        if let (Some(start), Some(end)) = (path.find('{'), path.find('}')) {
            path.replace_range(start..=end, value);
        }
    }
    path
}

impl Sccp<'_> {
    async fn get<R: JsonDeserialize>(
        &self,
        route: RouteDescriptor,
        path_and_query: &str,
    ) -> Result<R> {
        let operation = route.stable_route_id();
        let response = dispatch::send(
            self.client,
            operation,
            self.client
                .default_request(
                    Method::GET,
                    join_torii_url(&self.client.torii_url, path_and_query),
                )
                .max_response_bytes(MAX_RESPONSE_BYTES),
            "application/json",
        )
        .await?;
        if response.status() != crate::http::StatusCode::OK {
            return Err(Error::Http {
                operation,
                status: response.status().as_u16(),
                retry_after: crate::error::retry_after(response.headers()),
                body: response.into_body(),
            });
        }
        let _format = ChainDiscriminantGuard::enter(self.client.account_chain_discriminant);
        decode_body(operation, response.body())
    }

    /// Read the Taira identity, parameters and light-client profiles.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn capabilities(&self) -> Result<SccpCapabilitiesV1> {
        self.get(sccp::CAPABILITIES, sccp::CAPABILITIES.path())
            .await
    }

    /// Read current committee metadata; authenticate its keys through signed history.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or strict decoding errors.
    pub async fn current_committee(&self) -> Result<SccpGenerationV1> {
        self.get(sccp::CURRENT_COMMITTEE, sccp::CURRENT_COMMITTEE.path())
            .await
    }

    /// Read one generation's retained keys and current liability.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or strict decoding errors, including pruned history.
    pub async fn committee(&self, generation: u64) -> Result<SccpGenerationV1> {
        self.get(
            sccp::COMMITTEE,
            &path(sccp::COMMITTEE, &[&generation.to_string()]),
        )
        .await
    }

    /// Read current native rotation certificates after an independently pinned generation.
    /// The caller authenticates every step before changing its destination committee.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or strict decoding errors. An unavailable
    /// native archive is an explicit service error; it never supplies a synthetic rotation.
    pub async fn rotations(
        &self,
        after_generation: u64,
        limit: usize,
    ) -> Result<Vec<SccpRotationV1>> {
        self.get(
            sccp::COMMITTEE_ROTATIONS,
            &format!(
                "{}?after_generation={after_generation}&limit={limit}",
                sccp::COMMITTEE_ROTATIONS.path()
            ),
        )
        .await
    }

    /// Read the nonzero per-subject governance revisions (absent subjects are at 0).
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn governance_revisions(
        &self,
    ) -> Result<Vec<iroha_data_model::sccp::governance::SccpGovernanceBaseRevisionV1>> {
        self.get(sccp::GOVERNANCE, sccp::GOVERNANCE.path()).await
    }

    /// Read every open SCCP governance proposal, oldest first.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn governance_proposals(
        &self,
    ) -> Result<Vec<iroha_sccp::api::SccpGovernanceProposalStatusV1>> {
        self.get(
            sccp::GOVERNANCE_PROPOSALS,
            sccp::GOVERNANCE_PROPOSALS.path(),
        )
        .await
    }

    /// Read every installed inbound light client.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn light_clients(
        &self,
    ) -> Result<Vec<iroha_data_model::sccp::light_client::SccpLightClientV1>> {
        self.get(sccp::LIGHT_CLIENTS, sccp::LIGHT_CLIENTS.path())
            .await
    }

    /// Read the stored consensus sets of `network`'s light client.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn light_client_sets(
        &self,
        network: SccpNetworkV1,
    ) -> Result<Vec<iroha_data_model::sccp::light_client::SccpLcConsensusSetV1>> {
        self.get(
            sccp::LIGHT_CLIENT_SETS,
            &path(sccp::LIGHT_CLIENT_SETS, &[network.profile_key()]),
        )
        .await
    }

    /// Read every route with its escrow, stranded balance and revisions.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn registry(&self) -> Result<Vec<SccpRouteV1>> {
        self.get(sccp::REGISTRY, sccp::REGISTRY.path()).await
    }

    /// Read the status union of one message id: an outbound record with its state, an inbound
    /// record, or `Unknown` (for a burn whose proof Taira has not accepted yet).
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn message(&self, message_id: &[u8; 32]) -> Result<SccpMessageStatusV1> {
        self.get(sccp::MESSAGE, &path(sccp::MESSAGE, &[&hex32(message_id)]))
            .await
    }

    /// Read the newest records of one direction, at most `limit` (≤ 50), older than the
    /// `before` cursor of a previous page.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn recent_messages(
        &self,
        direction: SccpDirection,
        network: Option<SccpNetworkV1>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<SccpRecentMessagesV1> {
        self.get(
            sccp::MESSAGES_RECENT,
            &recent_path(direction, network, before, limit),
        )
        .await
    }

    /// Read the outbound records of `(network, revision)` from nonce `from_nonce`, at most
    /// `limit` (≤ 256), with their states.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (404 for an unknown revision) or decoding errors.
    pub async fn outbound(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        from_nonce: u64,
        limit: usize,
    ) -> Result<SccpOutboundPageV1> {
        let path = format!(
            "{}?from_nonce={from_nonce}&limit={limit}",
            path(
                sccp::OUTBOUND_BY_NONCE,
                &[network.profile_key(), &revision.to_string()]
            )
        );
        self.get(sccp::OUTBOUND_BY_NONCE, &path).await
    }

    /// Read the destination controls of `(network, revision)` above `after_nonce`, at most
    /// `limit` (≤ 64), with their committed record heights.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (404 for an unknown revision) or decoding errors.
    pub async fn controls(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        after_nonce: u64,
        limit: usize,
    ) -> Result<SccpControlPageV1> {
        let path = format!(
            "{}?after_nonce={after_nonce}&limit={limit}",
            path(
                sccp::CONTROLS,
                &[network.profile_key(), &revision.to_string()]
            )
        );
        self.get(sccp::CONTROLS, &path).await
    }

    /// Read the history path of SCCP block `height` within `history_root(size)` (the current
    /// size when `None`).
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn history(&self, height: u64, size: Option<u64>) -> Result<SccpHistoryPathViewV1> {
        let base = path(sccp::HISTORY, &[&height.to_string()]);
        let path = match size {
            Some(size) => format!("{base}?size={size}"),
            None => base,
        };
        self.get(sccp::HISTORY, &path).await
    }

    /// Read one inbound light client with its freshness, compiled profile and stored data.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (404 when not installed) or decoding errors.
    pub async fn light_client(&self, network: SccpNetworkV1) -> Result<SccpLightClientDetailV1> {
        self.get(
            sccp::LIGHT_CLIENT,
            &path(sccp::LIGHT_CLIENT, &[network.profile_key()]),
        )
        .await
    }

    /// Read the stored checkpoints that anchor an ancestry proof of source height `covering`.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (404 before Taira finalizes `covering`, 410 when no
    /// covering checkpoint is retained) or decoding errors.
    pub async fn light_client_checkpoints(
        &self,
        network: SccpNetworkV1,
        covering: u64,
    ) -> Result<SccpLcCheckpointCoverV1> {
        let path = format!(
            "{}?covering={covering}",
            path(sccp::LIGHT_CLIENT_CHECKPOINTS, &[network.profile_key()])
        );
        self.get(sccp::LIGHT_CLIENT_CHECKPOINTS, &path).await
    }

    /// Read one SCCP governance proposal in any phase.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (404 when unknown) or decoding errors.
    pub async fn governance_proposal(
        &self,
        content_id: &[u8; 32],
    ) -> Result<SccpGovernanceProposalDetailV1> {
        self.get(
            sccp::GOVERNANCE_PROPOSAL,
            &path(sccp::GOVERNANCE_PROPOSAL, &[&hex32(content_id)]),
        )
        .await
    }

    /// Read the requested message's proof at the selected certificate height.
    /// Identity and height equality do not authenticate the proof; the caller still verifies
    /// certificate authority, payload identity and inclusion. `Latest` supplies no freshness guarantee.
    ///
    /// # Errors
    /// Invalid zero height, structured transport/HTTP/decoding error, or response binding mismatch.
    pub async fn message_proof(
        &self,
        message_id: &[u8; 32],
        at: SccpProofHeightV1,
    ) -> Result<SccpMessageProofBundleV1> {
        let operation = sccp::MESSAGE_PROOF.stable_route_id();
        validate_proof_selector(operation, at)?;
        let path = format!(
            "{}?at={}",
            path(sccp::MESSAGE_PROOF, &[&hex32(message_id)]),
            at
        );
        let response: SccpMessageProofBundleV1 = self.get(sccp::MESSAGE_PROOF, &path).await?;
        if response.message_id != *message_id {
            return Err(Error::ResponseBinding {
                operation,
                field: "message_id",
            });
        }
        bind_proof_height(
            operation,
            at,
            response.block.height,
            response.certificate.height,
        )?;
        Ok(response)
    }

    /// Read the exact network, revision and nonce's proof at the selected certificate height.
    /// Equality does not authenticate the control or its cause; the caller still verifies
    /// certificate authority and inclusion. `Latest` supplies no freshness guarantee.
    ///
    /// # Errors
    /// Invalid zero height, structured transport/HTTP/decoding error, or response binding mismatch.
    pub async fn control_proof(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        control_nonce: u64,
        at: SccpProofHeightV1,
    ) -> Result<SccpControlProofBundleV1> {
        let operation = sccp::CONTROL_PROOF.stable_route_id();
        validate_proof_selector(operation, at)?;
        let path = format!(
            "{}?at={}",
            path(
                sccp::CONTROL_PROOF,
                &[
                    network.profile_key(),
                    &revision.to_string(),
                    &control_nonce.to_string()
                ]
            ),
            at
        );
        let response: SccpControlProofBundleV1 = self.get(sccp::CONTROL_PROOF, &path).await?;
        if response.network != network {
            return Err(Error::ResponseBinding {
                operation,
                field: "network",
            });
        }
        if response.revision != revision {
            return Err(Error::ResponseBinding {
                operation,
                field: "revision",
            });
        }
        if response.control_nonce != control_nonce {
            return Err(Error::ResponseBinding {
                operation,
                field: "control_nonce",
            });
        }
        bind_proof_height(
            operation,
            at,
            response.block.height,
            response.certificate.height,
        )?;
        Ok(response)
    }
}

fn validate_proof_selector(operation: &'static str, at: SccpProofHeightV1) -> Result<()> {
    if matches!(at, SccpProofHeightV1::At(0)) {
        return Err(Error::InvalidRequest {
            operation,
            details: "explicit SCCP proof height must be positive".to_owned(),
        });
    }
    Ok(())
}

fn bind_proof_height(
    operation: &'static str,
    at: SccpProofHeightV1,
    record_height: u64,
    certificate_height: u64,
) -> Result<()> {
    let expected = match at {
        SccpProofHeightV1::Record => record_height,
        SccpProofHeightV1::At(height) => height,
        SccpProofHeightV1::Latest => return Ok(()),
    };
    if certificate_height != expected {
        return Err(Error::ResponseBinding {
            operation,
            field: "certificate.height",
        });
    }
    Ok(())
}

/// The path and query of a recent-messages request.
fn recent_path(
    direction: SccpDirection,
    network: Option<SccpNetworkV1>,
    before: Option<&str>,
    limit: usize,
) -> String {
    let mut path = format!(
        "{}?direction={}&limit={limit}",
        sccp::MESSAGES_RECENT.path(),
        direction.query()
    );
    if let Some(network) = network {
        path.push_str("&network=");
        path.push_str(network.profile_key());
    }
    if let Some(before) = before {
        // Server cursors are `<height>:<index>` or `<height>:<hex>`; a cursor typed by hand is
        // percent-encoded whole so it cannot inject other query parameters.
        path.push_str("&before=");
        path.extend(url::form_urlencoded::byte_serialize(before.as_bytes()));
    }
    path
}

/// Decode one JSON response body of `operation`.
fn decode_body<R: JsonDeserialize>(operation: &'static str, body: &[u8]) -> Result<R> {
    norito::json::from_slice(body).map_err(|error| Error::Decode {
        operation,
        details: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_fill_placeholders_in_order() {
        assert_eq!(
            sccp::CURRENT_COMMITTEE.path(),
            "/v1/sccp/committees/current"
        );
        assert_eq!(path(sccp::COMMITTEE, &["7"]), "/v1/sccp/committees/7");
        assert_eq!(
            sccp::COMMITTEE_ROTATIONS.path(),
            "/v1/sccp/committees/rotations"
        );
        assert_eq!(
            path(sccp::MESSAGE_PROOF, &["ab"]),
            "/v1/sccp/messages/ab/proof"
        );
        assert_eq!(
            path(sccp::CONTROL_PROOF, &["ton-mainnet", "2", "7"]),
            "/v1/sccp/controls/ton-mainnet/2/7/proof"
        );
        assert_eq!(path(sccp::HISTORY, &["4"]), "/v1/sccp/history/4");
        assert_eq!(
            path(sccp::OUTBOUND_BY_NONCE, &["bsc-mainnet", "3"]),
            "/v1/sccp/outbound/bsc-mainnet/3"
        );
        assert_eq!(
            path(sccp::LIGHT_CLIENT_CHECKPOINTS, &["ethereum-mainnet"]),
            "/v1/sccp/light-clients/ethereum-mainnet/checkpoints"
        );
        assert_eq!(
            path(sccp::GOVERNANCE_PROPOSAL, &["ab"]),
            "/v1/sccp/governance/proposals/ab"
        );
    }

    #[test]
    fn recent_queries_encode_filters_and_cursors() {
        assert_eq!(
            recent_path(SccpDirection::Outbound, None, None, 50),
            "/v1/sccp/messages/recent?direction=outbound&limit=50"
        );
        assert_eq!(
            recent_path(
                SccpDirection::Inbound,
                Some(SccpNetworkV1::TonMainnet),
                Some("12:ab"),
                5
            ),
            "/v1/sccp/messages/recent?direction=inbound&limit=5&network=ton-mainnet&before=12%3Aab"
        );
        assert_eq!(
            recent_path(SccpDirection::Outbound, None, Some("1:2&limit=9#x"), 5),
            "/v1/sccp/messages/recent?direction=outbound&limit=5&before=1%3A2%26limit%3D9%23x",
            "a hand-typed cursor cannot add query parameters"
        );
    }

    #[test]
    fn read_views_decode_from_server_json() {
        use iroha_data_model::sccp::{
            inbound::{
                SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1, SccpSourceLocatorV1,
            },
            light_client::SccpLcPointV1,
        };
        use iroha_sccp::api::{
            SccpInboundMessageViewV1, SccpLcCheckpointCoverV1, SccpLcCheckpointEntryV1,
        };
        let unknown = norito::json::to_vec(&SccpMessageStatusV1::Unknown).expect("JSON");
        assert_eq!(
            decode_body::<SccpMessageStatusV1>("sccp.message.read", &unknown).expect("decode"),
            SccpMessageStatusV1::Unknown
        );
        let inbound = SccpMessageStatusV1::Inbound(SccpInboundMessageViewV1 {
            message_id: [4; 32],
            record: SccpInboundRecordV1 {
                network: SccpNetworkV1::BscMainnet,
                revision: 2,
                payload: vec![1, 2],
                source_locator: SccpSourceLocatorV1 {
                    source_height: 9,
                    block_hash: [5; 32],
                    index_in_block: 1,
                },
                proven_at_height: 30,
                fee_due: 0,
                status: SccpInboundStatusV1::pending(SccpPendingReasonV1::LiabilityShortfall),
            },
        });
        let json = norito::json::to_vec(&inbound).expect("JSON");
        assert_eq!(
            decode_body::<SccpMessageStatusV1>("sccp.message.read", &json).expect("decode"),
            inbound
        );
        let page = SccpRecentMessagesV1 {
            messages: vec![inbound],
            next_before: Some("30:04".to_owned()),
        };
        let json = norito::json::to_vec(&page).expect("JSON");
        assert_eq!(
            decode_body::<SccpRecentMessagesV1>("sccp.messages.recent", &json).expect("decode"),
            page
        );
        let checkpoint = iroha_data_model::sccp::light_client::SccpLcCheckpointV1 {
            data: iroha_data_model::sccp::light_client::SccpLcCheckpointDataV1 {
                source_height: 100,
                block_hash: [1; 32],
                state_root: None,
                receipts_or_tx_root: [2; 32],
                source_time_ms: 5,
            },
            recorded_at_taira_ms: 6,
            origin: iroha_data_model::sccp::light_client::SccpLcCheckpointOriginV1::Backfill,
        };
        let cover = SccpLcCheckpointCoverV1 {
            network: SccpNetworkV1::EthereumMainnet,
            covering: 90,
            head: SccpLcPointV1 {
                source_height: 200,
                block_hash: [3; 32],
                source_time_ms: 7,
            },
            nearest: SccpLcCheckpointEntryV1 {
                checkpoint,
                permanent: false,
            },
            nearest_permanent: None,
        };
        let json = norito::json::to_vec(&cover).expect("JSON");
        assert_eq!(
            decode_body::<SccpLcCheckpointCoverV1>("sccp.light_client.checkpoints", &json)
                .expect("decode"),
            cover
        );
        let error =
            decode_body::<SccpOutboundPageV1>("sccp.outbound.by_nonce", b"{\"records\":[]}")
                .expect_err("incomplete page");
        assert!(matches!(
            error,
            Error::Decode {
                operation: "sccp.outbound.by_nonce",
                ..
            }
        ));
    }

    #[test]
    fn proof_height_queries_are_canonical() {
        assert_eq!(SccpProofHeightV1::Record.to_string(), "record");
        assert_eq!(SccpProofHeightV1::Latest.to_string(), "latest");
        assert_eq!(SccpProofHeightV1::At(12).to_string(), "12");
    }
}

#[cfg(test)]
mod proof_binding_tests;
