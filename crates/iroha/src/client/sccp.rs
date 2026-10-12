//! Public asynchronous SCCP v1 reads on one immutable client context (`specs/sccp.md` §6).
//!
//! Every response is data from one Taira peer. These status and registry views do not
//! independently authenticate finality; callers must verify the corresponding native proofs.

use std::num::NonZeroU64;

use super::{Client, dispatch, join_torii_url};
use crate::{Error, Result, http::Method};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, bridge::SccpNetworkV1, sccp::registry::SccpRouteV1,
};
use iroha_sccp::api::{
    SccpCapabilitiesV1, SccpCertificateV1, SccpControlPageV1, SccpControlProofBundleV1,
    SccpGenerationV1, SccpGovernanceProposalDetailV1, SccpHistoryPathViewV1,
    SccpLcCheckpointCoverV1, SccpLightClientDetailV1, SccpMessageProofBundleV1,
    SccpMessageStatusV1, SccpOutboundPageV1, SccpRecentMessagesV1, SccpRotationV1,
};
use iroha_torii_shared::route_catalog::{RouteDescriptor, sccp};
use norito::json::JsonDeserialize;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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

/// Certified height selected for a native message or control proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpProofAt {
    /// The record's own committed height.
    Record,
    /// The peer's durable tip; callers still independently verify the certificate.
    Latest,
    /// One explicit height, making the response immutable at that selected height.
    Height(NonZeroU64),
}

impl SccpProofAt {
    fn query(self) -> String {
        match self {
            Self::Record => "record".into(),
            Self::Latest => "latest".into(),
            Self::Height(height) => height.to_string(),
        }
    }
}

/// Height selected for a native certificate read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpFinalityAt {
    /// The peer's durable tip.
    Latest,
    /// One explicit nonzero height. Genesis has no Commit certificate.
    Height(NonZeroU64),
}

impl SccpFinalityAt {
    fn path_value(self) -> String {
        match self {
            Self::Latest => "latest".into(),
            Self::Height(height) => height.to_string(),
        }
    }
}

/// Public SCCP read routes.
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

    /// Read the Taira identity, parameters and inbound light-client profiles.
    ///
    /// # Errors
    /// Returns structured transport, HTTP or decoding errors.
    pub async fn capabilities(&self) -> Result<SccpCapabilitiesV1> {
        self.get(sccp::CAPABILITIES, sccp::CAPABILITIES.path())
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

    /// Read a native message proof. Authenticate it against independently pinned
    /// destination state before use; a successful HTTP response conveys no authority.
    ///
    /// # Errors
    /// Returns structured transport, HTTP, retention or decoding errors.
    pub async fn message_proof(
        &self,
        message_id: &[u8; 32],
        at: SccpProofAt,
    ) -> Result<SccpMessageProofBundleV1> {
        let request = format!(
            "{}?at={}",
            path(sccp::MESSAGE_PROOF, &[&hex32(message_id)]),
            at.query()
        );
        self.get(sccp::MESSAGE_PROOF, &request).await
    }

    /// Read a native control proof including both pause tracks and the recorded block.
    /// The caller authenticates the certificate and expected route/revision independently.
    ///
    /// # Errors
    /// Returns structured transport, HTTP, retention or decoding errors.
    pub async fn control_proof(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        control_nonce: u64,
        at: SccpProofAt,
    ) -> Result<SccpControlProofBundleV1> {
        let request = format!(
            "{}?at={}",
            path(
                sccp::CONTROL_PROOF,
                &[
                    network.profile_key(),
                    &revision.to_string(),
                    &control_nonce.to_string()
                ]
            ),
            at.query()
        );
        self.get(sccp::CONTROL_PROOF, &request).await
    }

    /// Read the original native certificate DATA at an explicit height or the durable tip.
    /// A certificate is not trusted until verified under the pinned consensus instance and committee.
    ///
    /// # Errors
    /// Returns structured transport, HTTP, retention or decoding errors.
    pub async fn finality(&self, at: SccpFinalityAt) -> Result<SccpCertificateV1> {
        self.get(sccp::FINALITY, &path(sccp::FINALITY, &[&at.path_value()]))
            .await
    }

    /// Read the retained current committee, including a successor installed for the next
    /// height. This is peer DATA, not an independently authenticated deployment pin.
    ///
    /// # Errors
    /// Returns structured transport, unavailable-source or decoding errors.
    pub async fn current_committee(&self) -> Result<SccpGenerationV1> {
        self.get(sccp::CURRENT_COMMITTEE, sccp::CURRENT_COMMITTEE.path())
            .await
    }

    /// Read a retained generation with liability computed at the peer's current view.
    /// Its existence and keys convey no finality authority; historical liability can change.
    ///
    /// # Errors
    /// Preserves not-found, unavailable-source, transport and decoding errors.
    pub async fn committee(&self, generation: NonZeroU64) -> Result<SccpGenerationV1> {
        self.get(
            sccp::COMMITTEE,
            &path(sccp::COMMITTEE, &[&generation.to_string()]),
        )
        .await
    }

    /// Read up to `limit` (at most 16) ordered native transitions from the current generation.
    /// The first certificate is signed by `after_generation` for its handoff to the successor.
    /// Verify the sequence from the destination's actual current state before submission.
    ///
    /// # Errors
    /// Returns structured transport, HTTP (including pruned transitions) or decoding errors.
    pub async fn committee_rotations(
        &self,
        after_generation: u64,
        limit: usize,
    ) -> Result<Vec<SccpRotationV1>> {
        let request = format!(
            "{}?after_generation={after_generation}&limit={limit}",
            sccp::COMMITTEE_ROTATIONS.path()
        );
        self.get(sccp::COMMITTEE_ROTATIONS, &request).await
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
    /// `limit` (≤ 64), with their committed record state.
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
    fn native_proof_selectors_and_paths_are_exact() {
        let height = NonZeroU64::new(u64::MAX).unwrap();
        assert_eq!(SccpProofAt::Record.query(), "record");
        assert_eq!(SccpProofAt::Latest.query(), "latest");
        assert_eq!(SccpProofAt::Height(height).query(), u64::MAX.to_string());
        assert_eq!(SccpFinalityAt::Latest.path_value(), "latest");
        assert_eq!(
            sccp::CURRENT_COMMITTEE.path(),
            "/v1/sccp/committees/current"
        );
        assert_eq!(
            path(sccp::COMMITTEE, &[&height.to_string()]),
            format!("/v1/sccp/committees/{}", u64::MAX)
        );
        assert_eq!(
            SccpFinalityAt::Height(height).path_value(),
            u64::MAX.to_string()
        );
        assert_eq!(
            path(sccp::MESSAGE_PROOF, &["ab"]),
            "/v1/sccp/messages/ab/proof"
        );
        assert_eq!(
            path(sccp::CONTROL_PROOF, &["ton-mainnet", "2", "3"]),
            "/v1/sccp/controls/ton-mainnet/2/3/proof"
        );
        assert_eq!(
            path(sccp::FINALITY, &["latest"]),
            "/v1/sccp/finality/latest"
        );
        assert_eq!(
            sccp::COMMITTEE_ROTATIONS.path(),
            "/v1/sccp/committees/rotations"
        );
    }

    #[test]
    fn native_reads_share_bounded_async_transport_and_preserve_errors() {
        use crate::client::{
            capability_test_support::AsyncOnlyTransport,
            evidence_http_tests::{base_url, client_with_base_url},
        };
        use std::{
            sync::{Arc, Mutex, atomic::AtomicUsize},
            time::Duration,
        };

        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(AsyncOnlyTransport {
            responder: Box::new(|_| {
                Ok(crate::http::Response::builder()
                    .status(503)
                    .header("Retry-After", "2")
                    .body(b"native source unavailable".to_vec())
                    .unwrap())
            }),
            requests: requests.clone(),
            completed: Arc::new(AtomicUsize::new(0)),
            delay: Duration::ZERO,
        });
        let client = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport)
            .build()
            .unwrap();
        let blocking = crate::blocking::Client::from_client(client.clone()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let id = [0xab; 32];
        let expected = [
            sccp::MESSAGE_PROOF,
            sccp::CONTROL_PROOF,
            sccp::FINALITY,
            sccp::COMMITTEE_ROTATIONS,
            sccp::CURRENT_COMMITTEE,
            sccp::COMMITTEE,
        ];
        let check = |errors: [Option<Error>; 6]| {
            for (error, route) in errors.into_iter().zip(expected) {
                match error.expect("unavailable source") {
                    Error::Http {
                        operation,
                        status,
                        retry_after,
                        body,
                    } => {
                        assert_eq!(operation, route.stable_route_id());
                        assert_eq!(status, 503);
                        assert!(retry_after.is_some());
                        assert_eq!(body, b"native source unavailable");
                    }
                    error => panic!("original HTTP error lost: {error}"),
                }
            }
        };
        runtime.block_on(async {
            check([
                client
                    .sccp()
                    .message_proof(&id, SccpProofAt::Record)
                    .await
                    .err(),
                client
                    .sccp()
                    .control_proof(SccpNetworkV1::TonMainnet, 2, 3, SccpProofAt::Latest)
                    .await
                    .err(),
                client
                    .sccp()
                    .finality(SccpFinalityAt::Height(NonZeroU64::new(7).unwrap()))
                    .await
                    .err(),
                client.sccp().committee_rotations(4, 16).await.err(),
                client.sccp().current_committee().await.err(),
                client
                    .sccp()
                    .committee(NonZeroU64::new(1).unwrap())
                    .await
                    .err(),
            ]);
            // All six blocking operations reject an async context before I/O.
            let errors = [
                blocking
                    .sccp()
                    .message_proof(&id, SccpProofAt::Record)
                    .err(),
                blocking
                    .sccp()
                    .control_proof(SccpNetworkV1::TonMainnet, 2, 3, SccpProofAt::Latest)
                    .err(),
                blocking.sccp().finality(SccpFinalityAt::Latest).err(),
                blocking.sccp().committee_rotations(4, 16).err(),
                blocking.sccp().current_committee().err(),
                blocking.sccp().committee(NonZeroU64::new(1).unwrap()).err(),
            ];
            assert!(
                errors
                    .into_iter()
                    .all(|error| matches!(error, Some(Error::Blocking(_))))
            );
        });
        check([
            blocking
                .sccp()
                .message_proof(&id, SccpProofAt::Record)
                .err(),
            blocking
                .sccp()
                .control_proof(SccpNetworkV1::TonMainnet, 2, 3, SccpProofAt::Latest)
                .err(),
            blocking
                .sccp()
                .finality(SccpFinalityAt::Height(NonZeroU64::new(7).unwrap()))
                .err(),
            blocking.sccp().committee_rotations(4, 16).err(),
            blocking.sccp().current_committee().err(),
            blocking.sccp().committee(NonZeroU64::new(1).unwrap()).err(),
        ]);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 12);
        let expected_paths = [
            format!("/v1/sccp/messages/{}/proof?at=record", hex32(&id)),
            "/v1/sccp/controls/ton-mainnet/2/3/proof?at=latest".into(),
            "/v1/sccp/finality/7".into(),
            "/v1/sccp/committees/rotations?after_generation=4&limit=16".into(),
            "/v1/sccp/committees/current".into(),
            "/v1/sccp/committees/1".into(),
        ];
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request.method, Method::GET);
            assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
            assert_eq!(
                &request.url[url::Position::BeforePath..],
                expected_paths[index % 6]
            );
        }
    }

    #[test]
    fn committee_reads_decode_complete_data_without_creating_a_trust_pin() {
        use crate::client::{
            capability_test_support::AsyncOnlyTransport,
            evidence_http_tests::{base_url, client_with_base_url},
        };
        use iroha_sccp::api::{SccpGenerationCauseV1, SccpGenerationEndV1};
        use std::{
            sync::{Arc, Mutex, atomic::AtomicUsize},
            time::Duration,
        };
        let data = SccpGenerationV1 {
            generation: 7,
            committee_root: [0x11; 32],
            cause: SccpGenerationCauseV1::Heartbeat,
            start_height: 8,
            start_timestamp_ms: 9,
            start_lc: 6,
            validity_ms: 10,
            deadline_ms: 19,
            grace_ms: 11,
            progress_cap_ms: 12,
            liable_until_lc: 27,
            dest_cleared_lc: Some(31),
            liable: false,
            end: Some(SccpGenerationEndV1 {
                end_height: 20,
                end_timestamp_ms: 30,
                next_committee_root: [0x21; 32],
                successor_validity_ms: 40,
            }),
            keys: vec![[0x12; 48]; 4],
            members: vec![None; 4],
        };
        let body = norito::json::to_json(&data).unwrap().into_bytes();
        let transport = Arc::new(AsyncOnlyTransport {
            responder: Box::new(move |_| {
                Ok(crate::http::Response::builder()
                    .status(200)
                    .body(body.clone())
                    .unwrap())
            }),
            requests: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(AtomicUsize::new(0)),
            delay: Duration::ZERO,
        });
        let client = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport)
            .build()
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_eq!(client.sccp().current_committee().await.unwrap(), data);
            assert_eq!(
                client
                    .sccp()
                    .committee(NonZeroU64::new(7).unwrap())
                    .await
                    .unwrap(),
                data
            );
        });
        let blocking = crate::blocking::Client::from_client(client).unwrap();
        assert_eq!(blocking.sccp().current_committee().unwrap(), data);
        assert_eq!(
            blocking
                .sccp()
                .committee(NonZeroU64::new(7).unwrap())
                .unwrap(),
            data
        );
        let mut missing = norito::json::to_value(&data).unwrap();
        missing.as_object_mut().unwrap().remove("liable").unwrap();
        assert!(
            decode_body::<SccpGenerationV1>(
                sccp::COMMITTEE.stable_route_id(),
                norito::json::to_json(&missing).unwrap().as_bytes()
            )
            .is_err()
        );
        // Synthetic duplicate keys remain untrusted DATA; decoding grants no verification capability.
        assert_eq!(data.keys[0], data.keys[1]);
    }

    #[test]
    fn paths_fill_placeholders_in_order() {
        assert_eq!(path(sccp::MESSAGE, &["ab"]), "/v1/sccp/messages/ab");
        assert_eq!(
            path(sccp::CONTROLS, &["ton-mainnet", "2"]),
            "/v1/sccp/controls/ton-mainnet/2"
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
        // A held record remains retryable DATA; the shared closed reason survives transport.
        let mut held = inbound.clone();
        if let SccpMessageStatusV1::Inbound(view) = &mut held {
            view.record.status = SccpInboundStatusV1::pending(SccpPendingReasonV1::Held);
        } else {
            panic!("inbound fixture");
        }
        let held_json = norito::json::to_vec(&held).expect("held JSON");
        let decoded: SccpMessageStatusV1 =
            decode_body("sccp.message.read", &held_json).expect("held decode");
        assert_eq!(decoded, held);
        assert!(!decoded.is_final());
        let held_page = SccpRecentMessagesV1 {
            messages: vec![held],
            next_before: Some("30:04".to_owned()),
        };
        assert_eq!(
            decode_body::<SccpRecentMessagesV1>(
                "sccp.messages.recent",
                &norito::json::to_vec(&held_page).expect("held page JSON")
            )
            .expect("held page decode"),
            held_page
        );
        let hostile = String::from_utf8(held_json)
            .expect("JSON UTF-8")
            .replace(r#""reason":"held""#, r#""reason":"unknown""#);
        assert!(
            decode_body::<SccpMessageStatusV1>("sccp.message.read", hostile.as_bytes()).is_err()
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
}
