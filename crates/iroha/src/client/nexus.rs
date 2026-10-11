//! Public SORA Nexus observations with bounded canonical asynchronous transport.

use super::{Client, dispatch, join_torii_url};
use crate::{
    Error, Result,
    http::{Method, RequestBuilder, Response, StatusCode},
};
use iroha_data_model::{
    NetworkId,
    nexus::{
        PUBLIC_LANE_PREPARATION_REQUEST_MAX_BYTES, PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES,
        PublicLaneMonetaryPreconditionV1, PublicLaneMonetaryScopeV1,
        PublicLanePreparationOperationV1, PublicLanePreparationRequestV1, PublicLanePreparationV1,
        PublicLanePreparedPlanV1,
    },
};

const PREPARE: &str = "nexus.staking.prepare";
const APPLICATION_NORITO: &str = "application/x-norito";

/// Public SORA Nexus reads bound to one immutable client context.
#[derive(Clone, Copy, Debug)]
pub struct Nexus<'a> {
    pub(super) client: &'a Client,
}

impl Client {
    /// Access public Nexus operations through this context's asynchronous transport.
    #[must_use]
    pub const fn nexus(&self) -> Nexus<'_> {
        Nexus { client: self }
    }
}

impl Nexus<'_> {
    /// Prepare exact signing inputs using a coherent read-only server observation.
    ///
    /// This does not independently authenticate state. Inspect the exact effects
    /// before signing; execution checks expiry and recomputes every monetary leg.
    /// Reward responses bind the exact funded entitlement and current beneficiary.
    /// Uses this context's asynchronous transport and deadline, with one dispatch
    /// and no compatibility probe or retry.
    ///
    /// # Errors
    /// Returns structured request, transport, deadline, HTTP, response-bound,
    /// decoding or response-binding errors.
    pub async fn prepare_public_lane_plan(
        &self,
        request: &PublicLanePreparationRequestV1,
    ) -> Result<PublicLanePreparationV1> {
        ensure_deadline(self.client)?;
        let body = encode_request(request)?;
        let response = dispatch::send(
            self.client,
            PREPARE,
            self.client
                .request_without_canonical_account_auth(
                    Method::POST,
                    join_torii_url(
                        &self.client.torii_url,
                        iroha_torii_shared::route_catalog::core::NEXUS_STAKING_PREPARATION_POST
                            .path(),
                    ),
                )
                .replace_header("Content-Type", APPLICATION_NORITO)
                .max_response_bytes(PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES)
                .body(body),
            APPLICATION_NORITO,
        )
        .await?;
        let prepared = decode_response(response)?;
        validate_response(&prepared, request, self.client.network_id)?;
        ensure_deadline(self.client)?;
        Ok(prepared)
    }
}

fn encode_request(request: &PublicLanePreparationRequestV1) -> Result<Vec<u8>> {
    if request.valid_for_blocks == 0 {
        return Err(Error::InvalidRequest {
            operation: PREPARE,
            details: "preparation expiry offset must be positive".into(),
        });
    }
    // The canonical layout guard is strictly synchronous and ends before any
    // network await. Count and admit the complete frame before allocating output.
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::to_bytes_bounded(request, PUBLIC_LANE_PREPARATION_REQUEST_MAX_BYTES).map_err(
        |error| Error::InvalidRequest {
            operation: PREPARE,
            details: error.to_string(),
        },
    )
}

fn ensure_deadline(client: &Client) -> Result<()> {
    if client
        .http_transport
        .deadline()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(Error::Timeout { operation: PREPARE });
    }
    Ok(())
}

fn decode_response(response: Response<Vec<u8>>) -> Result<PublicLanePreparationV1> {
    if response.status() != StatusCode::OK {
        return Err(Error::Http {
            operation: PREPARE,
            status: response.status().as_u16(),
            retry_after: crate::error::retry_after(response.headers()),
            body: response.into_body(),
        });
    }
    Client::decode_canonical_norito_response(
        &response,
        PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES,
        PREPARE,
    )
}

fn validate_response(
    prepared: &PublicLanePreparationV1,
    request: &PublicLanePreparationRequestV1,
    network_id: NetworkId,
) -> Result<()> {
    if &prepared.request != request {
        return Err(Error::ResponseBinding {
            operation: PREPARE,
            field: "request",
        });
    }
    if prepared.network_id != network_id {
        return Err(Error::ResponseBinding {
            operation: PREPARE,
            field: "network_id",
        });
    }
    if prepared.observed_height == 0
        || prepared.observed_height.checked_add(1) != Some(prepared.assumed_execution_height)
    {
        return Err(Error::ResponseBinding {
            operation: PREPARE,
            field: "assumed_execution_height",
        });
    }
    let expiry = prepared
        .observed_height
        .checked_add(request.valid_for_blocks)
        .ok_or(Error::ResponseBinding {
            operation: PREPARE,
            field: "valid_until_height",
        })?;
    let assets = validate_plan(prepared, request, network_id, expiry)?;
    if prepared.balances.len() != assets.len()
        || !prepared
            .balances
            .iter()
            .map(|entry| &entry.asset)
            .eq(assets.iter())
        || !assets
            .iter()
            .all(|asset| asset.definition() == &prepared.xor_asset_definition_id)
    {
        return Err(Error::ResponseBinding {
            operation: PREPARE,
            field: "balances",
        });
    }
    Ok(())
}

fn validate_plan(
    prepared: &PublicLanePreparationV1,
    request: &PublicLanePreparationRequestV1,
    network_id: NetworkId,
    expiry: u64,
) -> Result<std::collections::BTreeSet<iroha_data_model::asset::AssetId>> {
    let mut assets = std::collections::BTreeSet::new();
    match (&request.operation, &prepared.plan) {
        (operation, PublicLanePreparedPlanV1::Monetary(plan)) => {
            if !plan.has_canonical_shape()
                || plan.network_scope != PublicLaneMonetaryScopeV1::Network(network_id)
                || plan.valid_until_height != expiry
            {
                return Err(Error::ResponseBinding {
                    operation: PREPARE,
                    field: "monetary_plan",
                });
            }
            let matches = match (operation, &plan.precondition) {
                (
                    PublicLanePreparationOperationV1::Registration(intent),
                    PublicLaneMonetaryPreconditionV1::Registration(_),
                ) => {
                    plan.source_asset.account() == &intent.validator && plan.amount == intent.amount
                }
                (
                    PublicLanePreparationOperationV1::Bond(intent),
                    PublicLaneMonetaryPreconditionV1::Bond(_),
                ) => plan.source_asset.account() == &intent.staker && plan.amount == intent.amount,
                (
                    PublicLanePreparationOperationV1::FinalizeUnbond(intent),
                    PublicLaneMonetaryPreconditionV1::Unbond(_),
                ) => plan.destination_asset.account() == &intent.staker,
                _ => false,
            };
            if !matches {
                return Err(Error::ResponseBinding {
                    operation: PREPARE,
                    field: "monetary_intent",
                });
            }
            assets.insert(plan.source_asset.clone());
            assets.insert(plan.destination_asset.clone());
        }
        (
            PublicLanePreparationOperationV1::ClaimRewards(intent),
            PublicLanePreparedPlanV1::Claim(plan),
        ) => {
            if !plan.has_canonical_shape(&intent.recipient)
                || plan.network_scope != PublicLaneMonetaryScopeV1::Network(network_id)
                || plan.valid_until_height != expiry
            {
                return Err(Error::ResponseBinding {
                    operation: PREPARE,
                    field: "reward_claim",
                });
            }
            assets.insert(plan.fee_claim.source_asset.clone());
            assets.insert(plan.fee_claim.destination_asset.clone());
        }
        _ => {
            return Err(Error::ResponseBinding {
                operation: PREPARE,
                field: "plan_kind",
            });
        }
    }
    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::nexus::{PublicLanePrepareClaimV1, PublicLaneRewardClaimPlanV1};
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::numeric::Quantity;

    fn fixture(network_id: NetworkId) -> (PublicLanePreparationRequestV1, PublicLanePreparationV1) {
        let request = PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 10,
            operation: PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
                recipient: iroha_test_samples::ALICE_ID.clone(),
            }),
        };
        let response = PublicLanePreparationV1 {
            request: request.clone(),
            network_id,
            observed_height: 5,
            observed_block_hash: Hash::new(b"block5"),
            observed_ledger_time_ms: 123,
            assumed_execution_height: 6,
            xor_asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
            plan: PublicLanePreparedPlanV1::Claim(PublicLaneRewardClaimPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
                valid_until_height: 15,
                fee_claim: iroha_data_model::nexus::PublicLaneFeeRewardClaimV1 {
                    lifecycle_seal: [1; 32],
                    beneficiary_id: iroha_test_samples::ALICE_ID.clone(),
                    beneficiary_revision: 0,
                    source_asset: iroha_data_model::asset::AssetId::new(
                        "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                        iroha_test_samples::BOB_ID.clone(),
                    ),
                    destination_asset: iroha_data_model::asset::AssetId::new(
                        "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                        iroha_test_samples::ALICE_ID.clone(),
                    ),
                    amount: 1_u64.into(),
                    expected_claim_sequence: 0,
                },
            }),
            balances: [
                iroha_test_samples::ALICE_ID.clone(),
                iroha_test_samples::BOB_ID.clone(),
            ]
            .into_iter()
            .map(|owner| {
                iroha_data_model::asset::AssetId::new(
                    "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                    owner,
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(
                |asset| iroha_data_model::nexus::PublicLanePreparationBalanceV1 {
                    asset,
                    balance: 10_u64.into(),
                    stake_reserved: Quantity::zero(),
                    rewards_reserved: Quantity::zero(),
                },
            )
            .collect(),
        };
        (request, response)
    }

    #[test]
    fn observational_plan_rejects_network_intent_expiry_and_balance_substitution() {
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"client-staking-preparation",
        )));
        let (request, response) = fixture(network_id);
        validate_response(&response, &request, network_id).unwrap();
        let other = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"other-network",
        )));
        assert!(validate_response(&response, &request, other).is_err());
        let mut changed = response.clone();
        changed.request.valid_for_blocks += 1;
        assert!(validate_response(&changed, &request, network_id).is_err());
        let mut changed = response.clone();
        changed.assumed_execution_height += 1;
        assert!(validate_response(&changed, &request, network_id).is_err());
        let mut changed = response.clone();
        changed
            .balances
            .push(iroha_data_model::nexus::PublicLanePreparationBalanceV1 {
                asset: iroha_data_model::asset::AssetId::new(
                    changed.xor_asset_definition_id.clone(),
                    iroha_test_samples::ALICE_ID.clone(),
                ),
                balance: Quantity::zero(),
                stake_reserved: Quantity::zero(),
                rewards_reserved: Quantity::zero(),
            });
        assert!(validate_response(&changed, &request, network_id).is_err());
        let mut changed = response;
        let PublicLanePreparedPlanV1::Claim(plan) = &mut changed.plan else {
            unreachable!()
        };
        plan.valid_until_height += 1;
        assert!(validate_response(&changed, &request, network_id).is_err());
    }

    #[test]
    fn observational_fee_claim_requires_exact_xor_balances_and_recipient() {
        use iroha_data_model::{
            asset::AssetId,
            nexus::{PublicLaneFeeRewardClaimV1, PublicLanePreparationBalanceV1},
        };
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"client-fee-reward-preparation",
        )));
        let (request, mut response) = fixture(network_id);
        let source = AssetId::new(
            response.xor_asset_definition_id.clone(),
            iroha_test_samples::BOB_ID.clone(),
        );
        let destination = AssetId::new(
            response.xor_asset_definition_id.clone(),
            iroha_test_samples::ALICE_ID.clone(),
        );
        let PublicLanePreparedPlanV1::Claim(plan) = &mut response.plan else {
            unreachable!()
        };
        plan.fee_claim = PublicLaneFeeRewardClaimV1 {
            lifecycle_seal: [1; 32],
            beneficiary_id: iroha_test_samples::ALICE_ID.clone(),
            beneficiary_revision: 2,
            source_asset: source.clone(),
            destination_asset: destination.clone(),
            amount: 1_u64.into(),
            expected_claim_sequence: 3,
        };
        response.balances.clear();
        assert!(validate_response(&response, &request, network_id).is_err());
        response.balances = [source, destination]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|asset| PublicLanePreparationBalanceV1 {
                asset,
                balance: 10_u64.into(),
                stake_reserved: Quantity::zero(),
                rewards_reserved: Quantity::zero(),
            })
            .collect();
        validate_response(&response, &request, network_id).unwrap();

        let mut changed = response.clone();
        changed.xor_asset_definition_id = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM".parse().unwrap();
        assert!(validate_response(&changed, &request, network_id).is_err());
        let mut changed = response;
        let PublicLanePreparedPlanV1::Claim(plan) = &mut changed.plan else {
            unreachable!()
        };
        plan.fee_claim.destination_asset = AssetId::new(
            changed.xor_asset_definition_id.clone(),
            iroha_test_samples::BOB_ID.clone(),
        );
        assert!(validate_response(&changed, &request, network_id).is_err());
    }

    use super::super::{
        capability_test_support::{AsyncOnlyTransport, GatedTransport, TransportGate},
        evidence_http_tests::{base_url, client_with_base_url},
    };
    use crate::{TransportErrorKind, blocking, http::TransportRequest};
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    fn attach(
        responder: impl Fn(&TransportRequest) -> eyre::Result<Response<Vec<u8>>> + Send + Sync + 'static,
        delay: Duration,
        timeout: Duration,
    ) -> (Client, Arc<Mutex<Vec<TransportRequest>>>, Arc<AtomicUsize>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let transport = Arc::new(AsyncOnlyTransport {
            responder: Box::new(responder),
            requests: requests.clone(),
            completed: completed.clone(),
            delay,
        });
        let mut builder = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport);
        builder.torii_request_timeout = timeout;
        for name in [
            "accept",
            "content-type",
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
            "x-iroha-witness",
        ] {
            builder
                .headers
                .insert(name.to_owned(), "stale-default".to_owned());
        }
        (builder.build().unwrap(), requests, completed)
    }

    fn successful_response() -> Response<Vec<u8>> {
        let (_, prepared) = fixture(super::super::test_network_id());
        Response::builder()
            .status(200)
            .header("Content-Type", APPLICATION_NORITO)
            .body(norito::encode_canonical(&prepared).unwrap())
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn staking_preparation_dispatch_is_async_public_and_exact() {
        fn require_send(_: impl Send) {}
        let response = successful_response();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(TransportGate::default());
        let transport = Arc::new(GatedTransport {
            inner: AsyncOnlyTransport {
                responder: Box::new(move |_| Ok(response.clone())),
                requests: requests.clone(),
                completed: completed.clone(),
                delay: Duration::ZERO,
            },
            gate: gate.clone(),
        });
        let mut builder = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport);
        builder.torii_request_timeout = Duration::ZERO;
        for name in [
            "accept",
            "content-type",
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
            "x-iroha-witness",
        ] {
            builder
                .headers
                .insert(name.to_owned(), "stale-default".to_owned());
        }
        let client = builder.build().unwrap();
        let (request, expected) = fixture(*client.network_id());
        let capability = client.nexus();
        require_send(capability.prepare_public_lane_plan(&request));
        let operation = capability.prepare_public_lane_plan(&request);
        tokio::pin!(operation);
        tokio::select! {
            early = &mut operation => panic!("operation completed before transport release: {early:?}"),
            () = gate.wait_until_entered() => {}
        }
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "transport cannot finish before release"
        );
        gate.release();
        let result = operation.await;
        assert_eq!(result.unwrap(), expected);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "no probes or retries");
        let sent = &requests[0];
        assert_eq!(sent.method, Method::POST);
        assert_eq!(
            sent.url.path(),
            iroha_torii_shared::route_catalog::core::NEXUS_STAKING_PREPARATION_POST.path()
        );
        assert!(sent.url.query().is_none());
        assert_eq!(sent.body, norito::encode_canonical(&request).unwrap());
        assert_eq!(
            sent.max_response_bytes,
            PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES
        );
        assert_eq!(sent.timeout, None);
        for name in ["accept", "content-type"] {
            let values: Vec<_> = sent.headers.iter().filter(|(key, _)| key == name).collect();
            assert_eq!(values.len(), 1);
            assert_eq!(values[0].1, APPLICATION_NORITO);
        }
        for name in [
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
            "x-iroha-witness",
        ] {
            assert!(!sent.headers.iter().any(|(key, _)| key == name));
        }
    }

    #[tokio::test]
    async fn staking_preparation_rejects_zero_expiry_before_dispatch() {
        let (client, requests, _) = attach(
            |_| panic!("must not dispatch"),
            Duration::ZERO,
            Duration::ZERO,
        );
        let (mut request, _) = fixture(*client.network_id());
        request.valid_for_blocks = 0;
        assert!(matches!(
            client.nexus().prepare_public_lane_plan(&request).await,
            Err(Error::InvalidRequest {
                operation: PREPARE,
                ..
            })
        ));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn staking_preparation_request_encoding_is_canonical_and_bounds_claim_work() {
        let (mut request, _) = fixture(super::super::test_network_id());
        let expected = norito::encode_canonical(&request).unwrap();
        {
            let _ambient_flags = norito::core::DecodeFlagsGuard::enter(0);
            assert_eq!(encode_request(&request).unwrap(), expected);
            assert_eq!(norito::core::get_decode_flags(), 0);
        }
        request.valid_for_blocks = 0;
        assert!(matches!(
            encode_request(&request),
            Err(Error::InvalidRequest {
                operation: PREPARE,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn staking_preparation_bounds_success_and_error_bodies() {
        for status in [200, 503] {
            let (client, requests, _) = attach(
                move |_| {
                    Ok(Response::builder()
                        .status(status)
                        .body(vec![0; PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES + 1])
                        .unwrap())
                },
                Duration::ZERO,
                Duration::ZERO,
            );
            let (request, _) = fixture(*client.network_id());
            {
                let actual_error = client
                    .nexus()
                    .prepare_public_lane_plan(&request)
                    .await
                    .unwrap_err();
                let Error::ResponseTooLarge {
                    maximum: actual_maximum,
                    actual: actual_actual,
                } = &actual_error
                else {
                    panic!("unexpected SDK error: {actual_error:?}");
                };
                assert_eq!(
                    (actual_maximum, actual_actual,),
                    (
                        &(PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES),
                        &(Some(PUBLIC_LANE_PREPARATION_RESPONSE_MAX_BYTES + 1)),
                    )
                );
            };
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn staking_preparation_requires_one_canonical_response() {
        let mut responses = Vec::new();
        for types in [
            vec![],
            vec!["application/json"],
            vec![APPLICATION_NORITO, APPLICATION_NORITO],
            vec!["application/x-norito, application/json"],
        ] {
            let mut response = successful_response();
            response.headers_mut().remove(http::header::CONTENT_TYPE);
            for media in types {
                response
                    .headers_mut()
                    .append(http::header::CONTENT_TYPE, media.parse().unwrap());
            }
            responses.push((response, false));
        }
        for body in [
            vec![],
            vec![0xff],
            [successful_response().body().as_slice(), &[0]].concat(),
        ] {
            let mut response = successful_response();
            *response.body_mut() = body;
            let canonical_failure = !response.body().is_empty();
            responses.push((response, canonical_failure));
        }
        for (response, canonical_failure) in responses {
            let (client, requests, _) = attach(
                move |_| Ok(response.clone()),
                Duration::ZERO,
                Duration::ZERO,
            );
            let (request, _) = fixture(*client.network_id());
            let failure = client
                .nexus()
                .prepare_public_lane_plan(&request)
                .await
                .unwrap_err();
            if canonical_failure {
                let Error::CanonicalDecode {
                    operation: PREPARE,
                    source,
                } = &failure
                else {
                    panic!("original canonical decoder failure: {failure:?}");
                };
                assert_eq!(source.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
                assert!(std::error::Error::source(&failure).is_some());
            } else {
                assert!(matches!(
                    failure,
                    Error::Decode {
                        operation: PREPARE,
                        ..
                    }
                ));
            }
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn staking_preparation_retains_original_decode_refusal_across_dispatch_context() {
        use norito::core::{DecodeAttemptErrorKind, with_decode_limits_scope};

        let response = successful_response();
        let original_body = response.body().clone();
        let failure = with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || decode_response(response.clone()),
        )
        .unwrap_err();
        let Error::CanonicalDecode { source, .. } = &failure else {
            panic!("original resource refusal: {failure:?}");
        };
        assert_eq!(source.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let original_scope = std::error::Error::source(source)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap();
        let norito::Error::ScopedDecodeResource(original_scope) = original_scope else {
            panic!("exact enclosing scope must survive decoding");
        };
        let original_scope = original_scope.clone();
        let failure = dispatch::transport_error(
            "unrelated.dispatch",
            eyre::Report::new(failure).wrap_err("staking preparation context"),
        );
        let Error::CanonicalDecode {
            operation: PREPARE,
            source,
        } = &failure
        else {
            panic!("original staking operation and decoder owner: {failure:?}");
        };
        assert_eq!(source.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let retained = std::error::Error::source(source)
            .unwrap()
            .downcast_ref::<norito::Error>()
            .unwrap();
        let norito::Error::ScopedDecodeResource(retained) = retained else {
            panic!("dispatch must retain the original enclosing scope");
        };
        assert_eq!(retained, &original_scope);
        let (_, expected) = fixture(super::super::test_network_id());
        assert_eq!(decode_response(response.clone()).unwrap(), expected);
        assert_eq!(response.body(), &original_body);
    }

    #[tokio::test]
    async fn staking_preparation_errors_preserve_identity_without_replay() {
        for status in [401, 429, 503] {
            let (client, requests, _) = attach(
                move |_| {
                    Ok(Response::builder()
                        .status(status)
                        .header("Retry-After", "3")
                        .body(b"staking-unavailable".to_vec())
                        .unwrap())
                },
                Duration::ZERO,
                Duration::ZERO,
            );
            let (request, _) = fixture(*client.network_id());
            {
                let actual_error = client
                    .nexus()
                    .prepare_public_lane_plan(&request)
                    .await
                    .unwrap_err();
                let Error::Http {
                    operation: actual_operation,
                    status: actual_status,
                    retry_after: actual_retry_after,
                    body: actual_body,
                } = &actual_error
                else {
                    panic!("unexpected SDK error: {actual_error:?}");
                };
                assert_eq!(
                    (
                        actual_operation,
                        actual_status,
                        actual_retry_after,
                        actual_body,
                    ),
                    (
                        &(PREPARE),
                        &(status),
                        &(Some(Duration::from_secs(3))),
                        &(b"staking-unavailable".to_vec()),
                    )
                );
            };
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
        let (client, requests, _) = attach(
            |_| Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let (request, _) = fixture(*client.network_id());
        assert!(matches!(
            client.nexus().prepare_public_lane_plan(&request).await,
            Err(Error::Transport {
                operation: PREPARE,
                kind: TransportErrorKind::Io(std::io::ErrorKind::ConnectionRefused),
                ..
            })
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn staking_preparation_enforces_request_and_absolute_deadlines() {
        for absolute in [false, true] {
            let timeout = if absolute {
                Duration::ZERO
            } else {
                Duration::from_millis(10)
            };
            let (client, requests, completed) = attach(
                |_| Ok(successful_response()),
                Duration::from_secs(60),
                timeout,
            );
            let client = if absolute {
                client.with_request_deadline(Instant::now() + Duration::from_millis(10))
            } else {
                client
            };
            let (request, _) = fixture(*client.network_id());
            {
                let actual_error = client
                    .nexus()
                    .prepare_public_lane_plan(&request)
                    .await
                    .unwrap_err();
                let Error::Timeout {
                    operation: actual_operation,
                } = &actual_error
                else {
                    panic!("unexpected SDK error: {actual_error:?}");
                };
                assert_eq!((actual_operation,), (&(PREPARE),));
            };
            assert_eq!(requests.lock().unwrap().len(), 1);
            assert_eq!(completed.load(Ordering::SeqCst), 0);
        }
        let (client, requests, _) = attach(
            |_| panic!("deadline expired"),
            Duration::ZERO,
            Duration::ZERO,
        );
        let (request, _) = fixture(*client.network_id());
        let client = client.with_request_deadline(Instant::now());
        {
            let actual_error = client
                .nexus()
                .prepare_public_lane_plan(&request)
                .await
                .unwrap_err();
            let Error::Timeout {
                operation: actual_operation,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!((actual_operation,), (&(PREPARE),));
        };
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn staking_preparation_binds_responses_to_the_immutable_context() {
        let (client, requests, _) = attach(
            |_| Ok(successful_response()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let (request, _) = fixture(*client.network_id());
        client
            .clone()
            .nexus()
            .prepare_public_lane_plan(&request)
            .await
            .unwrap();
        let mut builder = client.to_builder();
        builder.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"other-network"),
        ));
        builder.torii_url = "https://other.mock/root/".parse().unwrap();
        let other = builder.build().unwrap();
        {
            let actual_error = other
                .nexus()
                .prepare_public_lane_plan(&request)
                .await
                .unwrap_err();
            let Error::ResponseBinding {
                operation: actual_operation,
                field: actual_field,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!(
                (actual_operation, actual_field,),
                (&(PREPARE), &("network_id"),)
            );
        };
        assert_eq!(
            requests.lock().unwrap()[1].url.as_str(),
            "https://other.mock/root/v1/nexus/staking/prepare"
        );
        assert_eq!(client.endpoint(), &base_url());
    }

    #[test]
    fn blocking_staking_preparation_reuses_runtime_and_rejects_async_entry() {
        let (client, requests, _) = attach(
            |_| Ok(successful_response()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let (request, expected) = fixture(*client.network_id());
        let facade = blocking::Client::from_client(client).unwrap();
        assert_eq!(
            facade.nexus().prepare_public_lane_plan(&request).unwrap(),
            expected
        );
        assert_eq!(
            facade
                .clone()
                .nexus()
                .prepare_public_lane_plan(&request)
                .unwrap(),
            expected
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(matches!(
                facade.nexus().prepare_public_lane_plan(&request),
                Err(Error::Blocking(_))
            ));
            drop(facade);
        });
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}
