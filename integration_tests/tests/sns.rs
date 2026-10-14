//! SNS registrar integration coverage.
use eyre::{Result, WrapErr, eyre};
use integration_tests::sandbox::{self, start_network_async_or_skip};
use iroha::{blocking::Client as IrohaClient, sns::SnsNamespacePath};
use iroha_data_model::{
    account::AccountId,
    alias_setup::{ALIAS_LEASE_YEAR_MS, AliasQuoteGuardV1, AliasTargetV1, ResolvedDomainV1},
    asset::AssetDefinitionId,
    isi::alias_setup::RenewAliasLease,
    sns::{NameRecordV1, NameStatus},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{numeric::Quantity, soradns::derive_gateway_hosts};
use iroha_test_network::{NetworkBuilder, domain_setup_instruction};
use reqwest::{Client as HttpClient, Url};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, TryRecvError},
    },
    time::Duration,
};
use tokio::time::{sleep, timeout};
const METRIC_READY_RETRIES: usize = 60;
const METRIC_RETRY_DELAY_MS: u64 = 250;
const SNS_CLIENT_CALL_TIMEOUT: Duration = Duration::from_secs(180);
fn test_sns_lease_payment() -> Quantity {
    "0.5".parse().expect("valid test payment")
}
/// End-to-end registrar flow: register → fetch record → fetch policy.
#[tokio::test]
async fn sns_registrar_round_trip() -> Result<()> {
    let Some(network) = start_sns_network(stringify!(sns_registrar_round_trip)).await? else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let client = network.client();
    let label = unique_label("roundtrip");
    let response = setup_domain(&client, &label).await?;
    let literal = domain_literal(&label);
    assert_eq!(response.selector.normalized_label(), literal);
    assert_same_owner_controller(
        &response.owner,
        client.client().account(),
        "register response owner should match request owner controller",
    );
    assert!(
        matches!(response.status, NameStatus::Active),
        "new registrations must start in the Active state"
    );
    let fetched = get_sns_name(&client, &literal).await?;
    assert_eq!(fetched.name_hash, response.name_hash);
    assert_same_owner_controller(
        &fetched.owner,
        client.client().account(),
        "fetched owner should preserve request owner controller",
    );
    let policy = get_sns_policy(&client, response.selector.suffix_id).await?;
    assert_eq!(policy.suffix_key(), "domain");
    Ok(())
}
/// Registration increments telemetry metrics and yields deterministic gateway bindings.
#[tokio::test]
async fn sns_registration_emits_metrics_and_gateway_bindings() -> Result<()> {
    let Some(network) = start_sns_network(stringify!(
        sns_registration_emits_metrics_and_gateway_bindings
    ))
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let client = network.client();
    let metrics_endpoint = client.client().endpoint().join("metrics")?;
    let http = HttpClient::new();
    let metric_labels = [("result", "ok"), ("suffix", "domain")];
    let baseline = read_metric_sample(
        &http,
        &metrics_endpoint,
        "sns_registrar_status_total",
        &metric_labels,
    )
    .await?
    .unwrap_or(0.0);
    let label = unique_label("telemetry");
    let literal = domain_literal(&label);
    setup_domain(&client, &label).await?;
    let mut observed_after = None;
    for _ in 0..METRIC_READY_RETRIES {
        let current = read_metric_sample(
            &http,
            &metrics_endpoint,
            "sns_registrar_status_total",
            &metric_labels,
        )
        .await?;
        if let Some(value) = current.filter(|value| *value >= baseline + 1.0) {
            observed_after = Some(value);
            break;
        }
        sleep(Duration::from_millis(METRIC_RETRY_DELAY_MS)).await;
    }
    let observed_after = observed_after.unwrap_or(baseline);
    assert!(
        observed_after >= baseline + 1.0,
        "sns_registrar_status_total did not advance (baseline {baseline}, observed {observed_after})"
    );
    let bindings = derive_gateway_hosts(&format!("{literal}.domain"))
        .map_err(|err| eyre!("gateway host derivation failed: {err}"))?;
    assert!(
        bindings.canonical_host().ends_with(".gw.sora.id"),
        "canonical host {} must live under gw.sora.id",
        bindings.canonical_host()
    );
    assert!(
        bindings.pretty_host().ends_with(".gw.sora.name"),
        "pretty host {} must live under gw.sora.name",
        bindings.pretty_host()
    );
    assert!(
        bindings.matches_host(bindings.pretty_host()),
        "derived host should match its pretty form"
    );
    assert!(
        bindings.matches_host(bindings.canonical_host()),
        "derived host should match its canonical form"
    );
    Ok(())
}
/// Renewal uses an exact expiry CAS and rejects stale replay.
#[tokio::test]
async fn sns_renewal_uses_expiry_cas() -> Result<()> {
    let Some(network) = start_sns_network(stringify!(sns_renewal_uses_expiry_cas)).await? else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let client = network.client();
    let label = unique_label("renew-cas");
    let literal = domain_literal(&label);
    let record = setup_domain(&client, &label).await?;
    let original_expiry = record.expires_at_ms;
    let target_expiry = original_expiry
        .checked_add(ALIAS_LEASE_YEAR_MS)
        .ok_or_else(|| eyre!("test renewal expiry overflow"))?;
    let domain = DomainId::parse_fully_qualified(&literal)?;
    let renewal = RenewAliasLease::new(
        AliasTargetV1::Domain(ResolvedDomainV1::new(domain, DataSpaceId::UNIVERSAL)),
        original_expiry,
        target_expiry,
        AliasQuoteGuardV1 {
            expected_policy_version: 1,
            expected_payment_asset: AssetDefinitionId::parse_address_literal(
                "61CtjvNd9T3THAR65GsMVHr82Bjc",
            )?,
            max_amount: test_sns_lease_payment(),
            valid_until_ms: u64::MAX,
        },
    );
    submit_alias_instruction(&client, renewal.clone().into()).await?;
    let renewed = get_sns_name(&client, &literal).await?;
    assert_eq!(renewed.expires_at_ms, target_expiry);
    assert_eq!(renewed.owner, record.owner);
    let stale = submit_alias_instruction(&client, renewal.into())
        .await
        .expect_err("stale expiry CAS replay must fail");
    let stale_details = stale
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    assert!(
        stale_details.contains("alias.lease.expiry_conflict"),
        "unexpected stale-CAS error: {stale_details}"
    );
    Ok(())
}
async fn setup_domain(client: &IrohaClient, label: &str) -> Result<NameRecordV1> {
    let domain = DomainId::parse_fully_qualified(&domain_literal(label))?;
    let instruction = domain_setup_instruction(&domain, client.client().account())?;
    let client = client.clone();
    let submit_client = client.clone();
    run_sns_client_call("ensure SNS domain", move || {
        submit_client.submit(
            instruction,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        Ok(())
    })
    .await?;
    get_sns_name(&client, &domain.to_string()).await
}
async fn submit_alias_instruction(
    client: &IrohaClient,
    instruction: iroha_data_model::isi::InstructionBox,
) -> Result<()> {
    let client = client.clone();
    run_sns_client_call("submit alias lifecycle instruction", move || {
        client.submit(
            instruction,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        Ok(())
    })
    .await
}
async fn get_sns_name(client: &IrohaClient, literal: &str) -> Result<NameRecordV1> {
    let client = client.clone();
    let literal = literal.to_owned();
    run_sns_client_call("get SNS name", move || {
        client
            .client()
            .sns()
            .get_name(SnsNamespacePath::Domain, &literal)
    })
    .await
}
async fn get_sns_policy(
    client: &IrohaClient,
    suffix_id: u16,
) -> Result<iroha_data_model::sns::SuffixPolicyV1> {
    let client = client.clone();
    run_sns_client_call("get SNS policy", move || {
        client.client().sns().get_policy(suffix_id)
    })
    .await
}
async fn run_sns_client_call<T, F>(operation: &'static str, call: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("sns-client-{operation}"))
        .spawn(move || {
            let _ = sender.send(call());
        })
        .map_err(|err| eyre!("failed to spawn SNS client operation `{operation}`: {err}"))?;
    timeout(SNS_CLIENT_CALL_TIMEOUT, async move {
        loop {
            match receiver.try_recv() {
                Ok(result) => return result,
                Err(TryRecvError::Empty) => sleep(Duration::from_millis(50)).await,
                Err(TryRecvError::Disconnected) => {
                    return Err(eyre!(
                        "SNS client operation `{operation}` exited without a result"
                    ));
                }
            }
        }
    })
    .await
    .map_err(|_| {
        eyre!(
            "timed out waiting for SNS client operation `{operation}` after {:?}",
            SNS_CLIENT_CALL_TIMEOUT
        )
    })?
}
fn domain_literal(label: &str) -> String {
    format!("{label}.universal")
}
async fn start_sns_network(test_name: &str) -> Result<Option<sandbox::SerializedNetwork>> {
    start_network_async_or_skip(NetworkBuilder::new(), test_name).await
}
fn unique_label(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let next = COUNTER.fetch_add(1, Ordering::Relaxed);
    let normalized_prefix: String = prefix
        .chars()
        .map(|ch| ch.to_ascii_lowercase())
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    let normalized_prefix = if normalized_prefix.is_empty() {
        "sns"
    } else {
        normalized_prefix.as_str()
    };
    format!("{normalized_prefix}{next}")
}
#[test]
fn unique_label_matches_default_pricing_constraints() {
    let label = unique_label("renew-transfer");
    assert!(
        label.len() >= 3,
        "generated labels must satisfy min length: `{label}`"
    );
    assert!(
        label
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()),
        "generated labels must stay within [a-z0-9]: `{label}`"
    );
}
#[tokio::test]
async fn bounded_sns_client_call_returns_completed_result() -> Result<()> {
    let value =
        run_sns_client_call("test immediate result", || Ok::<_, eyre::Report>(42_u8)).await?;
    assert_eq!(value, 42);
    Ok(())
}
fn assert_same_owner_controller(actual: &AccountId, expected: &AccountId, context: &str) {
    assert_eq!(
        actual.controller(),
        expected.controller(),
        "{context}; expected owner controller `{expected}`, got `{actual}`"
    );
}
async fn read_metric_sample(
    http: &HttpClient,
    endpoint: &Url,
    metric_name: &str,
    labels: &[(&str, &str)],
) -> Result<Option<f64>> {
    let response = http
        .get(endpoint.clone())
        .send()
        .await?
        .error_for_status()
        .wrap_err("metrics endpoint returned error")?;
    let body = response.text().await?;
    Ok(parse_metric_value(&body, metric_name, labels))
}
fn parse_metric_value(body: &str, metric_name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(metric_name) {
            continue;
        }
        let remainder = &line[metric_name.len()..];
        let (label_map, value_str) = if let Some(rest) = remainder.strip_prefix('{') {
            let end = rest.find('}')?;
            let label_segment = &rest[..end];
            let map = parse_label_map(label_segment);
            (map, rest[end + 1..].trim())
        } else {
            (HashMap::new(), remainder.trim())
        };
        if labels.iter().all(|(key, value)| {
            label_map
                .get(*key)
                .map(String::as_str)
                .is_some_and(|current| current == *value)
        }) {
            let value_token = value_str.split_whitespace().next().unwrap_or_default();
            if let Ok(parsed) = value_token.parse::<f64>() {
                return Some(parsed);
            }
        }
    }
    None
}
fn parse_label_map(segment: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in segment.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let raw_value = parts.next().unwrap_or_default().trim();
        let cleaned = raw_value.trim_matches('"').replace("\\\"", "\"");
        if !key.is_empty() {
            map.insert(key.to_string(), cleaned);
        }
    }
    map
}
