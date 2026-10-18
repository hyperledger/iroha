//! Build a static HTML manifest and derive public DNS settings (including delegation placeholders)
//! for a regular internet zone pointing at the `SoraDNS` gateway. Provider storage ingest is
//! exercised by the internal finalized-ledger outbox suites, not by a public upload route.
use eyre::{Result, eyre};
use iroha_primitives::soradns::{GatewayHostBindings, derive_gateway_hosts};
use sorafs_car::{CarBuildPlan, CarWriter, compute_chunk_plan_digest_sha3};
use sorafs_manifest::{
    DagCodecId, ManifestBuilder, ManifestV1, PinPolicy, StorageClass, chunker_registry,
};
use std::collections::HashMap;
const WELCOME_TEXT: &str = "welcome to SORA Nexus / Hyperledger Iroha 3";
const DNS_TTL_SECS: u32 = 600;
const PLACEHOLDER_NS_HOSTS: [&str; 2] = ["ns1.soranet.example.", "ns2.soranet.example."];
const PLACEHOLDER_DS_KEY_TAG: u16 = 2371;
const PLACEHOLDER_DS_ALGO: u8 = 13;
const PLACEHOLDER_DS_DIGEST_TYPE: u8 = 2;
const PLACEHOLDER_DS_DIGEST_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsRecord {
    hostname: String,
    record_type: &'static str,
    values: Vec<String>,
    ttl_secs: u32,
}
impl DnsRecord {
    fn cname(hostname: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            hostname: hostname.into(),
            record_type: "CNAME",
            values,
            ttl_secs: DNS_TTL_SECS,
        }
    }
    fn alias(hostname: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            hostname: hostname.into(),
            record_type: "ALIAS",
            values,
            ttl_secs: DNS_TTL_SECS,
        }
    }
    fn ns(hostname: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            hostname: hostname.into(),
            record_type: "NS",
            values,
            ttl_secs: DNS_TTL_SECS,
        }
    }
    fn ds(hostname: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            hostname: hostname.into(),
            record_type: "DS",
            values,
            ttl_secs: DNS_TTL_SECS,
        }
    }
}
/// Minimal authoritative DNS stub for public-zone CNAME/ALIAS checks in tests.
struct ReferenceAuthoritativeDns {
    cname_records: HashMap<String, Vec<String>>,
    alias_records: HashMap<String, Vec<String>>,
}
impl ReferenceAuthoritativeDns {
    fn new(records: &[DnsRecord]) -> Self {
        let mut cname_records = HashMap::new();
        let mut alias_records = HashMap::new();
        for record in records {
            match record.record_type {
                "CNAME" => {
                    cname_records.insert(normalize_host(&record.hostname), record.values.clone());
                }
                "ALIAS" => {
                    alias_records.insert(normalize_host(&record.hostname), record.values.clone());
                }
                _ => {}
            }
        }
        Self {
            cname_records,
            alias_records,
        }
    }
    fn resolve_alias_or_cname(&self, hostname: &str) -> Option<&[String]> {
        let key = normalize_host(hostname);
        self.alias_records
            .get(&key)
            .or_else(|| self.cname_records.get(&key))
            .map(Vec::as_slice)
    }
}
fn normalize_host(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}
fn ds_placeholder_value() -> String {
    format!(
        "{PLACEHOLDER_DS_KEY_TAG} {PLACEHOLDER_DS_ALGO} {PLACEHOLDER_DS_DIGEST_TYPE} {PLACEHOLDER_DS_DIGEST_HEX}"
    )
}
fn delegation_records_for_zone(zone: &str) -> Vec<DnsRecord> {
    vec![
        DnsRecord::ns(
            zone.to_string(),
            PLACEHOLDER_NS_HOSTS
                .iter()
                .copied()
                .map(str::to_string)
                .collect(),
        ),
        DnsRecord::ds(zone.to_string(), vec![ds_placeholder_value()]),
    ]
}
// Regular DNS deployments use ALIAS/ANAME for apex/TLDs and CNAME for subdomains.
fn public_dns_settings_for_domain(bindings: &GatewayHostBindings, zone: &str) -> Vec<DnsRecord> {
    let pretty = bindings.pretty_host().to_string();
    let normalized = bindings.normalized_name().to_string();
    let mut records = Vec::new();
    records.push(DnsRecord::alias(zone.to_string(), vec![pretty.clone()]));
    if normalized != zone {
        records.push(DnsRecord::cname(normalized, vec![pretty]));
    }
    records.extend(delegation_records_for_zone(zone));
    records
}
fn build_manifest_and_plan(payload: &[u8]) -> Result<(ManifestV1, CarBuildPlan)> {
    let descriptor = chunker_registry::default_descriptor();
    let plan = CarBuildPlan::single_file_with_profile(payload, descriptor.profile)?;
    let mut car_bytes = Vec::new();
    let stats = CarWriter::new(&plan, payload)?.write_to(&mut car_bytes)?;
    let root = stats
        .root_cids
        .first()
        .cloned()
        .ok_or_else(|| eyre!("car emission produced no root CID"))?;
    let manifest = ManifestBuilder::new()
        .root_cid(root)
        .dag_codec(DagCodecId(stats.dag_codec))
        .chunking_from_registry(descriptor.id)
        .chunk_digest_sha3_256(compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(sorafs_car::compute_por_root(payload, &plan)?)
        .content_length(plan.content_length)
        .car_digest(stats.car_archive_digest.into())
        .car_size(stats.car_size)
        .pin_policy(PinPolicy {
            min_replicas: 1,
            storage_class: StorageClass::Hot,
            retention_epoch: 10,
        })
        .add_metadata("content-type", "text/html; charset=utf-8")
        .build()?;
    Ok((manifest, plan))
}
#[test]
fn public_dns_settings_include_delegation_placeholders() {
    let bindings = derive_gateway_hosts("sora-nexus.sora").expect("derive hosts");
    let zone = "sora";
    let records = public_dns_settings_for_domain(&bindings, zone);
    let alias_records: Vec<_> = records
        .iter()
        .filter(|record| record.record_type == "ALIAS")
        .collect();
    let cname_records: Vec<_> = records
        .iter()
        .filter(|record| record.record_type == "CNAME")
        .collect();
    let ns_records: Vec<_> = records
        .iter()
        .filter(|record| record.record_type == "NS")
        .collect();
    let ds_records: Vec<_> = records
        .iter()
        .filter(|record| record.record_type == "DS")
        .collect();
    assert_eq!(alias_records.len(), 1, "expected apex ALIAS record");
    assert_eq!(alias_records[0].hostname, zone);
    assert_eq!(
        alias_records[0].values,
        vec![bindings.pretty_host().to_string()]
    );
    assert_eq!(cname_records.len(), 1, "expected subdomain CNAME record");
    assert_eq!(cname_records[0].hostname, bindings.normalized_name());
    assert_eq!(
        cname_records[0].values,
        vec![bindings.pretty_host().to_string()]
    );
    assert_eq!(ns_records.len(), 1, "expected NS delegation record");
    assert_eq!(ns_records[0].hostname, zone);
    assert_eq!(
        ns_records[0].values,
        PLACEHOLDER_NS_HOSTS
            .iter()
            .copied()
            .map(str::to_string)
            .collect::<Vec<_>>()
    );
    assert_eq!(ds_records.len(), 1, "expected DS delegation record");
    assert_eq!(ds_records[0].hostname, zone);
    assert_eq!(ds_records[0].values, vec![ds_placeholder_value()]);
}
#[test]
fn soranet_webpage_manifest_and_dns_settings() -> Result<()> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{WELCOME_TEXT}</body></html>"
    );
    let payload = html.as_bytes().to_vec();
    let (manifest, plan) = build_manifest_and_plan(&payload)?;
    assert_eq!(manifest.content_length, payload.len() as u64);
    assert_eq!(plan.content_length, payload.len() as u64);
    assert!(!manifest.root_cid.is_empty());
    let fqdn = "sora-nexus.sora";
    let zone = "sora";
    let bindings = derive_gateway_hosts(fqdn)?;
    let dns_records = public_dns_settings_for_domain(&bindings, zone);
    let cname_count = dns_records
        .iter()
        .filter(|record| record.record_type == "CNAME")
        .count();
    let alias_count = dns_records
        .iter()
        .filter(|record| record.record_type == "ALIAS")
        .count();
    assert_eq!(cname_count, 1, "expected one CNAME record");
    assert_eq!(alias_count, 1, "expected one ALIAS record");
    assert!(
        dns_records
            .iter()
            .any(|record| record.record_type == "NS" || record.record_type == "DS"),
        "dns records should include NS/DS delegation placeholders"
    );
    let gateway = ReferenceAuthoritativeDns::new(&dns_records);
    let pretty_host = bindings.pretty_host().to_string();
    assert_eq!(
        gateway.resolve_alias_or_cname(fqdn),
        Some([pretty_host.clone()].as_slice()),
        "domain CNAME should point at the pretty host"
    );
    assert_eq!(
        gateway.resolve_alias_or_cname(zone),
        Some([pretty_host.clone()].as_slice()),
        "apex ALIAS should point at the pretty host"
    );
    assert!(
        gateway
            .resolve_alias_or_cname(bindings.canonical_host())
            .is_none(),
        "canonical host is managed under gw.sora.id, not the public zone"
    );
    Ok(())
}
