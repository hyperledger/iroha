//! Real governed catalog bootstrap for the four-peer publication lifecycle.
//!
//! The optional public HTTPS feed remains unused in this scenario. The stock transport and
//! controller are constructed normally; independent governance and gateway keys authorize an
//! empty catalog through the ordinary account-authenticated stage, acknowledge and promote API.

use eyre::{Result, ensure};
use iroha_config::parameters::defaults::sorafs::gateway::compliance::{
    GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1, GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::prelude::*;
use sha2::{Digest as _, Sha256};
use sorafs_manifest::gateway_compliance::{
    GatewayComplianceAcknowledgementPayloadV1, GatewayComplianceAcknowledgementV1,
    GatewayComplianceCatalogApprovalV1, GatewayComplianceCatalogPayloadV1,
    GatewayComplianceCatalogV1, GatewayComplianceTrustPolicyV1, GatewayComplianceTrustedSignerV1,
    gateway_compliance_feed_transport_policy_digest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{sorafs_publication_config::set, sorafs_publication_http};

const CATALOG_SIGNER: &str = "publication-catalog";
const FEED_HOST: &str = "compliance.example";
const FEED_PIN: [u8; 32] = [7; 32];

/// Independent catalog and gateway identities, retained only in this disposable test process.
pub struct PublicationComplianceFixture {
    root: PathBuf,
    catalog_key: KeyPair,
    gateway_keys: Vec<KeyPair>,
    policy: GatewayComplianceTrustPolicyV1,
}

impl PublicationComplianceFixture {
    pub fn new(root: &Path, count: usize) -> Result<Self> {
        ensure!(
            (1..=4).contains(&count),
            "bounded publication gateway count"
        );
        let root = root.join("compliance");
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let catalog_key = KeyPair::try_from_seed(vec![0xD0; 32], Algorithm::Ed25519)?;
        let gateway_keys = (0..count)
            .map(|index| {
                KeyPair::try_from_seed(
                    vec![0xD1 + u8::try_from(index).expect("fixture provider index fits u8"); 32],
                    Algorithm::Ed25519,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signer = |signer_id: String, key: &KeyPair| -> Result<_> {
            Ok(GatewayComplianceTrustedSignerV1 {
                signer_id,
                public_key: key.public_key().to_bytes().1.try_into()?,
            })
        };
        let policy = GatewayComplianceTrustPolicyV1 {
            policy_id: [0xCF; 32],
            catalog_threshold: 1,
            catalog_signers: vec![signer(CATALOG_SIGNER.into(), &catalog_key)?],
            revoked_catalog_signer_ids: Vec::new(),
            gateway_ack_threshold: 1,
            gateway_signers: gateway_keys
                .iter()
                .enumerate()
                .map(|(index, key)| signer(gateway_id(index), key))
                .collect::<Result<Vec<_>>>()?,
            revoked_gateway_signer_ids: Vec::new(),
        };
        policy.validate()?;
        Ok(Self {
            root,
            catalog_key,
            gateway_keys,
            policy,
        })
    }

    /// Register and grant the ordinary operator role to an already registered universal account.
    pub fn genesis_instructions(operator: &AccountId) -> Result<Vec<InstructionBox>> {
        // Role::new explicitly grants the registered role to its initial account.
        Ok(vec![
            Register::role(Role::new(
                "sorafs_gateway_compliance_operator".parse()?,
                operator.clone(),
            ))
            .into(),
        ])
    }

    pub fn config(&self, index: usize) -> Result<toml::Table> {
        ensure!(
            index < self.gateway_keys.len(),
            "unknown compliance gateway"
        );
        let directory = self.root.join(gateway_id(index));
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let pins = BTreeMap::from([(FEED_HOST.to_owned(), BTreeSet::from([FEED_PIN]))]);
        let digest = gateway_compliance_feed_transport_policy_digest(&pins)?;
        let signer = |entry: &GatewayComplianceTrustedSignerV1| {
            toml::Value::Table(toml::Table::from_iter([
                (
                    "signer_id".into(),
                    toml::Value::String(entry.signer_id.clone()),
                ),
                (
                    "public_key_hex".into(),
                    toml::Value::String(hex::encode(entry.public_key)),
                ),
            ]))
        };
        let config = toml::Table::from_iter([
            ("enabled".into(), toml::Value::Boolean(true)),
            (
                "feed_transport_provider_handle".into(),
                GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.into(),
            ),
            (
                "feed_transport_provider_revision".into(),
                (i64::try_from(GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1)
                    .expect("transport revision fits TOML integer"))
                .into(),
            ),
            (
                "feed_transport_provider_policy_digest_hex".into(),
                hex::encode(digest).into(),
            ),
            (
                "checkpoint_path".into(),
                directory
                    .join("checkpoint.norito")
                    .display()
                    .to_string()
                    .into(),
            ),
            (
                "policy_id_hex".into(),
                hex::encode(self.policy.policy_id).into(),
            ),
            (
                "region_id".into(),
                format!("publication-region-{index}").into(),
            ),
            ("gateway_id".into(), gateway_id(index).into()),
            (
                "catalog_threshold".into(),
                i64::from(self.policy.catalog_threshold).into(),
            ),
            (
                "catalog_signers".into(),
                self.policy
                    .catalog_signers
                    .iter()
                    .map(signer)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "gateway_ack_threshold".into(),
                i64::from(self.policy.gateway_ack_threshold).into(),
            ),
            (
                "gateway_signers".into(),
                self.policy
                    .gateway_signers
                    .iter()
                    .map(signer)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "feeds".into(),
                vec![toml::Value::Table(toml::Table::from_iter([
                    ("feed_id".into(), "optional-public-feed".into()),
                    ("url".into(), format!("https://{FEED_HOST}/catalog").into()),
                    ("required".into(), false.into()),
                    (
                        "hosts".into(),
                        vec![toml::Value::Table(toml::Table::from_iter([
                            ("hostname".into(), FEED_HOST.into()),
                            (
                                "accepted_spki_sha256_hex".into(),
                                vec![toml::Value::String(hex::encode(FEED_PIN))].into(),
                            ),
                        ]))]
                        .into(),
                    ),
                ]))]
                .into(),
            ),
        ]);
        let mut layer = toml::Table::new();
        set(&mut layer, &["sorafs", "gateway", "compliance"], config);
        Ok(layer)
    }

    fn catalog(&self, now: u64) -> Result<GatewayComplianceCatalogV1> {
        let payload = GatewayComplianceCatalogPayloadV1 {
            version: 1,
            sequence: 1,
            predecessor_digest: None,
            policy_digest: self.policy.canonical_digest()?,
            generated_at_unix: now,
            valid_until_unix: now + 3600,
            source_anchors: Vec::new(),
            baseline_rules: Vec::new(),
            appeal_overrides: Vec::new(),
            legal_safety_holds: Vec::new(),
            toggles: Vec::new(),
        };
        let signature =
            Signature::try_new(self.catalog_key.private_key(), &payload.signing_digest()?)?;
        Ok(GatewayComplianceCatalogV1 {
            payload,
            approvals: vec![GatewayComplianceCatalogApprovalV1 {
                version: 1,
                signer_id: CATALOG_SIGNER.into(),
                signature: signature.payload().try_into()?,
            }],
        })
    }

    pub async fn install(
        &self,
        http: &reqwest::Client,
        network: &NetworkId,
        base: &str,
        operator: &KeyPair,
        index: usize,
    ) -> Result<()> {
        let gateway = self
            .gateway_keys
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown gateway"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let catalog = self.catalog(now)?;
        let digest = catalog.verify(&self.policy, now, 0)?;
        mutate(
            http,
            network,
            base,
            operator,
            ("stage", "stage"),
            norito::json::to_vec(&catalog)?,
            digest,
        )
        .await?;
        let payload = GatewayComplianceAcknowledgementPayloadV1 {
            version: 1,
            gateway_id: gateway_id(index),
            catalog_digest: digest,
            observed_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            accepted: true,
            rejection_code: None,
        };
        let signature = Signature::try_new(gateway.private_key(), &payload.signing_digest()?)?;
        let acknowledgement = GatewayComplianceAcknowledgementV1 {
            payload,
            signature: signature.payload().try_into()?,
        };
        mutate(
            http,
            network,
            base,
            operator,
            ("acknowledge", "acknowledge"),
            norito::json::to_vec(&acknowledgement)?,
            digest,
        )
        .await?;
        let target = format!(
            "promote?expected_catalog_digest={}&expected_sequence=1",
            hex::encode(digest)
        );
        mutate(
            http,
            network,
            base,
            operator,
            ("promote", &target),
            Vec::new(),
            digest,
        )
        .await
    }
}

fn gateway_id(index: usize) -> String {
    format!("publication-gateway-{index}")
}

/// Independent implementation of the documented HTTP mutation binding (including query bytes).
fn idempotency(action: &str, path: &str, body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iroha.sorafs.gateway.compliance.idempotency.v1");
    for field in [action.as_bytes(), path.as_bytes(), body] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hex::encode(hash.finalize())
}

async fn mutate(
    http: &reqwest::Client,
    network: &NetworkId,
    base: &str,
    operator: &KeyPair,
    (action, target): (&str, &str),
    body: Vec<u8>,
    digest: [u8; 32],
) -> Result<()> {
    let path = format!("/v1/sorafs/gateway/compliance/{target}");
    let key = idempotency(action, &path, &body);
    let response =
        sorafs_publication_http::post_json(http, network, base, operator, &path, body, &key)
            .await?;
    let status = response.status();
    let body = sorafs_publication_http::bytes(response, 64 * 1024).await?;
    ensure!(
        status.is_success(),
        "compliance {action} rejected: {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let value: norito::json::Value = norito::json::from_slice(&body)?;
    ensure!(
        value["catalog_digest_hex"].as_str() == Some(hex::encode(digest).as_str()),
        "compliance response changed catalog identity"
    );
    ensure!(
        value["idempotency_key"].as_str() == Some(key.as_str()),
        "compliance response changed replay binding"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_is_governed_and_native_feed_policy_matches_configuration() -> Result<()> {
        let root = tempfile::tempdir()?;
        let fixture = PublicationComplianceFixture::new(root.path(), 3)?;
        let now = 1_900_000_000;
        let mut catalog = fixture.catalog(now)?;
        catalog.verify(&fixture.policy, now, 0)?;
        catalog.payload.sequence += 1;
        ensure!(
            catalog.verify(&fixture.policy, now, 0).is_err(),
            "modified catalog signature accepted"
        );
        let layer = fixture.config(1)?;
        let config = &layer["sorafs"]["gateway"]["compliance"];
        ensure!(
            config["gateway_id"].as_str() == Some("publication-gateway-1"),
            "wrong configured gateway"
        );
        ensure!(
            config["feeds"][0]["required"].as_bool() == Some(false),
            "fixture unexpectedly requires network feed"
        );
        let pins = BTreeMap::from([(FEED_HOST.to_owned(), BTreeSet::from([FEED_PIN]))]);
        let expected = hex::encode(gateway_compliance_feed_transport_policy_digest(&pins)?);
        ensure!(
            config["feed_transport_provider_policy_digest_hex"].as_str() == Some(expected.as_str()),
            "native feed binding changed the exact configured trust inventory"
        );
        ensure!(fixture.config(3).is_err(), "unregistered gateway accepted");
        Ok(())
    }
    #[test]
    fn replay_binding_covers_action_body_and_exact_promotion_query() {
        let path =
            "/v1/sorafs/gateway/compliance/promote?expected_catalog_digest=abc&expected_sequence=1";
        let key = idempotency("promote", path, b"");
        assert_ne!(key, idempotency("stage", path, b""));
        assert_ne!(key, idempotency("promote", path, b"{}"));
        assert_ne!(
            key,
            idempotency("promote", &path.replace("sequence=1", "sequence=2"), b"")
        );
    }
}
