//! File-only configuration for native AMX relay custody and destination trust.

use std::{collections::BTreeSet, path::PathBuf, time::Duration};

use error_stack::Report;
use iroha_config_base::{ReadConfig, WithOrigin, util::Emitter};
use iroha_crypto::PublicKey;
use iroha_data_model::{
    NetworkId, account::AccountId, block::consensus::SumeragiRootScope,
    transaction::FeePaymentIntent,
};
use iroha_model_base::chain::ChainId;

use super::ParseError;
use crate::parameters::{actual, defaults::amx_relay as defaults};

/// Local service settings; no environment variable can supply relay authority.
#[derive(Debug, Clone, ReadConfig)]
pub struct AmxRelay {
    /// Existing durable workflow directory, resolved relative to this configuration file.
    #[config(default = "PathBuf::from(defaults::JOURNAL_DIR)")]
    pub journal_dir: WithOrigin<PathBuf>,
    /// Local polling cadence in milliseconds, never a protocol timeout.
    #[config(default = "defaults::POLL_INTERVAL_MS")]
    pub poll_interval_ms: u64,
    /// Maximum source heights visited by one service pass.
    #[config(default = "defaults::MAX_SOURCE_HEIGHTS_PER_PASS")]
    pub max_source_heights_per_pass: usize,
    /// Maximum authenticated destination proof reads in one observation.
    #[config(default = "defaults::MAX_FINALITY_PROOF_READS")]
    pub max_finality_proof_reads: usize,
    /// Explicit destinations; no route means no relay signing or fee spending.
    #[config(default)]
    pub routes: WithOrigin<Vec<AmxRelayRoute>>,
}

/// Exact public route pins and file references to account custody.
#[derive(Debug, Clone, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct AmxRelayRoute {
    /// Exact destination network.
    pub network_id: NetworkId,
    /// Exact consensus chain label.
    pub chain_id: ChainId,
    /// Exact native Norito JSON root scope. The Global variant has required null content,
    /// which TOML cannot represent; private scopes use this same canonical representation.
    pub scope_json: String,
    /// Separately funded account that authorizes the relay fees.
    pub authority: AccountId,
    /// Explicit SDK account file; runtime checks its authority, network and chain.
    pub account_config: PathBuf,
    /// Canonical signed genesis file, independently pinned below.
    pub signed_genesis: PathBuf,
    /// Lowercase SHA-256 digest of the exact canonical signed genesis file.
    pub signed_genesis_sha256: String,
    /// Independently selected genesis signer.
    pub genesis_public_key: PublicKey,
    /// Exact native Norito JSON fee intent, including the required nullable gas limit.
    /// TOML has no null value, so the one canonical wire type is supplied as JSON text.
    pub fee_payment_json: String,
}

fn invalid(emitter: &mut Emitter<ParseError>, detail: impl Into<String>) {
    emitter.emit(Report::new(ParseError::InvalidAmxRelayConfig).attach(detail.into()));
}

impl AmxRelay {
    /// Validate local bounds and resolve file references without reading keys or trust files.
    pub(super) fn parse(self, emitter: &mut Emitter<ParseError>) -> actual::AmxRelay {
        if self.journal_dir.value().as_os_str().is_empty() {
            invalid(
                emitter,
                "amx_relay.journal_dir must name a durable workflow directory",
            );
        }
        if !(1..=defaults::MAX_POLL_INTERVAL_MS).contains(&self.poll_interval_ms) {
            invalid(
                emitter,
                "amx_relay.poll_interval_ms is outside its nonzero local bound",
            );
        }
        if !(1..=defaults::MAX_SOURCE_HEIGHTS_PER_PASS).contains(&self.max_source_heights_per_pass)
        {
            invalid(
                emitter,
                "amx_relay.max_source_heights_per_pass is outside its nonzero local bound",
            );
        }
        if !(1..=defaults::MAX_FINALITY_PROOF_READS).contains(&self.max_finality_proof_reads) {
            invalid(
                emitter,
                "amx_relay.max_finality_proof_reads is outside its nonzero local bound",
            );
        }
        let (routes, origin) = self.routes.into_tuple();
        let mut parsed = Vec::new();
        if routes.len() > defaults::MAX_ROUTES {
            invalid(
                emitter,
                "amx_relay.routes exceeds the configured-route bound",
            );
        } else {
            let mut seen = BTreeSet::new();
            let mut participants = BTreeSet::new();
            for route in routes {
                if !seen.insert(route.network_id) {
                    invalid(
                        emitter,
                        "amx_relay.routes must contain only one authority per destination network",
                    );
                    continue;
                }
                let Ok(scope) = norito::json::from_str::<SumeragiRootScope>(&route.scope_json)
                else {
                    invalid(
                        emitter,
                        "amx_relay scope_json must be an exact native root scope",
                    );
                    continue;
                };
                if let SumeragiRootScope::Dataspace {
                    parent_network_id,
                    dataspace_id,
                } = scope
                    && !participants.insert((parent_network_id, dataspace_id))
                {
                    invalid(
                        emitter,
                        "amx_relay routes must select exactly one lineage per participant scope",
                    );
                    continue;
                }
                if scope.validate().is_err() {
                    invalid(emitter, "amx_relay route has an invalid private root scope");
                    continue;
                }
                if route.account_config.as_os_str().is_empty()
                    || route.signed_genesis.as_os_str().is_empty()
                {
                    invalid(
                        emitter,
                        "amx_relay routes require explicit account and signed-genesis files",
                    );
                    continue;
                }
                let sha256 = &route.signed_genesis_sha256;
                if sha256.len() != 64
                    || !sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    invalid(
                        emitter,
                        "amx_relay signed_genesis_sha256 must be exactly 64 lowercase hex characters",
                    );
                    continue;
                }
                let mut digest = [0; 32];
                if hex::decode_to_slice(sha256, &mut digest).is_err() || digest == [0; 32] {
                    invalid(
                        emitter,
                        "amx_relay signed_genesis_sha256 must be a nonzero digest",
                    );
                    continue;
                }
                let Ok(fee_payment) =
                    norito::json::from_str::<FeePaymentIntent>(&route.fee_payment_json)
                else {
                    invalid(
                        emitter,
                        "amx_relay fee_payment_json must be an exact native fee authorization",
                    );
                    continue;
                };
                if fee_payment.validate().is_err() {
                    invalid(
                        emitter,
                        "amx_relay fee_payment_json must be an exact canonical fee authorization",
                    );
                    continue;
                }
                parsed.push(actual::AmxRelayRoute {
                    network_id: route.network_id,
                    chain_id: route.chain_id,
                    scope,
                    authority: route.authority,
                    account_config: WithOrigin::new(route.account_config, origin.clone())
                        .resolve_relative_path(),
                    signed_genesis: WithOrigin::new(route.signed_genesis, origin.clone())
                        .resolve_relative_path(),
                    signed_genesis_sha256: digest,
                    genesis_public_key: route.genesis_public_key,
                    fee_payment,
                });
            }
        }
        actual::AmxRelay {
            journal_dir: self.journal_dir.resolve_relative_path(),
            poll_interval: Duration::from_millis(self.poll_interval_ms),
            max_source_heights_per_pass: self.max_source_heights_per_pass,
            max_finality_proof_reads: self.max_finality_proof_reads,
            routes: parsed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config_base::read::ConfigReader;
    use iroha_crypto::{Hash, HashOf, KeyPair};

    fn settings() -> AmxRelay {
        ConfigReader::new().read_and_complete::<AmxRelay>().unwrap()
    }

    fn route() -> AmxRelayRoute {
        let key = KeyPair::from_seed(vec![17; 32], iroha_crypto::Algorithm::Ed25519);
        AmxRelayRoute {
            network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                b"relay-test",
            ))),
            chain_id: "relay-test".parse().unwrap(),
            scope_json: norito::json::to_json(&SumeragiRootScope::Global).unwrap(),
            authority: AccountId::new(key.public_key().clone()),
            account_config: "account.toml".into(),
            signed_genesis: "genesis.nrt".into(),
            signed_genesis_sha256: "ab".repeat(32),
            genesis_public_key: key.public_key().clone(),
            fee_payment_json: norito::json::to_json(&FeePaymentIntent::authority(Vec::new(), None))
                .unwrap(),
        }
    }

    #[test]
    fn amx_relay_defaults_never_infer_signing_authority() {
        let mut errors = Emitter::new();
        let actual = settings().parse(&mut errors);
        errors.into_result().unwrap();
        assert!(actual.routes.is_empty());
        assert!(!actual.journal_dir.as_os_str().is_empty());
        assert_eq!(
            actual.poll_interval,
            Duration::from_millis(defaults::POLL_INTERVAL_MS)
        );
    }

    #[test]
    fn amx_relay_requires_bounded_work_and_explicit_unique_routes() {
        for mutate in [
            |settings: &mut AmxRelay| settings.poll_interval_ms = 0,
            |settings: &mut AmxRelay| settings.max_source_heights_per_pass = 0,
            |settings: &mut AmxRelay| settings.max_finality_proof_reads = usize::MAX,
            |settings: &mut AmxRelay| settings.journal_dir = WithOrigin::inline(PathBuf::new()),
            |settings: &mut AmxRelay| settings.routes = WithOrigin::inline(vec![route(), route()]),
        ] {
            let mut value = settings();
            mutate(&mut value);
            let mut errors = Emitter::new();
            value.parse(&mut errors);
            assert!(errors.into_result().is_err());
        }
    }

    #[test]
    fn amx_relay_rejects_ambiguous_participant_lineages() {
        let mut first = route();
        first.scope_json = norito::json::to_json(&SumeragiRootScope::Dataspace {
            parent_network_id: first.network_id,
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(1),
        })
        .unwrap();
        let mut second = first.clone();
        second.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"other-participant-lineage"),
        ));
        let mut value = settings();
        value.routes = WithOrigin::inline(vec![first, second]);
        let mut errors = Emitter::new();
        assert_eq!(value.parse(&mut errors).routes.len(), 1);
        assert!(errors.into_result().is_err());
    }

    #[test]
    fn amx_relay_rejects_unpinned_or_missing_custody_files() {
        for mutate in [
            |route: &mut AmxRelayRoute| route.signed_genesis_sha256 = "AB".repeat(32),
            |route: &mut AmxRelayRoute| route.signed_genesis_sha256 = "00".repeat(32),
            |route: &mut AmxRelayRoute| route.account_config = PathBuf::new(),
            |route: &mut AmxRelayRoute| route.signed_genesis = PathBuf::new(),
        ] {
            let mut candidate = route();
            mutate(&mut candidate);
            let mut value = settings();
            value.routes = WithOrigin::inline(vec![candidate]);
            let mut errors = Emitter::new();
            assert!(value.parse(&mut errors).routes.is_empty());
            assert!(errors.into_result().is_err());
        }
        let mut value = settings();
        value.routes = WithOrigin::inline(vec![route()]);
        let mut errors = Emitter::new();
        let actual = value.parse(&mut errors);
        errors.into_result().unwrap();
        assert_eq!(actual.routes[0].authority, route().authority);
        assert_eq!(actual.routes[0].signed_genesis_sha256, [0xab; 32]);
    }

    fn route_table(route: AmxRelayRoute) -> toml::Table {
        use iroha_config_base::toml::WriteExt as _;
        toml::Table::new()
            .write("network_id", route.network_id.to_string())
            .write("chain_id", route.chain_id.to_string())
            .write("scope_json", route.scope_json)
            .write("authority", route.authority.to_string())
            .write(
                "account_config",
                route.account_config.to_string_lossy().into_owned(),
            )
            .write(
                "signed_genesis",
                route.signed_genesis.to_string_lossy().into_owned(),
            )
            .write("signed_genesis_sha256", route.signed_genesis_sha256)
            .write("genesis_public_key", route.genesis_public_key.to_string())
            .write("fee_payment_json", route.fee_payment_json)
    }

    fn read_file_route(
        route: toml::Table,
    ) -> Result<AmxRelay, error_stack::Report<[iroha_config_base::read::Error]>> {
        use iroha_config_base::toml::{TomlSource, WriteExt as _};
        let table = toml::Table::new().write("routes", vec![toml::Value::Table(route)]);
        let source = toml::to_string(&table).unwrap();
        let parsed = source.parse::<toml::Table>().unwrap();
        ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(parsed))
            .read_and_complete::<AmxRelay>()
    }

    #[test]
    fn amx_relay_file_route_preserves_explicit_null_gas_authorization() {
        for scope in [
            SumeragiRootScope::Global,
            SumeragiRootScope::Dataspace {
                parent_network_id: route().network_id,
                dataspace_id: iroha_model_base::topology::DataSpaceId::new((1_u64 << 40) + 117),
            },
        ] {
            let mut selected = route();
            selected.scope_json = norito::json::to_json(&scope).unwrap();
            let user = read_file_route(route_table(selected)).unwrap();
            let mut errors = Emitter::new();
            let actual = user.parse(&mut errors);
            errors.into_result().unwrap();
            assert_eq!(actual.routes.len(), 1);
            assert_eq!(actual.routes[0].scope, scope);
            assert_eq!(
                actual.routes[0].fee_payment,
                FeePaymentIntent::authority(Vec::new(), None)
            );
            assert_eq!(actual.routes[0].authority, route().authority);
        }
    }

    #[test]
    fn amx_relay_file_route_rejects_retired_fee_object_and_incomplete_json() {
        let mut retired = route_table(route());
        retired.remove("fee_payment_json");
        retired.insert("fee_payment".into(), toml::Value::Table(toml::Table::new()));
        let error = read_file_route(retired).unwrap_err();
        assert!(
            format!("{error:?}").contains("fee_payment"),
            "wrong file refusal: {error:?}"
        );
        for json in [
            r#"{"payer":"authority","value":{"charge_limits":[]}}"#,
            "{}",
        ] {
            let mut candidate = route();
            candidate.fee_payment_json = json.to_owned();
            let user = read_file_route(route_table(candidate))
                .expect("outer route and canonical scope must decode");
            let mut errors = Emitter::new();
            assert!(user.parse(&mut errors).routes.is_empty());
            let error = errors.into_result().unwrap_err();
            assert!(
                format!("{error:?}").contains("fee_payment_json"),
                "wrong fee refusal: {error:?}"
            );
        }
    }

    #[test]
    fn amx_relay_file_route_rejects_retired_scope_and_incomplete_scope_json() {
        let mut retired = route_table(route());
        retired.remove("scope_json");
        retired.insert("scope".into(), toml::Value::Table(toml::Table::new()));
        let error = read_file_route(retired).unwrap_err();
        assert!(
            format!("{error:?}").contains("scope"),
            "wrong file refusal: {error:?}"
        );
        for json in [r#"{"kind":"global"}"#, "{}"] {
            let mut candidate = route();
            candidate.scope_json = json.to_owned();
            let user = read_file_route(route_table(candidate)).unwrap();
            let mut errors = Emitter::new();
            assert!(user.parse(&mut errors).routes.is_empty());
            let error = errors.into_result().unwrap_err();
            assert!(
                format!("{error:?}").contains("scope_json"),
                "wrong scope refusal: {error:?}"
            );
        }
    }
}
