//! Explicit admission work costs for fully numeric-loopback managed validators.

use toml::{Table, Value};

const MEMORY_KIB: i64 = 4_096;
const TIME_COST: i64 = 1;
const LANES: i64 = 1;
const DIFFICULTY: i64 = 6;

// This adapter is called only by managed_peer_config. Ordinary exported localnets never
// enter it. Requiring every original endpoint avoids treating localhost DNS or a loopback
// advertisement with a public listener as an isolated local deployment.
pub(super) fn apply_if_loopback(table: &mut Table) {
    if !all_endpoints_loopback(table) {
        return;
    }
    let Some(pow) = table
        .get_mut("network")
        .and_then(Value::as_table_mut)
        .and_then(|network| network.get_mut("soranet_handshake"))
        .and_then(Value::as_table_mut)
        .and_then(|handshake| handshake.get_mut("pow"))
        .and_then(Value::as_table_mut)
    else {
        return;
    };
    pow.insert("difficulty".into(), Value::Integer(DIFFICULTY));
    pow.insert(
        "puzzle".into(),
        Value::Table(Table::from_iter([
            ("memory_kib".into(), Value::Integer(MEMORY_KIB)),
            ("time_cost".into(), Value::Integer(TIME_COST)),
            ("lanes".into(), Value::Integer(LANES)),
        ])),
    );
}

fn all_endpoints_loopback(table: &Table) -> bool {
    // Stock Global and private-root genesis share this local chain label. Parent-network
    // identity and the private dataspace alias live separately in signed private genesis.
    if table.get("chain").and_then(Value::as_str) != Some(super::DEFAULT_CHAIN_ID) {
        return false;
    }
    let Some(network) = table.get("network").and_then(Value::as_table) else {
        return false;
    };
    let Some(torii) = table.get("torii").and_then(Value::as_table) else {
        return false;
    };
    if ![
        network.get("address"),
        network.get("public_address"),
        torii.get("address"),
    ]
    .into_iter()
    .all(|address| {
        address
            .and_then(Value::as_str)
            .is_some_and(loopback_literal)
    }) {
        return false;
    }
    let Some(peers) = table.get("trusted_peers").and_then(Value::as_array) else {
        return false;
    };
    if peers.is_empty()
        || !peers.iter().all(|peer| {
            peer.as_str()
                .and_then(|peer| peer.parse::<iroha_data_model::peer::Peer>().ok())
                .is_some_and(|peer| {
                    peer.address().port() != 0
                        && peer
                            .address()
                            .ip()
                            .map(std::net::IpAddr::from)
                            .is_some_and(|ip| ip.is_loopback())
                })
        })
    {
        return false;
    }
    torii
        .get("peer_telemetry_urls")
        .and_then(Value::as_array)
        .is_some_and(|urls| {
            urls.iter().all(|value| {
                value
                    .as_str()
                    .and_then(|value| url::Url::parse(value).ok())
                    .is_some_and(|url| {
                        matches!(url.scheme(), "http" | "https")
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.port_or_known_default().is_some_and(|port| port != 0)
                            && match url.host() {
                                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                                _ => false,
                            }
                    })
            })
        })
}

fn loopback_literal(value: &str) -> bool {
    norito::literal::parse("addr", value)
        .ok()
        .and_then(|body| body.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| address.port() != 0 && address.ip().is_loopback())
}

#[cfg(test)]
pub(super) fn assert_managed_profile(
    table: &Table,
    actual: &iroha_config::parameters::actual::SoranetPow,
) {
    assert_eq!(actual.difficulty, 6);
    assert_eq!(actual.puzzle.memory_kib.get(), 4_096);
    assert_eq!(actual.puzzle.time_cost.get(), 1);
    assert_eq!(actual.puzzle.lanes.get(), 1);
    let pow = &table["network"]["soranet_handshake"]["pow"];
    assert_eq!(pow["difficulty"].as_integer(), Some(6));
    assert_eq!(pow["puzzle"]["memory_kib"].as_integer(), Some(4_096));
    assert_eq!(pow["puzzle"]["time_cost"].as_integer(), Some(1));
    assert_eq!(pow["puzzle"]["lanes"].as_integer(), Some(1));
    assert_other_admission_settings(actual);
}

#[cfg(test)]
pub(super) fn assert_public_profile(actual: &iroha_config::parameters::actual::SoranetPow) {
    assert_eq!(actual.difficulty, 6);
    assert_eq!(actual.puzzle.memory_kib.get(), 65_536);
    assert_eq!(actual.puzzle.time_cost.get(), 2);
    assert_eq!(actual.puzzle.lanes.get(), 1);
    assert_other_admission_settings(actual);
}

#[cfg(test)]
fn assert_other_admission_settings(actual: &iroha_config::parameters::actual::SoranetPow) {
    let expected = iroha_config::parameters::actual::SoranetPow::default_const();
    assert_eq!(actual.max_future_skew, expected.max_future_skew);
    assert_eq!(actual.min_ticket_ttl, expected.min_ticket_ttl);
    assert_eq!(actual.ticket_ttl, expected.ticket_ttl);
    assert_eq!(
        actual.outbound_mint_capacity,
        expected.outbound_mint_capacity
    );
    assert_eq!(
        actual.inbound_verify_capacity,
        expected.inbound_verify_capacity
    );
    assert_eq!(
        actual.revocation_store_capacity,
        expected.revocation_store_capacity
    );
    assert_eq!(actual.revocation_max_ttl, expected.revocation_max_ttl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localnet::*;

    fn fixture(host: &str) -> Table {
        let host = CanonicalHost::parse(host, "test endpoint").unwrap();
        let key = iroha_test_samples::REAL_GENESIS_ACCOUNT_KEYPAIR.public_key();
        let mut table = format!(
            "chain = '{}'\ntrusted_peers = ['{}@{}']\n[sumeragi]\nrole = 'validator'\n[network]\naddress = '{}'\npublic_address = '{}'\n[network.soranet_handshake.pow]\nrevocation_store_path = '/private/runtime/original-revocations.nrt'\nmin_ticket_ttl_secs = 41\n[torii]\naddress = '{}'\npeer_telemetry_urls = ['{}']\n",
            DEFAULT_CHAIN_ID,
            key,
            host.addr_literal(13_337),
            host.addr_literal(13_337),
            host.addr_literal(13_337),
            host.addr_literal(8_080),
            host.torii_url(8_080),
        )
        .parse::<Table>()
        .unwrap();
        // Confirm the fully selected fixture independently before changing any endpoint.
        assert!(all_endpoints_loopback(&table));
        table["network"]["soranet_handshake"]["pow"]
            .as_table_mut()
            .unwrap()
            .insert("ticket_ttl_secs".into(), Value::Integer(123));
        table
    }

    #[test]
    fn managed_loopback_admission_is_explicit_and_preserves_other_fields() {
        for host in ["127.0.0.1", "::1"] {
            let mut table = fixture(host);
            let original = table.clone();
            apply_if_loopback(&mut table);
            assert_eq!(
                table["network"]["soranet_handshake"]["pow"]["difficulty"].as_integer(),
                Some(6)
            );
            assert_eq!(
                table["network"]["soranet_handshake"]["pow"]["puzzle"]["memory_kib"].as_integer(),
                Some(4_096)
            );
            let pow = table["network"]["soranet_handshake"]["pow"]
                .as_table_mut()
                .unwrap();
            pow.remove("difficulty");
            pow.remove("puzzle");
            assert_eq!(table, original, "only explicit cost fields may change");
        }
    }

    #[test]
    fn every_managed_endpoint_must_be_numeric_loopback_before_cost_changes() {
        for endpoint in [
            "0.0.0.0:1337",
            "192.0.2.1:1337",
            "localhost:1337",
            "[::]:1337",
            "[2001:db8::1]:1337",
            "127.0.0.1:0",
        ] {
            for field in ["address", "public_address", "torii"] {
                let mut table = fixture("127.0.0.1");
                let value = Value::String(norito::literal::format("addr", endpoint));
                if field == "torii" {
                    table["torii"]["address"] = value;
                } else {
                    table["network"][field] = value;
                }
                let original = table.clone();
                assert!(!all_endpoints_loopback(&table));
                apply_if_loopback(&mut table);
                assert_eq!(table, original);
            }
            let mut table = fixture("127.0.0.1");
            let key = iroha_test_samples::REAL_GENESIS_ACCOUNT_KEYPAIR.public_key();
            table["trusted_peers"]
                .as_array_mut()
                .unwrap()
                .push(Value::String(format!(
                    "{key}@{}",
                    norito::literal::format("addr", endpoint)
                )));
            let original = table.clone();
            apply_if_loopback(&mut table);
            assert_eq!(
                table, original,
                "a foreign roster endpoint must retain public costs"
            );
        }
        for endpoint in [
            "http://localhost:8080/",
            "http://192.0.2.1:8080/",
            "http://[::]:8080/",
            "http://127.0.0.1:0/",
            "http://user@127.0.0.1:8080/",
        ] {
            let mut table = fixture("127.0.0.1");
            table["torii"]["peer_telemetry_urls"]
                .as_array_mut()
                .unwrap()
                .push(Value::String(endpoint.into()));
            let original = table.clone();
            apply_if_loopback(&mut table);
            assert_eq!(table, original);
        }
    }

    #[test]
    fn public_chain_or_incomplete_endpoint_selection_keeps_original_costs() {
        let mut cases = Vec::new();
        for chain in [
            PUBLIC_TAIRA_CHAIN_ID,
            PUBLIC_NEXUS_CHAIN_ID,
            "another-local-chain",
        ] {
            let mut table = fixture("127.0.0.1");
            table.insert("chain".into(), Value::String(chain.into()));
            cases.push(table);
        }
        let mut missing = fixture("127.0.0.1");
        missing.remove("trusted_peers");
        cases.push(missing);
        let mut empty = fixture("127.0.0.1");
        empty["trusted_peers"] = Value::Array(Vec::new());
        cases.push(empty);
        let mut malformed = fixture("127.0.0.1");
        malformed["network"]["address"] = Value::String("addr:127.0.0.1:1337#0000".into());
        cases.push(malformed);
        for mut table in cases {
            let original = table.clone();
            apply_if_loopback(&mut table);
            assert_eq!(table, original);
        }
    }

    #[test]
    fn exported_loopback_localnet_keeps_standard_admission_policy() {
        let _guard = crate::managed::native_test_guard();
        let directory = localnet_test_helpers::private_tempdir().unwrap();
        let opts = LocalnetOptions {
            service_profile: LocalnetServiceProfile::Standard,
            sora_profile: None,
            perf_profile: None,
            peers: std::num::NonZeroU16::new(4).unwrap(),
            seed: Some("exported-loopback-puzzle-policy".into()),
            bind_host: "127.0.0.1".into(),
            public_host: "127.0.0.1".into(),
            base_api_port: 18_080,
            base_p2p_port: 23_337,
            out_dir: directory.path().to_path_buf(),
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Permissioned,
        };
        generate_localnet(&opts, &mut std::io::BufWriter::new(Vec::new())).unwrap();
        for index in 0..4 {
            let path = directory.path().join(format!("peer{index}.toml"));
            let bytes = iroha_fs::read_private(&path, 1024 * 1024).unwrap();
            let source = std::str::from_utf8(&bytes).unwrap();
            let config = parse_localnet_peer_config(source, Some(&path)).unwrap();
            assert_public_profile(&config.network.soranet_handshake.pow);
            let table = source.parse::<Table>().unwrap();
            assert!(
                table["network"]["soranet_handshake"]["pow"]
                    .get("puzzle")
                    .is_none()
            );
            assert!(table.get("data_dir").is_none());
        }
    }
}
