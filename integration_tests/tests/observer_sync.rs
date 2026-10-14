//! Observer/sync-only node catches up behind a small validator swarm.
use eyre::{Result, WrapErr, eyre};
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_config::base::toml::WriteExt as _;
use iroha_model_base::name::Name;
use iroha_primitives::unique_vec::UniqueVec;
use iroha_test_network::{
    NetworkBuilder, NetworkPeer, NetworkPeerBuilder, init_instruction_registry,
};
use iroha_test_samples::ALICE_ID;
use norito::json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use toml::{Table, Value as TomlValue};
#[test]
#[allow(clippy::too_many_lines)]
fn observer_node_catches_up() -> Result<()> {
    init_instruction_registry();
    // Prepare a validator network that satisfies DA quorum requirements.
    let Some((network, rt)) = sandbox::build_network_blocking_or_skip(
        NetworkBuilder::new().with_min_peers(4),
        stringify!(observer_node_catches_up),
    ) else {
        return Ok(());
    };
    // Build observer peer (sync-only) ahead of validator bootstrap so validators trust it.
    let observer = NetworkPeerBuilder::new()
        .with_seed(Some(b"observer"))
        .build(network.env());
    // Prepare a trusted_peers override including existing peers and the observer itself.
    // The observer is trusted for networking/block sync, but it is intentionally omitted
    // from `trusted_peers_pop` so the validator roster remains the four validator peers.
    let mut tp: UniqueVec<Peer> = network
        .peers()
        .iter()
        .map(|p| Peer::new(p.p2p_address(), p.id()))
        .collect();
    // Add observer itself to trusted peers; ignore duplicates
    let _ = tp.push(Peer::new(observer.p2p_address(), observer.id()));
    let mut pops_by_peer_id = HashMap::new();
    for peer in network.peers() {
        let pop = peer.bls_pop().expect("network peers should have BLS PoPs");
        pops_by_peer_id.insert(peer.id(), pop.to_vec());
    }
    let trusted_peers: Vec<String> = tp.iter().map(|peer| peer.to_string()).collect();
    let mut trusted_peers_pop = Vec::new();
    let mut seen = HashSet::new();
    for peer in network.peers() {
        let peer_id = peer.id();
        if !seen.insert(peer_id.clone()) {
            continue;
        }
        let pop = pops_by_peer_id
            .get(&peer_id)
            .unwrap_or_else(|| panic!("missing PoP for validator peer {}", peer_id.public_key()));
        let mut pop_entry = Table::new();
        pop_entry.insert(
            "public_key".into(),
            TomlValue::String(peer_id.public_key().to_string()),
        );
        pop_entry.insert(
            "pop_hex".into(),
            TomlValue::String(format!("0x{}", hex::encode(pop))),
        );
        trusted_peers_pop.push(TomlValue::Table(pop_entry));
    }
    let trusted_observer_layer = Table::new()
        .write(["trusted_peers"], trusted_peers.clone())
        .write(
            ["trusted_peers_pop"],
            TomlValue::Array(trusted_peers_pop.clone()),
        );
    // Start validators with the observer in trusted peers so permissioned networking accepts it.
    let validator_layers: Vec<_> = network
        .config_layers()
        .chain(std::iter::once(std::borrow::Cow::Owned(
            trusted_observer_layer.clone(),
        )))
        .collect();
    let genesis = network.genesis();
    for peer in network.peers() {
        sandbox::handle_result(
            rt.block_on(async {
                peer.start_checked(validator_layers.iter(), Some(&genesis))
                    .await
            }),
            "observer_node_catches_up_start_validator",
        )?;
    }
    let override_layer = trusted_observer_layer
        .write(["sumeragi", "role"], "observer")
        .write(["logger", "level"], "INFO");
    // Start the observer with role override and extended trusted peers
    if sandbox::handle_result(
        rt.block_on(async {
            observer
                .start_checked(
                    network
                        .config_layers()
                        .chain(std::iter::once(std::borrow::Cow::Owned(
                            override_layer.clone(),
                        ))),
                    Some(&network.genesis()),
                )
                .await
        }),
        "observer_node_catches_up_start_observer",
    )?
    .is_none()
    {
        return Ok(());
    }
    let sync_timeout = network.sync_timeout();
    let wait_for_observer = |height| -> Result<()> {
        rt.block_on(async {
            tokio::time::timeout(sync_timeout, observer.once_block(height))
                .await
                .map_err(|_| {
                    eyre!("observer did not reach height {height} within {sync_timeout:?}")
                })
        })?;
        Ok(())
    };
    // Observer should have at least the genesis block
    wait_for_observer(1)?;
    // Produce non-genesis blocks and verify height parity across all peers
    // Baseline timestamp (ms) to filter POST /v1/accounts/:id/transactions/query later.
    let now_ms = || -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        u64::try_from(ms).unwrap_or(u64::MAX)
    };
    let _t0 = now_ms();
    let alice = ALICE_ID.clone();
    let key: Name = "note".parse().unwrap();
    let client =
        integration_tests::sync::rebind_blocking_client(&network.peer().client(), |client| {
            client.transaction_status_timeout = std::time::Duration::from_millis(180_000);
        });
    // 1st block: set note = "v1"
    println!("observer_sync: submitting v1");
    let t1_lo = now_ms();
    client.submit(
        SetKeyValue::account(alice.clone(), key.clone(), norito::json!("v1")),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    println!("observer_sync: v1 committed");
    // Wait until validators reach total >= 2 and observer catches up
    rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 2).await })?;
    wait_for_observer(2)?;
    // 2nd block: set note = "v2"
    let _t2_lo = now_ms();
    println!("observer_sync: submitting v2");
    client.submit(
        SetKeyValue::account(alice, key, norito::json!("v2")),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    println!("observer_sync: v2 committed");
    // Wait until validators reach total >= 3 and observer catches up
    rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 3).await })?;
    wait_for_observer(3)?;
    // 3rd block: change some other metadata to ensure another non-genesis block
    let alice2 = ALICE_ID.clone();
    let key2: Name = "znote".parse().unwrap();
    let _t3_lo = now_ms();
    println!("observer_sync: submitting v3");
    client.submit(
        SetKeyValue::account(alice2, key2, norito::json!("v3")),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    println!("observer_sync: v3 committed");
    // Wait until validators reach total >= 4 and observer catches up
    rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 4).await })?;
    wait_for_observer(4)?;
    // 4th block: set note = "v4"
    let t4_lo = now_ms();
    println!("observer_sync: submitting v4");
    client.submit(
        SetKeyValue::account(
            ALICE_ID.clone(),
            "note".parse::<Name>().unwrap(),
            norito::json!("v4"),
        ),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    println!("observer_sync: v4 committed");
    rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 5).await })?;
    wait_for_observer(5)?;
    // 5th block: set znote = "v5"
    let t5_lo = now_ms();
    println!("observer_sync: submitting v5");
    client.submit(
        SetKeyValue::account(
            ALICE_ID.clone(),
            "znote".parse::<Name>().unwrap(),
            norito::json!("v5"),
        ),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    println!("observer_sync: v5 committed");
    rt.block_on(async { network.ensure_blocks_with(|h| h.total >= 6).await })?;
    wait_for_observer(6)?;
    let t_hi = now_ms();
    // Verify exact height parity across validators and observer
    let mut validator_totals = Vec::new();
    for p in network.peers() {
        let s = rt
            .block_on(async { p.status().await })
            .expect("peer status");
        validator_totals.push(s.blocks);
    }
    let target_height = *validator_totals.iter().max().unwrap_or(&0);
    wait_for_observer(target_height)?;
    let mut all_totals = Vec::new();
    for p in network.peers() {
        let s = rt
            .block_on(async { p.status().await })
            .expect("peer status");
        all_totals.push(s.blocks);
    }
    let s_obs = rt
        .block_on(async { observer.status().await })
        .expect("observer status");
    all_totals.push(s_obs.blocks);
    assert!(
        all_totals.iter().all(|&t| t == all_totals[0]),
        "heights differ: {all_totals:?}"
    );
    // Verify state reflects latest metadata values on all peers (validators + observer).
    // Kura heights can advance before state/indices are fully applied, so poll for metadata.
    let note_key: Name = "note".parse().unwrap();
    let znote_key: Name = "znote".parse().unwrap();
    let wait_for_metadata = |peer: &NetworkPeer| -> Result<()> {
        let deadline = std::time::Instant::now() + sync_timeout;
        let peer_id = peer.id().to_string();
        let mut last_note: Option<String> = None;
        let mut last_znote: Option<String> = None;
        loop {
            let client = peer.client();
            let accounts = client.client().query(FindAccounts).execute_all().unwrap();
            let alice = accounts
                .into_iter()
                .find(|a| a.id() == &ALICE_ID.clone())
                .expect("Alice account must exist");
            if let Some(note) = alice.metadata().get(&note_key) {
                last_note = Some(note.as_ref().to_string());
            }
            if let Some(znote) = alice.metadata().get(&znote_key) {
                last_znote = Some(znote.as_ref().to_string());
            }
            if last_note.as_deref() == Some("v4") && last_znote.as_deref() == Some("v5") {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre!(
                    "peer {peer_id} did not observe note=v4/znote=v5 within {sync_timeout:?} (last note={last_note:?}, znote={last_znote:?})"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    };
    for p in network.peers() {
        wait_for_metadata(p)?;
    }
    wait_for_metadata(&observer)?;
    // Redundant HTTP verification via Torii: fetch last transactions for Alice from each peer
    let alice_id_str = format!("{}", *ALICE_ID);
    let fetch_tx_http = |peer: &NetworkPeer, limit: usize| -> Result<(u64, Vec<JsonValue>)> {
        let url = format!(
            "{}/v1/accounts/{}/transactions?limit={}",
            peer.torii_url(),
            &*ALICE_ID,
            limit
        );
        let body = rt.block_on(async {
            integration_tests::http::client()
                .get(url)
                .header("Accept", "application/json")
                .send()
                .await?
                .text()
                .await
        })?;
        let parsed: JsonValue = norito::json::from_str(&body)?;
        let (items, total) = match parsed {
            JsonValue::Object(m) => {
                let total = m
                    .get("items")
                    .and_then(norito::json::Value::as_array)
                    .map_or(0, |items| items.len() as u64);
                let items = m
                    .get("items")
                    .and_then(|v| match v {
                        JsonValue::Array(a) => Some(a.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                (items, total)
            }
            _ => (Vec::new(), 0),
        };
        Ok((total, items))
    };
    for p in network.peers() {
        let (total, items) = fetch_tx_http(p, 5)?;
        assert!(
            total >= 5,
            "expected at least 5 Alice txs via HTTP; got {total}"
        );
        assert!(
            !items.is_empty(),
            "expected items via HTTP for {}",
            p.torii_url()
        );
    }
    {
        let (total, items) = fetch_tx_http(&observer, 5)?;
        assert!(
            total >= 5,
            "observer HTTP must report at least 5 txs; got {total}"
        );
        assert!(!items.is_empty(), "expected items via HTTP for observer");
    }
    // POST /v1/accounts/{alice}/transactions/query with timestamp filter since t0
    let post_tx_query =
        |peer: &NetworkPeer, min_ts: u64, max_ts: Option<u64>| -> Result<(u64, Vec<JsonValue>)> {
            let url = format!(
                "{}/v1/accounts/{}/transactions/query",
                peer.torii_url(),
                &*ALICE_ID,
            );
            let mut args = vec![
                {
                    let args = norito::json::array([
                        norito::json::to_value("authority").expect("serialize key"),
                        norito::json::to_value(alice_id_str.as_str())
                            .expect("serialize authority value"),
                    ])
                    .expect("serialize args array");
                    norito::json::object([
                        ("op", norito::json::to_value("eq").expect("serialize op")),
                        ("args", args),
                    ])
                    .expect("serialize equality filter")
                },
                norito::json!({"op":"gte","args":["timestamp_ms", min_ts]}),
            ];
            if let Some(max_ts) = max_ts {
                args.push(norito::json!({"op":"lte","args":["timestamp_ms", max_ts]}));
            }
            let env = norito::json!({
                "filter": {"op": "and", "args": args},
                "limit": 100
            });
            let body = norito::json::to_json(&env)?;
            let client = integration_tests::http::client();
            let resp_txt = rt.block_on(async {
                client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .body(body)
                    .send()
                    .await?
                    .text()
                    .await
            })?;
            let parsed: JsonValue = norito::json::from_str(&resp_txt)?;
            let (items, total) = match parsed {
                JsonValue::Object(m) => {
                    let total = m
                        .get("items")
                        .and_then(norito::json::Value::as_array)
                        .map_or(0, |items| items.len() as u64);
                    let items = m
                        .get("items")
                        .and_then(|v| match v {
                            JsonValue::Array(a) => Some(a.clone()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    (items, total)
                }
                _ => (Vec::new(), 0),
            };
            Ok((total, items))
        };
    // For a narrower window, use [t1_lo, t_hi], expecting exactly 5 Alice txs
    // Removed unused underscore-prefixed binding _extract_ts
    // Helpers to extract timestamp and hash
    let extract_ts = |it: &JsonValue| -> u64 {
        it.as_object()
            .and_then(|m| m.get("timestamp_ms").and_then(norito::json::Value::as_u64))
            .unwrap_or(0)
    };
    let extract_hash = |it: &JsonValue| -> String {
        it.as_object()
            .and_then(|m| m.get("entrypoint_hash").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string()
    };
    for p in network.peers() {
        let (total, mut items) = post_tx_query(p, t1_lo, Some(t_hi))?;
        assert_eq!(
            total,
            5,
            "expected exactly 5 filtered txs on {}",
            p.torii_url()
        );
        assert_eq!(items.len(), 5, "expected 5 items on {}", p.torii_url());
        // All items must be authored by Alice
        for it in &items {
            let auth = match it {
                JsonValue::Object(m) => m
                    .get("authority")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                _ => String::new(),
            };
            assert_eq!(auth, alice_id_str);
        }
        // Sort by timestamp and check the most recent two correspond to last two updates
        items.sort_by_key(&extract_ts);
        let last = items.last().unwrap();
        let prev = &items[items.len() - 2];
        let last_ts = extract_ts(last);
        let prev_ts = extract_ts(prev);
        assert!(
            last_ts >= t5_lo,
            "last tx timestamp {last_ts} < t5_lo {t5_lo}"
        );
        assert!(
            prev_ts >= t4_lo,
            "prev tx timestamp {prev_ts} < t4_lo {t4_lo}"
        );
        // Cross-check entrypoint_hash uniqueness for final two operations
        let last_hash = extract_hash(last);
        let prev_hash = extract_hash(prev);
        assert_ne!(
            last_hash,
            prev_hash,
            "last two entrypoint_hash identical on {}",
            p.torii_url()
        );
    }
    {
        let (total, mut items) = post_tx_query(&observer, t1_lo, Some(t_hi))?;
        assert_eq!(total, 5, "observer expected exactly 5 filtered txs");
        assert_eq!(items.len(), 5, "observer expected 5 items");
        items.sort_by_key(&extract_ts);
        let last = items.last().unwrap();
        let prev = &items[items.len() - 2];
        let last_ts = extract_ts(last);
        let prev_ts = extract_ts(prev);
        assert!(last_ts >= t5_lo);
        assert!(prev_ts >= t4_lo);
        let last_hash = extract_hash(last);
        let prev_hash = extract_hash(prev);
        assert_ne!(
            last_hash, prev_hash,
            "observer last two entrypoint_hash identical"
        );
    }
    let fetch_status_json = |url: String| -> Result<JsonValue> {
        let body = rt.block_on(async {
            integration_tests::http::client()
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await?
                .error_for_status()?
                .text()
                .await
        })?;
        norito::json::from_str(&body).wrap_err_with(|| {
            let snippet = body.chars().take(120).collect::<String>();
            format!("HTTP /status did not return JSON from {url}; body starts with `{snippet}`")
        })
    };
    // HTTP /status parity snapshot: compare HTTP JSON blocks/non_empty with peer.status()
    for p in network.peers() {
        let s = rt
            .block_on(async { p.status().await })
            .expect("peer status");
        let url = format!("{}/status", p.torii_url());
        let jv = fetch_status_json(url)?;
        let blocks = jv
            .as_object()
            .and_then(|m| m.get("blocks").and_then(norito::json::Value::as_u64))
            .unwrap_or_default();
        let non_empty = jv
            .as_object()
            .and_then(|m| {
                m.get("blocks_non_empty")
                    .and_then(norito::json::Value::as_u64)
            })
            .unwrap_or_default();
        assert_eq!(blocks, s.blocks, "HTTP /status mismatch (blocks)");
        assert_eq!(
            non_empty, s.blocks_non_empty,
            "HTTP /status mismatch (non_empty)"
        );
    }
    {
        let s = rt
            .block_on(async { observer.status().await })
            .expect("observer status");
        let url = format!("{}/status", observer.torii_url());
        let jv = fetch_status_json(url)?;
        let blocks = jv
            .as_object()
            .and_then(|m| m.get("blocks").and_then(norito::json::Value::as_u64))
            .unwrap_or_default();
        let non_empty = jv
            .as_object()
            .and_then(|m| {
                m.get("blocks_non_empty")
                    .and_then(norito::json::Value::as_u64)
            })
            .unwrap_or_default();
        assert_eq!(blocks, s.blocks, "Observer HTTP /status mismatch (blocks)");
        assert_eq!(
            non_empty, s.blocks_non_empty,
            "Observer HTTP /status mismatch (non_empty)"
        );
    }
    Ok(())
}
