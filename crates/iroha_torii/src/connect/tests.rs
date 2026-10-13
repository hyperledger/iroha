//! Connect session, relay, and WebSocket tests.

use super::*;
use iroha_crypto::{Hash, KeyPair};
use std::{collections::BTreeMap, num::NonZeroU64};
use tokio::time::{Duration, timeout};
fn test_session_identity(seed: u8) -> (Sid, [u8; 32], [u8; 16]) {
    let app_pk = [seed.max(1); 32];
    let nonce = [seed.wrapping_add(1).max(1); 16];
    let sid = connect_sdk::derive_session_id(&test_network_id(), &app_pk, &nonce);
    (sid, app_pk, nonce)
}
fn enabled_test_config() -> iroha_config::parameters::actual::Connect {
    iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 16,
        ws_per_ip_max_sessions: 8,
        ws_rate_per_ip_per_min: 60,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 256_000,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 1,
    }
}

#[test]
fn configured_bus_is_inert_until_torii_starts_it() {
    let bus = Bus::from_config(&enabled_test_config(), test_network_id());
    assert_eq!(
        std::sync::Arc::strong_count(&bus.inner),
        1,
        "construction must not detach a self-retaining cleaner"
    );
}

#[tokio::test]
async fn cleaner_stops_and_releases_its_bus_on_shutdown() {
    let bus = Bus::from_config(&enabled_test_config(), test_network_id());
    let shutdown = ShutdownSignal::new();
    let cleaner = bus.start_cleaner(shutdown.clone());
    assert_eq!(std::sync::Arc::strong_count(&bus.inner), 2);
    shutdown.send();
    let exit = timeout(Duration::from_secs(1), cleaner)
        .await
        .expect("Connect cleaner must observe shutdown")
        .expect("Connect cleaner must not panic");
    assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
    assert_eq!(std::sync::Arc::strong_count(&bus.inner), 1);
}

#[tokio::test]
async fn websocket_writer_panic_is_contained_and_disconnects_session() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x6d);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    let mut reservation = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("reserve app endpoint");
    let session = reservation.session.clone();
    let (_inbox, endpoint_lease) = reservation
        .commit_and_attach()
        .await
        .expect("attach app endpoint");

    let outcome = recover_ws_session(async move {
        let _endpoint_lease = endpoint_lease;
        drive_ws_halves(std::future::pending::<Result<(), String>>(), async {
            assert!(
                iroha_panic_hook::is_suppressed(),
                "the physical writer future must run inside the session recovery boundary"
            );
            panic!("injected Connect websocket writer panic");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await
    })
    .await;

    assert_eq!(
        outcome,
        Err("connect websocket session panicked".to_owned())
    );
    assert!(
        !iroha_panic_hook::is_suppressed(),
        "panic-hook suppression must not leak into the caller"
    );
    timeout(Duration::from_secs(1), async {
        while bus.session_is_current(&sid, &session).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panicked writer releases and disconnects its endpoint");
}

fn test_claim(
    seed: u8,
    app_token: &str,
    wallet_token: &str,
    management_token: &str,
    relay_token: &str,
) -> proto::ConnectSessionClaimV1 {
    let (sid, app_pk, nonce) = test_session_identity(seed);
    proto::ConnectSessionClaimV1 {
        sid,
        network_id: test_network_id(),
        app_pk,
        nonce,
        token_app_hash: connect_sdk::token_auth_hash(connect_sdk::TokenKind::App, &sid, app_token),
        token_wallet_hash: connect_sdk::token_auth_hash(
            connect_sdk::TokenKind::Wallet,
            &sid,
            wallet_token,
        ),
        token_management_hash: connect_sdk::token_auth_hash(
            connect_sdk::TokenKind::Management,
            &sid,
            management_token,
        ),
        relay_mac_key: connect_sdk::derive_relay_mac_key(&sid, relay_token),
        relay_auth_hash: connect_sdk::relay_auth_hash(&sid, relay_token),
        expires_at_ms: expires_at_ms(Duration::from_mins(5)),
    }
}
fn signed_approval_control(
    key_pair: &KeyPair,
    constraints: &proto::Constraints,
    sid: &Sid,
    app_pk: &[u8; 32],
    wallet_pk: [u8; 32],
    relay_token: &str,
) -> proto::ConnectControlV1 {
    let account_id = AccountId::new(key_pair.public_key().clone()).to_string();
    let relay_auth = connect_sdk::relay_auth_hash(sid, relay_token);
    let preimage = connect_sdk::build_approve_preimage(
        constraints,
        sid,
        app_pk,
        &wallet_pk,
        &account_id,
        None,
        None,
        &relay_auth,
    );
    let sig_wallet = proto::WalletSignatureV1::new(
        Algorithm::Ed25519,
        Signature::try_new(key_pair.private_key(), &preimage).expect("approval fixture signs"),
    );
    proto::ConnectControlV1::Approve {
        wallet_pk,
        account_id,
        permissions: None,
        proof: None,
        sig_wallet,
    }
}
#[tokio::test]
async fn register_tokens_rejects_duplicate_sid() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x11);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "t-app".into(),
            wallet: "t-wallet".into(),
            management: "t-management".into(),
            relay: "t-relay".into(),
        },
    )
    .await
    .expect("first registration succeeds");
    let err = bus
        .register_tokens(
            sid,
            app_pk,
            nonce,
            crate::connect::SessionTokens {
                app: "t-app-2".into(),
                wallet: "t-wallet-2".into(),
                management: "t-management-2".into(),
                relay: "t-relay-2".into(),
            },
        )
        .await
        .expect_err("duplicate sid should be rejected");
    assert_eq!(err, RegisterSessionError::Exists);
}
#[tokio::test]
async fn concurrent_registration_cannot_replace_session_identity() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x31);
    let first = bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token-a".into(),
            wallet: "wallet-token-a".into(),
            management: "management-token-a".into(),
            relay: "relay-token-a".into(),
        },
    );
    let second = bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token-b".into(),
            wallet: "wallet-token-b".into(),
            management: "management-token-b".into(),
            relay: "relay-token-b".into(),
        },
    );
    let (first, second) = tokio::join!(first, second);
    assert!(
        matches!(
            (&first, &second),
            (Ok(()), Err(RegisterSessionError::Exists))
                | (Err(RegisterSessionError::Exists), Ok(()))
        ),
        "exactly one registration must win: first={first:?}, second={second:?}"
    );
    assert_eq!(bus.inner.read().await.len(), 1);
    let accepted_a = bus
        .authorize_management_token(sid, "management-token-a")
        .await;
    let accepted_b = bus
        .authorize_management_token(sid, "management-token-b")
        .await;
    assert_ne!(
        accepted_a, accepted_b,
        "the losing registration must not replace the winning token binding"
    );
}
#[tokio::test]
async fn register_tokens_stores_token_hashes() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x51);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    let session = bus
        .inner
        .read()
        .await
        .get(&sid.to_vec())
        .cloned()
        .expect("session registered");
    assert_eq!(
        *session.app_token_hash.lock().await,
        Some(connect_sdk::token_auth_hash(
            connect_sdk::TokenKind::App,
            &sid,
            "app-token"
        ))
    );
    assert_eq!(
        *session.management_token_hash.lock().await,
        Some(connect_sdk::token_auth_hash(
            connect_sdk::TokenKind::Management,
            &sid,
            "management-token"
        ))
    );
    assert!(
        bus.authorize_management_token(sid, "management-token")
            .await
    );
    assert!(!bus.authorize_management_token(sid, "wrong-token").await);
    let mut reservation = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("app token accepted");
    let _app_inbox = reservation
        .commit_and_attach()
        .await
        .expect("app endpoint attaches");
    assert_eq!(*session.app_token_hash.lock().await, None);
    assert!(
        bus.reserve_token(sid, proto::Role::App, "app-token")
            .await
            .is_err(),
        "role token is one-time"
    );
}
#[tokio::test]
async fn dropped_role_token_reservation_can_be_retried() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x61);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");

    let reservation = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("first reservation succeeds");
    assert!(
        bus.reserve_token(sid, proto::Role::App, "app-token")
            .await
            .is_err(),
        "a concurrent upgrade must not share a one-time token"
    );
    drop(reservation);

    let retry = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("dropping an uncommitted upgrade restores availability");
    drop(retry);
}
#[tokio::test]
async fn remote_role_consumption_wins_over_reservation_rollback() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x62);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    let reservation = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("reserve app role");
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::RoleConsumed(
        proto::ConnectSessionRoleConsumedV1 {
            sid,
            role: proto::Role::App,
        },
    ))
    .await;
    drop(reservation);
    assert!(
        bus.reserve_token(sid, proto::Role::App, "app-token")
            .await
            .is_err(),
        "rolling back a stale local reservation must not resurrect a remotely consumed token"
    );
}
#[tokio::test]
async fn terminated_reserved_session_cannot_be_reattached_or_replace_retry() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x63);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "old-app-token".into(),
            wallet: "old-wallet-token".into(),
            management: "old-management-token".into(),
            relay: "old-relay-token".into(),
        },
    )
    .await
    .expect("register old session");
    let mut stale = bus
        .reserve_token(sid, proto::Role::App, "old-app-token")
        .await
        .expect("reserve old session");
    assert!(bus.terminate_session(sid, "test termination").await);
    assert!(stale.commit_and_attach().await.is_err());

    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "new-app-token".into(),
            wallet: "new-wallet-token".into(),
            management: "new-management-token".into(),
            relay: "new-relay-token".into(),
        },
    )
    .await
    .expect("register replacement session");
    drop(stale);
    let retry = bus
        .reserve_token(sid, proto::Role::App, "new-app-token")
        .await
        .expect("stale rollback cannot affect replacement session");
    drop(retry);
}
#[tokio::test]
async fn stale_management_token_cannot_terminate_replacement_session() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x69);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "old-app-token".into(),
            wallet: "old-wallet-token".into(),
            management: "old-management-token".into(),
            relay: "old-relay-token".into(),
        },
    )
    .await
    .expect("register old session");
    assert!(bus.terminate_session(sid, "replace in test").await);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "new-app-token".into(),
            wallet: "new-wallet-token".into(),
            management: "new-management-token".into(),
            relay: "new-relay-token".into(),
        },
    )
    .await
    .expect("register replacement session");

    assert!(
        !bus.terminate_session_authorized(sid, "old-management-token", "stale delete",)
            .await
    );
    assert!(
        bus.session_status(sid, "new-management-token")
            .await
            .is_some(),
        "the stale authorized operation must not remove a new SID incarnation"
    );
    assert!(
        bus.terminate_session_authorized(sid, "new-management-token", "current delete",)
            .await
    );
}
#[tokio::test]
async fn stale_relay_work_cannot_touch_deliver_to_or_terminate_replacement() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x6A);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "old-app-token".into(),
            wallet: "old-wallet-token".into(),
            management: "old-management-token".into(),
            relay: "old-relay-token".into(),
        },
    )
    .await
    .expect("register old session");
    let stale = bus
        .inner
        .read()
        .await
        .get(&sid.to_vec())
        .cloned()
        .expect("old session");
    assert!(bus.terminate_session(sid, "replace in test").await);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "new-app-token".into(),
            wallet: "new-wallet-token".into(),
            management: "new-management-token".into(),
            relay: "new-relay-token".into(),
        },
    )
    .await
    .expect("register replacement session");
    let replacement = bus
        .inner
        .read()
        .await
        .get(&sid.to_vec())
        .cloned()
        .expect("replacement session");
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let replacement_activity = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("test instant");
    *replacement.last_activity.lock().await = replacement_activity;

    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    bus.relay_with_session(frame, 0, stale.clone()).await;
    assert!(
        timeout(Duration::from_millis(20), wallet_inbox.recv())
            .await
            .is_err(),
        "stale relay work must not deliver into the replacement endpoint"
    );
    assert_eq!(*replacement.last_seq_app_to_wallet.lock().await, None);
    assert_eq!(
        *replacement.last_activity.lock().await,
        replacement_activity
    );
    assert!(!bus.touch_session_if_current(&sid, &stale).await);
    assert!(
        bus.session_expired_for(&sid, &stale, Instant::now()).await,
        "a replaced incarnation is terminal for its old websocket"
    );
    assert!(
        !bus.terminate_session_if_current(sid, &stale, "stale relay", true)
            .await
    );
    assert!(
        bus.session_status(sid, "new-management-token")
            .await
            .is_some()
    );
}
#[tokio::test]
async fn committed_attach_drains_more_than_channel_capacity_in_order() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x64);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    for seq in 1..=65 {
        bus.relay(proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::AppToWallet,
            seq,
            kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: seq }),
        })
        .await;
    }
    let mut reservation = bus
        .reserve_token(sid, proto::Role::Wallet, "wallet-token")
        .await
        .expect("reserve wallet role");
    let (mut inbox, _endpoint_lease) =
        timeout(Duration::from_millis(100), reservation.commit_and_attach())
            .await
            .expect("attach must not block on the 64-frame live channel")
            .expect("attach succeeds");
    for seq in 1..=65 {
        let frame = inbox.recv().await.expect("buffered frame");
        assert_eq!(frame.seq, seq);
    }
}
#[tokio::test]
async fn offline_buffer_overflow_terminates_instead_of_creating_sequence_gap() {
    let (sid, app_pk, nonce) = test_session_identity(0x68);
    let first = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    let second = proto::ConnectFrameV1 {
        seq: 2,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 2 }),
        ..first.clone()
    };
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 16,
        ws_per_ip_max_sessions: 16,
        ws_rate_per_ip_per_min: 0,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: encoded_len(&first).expect("encoded frame size"),
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: false,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    bus.relay(first).await;
    assert_eq!(
        bus.session_status(sid, "management-token")
            .await
            .expect("session remains after first buffered frame")
            .buffered_frames,
        1
    );

    bus.relay(second).await;
    assert!(
        bus.session_status(sid, "management-token").await.is_none(),
        "overflow must remove the irrecoverably gapped session"
    );
    let close = timeout(Duration::from_millis(100), app_inbox.recv())
        .await
        .expect("sender receives overflow close")
        .expect("close frame");
    assert!(matches!(
        close.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { reason, .. })
            if reason == CLOSE_REASON_BUFFER_OVERFLOW
    ));
    assert_eq!(bus.status().await.buffer_drops_total, 1);
}
#[tokio::test]
async fn p2p_session_claim_installs_shadow_session() {
    let bus = Bus::new();
    let claim = test_claim(
        0x52,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let sid = claim.sid;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    let status = bus
        .session_status(sid, "management-token")
        .await
        .expect("management token works on peer-claimed session");
    assert_eq!(status.origin, "peer_claimed");
    assert_eq!(bus.status().await.p2p_session_claims_installed_total, 1);
    let mut reservation = bus
        .reserve_token(sid, proto::Role::Wallet, "wallet-token")
        .await
        .expect("wallet can attach through peer-claimed session");
    let _wallet_inbox = reservation
        .commit_and_attach()
        .await
        .expect("wallet endpoint attaches");
}
#[tokio::test]
async fn peer_claim_absolute_expiry_is_retained_and_pruned() {
    let bus = Bus::new();
    let mut claim = test_claim(
        0x62,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    claim.expires_at_ms = crate::utils::unix_now_ms().saturating_add(60_000);
    let sid = claim.sid;
    let expires_at_ms = claim.expires_at_ms;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    let session = bus
        .inner
        .read()
        .await
        .get(&sid.to_vec())
        .cloned()
        .expect("peer shadow installed");
    assert_eq!(session.peer_claim_expires_at_ms, Some(expires_at_ms));

    let mut reservation = bus
        .reserve_token(sid, proto::Role::Wallet, "wallet-token")
        .await
        .expect("unexpired peer token reserves");
    let (_inbox, _lease) = reservation
        .commit_and_attach()
        .await
        .expect("unexpired peer endpoint attaches");
    assert_eq!(
        bus.prune_expired_sessions_at(Instant::now(), expires_at_ms)
            .await,
        1,
        "the absolute claim deadline overrides activity and attachment"
    );
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn expired_peer_claim_rejects_tokens_and_management_reads() {
    let bus = Bus::new();
    let claim = test_claim(
        0x63,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let session = Arc::new(Session::new(
        SessionOrigin::PeerClaimed,
        Some(crate::utils::unix_now_ms()),
    ));
    *session.app_token_hash.lock().await = Some(claim.token_app_hash);
    *session.management_token_hash.lock().await = Some(claim.token_management_hash);
    bus.inner.write().await.insert(claim.sid.to_vec(), session);

    assert!(
        bus.reserve_token(claim.sid, proto::Role::App, "app-token")
            .await
            .is_err()
    );
    assert!(
        !bus.authorize_management_token(claim.sid, "management-token")
            .await
    );
    assert!(
        bus.session_status(claim.sid, "management-token")
            .await
            .is_none()
    );
}
#[tokio::test]
async fn p2p_role_consumed_clears_peer_token_hash() {
    let bus = Bus::new();
    let claim = test_claim(
        0x53,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let sid = claim.sid;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::RoleConsumed(
        proto::ConnectSessionRoleConsumedV1 {
            sid,
            role: proto::Role::App,
        },
    ))
    .await;
    assert!(
        bus.reserve_token(sid, proto::Role::App, "app-token")
            .await
            .is_err(),
        "consumed role gossip prevents duplicate app attach"
    );
    assert_eq!(bus.status().await.p2p_role_consumed_total, 1);
}
#[tokio::test]
async fn p2p_session_terminated_removes_peer_session() {
    let bus = Bus::new();
    let claim = test_claim(
        0x54,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let sid = claim.sid;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionTerminated(
        proto::ConnectSessionTerminatedV1 {
            sid,
            reason: "connect_session_revoked_by_test".into(),
        },
    ))
    .await;
    assert!(bus.session_status(sid, "management-token").await.is_none());
    assert_eq!(bus.status().await.p2p_session_terminated_total, 1);
}
#[tokio::test]
async fn p2p_conflicting_session_claim_is_ignored() {
    let bus = Bus::new();
    let claim = test_claim(
        0x55,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let sid = claim.sid;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    let conflict = test_claim(
        0x55,
        "app-token",
        "wallet-token",
        "management-token",
        "other-relay-token",
    );
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(conflict))
        .await;
    let status = bus.status().await;
    assert_eq!(status.p2p_session_claim_conflicts_total, 1);
    assert!(
        bus.authorize_management_token(sid, "management-token")
            .await
    );
}
#[tokio::test]
async fn p2p_matching_claim_cannot_extend_absolute_deadline() {
    let bus = Bus::new();
    let claim = test_claim(
        0x65,
        "app-token",
        "wallet-token",
        "management-token",
        "relay-token",
    );
    let sid = claim.sid;
    let original_expiry = claim.expires_at_ms;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    let mut extension = claim;
    extension.expires_at_ms = extension.expires_at_ms.saturating_add(60_000);
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(extension))
        .await;

    let session = bus
        .inner
        .read()
        .await
        .get(&sid.to_vec())
        .cloned()
        .expect("original peer shadow remains");
    assert_eq!(session.peer_claim_expires_at_ms, Some(original_expiry));
    assert_eq!(bus.status().await.p2p_session_claim_conflicts_total, 1);
}
#[tokio::test]
async fn p2p_relay_requires_prior_session_claim() {
    let bus = Bus::new();
    let (sid, _, _) = test_session_identity(0x56);
    let relay_token = "relay-token";
    let relay_key = connect_sdk::derive_relay_mac_key(&sid, relay_token);
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 42 }),
    };
    let envelope =
        connect_sdk::seal_relay_envelope(&relay_key, frame.clone(), 1).expect("envelope");
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::RelayEnvelope(envelope.clone()))
        .await;
    assert_eq!(bus.status().await.p2p_unknown_session_drops_total, 1);
    let claim = test_claim(
        0x56,
        "app-token",
        "wallet-token",
        "management-token",
        relay_token,
    );
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::SessionClaim(claim))
        .await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    bus.handle_p2p_message(proto::ConnectP2pMessageV1::RelayEnvelope(envelope))
        .await;
    let delivered = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("wallet receives relay after claim")
        .expect("frame delivered");
    assert_eq!(delivered, frame);
}
#[tokio::test]
async fn session_creation_rate_limited() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 16,
        ws_per_ip_max_sessions: 16,
        ws_rate_per_ip_per_min: 1,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    bus.pre_session_create(ip).await.expect("first create ok");
    let err = bus.pre_session_create(ip).await.expect_err("rate limit");
    assert_eq!(err.0, axum::http::StatusCode::TOO_MANY_REQUESTS);
}
#[tokio::test]
async fn session_creation_respects_global_cap() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1,
        ws_per_ip_max_sessions: 16,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let (sid, app_pk, nonce) = test_session_identity(0xAB);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "t-app".into(),
            wallet: "t-wallet".into(),
            management: "t-management".into(),
            relay: "t-relay".into(),
        },
    )
    .await
    .expect("first registration ok");
    let err = bus
        .pre_session_create("203.0.113.1".parse().unwrap())
        .await
        .expect_err("cap enforced");
    assert_eq!(err.0, axum::http::StatusCode::TOO_MANY_REQUESTS);
}
#[tokio::test]
async fn bus_attach_forward_detach() {
    let bus = Bus::new();
    let sid = [7u8; 32];
    // Attach app and wallet endpoints
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    // Send a frame from app to wallet
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    bus.relay(frame.clone()).await;
    let got = wallet_inbox.recv().await.expect("wallet should receive");
    assert_eq!(got, frame);
    // Detach
    bus.detach(sid, proto::Role::App).await;
    bus.detach(sid, proto::Role::Wallet).await;
}
#[tokio::test]
async fn per_ip_session_cap_enforced() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 2,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    // Two sessions should be allowed
    let mut first = bus.pre_ws_handshake(ip).await.expect("first ok");
    let mut second = bus.pre_ws_handshake(ip).await.expect("second ok");
    // Third should be rejected by per-ip cap
    assert!(bus.pre_ws_handshake(ip).await.is_err());
    // Close one and attempt again
    first.release().await;
    let mut third = bus
        .pre_ws_handshake(ip)
        .await
        .expect("third ok after release");
    second.release().await;
    third.release().await;
}
#[tokio::test]
async fn dropped_ws_permit_releases_capacity() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1,
        ws_per_ip_max_sessions: 1,
        ws_rate_per_ip_per_min: 0,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "192.0.2.44".parse().expect("test IP");
    let permit = bus.pre_ws_handshake(ip).await.expect("reserve slot");
    drop(permit);
    timeout(Duration::from_millis(100), async {
        loop {
            if bus.status().await.sessions_total == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drop cleanup releases the slot");
    let mut retry = bus
        .pre_ws_handshake(ip)
        .await
        .expect("capacity is reusable after cancelled upgrade");
    retry.release().await;
}
#[tokio::test]
async fn panicking_upgrade_callback_releases_ws_permit_capacity() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1,
        ws_per_ip_max_sessions: 1,
        ws_rate_per_ip_per_min: 0,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "192.0.2.45".parse().expect("test IP");
    let permit = bus.pre_ws_handshake(ip).await.expect("reserve slot");
    let result = crate::panic_recovery::catch_async_recoverable(async move {
        let _permit = permit;
        panic!("injected upgrade callback panic");
    })
    .await;
    assert!(result.is_err());
    timeout(Duration::from_millis(100), async {
        while bus.status().await.sessions_total != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panic cleanup releases the slot");
    let mut retry = bus
        .pre_ws_handshake(ip)
        .await
        .expect("capacity is reusable after a callback panic");
    retry.release().await;
}
#[tokio::test]
async fn cancelled_ws_reservation_cannot_leak_capacity_at_lock_boundaries() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1,
        ws_per_ip_max_sessions: 1,
        ws_rate_per_ip_per_min: 1,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "198.51.100.77".parse().expect("test IP");

    let counts_guard = bus.per_ip_counts.lock().await;
    let blocked_bus = bus.clone();
    let blocked = tokio::spawn(async move { blocked_bus.pre_ws_handshake(ip).await });
    tokio::task::yield_now().await;
    blocked.abort();
    drop(counts_guard);
    assert!(blocked.await.is_err());
    assert_eq!(bus.status().await.sessions_total, 0);

    let buckets_guard = bus.handshake_buckets.lock().await;
    let blocked_bus = bus.clone();
    let blocked = tokio::spawn(async move { blocked_bus.pre_ws_handshake(ip).await });
    timeout(Duration::from_millis(100), async {
        while bus.status().await.sessions_total == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reservation reaches the rate bucket");
    blocked.abort();
    drop(buckets_guard);
    assert!(blocked.await.is_err());
    timeout(Duration::from_millis(100), async {
        while bus.status().await.sessions_total != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("permit drop releases cancellation at rate bucket");

    let mut retry = bus
        .pre_ws_handshake(ip)
        .await
        .expect("capacity remains reusable");
    retry.release().await;
}
#[tokio::test]
async fn blocked_delivery_does_not_hold_global_session_map() {
    let bus = Bus::new();
    let sid = [0x65; SID_LEN];
    let wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    let session = bus.get_or_create(&sid).await;
    for _ in 0..64 {
        assert_eq!(
            bus.deliver_local_only(&session, &frame)
                .await
                .expect("delivery does not time out before capacity"),
            LocalDelivery::Delivered
        );
    }
    let blocked_bus = bus.clone();
    let blocked_session = session.clone();
    let blocked_frame = frame.clone();
    let blocked = tokio::spawn(async move {
        blocked_bus
            .deliver_local_only(&blocked_session, &blocked_frame)
            .await
    });
    tokio::task::yield_now().await;

    timeout(
        Duration::from_millis(100),
        bus.terminate_session([0x66; SID_LEN], "unrelated test session"),
    )
    .await
    .expect("an unrelated map writer must not wait for a full role inbox");
    drop(wallet_inbox);
    assert_eq!(
        timeout(Duration::from_millis(100), blocked)
            .await
            .expect("blocked sender observes receiver close")
            .expect("delivery task completes")
            .expect("closed receiver is not a delivery timeout"),
        LocalDelivery::Offline
    );
}
#[tokio::test]
async fn terminate_session_sends_close_frames() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x42);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session tokens");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let removed = bus
        .terminate_session(sid, "connect_session_revoked_by_test")
        .await;
    assert!(removed);
    let close_to_app = timeout(Duration::from_millis(100), app_inbox.recv())
        .await
        .expect("app should receive close")
        .expect("close frame");
    assert_eq!(close_to_app.dir, proto::Dir::WalletToApp);
    assert!(matches!(
        close_to_app.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    let close_to_wallet = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("wallet should receive close")
        .expect("close frame");
    assert_eq!(close_to_wallet.dir, proto::Dir::AppToWallet);
    assert!(matches!(
        close_to_wallet.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    let second = bus
        .terminate_session(sid, "connect_session_revoked_by_test")
        .await;
    assert!(
        !second,
        "subsequent termination should report session missing"
    );
}
#[tokio::test]
async fn attached_transport_loss_terminates_session_and_notifies_survivor() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x67);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session");
    let mut reservation = bus
        .reserve_token(sid, proto::Role::App, "app-token")
        .await
        .expect("reserve app role");
    let (app_inbox, app_endpoint_lease) = reservation
        .commit_and_attach()
        .await
        .expect("attach app role");
    let mut wallet_reservation = bus
        .reserve_token(sid, proto::Role::Wallet, "wallet-token")
        .await
        .expect("reserve wallet role");
    let (mut wallet_inbox, wallet_endpoint_lease) = wallet_reservation
        .commit_and_attach()
        .await
        .expect("attach wallet role");

    drop(app_inbox);
    drop(app_endpoint_lease);
    let close = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("surviving endpoint receives terminal control")
        .expect("terminal close frame");
    assert!(matches!(
        close.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { reason, .. })
            if reason == CLOSE_REASON_TRANSPORT_CLOSED
    ));
    assert!(
        bus.session_status(sid, "management-token").await.is_none(),
        "a consumed role cannot reconnect, so transport loss must discard the SID"
    );
    drop(wallet_endpoint_lease);
}
#[tokio::test]
async fn clones_share_session_counters() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1,
        ws_per_ip_max_sessions: 5,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus_primary = Bus::from_config(&cfg, test_network_id());
    let bus_clone = bus_primary.clone();
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let mut permit = bus_primary.pre_ws_handshake(ip).await.unwrap();
    let status_from_clone = bus_clone.status().await;
    assert_eq!(status_from_clone.sessions_total, 1);
    assert!(bus_clone.pre_ws_handshake(ip).await.is_err());
    permit.release().await;
    let status_after_close = bus_primary.status().await;
    assert_eq!(status_after_close.sessions_total, 0);
    // Once closed, the clone should permit another handshake.
    let mut reopened = bus_clone.pre_ws_handshake(ip).await.expect("reopen ok");
    reopened.release().await;
}
#[tokio::test]
async fn session_expired_returns_true_when_missing() {
    let bus = Bus::new();
    let sid = [0x10u8; 32];
    let expired = bus.session_expired(&sid, Instant::now()).await;
    assert!(expired, "missing sessions should be treated as expired");
}
#[tokio::test]
async fn prune_expired_sessions_skips_active_endpoints() {
    let bus = Bus::new();
    let sid = [0x21u8; 32];
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let sess = bus.get_or_create(&sid).await;
    *sess.last_activity.lock().await = Instant::now()
        .checked_sub(Duration::from_mins(10))
        .expect("activity instant fits");
    let removed = bus.prune_expired_sessions(Instant::now()).await;
    assert_eq!(removed, 0);
    assert!(bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn prune_expired_sessions_removes_inactive_sessions() {
    let bus = Bus::new();
    let sid = [0x22u8; 32];
    let sess = bus.get_or_create(&sid).await;
    *sess.last_activity.lock().await = Instant::now()
        .checked_sub(Duration::from_mins(10))
        .expect("activity instant fits");
    let removed = bus.prune_expired_sessions(Instant::now()).await;
    assert_eq!(removed, 1);
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn expired_candidate_recheck_preserves_attached_or_replaced_session() {
    let bus = Bus::new();
    let now = Instant::now();
    let ttl = Duration::from_secs(1);

    let attached_sid = [0x23u8; SID_LEN];
    let attached_candidate = bus.get_or_create(&attached_sid).await;
    *attached_candidate.last_activity.lock().await = now
        .checked_sub(Duration::from_secs(2))
        .expect("test instant");
    let _attached = bus.attach(attached_sid, proto::Role::App).await;
    assert_eq!(
        bus.remove_expired_candidates(now, ttl, vec![(attached_sid.to_vec(), attached_candidate)],)
            .await,
        0
    );
    assert!(bus.inner.read().await.contains_key(&attached_sid.to_vec()));

    let replaced_sid = [0x24u8; SID_LEN];
    let stale_candidate = bus.get_or_create(&replaced_sid).await;
    *stale_candidate.last_activity.lock().await = now
        .checked_sub(Duration::from_secs(2))
        .expect("test instant");
    let replacement = Arc::new(Session::default());
    bus.inner
        .write()
        .await
        .insert(replaced_sid.to_vec(), replacement.clone());
    assert_eq!(
        bus.remove_expired_candidates(now, ttl, vec![(replaced_sid.to_vec(), stale_candidate)],)
            .await,
        0
    );
    let current = bus
        .inner
        .read()
        .await
        .get(&replaced_sid.to_vec())
        .cloned()
        .expect("replacement remains");
    assert!(Arc::ptr_eq(&current, &replacement));
}
#[tokio::test]
async fn prune_handshake_buckets_removes_idle_entries() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 1000,
        ws_rate_per_ip_per_min: 1,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "203.0.113.99".parse().unwrap();
    let mut permit = bus.pre_ws_handshake(ip).await.expect("handshake ok");
    let expiry = Instant::now() + bus.handshake_bucket_ttl() + Duration::from_secs(1);
    let removed = bus.prune_handshake_buckets(expiry).await;
    assert_eq!(removed, 1);
    let removed_again = bus.prune_handshake_buckets(expiry).await;
    assert_eq!(removed_again, 0);
    permit.release().await;
}
#[tokio::test]
async fn handshake_rate_zero_disables_limit() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 1000,
        ws_rate_per_ip_per_min: 0,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "203.0.113.10".parse().unwrap();
    for _ in 0..4 {
        let mut permit = bus.pre_ws_handshake(ip).await.expect("handshake ok");
        permit.release().await;
    }
}
#[tokio::test]
async fn per_ip_session_cap_zero_disables_limit() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 0,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    let mut first = bus.pre_ws_handshake(ip).await.expect("first ok");
    let mut second = bus.pre_ws_handshake(ip).await.expect("second ok");
    let mut third = bus.pre_ws_handshake(ip).await.expect("third ok");
    first.release().await;
    second.release().await;
    third.release().await;
}
#[tokio::test]
async fn handshake_rate_limited() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 1000,
        ws_rate_per_ip_per_min: 2,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    // Two immediate handshakes allowed (burst = 2)
    let mut first = bus.pre_ws_handshake(ip).await.expect("first ok");
    let mut second = bus.pre_ws_handshake(ip).await.expect("second ok");
    // Third should be rate-limited
    assert!(bus.pre_ws_handshake(ip).await.is_err());
    first.release().await;
    second.release().await;
}
#[tokio::test]
async fn heartbeat_failure_detected() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 16,
        ws_per_ip_max_sessions: 16,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(1),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_millis(100),
        ping_miss_tolerance: 2,
        ping_min_interval: Duration::from_millis(50),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: false,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let sid = [0xAAu8; 32];
    let mut _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut _wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    for nonce in 1..=2u64 {
        let frame = proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::WalletToApp,
            seq: nonce,
            kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce }),
        };
        bus.relay(frame).await;
    }
    {
        let session = {
            let map = bus.inner.read().await;
            map.get(&sid.to_vec()).cloned().expect("session exists")
        };
        let mut queue = session.heartbeat_queue(proto::Role::App).await;
        let now = Instant::now();
        for (idx, entry) in queue.pending.iter_mut().enumerate() {
            let factor = (idx as f32) + 2.0;
            entry.sent_at = now
                .checked_sub(cfg.ping_interval.mul_f32(factor))
                .expect("ping interval scaling stays within instant range");
        }
    }
    let failure = bus
        .evaluate_heartbeat(&sid, proto::Role::App, Instant::now())
        .await;
    assert!(
        matches!(failure, Some(f) if f.misses >= 2),
        "expected heartbeat misses to be detected"
    );
}
#[tokio::test]
async fn closes_session_on_non_contiguous_seq_frames() {
    let bus = Bus::new();
    let sid = [5u8; 32];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    // Send first contiguous frame.
    let f1 = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 7 }),
    };
    bus.relay(f1).await;
    let got = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive seq=1");
    assert_eq!(got.seq, 1);
    // Skip seq=2 and send seq=3; session should be terminated.
    let f3 = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 3,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 8 }),
    };
    bus.relay(f3).await;
    let close_to_wallet = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("wallet close")
        .expect("close frame");
    let close_to_app = timeout(Duration::from_millis(100), app_inbox.recv())
        .await
        .expect("app close")
        .expect("close frame");
    assert!(matches!(
        close_to_wallet.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    assert!(matches!(
        close_to_app.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    let st = bus.status().await;
    assert!(st.monotonic_drops_total >= 1);
    assert!(st.sequence_violation_closes_total >= 1);
}
#[tokio::test]
async fn duplicate_frame_does_not_close_session() {
    let bus = Bus::new();
    let sid = [0x6Au8; 32];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let f1 = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 11 }),
    };
    bus.relay(f1.clone()).await;
    let got1 = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive first frame");
    assert_eq!(got1.seq, 1);
    // Duplicate seq=1 should be dropped by dedupe, not treated as sequence violation.
    bus.relay(f1).await;
    assert!(
        timeout(Duration::from_millis(50), wallet_inbox.recv())
            .await
            .is_err(),
        "duplicate frame should not be delivered"
    );
    assert!(
        timeout(Duration::from_millis(50), app_inbox.recv())
            .await
            .is_err(),
        "duplicate frame should not close the session"
    );
    let f2 = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 2,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 12 }),
    };
    bus.relay(f2).await;
    let got2 = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive next contiguous frame");
    assert_eq!(got2.seq, 2);
    let st = bus.status().await;
    assert!(st.dedupe_drops_total >= 1);
    assert_eq!(st.sequence_violation_closes_total, 0);
}
#[tokio::test]
async fn closes_session_on_role_direction_mismatch() {
    let bus = Bus::new();
    let sid = [0x9Au8; 32];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    // App role is only allowed to send AppToWallet, so this must close the session.
    let mismatch = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    let accepted = bus.relay_from_role(proto::Role::App, mismatch).await;
    assert!(!accepted, "mismatched role/direction must be rejected");
    let close_to_wallet = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("wallet close")
        .expect("close frame");
    let close_to_app = timeout(Duration::from_millis(100), app_inbox.recv())
        .await
        .expect("app close")
        .expect("close frame");
    assert!(matches!(
        close_to_wallet.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    assert!(matches!(
        close_to_app.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    let st = bus.status().await;
    assert!(st.role_direction_mismatch_total >= 1);
}
#[test]
fn websocket_writer_treats_reject_and_close_as_terminal() {
    let frame = |kind| proto::ConnectFrameV1 {
        sid: [0x9B; SID_LEN],
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(kind),
    };
    assert!(is_terminal_peer_control(&frame(
        proto::ConnectControlV1::Reject {
            code: 1,
            code_id: "USER_DENIED".to_owned(),
            reason: "denied in test".to_owned(),
        },
    )));
    assert!(is_terminal_peer_control(&frame(
        proto::ConnectControlV1::Close {
            who: proto::Role::Wallet,
            code: CLOSE_CODE_PURGED,
            reason: CLOSE_REASON_PURGED.to_owned(),
            retryable: false,
        },
    )));
    assert!(!is_terminal_peer_control(&frame(
        proto::ConnectControlV1::Ping { nonce: 7 },
    )));
}
#[tokio::test]
async fn preapproval_reject_is_terminal_after_peer_delivery() {
    let bus = Bus::new();
    let sid = [0x9Bu8; SID_LEN];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let reject = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Reject {
            code: 1,
            code_id: "USER_DENIED".to_owned(),
            reason: "denied in test".to_owned(),
        }),
    };
    assert!(bus.relay_from_role(proto::Role::Wallet, reject).await);
    let delivered = app_inbox.recv().await.expect("app receives rejection");
    assert!(matches!(
        delivered.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Reject { .. })
    ));
    let close_to_app = app_inbox.recv().await.expect("app receives terminal close");
    let close_to_wallet = wallet_inbox
        .recv()
        .await
        .expect("wallet receives terminal close");
    for close in [close_to_app, close_to_wallet] {
        assert!(matches!(
            close.kind,
            proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
                if reason == CLOSE_REASON_REJECTED
        ));
    }
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn ciphertext_direction_substitution_terminates_session() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x6A);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register direction-substitution fixture");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Ciphertext(proto::ConnectCiphertextV1 {
            dir: proto::Dir::WalletToApp,
            aead: vec![0xA5; 32],
        }),
    })
    .await;
    for inbox in [&mut app_inbox, &mut wallet_inbox] {
        let closed = timeout(Duration::from_millis(50), inbox.recv())
            .await
            .expect("peer receives direction-substitution close")
            .expect("close frame");
        assert!(matches!(
            closed.kind,
            proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
                if reason == CLOSE_REASON_ROLE_DIRECTION_MISMATCH
        ));
    }
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
    assert!(bus.status().await.role_direction_mismatch_total >= 1);
}
#[test]
fn expected_direction_matches_role() {
    assert_eq!(
        expected_direction_for_role(proto::Role::App),
        proto::Dir::AppToWallet
    );
    assert_eq!(
        expected_direction_for_role(proto::Role::Wallet),
        proto::Dir::WalletToApp
    );
}
#[test]
fn relay_strategy_parser_accepts_exact_v1_names() {
    assert_eq!(
        RelayStrategy::from_config(
            iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        ),
        RelayStrategy::Broadcast
    );
    assert_eq!(
        RelayStrategy::from_config(
            iroha_config::parameters::actual::ConnectRelayStrategy::LocalOnly,
        ),
        RelayStrategy::LocalOnly
    );
}
#[tokio::test]
async fn broadcast_strategy_with_zero_ttl_reports_local_only_when_p2p_attached() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 10,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    {
        let mut p2p = bus.p2p.write().await;
        *p2p = Some(corelib::IrohaNetwork::closed_for_tests());
    }
    let status = bus.status().await;
    assert_eq!(status.policy.relay_strategy, "broadcast");
    assert!(status.policy.relay_p2p_attached);
    assert_eq!(status.policy.p2p_ttl_hops, 0);
    assert_eq!(status.policy.relay_effective_strategy, "local_only");
}
#[tokio::test]
async fn broadcast_strategy_records_p2p_rebroadcast_when_network_attached() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 10,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 1,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    {
        let mut p2p = bus.p2p.write().await;
        *p2p = Some(corelib::IrohaNetwork::closed_for_tests());
    }
    let (sid, app_pk, nonce) = test_session_identity(0xB1);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register session tokens");
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 42 }),
    };
    bus.relay(frame).await;
    let got = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive frame");
    assert_eq!(got.seq, 1);
    let status = bus.status().await;
    assert!(status.policy.relay_p2p_attached);
    assert_eq!(status.policy.relay_effective_strategy, "broadcast");
    assert_eq!(status.p2p_rebroadcasts_total, 1);
    assert_eq!(status.p2p_rebroadcast_skipped_total, 0);
}
#[tokio::test]
async fn broadcast_strategy_without_network_does_not_increment_rebroadcast_counter() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 10,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 1,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let sid = [0xB4u8; 32];
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 45 }),
    };
    bus.relay(frame).await;
    let got = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive frame");
    assert_eq!(got.seq, 1);
    let status = bus.status().await;
    assert_eq!(
        status.policy.relay_strategy, "broadcast",
        "policy should still report broadcast"
    );
    assert!(!status.policy.relay_p2p_attached);
    assert_eq!(
        status.policy.relay_effective_strategy, "local_only",
        "without a P2P network, broadcast falls back to local-only delivery"
    );
    assert_eq!(status.p2p_rebroadcasts_total, 0);
    assert_eq!(
        status.p2p_rebroadcast_skipped_total, 1,
        "rebroadcast should be skipped when no P2P network is attached"
    );
}
#[tokio::test]
async fn local_only_strategy_skips_p2p_rebroadcast_when_network_attached() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 10,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: true,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::LocalOnly,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    {
        let mut p2p = bus.p2p.write().await;
        *p2p = Some(corelib::IrohaNetwork::closed_for_tests());
    }
    let sid = [0xB2u8; 32];
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 43 }),
    };
    bus.relay(frame).await;
    let got = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive frame");
    assert_eq!(got.seq, 1);
    let status = bus.status().await;
    assert_eq!(
        status.policy.relay_strategy, "local_only",
        "local-only policy must remain local"
    );
    assert!(status.policy.relay_p2p_attached);
    assert_eq!(status.policy.relay_effective_strategy, "local_only");
    assert_eq!(status.p2p_rebroadcasts_total, 0);
    assert_eq!(status.p2p_rebroadcast_skipped_total, 0);
}
#[tokio::test]
async fn relay_disabled_skips_p2p_rebroadcast_when_network_attached() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 1000,
        ws_per_ip_max_sessions: 10,
        ws_rate_per_ip_per_min: 120,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_secs(30),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_secs(15),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: false,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::Broadcast,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    {
        let mut p2p = bus.p2p.write().await;
        *p2p = Some(corelib::IrohaNetwork::closed_for_tests());
    }
    let sid = [0xB3u8; 32];
    let _app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let frame = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 44 }),
    };
    bus.relay(frame).await;
    let got = wallet_inbox
        .recv()
        .await
        .expect("wallet should receive frame");
    assert_eq!(got.seq, 1);
    let status = bus.status().await;
    assert!(!status.policy.relay_enabled);
    assert!(status.policy.relay_p2p_attached);
    assert_eq!(status.policy.relay_effective_strategy, "local_only");
    assert_eq!(status.p2p_rebroadcasts_total, 0);
    assert_eq!(status.p2p_rebroadcast_skipped_total, 0);
}
#[tokio::test]
async fn drops_oversized_frames_on_p2p_ingress() {
    let bus = Bus::new();
    let sid = [0x77u8; 32];
    // Ensure session exists so relay does not drop early.
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let oversized = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Ciphertext(proto::ConnectCiphertextV1 {
            dir: proto::Dir::AppToWallet,
            aead: vec![0u8; 70_000], // exceeds 64_000 default cap once encoded
        }),
    };
    bus.relay(oversized).await;
    assert!(
        timeout(Duration::from_millis(50), wallet_inbox.recv())
            .await
            .is_err(),
        "oversized frame should be dropped before delivery"
    );
    let status = bus.status().await;
    assert_eq!(status.frames_out_total, 0, "no frames delivered");
}
#[tokio::test]
async fn execution_transport_config_relays_complete_large_frames_after_signed_approval() {
    // These opaque ciphertext bytes exercise relay admission and delivery;
    // payload decryption and transaction approval belong to the wallet SDK.
    for execution_transport in [false, true] {
        let mut cfg = enabled_test_config();
        cfg.relay_enabled = false;
        if execution_transport {
            cfg.frame_max_bytes = 4 * 1024 * 1024 + 4096;
            cfg.session_buffer_max_bytes = 8 * 1024 * 1024;
        }
        let bus = Bus::from_config(&cfg, test_network_id());
        assert_eq!(
            bus.frame_limits(),
            (cfg.frame_max_bytes, cfg.session_buffer_max_bytes)
        );
        let (sid, app_pk, nonce) = test_session_identity(0x76);
        bus.register_tokens(
            sid,
            app_pk,
            nonce,
            crate::connect::SessionTokens {
                app: "app-token".into(),
                wallet: "wallet-token".into(),
                management: "management-token".into(),
                relay: "relay-token".into(),
            },
        )
        .await
        .expect("session registration");
        let mut app_inbox = bus.attach(sid, proto::Role::App).await;
        let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
        let constraints = proto::Constraints {
            network_id: test_network_id(),
        };
        bus.relay(proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::AppToWallet,
            seq: 1,
            kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
                app_pk,
                app_meta: None,
                constraints: constraints.clone(),
                permissions: None,
            }),
        })
        .await;
        wallet_inbox.recv().await.expect("wallet receives Open");
        let key_pair =
            KeyPair::try_from_seed(vec![0x77; 32], Algorithm::Ed25519).expect("approval keypair");
        bus.relay(proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::WalletToApp,
            seq: 1,
            kind: proto::FrameKind::Control(signed_approval_control(
                &key_pair,
                &constraints,
                &sid,
                &app_pk,
                [0x78; 32],
                "relay-token",
            )),
        })
        .await;
        assert!(matches!(
            app_inbox.recv().await.expect("verified approval").kind,
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { .. })
        ));
        let large = proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::AppToWallet,
            seq: 2,
            kind: proto::FrameKind::Ciphertext(proto::ConnectCiphertextV1 {
                dir: proto::Dir::AppToWallet,
                aead: vec![0xA5; 4 * 1024 * 1024],
            }),
        };
        let wire = norito::to_bytes(&large).expect("encode complete frame");
        assert!(wire.len() < 4 * 1024 * 1024 + 4096);
        bus.relay(large).await;
        if execution_transport {
            let received = timeout(Duration::from_secs(1), wallet_inbox.recv())
                .await
                .expect("configured relay delivers complete frame")
                .expect("frame");
            assert_eq!(
                norito::to_bytes(&received).expect("encode delivered frame"),
                wire
            );
        } else {
            assert!(
                timeout(Duration::from_millis(50), wallet_inbox.recv())
                    .await
                    .is_err(),
                "ordinary configuration must retain its original frame bound"
            );
        }
        bus.relay(proto::ConnectFrameV1 {
            sid,
            dir: proto::Dir::AppToWallet,
            seq: if execution_transport { 3 } else { 2 },
            kind: proto::FrameKind::Ciphertext(proto::ConnectCiphertextV1 {
                dir: proto::Dir::AppToWallet,
                aead: vec![0xA5; cfg.frame_max_bytes],
            }),
        })
        .await;
        assert!(
            timeout(Duration::from_millis(50), wallet_inbox.recv())
                .await
                .is_err(),
            "encoded frame overhead cannot bypass the configured bound"
        );
    }
}

#[tokio::test]
async fn ciphertext_before_verified_approval_terminates_session() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x70);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register pre-approval ciphertext fixture");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Ciphertext(proto::ConnectCiphertextV1 {
            dir: proto::Dir::AppToWallet,
            aead: vec![0xA5; 32],
        }),
    })
    .await;
    for inbox in [&mut app_inbox, &mut wallet_inbox] {
        let closed = timeout(Duration::from_millis(50), inbox.recv())
            .await
            .expect("peer receives pre-approval rejection close")
            .expect("close frame");
        assert!(matches!(
            closed.kind,
            proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
                if reason == CLOSE_REASON_APPROVAL_INVALID
        ));
    }
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn drops_plaintext_control_after_approve() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(6);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register approval fixture session");
    // Attach both sides
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let constraints = proto::Constraints {
        network_id: test_network_id(),
    };
    let open = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: constraints.clone(),
            permissions: None,
        }),
    };
    bus.relay(open).await;
    wallet_inbox
        .recv()
        .await
        .expect("wallet should receive Open");
    let key_pair = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
        .expect("approval fixture keypair");
    let account_id = AccountId::new(key_pair.public_key().clone()).to_string();
    let wallet_pk = [1u8; 32];
    let relay_auth = connect_sdk::relay_auth_hash(&sid, "relay-token");
    let preimage = connect_sdk::build_approve_preimage(
        &constraints,
        &sid,
        &app_pk,
        &wallet_pk,
        &account_id,
        None,
        None,
        &relay_auth,
    );
    let sig_wallet = proto::WalletSignatureV1::new(
        Algorithm::Ed25519,
        Signature::try_new(key_pair.private_key(), &preimage).expect("approval fixture signs"),
    );
    // Send Approve from wallet to app (seq=1)
    let approve = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Approve {
            wallet_pk,
            account_id,
            permissions: None,
            proof: None,
            sig_wallet,
        }),
    };
    bus.relay(approve.clone()).await;
    // App should receive Approve
    let got = app_inbox.recv().await.expect("app should receive Approve");
    assert!(matches!(
        got.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Approve { .. })
    ));
    // Now send plaintext Close after approval; should be dropped.
    // Open consumed App->Wallet sequence 1; use the next sequence so the
    // plaintext policy, rather than replay protection, rejects this frame.
    assert_eq!(bus.status().await.plaintext_control_drops_total, 0);
    let close = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 2,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Close {
            who: proto::Role::App,
            code: 1000,
            reason: "test".into(),
            retryable: false,
        }),
    };
    bus.relay(close).await;
    // Wallet should not receive within timeout
    assert!(
        timeout(Duration::from_millis(50), wallet_inbox.recv())
            .await
            .is_err()
    );
    let st = bus.status().await;
    assert_eq!(st.plaintext_control_drops_total, 1);
    assert_eq!(st.monotonic_drops_total, 0);
    assert!(bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn wrong_network_open_is_rejected_before_wallet_delivery() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x71);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register wrong-network fixture session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let foreign_network = NetworkId::from_genesis_hash(HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(Hash::new(
        b"torii-connect-test-foreign-genesis",
    )));
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: proto::Constraints {
                network_id: foreign_network,
            },
            permissions: None,
        }),
    })
    .await;
    let wallet_closed = timeout(Duration::from_millis(50), wallet_inbox.recv())
        .await
        .expect("wallet receives rejection close")
        .expect("close frame");
    assert!(matches!(
        wallet_closed.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
            if reason == CLOSE_REASON_NETWORK_MISMATCH
    ));
    let closed = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app receives rejection close")
        .expect("close frame");
    assert!(matches!(
        closed.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
            if reason == CLOSE_REASON_NETWORK_MISMATCH
    ));
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn substituted_wallet_approval_is_rejected_before_app_delivery() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x72);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register substitution fixture session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let constraints = proto::Constraints {
        network_id: test_network_id(),
    };
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: constraints.clone(),
            permissions: None,
        }),
    })
    .await;
    wallet_inbox.recv().await.expect("wallet receives Open");
    let key_pair = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
        .expect("approval substitution fixture keypair");
    let mut approve = signed_approval_control(
        &key_pair,
        &constraints,
        &sid,
        &app_pk,
        [0x74; 32],
        "relay-token",
    );
    let proto::ConnectControlV1::Approve { wallet_pk, .. } = &mut approve else {
        unreachable!("approval helper must return Approve")
    };
    *wallet_pk = [0x75; 32];
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(approve),
    })
    .await;
    let closed = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app receives invalid-approval close")
        .expect("close frame");
    assert!(matches!(
        closed.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
            if reason == CLOSE_REASON_APPROVAL_INVALID
    ));
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn noncanonical_wallet_account_id_is_rejected_before_app_delivery() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0xA2);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register noncanonical-account fixture session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let constraints = proto::Constraints {
        network_id: test_network_id(),
    };
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: constraints.clone(),
            permissions: None,
        }),
    })
    .await;
    wallet_inbox.recv().await.expect("wallet receives Open");
    let key_pair = KeyPair::try_from_seed(vec![0xA3; 32], Algorithm::Ed25519)
        .expect("noncanonical-account fixture keypair");
    let wallet_pk = [0xA4; 32];
    let canonical = AccountId::new(key_pair.public_key().clone()).to_string();
    let account_id = format!(" {canonical}\t");
    let relay_auth = connect_sdk::relay_auth_hash(&sid, "relay-token");
    let preimage = connect_sdk::build_approve_preimage(
        &constraints,
        &sid,
        &app_pk,
        &wallet_pk,
        &account_id,
        None,
        None,
        &relay_auth,
    );
    let sig_wallet = proto::WalletSignatureV1::new(
        Algorithm::Ed25519,
        Signature::try_new(key_pair.private_key(), &preimage)
            .expect("sign noncanonical account spelling exactly"),
    );
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Approve {
            wallet_pk,
            account_id,
            permissions: None,
            proof: None,
            sig_wallet,
        }),
    })
    .await;
    let closed = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app receives noncanonical-account rejection close")
        .expect("close frame");
    assert!(matches!(
        closed.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
            if reason == CLOSE_REASON_APPROVAL_INVALID
    ));
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn repeated_valid_wallet_approval_terminates_the_session() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x76);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register replay fixture session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let constraints = proto::Constraints {
        network_id: test_network_id(),
    };
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: constraints.clone(),
            permissions: None,
        }),
    })
    .await;
    wallet_inbox.recv().await.expect("wallet receives Open");
    let key_pair = KeyPair::try_from_seed(vec![0x77; 32], Algorithm::Ed25519)
        .expect("approval replay fixture keypair");
    let approve = signed_approval_control(
        &key_pair,
        &constraints,
        &sid,
        &app_pk,
        [0x78; 32],
        "relay-token",
    );
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(approve.clone()),
    })
    .await;
    assert!(matches!(
        app_inbox
            .recv()
            .await
            .expect("app receives first approval")
            .kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Approve { .. })
    ));
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 2,
        kind: proto::FrameKind::Control(approve),
    })
    .await;
    let closed = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app receives replay close")
        .expect("close frame");
    assert!(matches!(
        closed.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { ref reason, .. })
            if reason == CLOSE_REASON_APPROVAL_REPLAY
    ));
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn concurrent_wallet_approvals_cannot_both_reach_the_app() {
    let bus = Bus::new();
    let (sid, app_pk, nonce) = test_session_identity(0x79);
    bus.register_tokens(
        sid,
        app_pk,
        nonce,
        crate::connect::SessionTokens {
            app: "app-token".into(),
            wallet: "wallet-token".into(),
            management: "management-token".into(),
            relay: "relay-token".into(),
        },
    )
    .await
    .expect("register concurrent approval fixture session");
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let constraints = proto::Constraints {
        network_id: test_network_id(),
    };
    bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk,
            app_meta: None,
            constraints: constraints.clone(),
            permissions: None,
        }),
    })
    .await;
    wallet_inbox.recv().await.expect("wallet receives Open");
    let key_pair = KeyPair::try_from_seed(vec![0x7A; 32], Algorithm::Ed25519)
        .expect("concurrent approval fixture keypair");
    let approve = signed_approval_control(
        &key_pair,
        &constraints,
        &sid,
        &app_pk,
        [0x7B; 32],
        "relay-token",
    );
    let first = bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(approve.clone()),
    });
    let second = bus.relay(proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 2,
        kind: proto::FrameKind::Control(approve),
    });
    tokio::join!(first, second);
    let mut approvals = 0;
    let mut closes = 0;
    while let Ok(Some(frame)) = timeout(Duration::from_millis(10), app_inbox.recv()).await {
        match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { .. }) => {
                approvals += 1;
            }
            proto::FrameKind::Control(proto::ConnectControlV1::Close { .. }) => closes += 1,
            _ => {}
        }
    }
    assert!(
        approvals <= 1,
        "approval gate delivered {approvals} replays"
    );
    assert!(closes >= 1, "approval race must close the session");
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
}
#[tokio::test]
async fn server_events_do_not_advance_peer_seq() {
    let bus = Bus::new();
    let sid = [0xACu8; 32];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let session = bus.get_or_create(&sid).await;
    let initial = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 1 }),
    };
    bus.relay(initial).await;
    let got = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app frame")
        .expect("frame");
    assert_eq!(got.seq, 1);
    assert_eq!(*session.last_seq_wallet_to_app.lock().await, Some(1));
    let before_activity = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .expect("activity instant fits");
    *session.last_activity.lock().await = before_activity;
    let control = proto::ConnectControlV1::ServerEvent {
        event: proto::ServerEventV1::BlockProofs {
            height: 1,
            entry_hash: "00".into(),
            proofs_json: "{}".into(),
        },
    };
    bus.send_server_event(
        &sid,
        session.clone(),
        proto::Dir::WalletToApp,
        &control,
        proto::Role::App,
    )
    .await;
    let server_frame = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("server event")
        .expect("frame");
    assert!(matches!(
        server_frame.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::ServerEvent { .. })
    ));
    assert_eq!(*session.last_seq_wallet_to_app.lock().await, Some(1));
    let after_activity = *session.last_activity.lock().await;
    assert!(
        after_activity > before_activity,
        "server events should update session activity"
    );
    let next = proto::ConnectFrameV1 {
        sid,
        dir: proto::Dir::WalletToApp,
        seq: 2,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 2 }),
    };
    bus.relay(next).await;
    let got_next = timeout(Duration::from_millis(50), app_inbox.recv())
        .await
        .expect("app frame")
        .expect("frame");
    assert_eq!(got_next.seq, 2);
}
#[tokio::test]
async fn stalled_server_event_delivery_is_bounded_and_quarantines_exact_session() {
    let cfg = iroha_config::parameters::actual::Connect {
        enabled: true,
        ws_max_sessions: 16,
        ws_per_ip_max_sessions: 16,
        ws_rate_per_ip_per_min: 0,
        session_ttl: Duration::from_mins(5),
        frame_max_bytes: 64_000,
        session_buffer_max_bytes: 262_144,
        ping_interval: Duration::from_millis(10),
        ping_miss_tolerance: 3,
        ping_min_interval: Duration::from_millis(10),
        dedupe_ttl: Duration::from_mins(2),
        dedupe_cap: 8192,
        relay_enabled: false,
        relay_strategy: iroha_config::parameters::actual::ConnectRelayStrategy::LocalOnly,
        p2p_ttl_hops: 0,
    };
    let bus = Bus::from_config(&cfg, test_network_id());
    let sid = [0xAE; SID_LEN];
    let _stalled_inbox = bus.attach(sid, proto::Role::App).await;
    let session = bus.get_or_create(&sid).await;
    let control = proto::ConnectControlV1::ServerEvent {
        event: proto::ServerEventV1::BlockProofs {
            height: 1,
            entry_hash: "00".into(),
            proofs_json: "{}".into(),
        },
    };
    for _ in 0..64 {
        bus.send_server_event(
            &sid,
            session.clone(),
            proto::Dir::WalletToApp,
            &control,
            proto::Role::App,
        )
        .await;
    }
    assert_eq!(bus.status().await.frames_out_total, 64);

    timeout(
        Duration::from_millis(100),
        bus.send_server_event(
            &sid,
            session,
            proto::Dir::WalletToApp,
            &control,
            proto::Role::App,
        ),
    )
    .await
    .expect("a full local endpoint cannot block server-event fanout");
    assert!(!bus.inner.read().await.contains_key(&sid.to_vec()));
    assert_eq!(
        bus.status().await.frames_out_total,
        64,
        "timed-out sends are not counted as delivered"
    );
}
#[tokio::test]
async fn notify_close_updates_activity_without_touching_peer_seq() {
    let bus = Bus::new();
    let sid = [0xADu8; 32];
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let session = bus.get_or_create(&sid).await;
    *session.last_seq_app_to_wallet.lock().await = Some(7);
    let before_activity = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("activity instant fits");
    *session.last_activity.lock().await = before_activity;
    bus.notify_close(session.clone(), sid, proto::Role::Wallet, "test close")
        .await;
    let close_frame = timeout(Duration::from_millis(50), wallet_inbox.recv())
        .await
        .expect("close frame")
        .expect("frame");
    assert!(matches!(
        close_frame.kind,
        proto::FrameKind::Control(proto::ConnectControlV1::Close { .. })
    ));
    assert_eq!(close_frame.seq, 1);
    assert_eq!(*session.last_seq_app_to_wallet.lock().await, Some(7));
    let after_activity = *session.last_activity.lock().await;
    assert!(
        after_activity > before_activity,
        "close frames should update session activity"
    );
}
#[tokio::test]
async fn broadcasts_block_proofs_to_app_and_wallet() {
    use iroha_data_model::{
        block::{
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
            proofs::ExecutionReceiptProof,
        },
        transaction::signed::TransactionResult,
    };
    let bus = Bus::new();
    let sid = [0xBCu8; 32];
    let mut app_inbox = bus.attach(sid, proto::Role::App).await;
    let mut wallet_inbox = bus.attach(sid, proto::Role::Wallet).await;
    let entry_hash =
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed([0x11u8; 32]));
    let entry_tree: MerkleTree<TransactionEntrypoint> = [entry_hash].into_iter().collect();
    let entry_commitment = entry_tree.commitment().expect("entry commitment");
    let entry_proof: BlockReceiptProof =
        BlockReceiptProof::new(entry_hash, entry_tree.get_proof(0).expect("entry proof"));
    let output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: TransactionResult::new(Ok(vec![])),
        completions: vec![],
    });
    let output_tree: MerkleTree<ExecutionOutputV1> = [HashOf::new(&output)].into_iter().collect();
    let output_commitment = output_tree.commitment().expect("output commitment");
    let output_proof =
        ExecutionReceiptProof::new(output, output_tree.get_proof(0).expect("output proof"));
    assert!(output_proof.verify(&output_commitment));
    let proofs = BlockProofs {
        block_height: NonZeroU64::new(1).expect("non-zero height"),
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"connect carrier block")),
        executed_block_wire_hash: Hash::new(b"connect executed block wire"),
        entry_hash,
        entry_commitment,
        entry_proof,
        output_commitment,
        output_proof,
        fastpq_transcripts: BTreeMap::new(),
    };
    let expected_entry_hex = hex::encode(entry_hash.as_ref());
    let expected_json = norito::json::to_json(&proofs).expect("serialize proofs");
    bus.broadcast_block_proof(&proofs)
        .await
        .expect("broadcast block proof");
    let to_app = timeout(Duration::from_millis(100), app_inbox.recv())
        .await
        .expect("app frame")
        .expect("frame");
    assert_eq!(to_app.dir, proto::Dir::WalletToApp);
    if let proto::FrameKind::Control(proto::ConnectControlV1::ServerEvent { event }) = to_app.kind {
        let proto::ServerEventV1::BlockProofs {
            height,
            entry_hash,
            proofs_json,
        } = event;
        assert_eq!(height, 1);
        assert_eq!(entry_hash, expected_entry_hex);
        assert_eq!(proofs_json, expected_json);
    } else {
        panic!("expected server event frame for app");
    }
    let to_wallet = timeout(Duration::from_millis(100), wallet_inbox.recv())
        .await
        .expect("wallet frame")
        .expect("frame");
    assert_eq!(to_wallet.dir, proto::Dir::AppToWallet);
    if let proto::FrameKind::Control(proto::ConnectControlV1::ServerEvent { event }) =
        to_wallet.kind
    {
        let proto::ServerEventV1::BlockProofs {
            height,
            entry_hash,
            proofs_json,
        } = event;
        assert_eq!(height, 1);
        assert_eq!(entry_hash, expected_entry_hex);
        assert_eq!(proofs_json, expected_json);
    } else {
        panic!("expected server event frame for wallet");
    }
}
#[test]
fn decode_sid_accepts_base64url() {
    let sid = [0x11u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sid);
    let decoded = decode_sid(&encoded).expect("decode base64url sid");
    assert_eq!(decoded, sid);
}
#[test]
fn decode_sid_rejects_hex() {
    let sid = [0x22u8; 32];
    let hex = hex::encode(sid);
    assert!(decode_sid(&hex).is_err(), "hex should be rejected");
}

#[tokio::test]
async fn default_handshake_budget_admits_ten_thousand_operations_with_one_bucket() {
    let mut config = enabled_test_config();
    config.ws_rate_per_ip_per_min =
        iroha_config::parameters::defaults::connect::WS_RATE_PER_IP_PER_MIN;
    config.ws_per_ip_max_sessions =
        iroha_config::parameters::defaults::connect::WS_PER_IP_MAX_SESSIONS;
    let bus = Bus::from_config(&config, test_network_id());
    assert_eq!(bus.policy.ws_rate_per_ip_per_min, 60_000_000);
    assert_eq!(Policy::default().ws_rate_per_ip_per_min, 60_000_000);
    let ip: IpAddr = "198.51.100.10".parse().expect("client IP");
    bus.pre_session_create(ip)
        .await
        .expect("first creation admission");
    let capacity = bus.handshake_buckets.lock().await.capacity();
    for request in 0..10_000 {
        bus.pre_session_create(ip).await.unwrap_or_else(|error| {
            panic!("solo session creation throttled at {request}: {error:?}")
        });
        let mut permit = bus.pre_ws_handshake(ip).await.unwrap_or_else(|error| {
            panic!("solo WebSocket handshake throttled at {request}: {error:?}")
        });
        permit.release().await;
    }
    let buckets = bus.handshake_buckets.lock().await;
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets.capacity(), capacity);
    drop(buckets);
    assert!(bus.inner.read().await.is_empty());
    assert!(bus.per_ip_counts.lock().await.is_empty());
    assert_eq!(bus.shared.sessions_total.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn default_handshake_rate_preserves_session_caps_and_explicit_small_budgets() {
    let mut config = enabled_test_config();
    config.ws_rate_per_ip_per_min =
        iroha_config::parameters::defaults::connect::WS_RATE_PER_IP_PER_MIN;
    config.ws_per_ip_max_sessions =
        iroha_config::parameters::defaults::connect::WS_PER_IP_MAX_SESSIONS;
    let bus = Bus::from_config(&config, test_network_id());
    let ip: IpAddr = "198.51.100.10".parse().expect("client IP");
    let mut permits = Vec::new();
    for _ in 0..config.ws_per_ip_max_sessions {
        permits.push(bus.pre_ws_handshake(ip).await.expect("within session cap"));
    }
    let error = bus.pre_ws_handshake(ip).await.err().expect("session cap");
    assert_eq!(error.0, axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.1, "connect: per-ip session cap");
    for permit in &mut permits {
        permit.release().await;
    }
    assert!(bus.per_ip_counts.lock().await.is_empty());

    config.ws_rate_per_ip_per_min = 2;
    let bounded = Bus::from_config(&config, test_network_id());
    bounded.pre_session_create(ip).await.expect("first token");
    bounded.pre_session_create(ip).await.expect("second token");
    let error = bounded
        .pre_session_create(ip)
        .await
        .expect_err("finite rate");
    assert_eq!(error.0, axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.1, "connect: per-ip handshake rate");
    assert_eq!(bounded.handshake_buckets.lock().await.len(), 1);
}
