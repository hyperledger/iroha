//! Minimal Iroha Connect app-side example.
//!
//! - Creates a session via Torii POST /v1/connect/session
//! - Connects to WS with Authorization bearer token as app role
//! - Uses `connect_sdk` to seal a `SignRequestTx` payload and send as a frame
//! - Optional: send encrypted Close/Reject instead via --action close|reject
//!
//! Build (example only):
//!   cargo run -p `iroha_torii_shared` --example `connect_app` -- \
//!     --node <http://127.0.0.1:8080> --network-id <hash:...#....> \
//!     [--action ok|reject|close]
#[cfg(feature = "connect")]
use base64::Engine;
#[cfg(feature = "connect")]
use futures_util::{SinkExt, StreamExt as _};
#[cfg(feature = "connect")]
use iroha_crypto::kex::X25519Sha256;
#[cfg(feature = "connect")]
use iroha_crypto::{KeyGenOption, kex::KeyExchangeScheme as _};
#[cfg(feature = "connect")]
use iroha_data_model::{NetworkId, account::AccountId};
#[cfg(feature = "connect")]
use iroha_torii_shared::connect as proto;
#[cfg(feature = "connect")]
use iroha_torii_shared::connect_sdk as sdk;
#[cfg(feature = "connect")]
use norito::codec::DecodeAll as _;
#[cfg(feature = "connect")]
use norito::codec::Encode as _;
#[cfg(feature = "connect")]
use norito::derive::JsonDeserialize;
#[cfg(feature = "connect")]
use norito::json;
#[cfg(feature = "connect")]
use rand::rand_core::TryRngCore as _;
#[cfg(feature = "connect")]
use reqwest::Client;
#[cfg(feature = "connect")]
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
#[cfg(feature = "connect")]
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
#[cfg(feature = "connect")]
use tokio_tungstenite::tungstenite::{Bytes, Message};
#[cfg(feature = "connect")]
#[derive(JsonDeserialize)]
struct SessionResp {
    sid: String,
    network_id: NetworkId,
    app_pk: String,
    nonce: String,
    wallet_uri: String,
    app_uri: String,
    token_app: String,
    token_wallet: String,
    token_management: String,
    token_relay: String,
}
#[cfg(feature = "connect")]
type AppWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
#[cfg(feature = "connect")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    run_connect_app().await
}
#[cfg(feature = "connect")]
#[allow(clippy::future_not_send)]
async fn run_connect_app() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let node = required_arg(&mut args, "--node")?;
    let network_id_literal = required_arg(&mut args, "--network-id")?;
    let network_id: NetworkId = network_id_literal.parse()?;
    if network_id.to_string() != network_id_literal {
        anyhow::bail!("--network-id must use the canonical checksummed spelling");
    }
    let action = match args.next() {
        Some(flag) if flag == "--action" => args
            .next()
            .ok_or_else(|| anyhow::anyhow!("--action requires ok, reject, or close"))?,
        Some(other) => anyhow::bail!("unexpected argument `{other}`; expected --action"),
        None => "ok".into(),
    };
    if let Some(other) = args.next() {
        anyhow::bail!("unexpected trailing argument `{other}`");
    }
    let client = Client::new();
    let x = X25519Sha256::new();
    let (app_pk, app_secret_key) = x.try_keypair(KeyGenOption::Random)?;
    let app_pk_bytes: [u8; 32] = *app_pk.as_bytes();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.try_fill_bytes(&mut nonce)?;
    if nonce.iter().all(|byte| *byte == 0) {
        anyhow::bail!("operating-system RNG returned an invalid all-zero Connect nonce");
    }
    let SessionResp {
        sid,
        network_id: response_network_id,
        app_pk: response_app_pk,
        nonce: response_nonce,
        wallet_uri,
        app_uri: _app_uri,
        token_app,
        token_wallet: _token_wallet,
        token_management: _token_management,
        token_relay,
    } = request_session(&client, &node, network_id, &app_pk_bytes, &nonce).await?;
    let sid_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sid.as_bytes())
        .map_err(|_| anyhow::anyhow!("Torii returned a noncanonical Connect SID"))?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sid_bytes) != sid {
        anyhow::bail!("Torii returned a noncanonical Connect SID spelling");
    }
    let sid_arr: [u8; 32] = sid_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Torii returned a Connect SID with the wrong length"))?;
    if response_network_id != network_id
        || response_app_pk != base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(app_pk_bytes)
        || response_nonce != base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        || sid_arr != sdk::derive_session_id(&network_id, &app_pk_bytes, &nonce)
    {
        anyhow::bail!("Torii substituted the canonical Connect session identity");
    }
    println!(
        "session created for {response_network_id}; deliver this wallet URI securely: {wallet_uri}"
    );
    let ws_url = format!(
        "{}/v1/connect/ws?sid={sid}&role=app",
        node.replace("http", "ws")
    );
    let mut request = ws_url.into_client_request()?;
    request
        .headers_mut()
        .insert(AUTHORIZATION, format!("Bearer {token_app}").parse()?);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;
    println!("WS connected");
    let constraints = proto::Constraints { network_id };
    let open = proto::ConnectFrameV1 {
        sid: sid_arr,
        dir: proto::Dir::AppToWallet,
        seq: 1,
        kind: proto::FrameKind::Control(proto::ConnectControlV1::Open {
            app_pk: app_pk_bytes,
            app_meta: None,
            constraints,
            permissions: None,
        }),
    };
    ws.send(Message::Binary(Bytes::from(open.encode()))).await?;
    let approval = ws
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("wallet closed before approval"))??;
    let Message::Binary(approval) = approval else {
        anyhow::bail!("expected a binary wallet approval frame");
    };
    let mut approval_cursor = approval.as_ref();
    let approval_frame = proto::ConnectFrameV1::decode_all(&mut approval_cursor)?;
    if approval_frame.sid != sid_arr
        || approval_frame.dir != proto::Dir::WalletToApp
        || approval_frame.seq != 1
    {
        anyhow::bail!("wallet approval substituted the session, direction, or sequence");
    }
    let proto::FrameKind::Control(proto::ConnectControlV1::Approve {
        wallet_pk,
        account_id,
        permissions,
        proof,
        sig_wallet,
    }) = approval_frame.kind
    else {
        anyhow::bail!("expected the one-shot wallet Approve control");
    };
    let account = AccountId::parse_encoded(&account_id)?;
    let signatory = account
        .try_signatory()
        .ok_or_else(|| anyhow::anyhow!("Connect demo requires a single-key account"))?;
    let relay_auth = sdk::relay_auth_hash(&sid_arr, &token_relay);
    sdk::verify_wallet_approval_signature(
        signatory,
        &constraints,
        &sid_arr,
        &app_pk_bytes,
        &wallet_pk,
        &account_id,
        permissions.as_ref(),
        proof.as_ref(),
        &relay_auth,
        &sig_wallet,
    )
    .map_err(anyhow::Error::msg)?;
    let wallet_pk_bytes: [u8; 32] = wallet_pk;
    let (k_app, k_wallet) =
        sdk::x25519_derive_keys(&app_secret_key.to_bytes(), &wallet_pk_bytes, &sid_arr)
            .expect("x25519 derive keys");
    send_app_action(&mut ws, &k_app, &sid_arr, action.as_str()).await?;
    if let Some(Ok(Message::Binary(bin))) = ws.next().await {
        let mut cursor = bin.as_ref();
        if let Ok(frame) = proto::ConnectFrameV1::decode_all(&mut cursor)
            && let Ok(env) = sdk::open_envelope_current(&k_wallet, &frame)
        {
            log_app_response(&env);
        }
    }
    Ok(())
}
#[cfg(feature = "connect")]
fn required_arg(
    args: &mut impl Iterator<Item = String>,
    expected_flag: &'static str,
) -> anyhow::Result<String> {
    let supplied_flag = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing required {expected_flag} argument"))?;
    if supplied_flag != expected_flag {
        anyhow::bail!("expected {expected_flag}, found `{supplied_flag}`");
    }
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{expected_flag} requires a value"))
}
#[cfg(feature = "connect")]
async fn request_session(
    client: &Client,
    node: &str,
    network_id: NetworkId,
    app_pk: &[u8; 32],
    nonce: &[u8; 16],
) -> anyhow::Result<SessionResp> {
    let url = format!("{node}/v1/connect/session");
    let sid = sdk::derive_session_id(&network_id, app_pk, nonce);
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let request = norito::json!({
        "sid": (encode(&sid)),
        "network_id": (network_id.to_string()),
        "app_pk": (encode(app_pk)),
        "nonce": (encode(nonce)),
        "node": (node)
    });
    let body = client
        .post(url)
        .header("content-type", "application/json")
        .body(json::to_vec(&request)?)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let resp = json::from_slice(body.as_ref())?;
    Ok(resp)
}
#[cfg(feature = "connect")]
async fn send_app_action(
    ws: &mut AppWebSocket,
    k_app: &[u8; 32],
    sid: &[u8; 32],
    action: &str,
) -> anyhow::Result<()> {
    match action {
        "ok" => {
            let payload = proto::ConnectPayloadV1::SignRequestTx {
                tx_bytes: b"...".to_vec(),
            };
            let frame = sdk::seal_envelope_current(k_app, sid, proto::Dir::AppToWallet, 2, payload);
            ws.send(Message::Binary(Bytes::from(frame.encode())))
                .await?;
            println!("app: sent SignRequestTx");
        }
        "reject" => {
            let rej = sdk::encrypt_reject_current(
                k_app,
                sid,
                proto::Dir::AppToWallet,
                2,
                401,
                "UNAUTHORIZED".into(),
                "app rejected".into(),
            );
            ws.send(Message::Binary(Bytes::from(rej.encode()))).await?;
            println!("app: sent encrypted Reject");
        }
        "close" => {
            let close = sdk::encrypt_close_current(
                k_app,
                sid,
                proto::Dir::AppToWallet,
                2,
                proto::Role::App,
                1000,
                "done".into(),
                false,
            );
            ws.send(Message::Binary(Bytes::from(close.encode())))
                .await?;
            println!("app: sent encrypted Close");
        }
        other => {
            println!("app: unknown action '{other}', defaulting to ok");
            let payload = proto::ConnectPayloadV1::SignRequestTx {
                tx_bytes: b"...".to_vec(),
            };
            let frame = sdk::seal_envelope_current(k_app, sid, proto::Dir::AppToWallet, 2, payload);
            ws.send(Message::Binary(Bytes::from(frame.encode())))
                .await?;
        }
    }
    Ok(())
}
#[cfg(feature = "connect")]
fn log_app_response(env: &proto::EnvelopeV1) {
    match &env.payload {
        proto::ConnectPayloadV1::SignResultOk { signature } => {
            let sig_hex = hex::encode(signature.bytes());
            println!(
                "app: got SignResultOk algo={} sig={sig_hex}",
                signature.algorithm.as_static_str()
            );
        }
        proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Close {
            who,
            code,
            reason,
            retryable,
        }) => {
            println!(
                "app: got encrypted Close who={who:?} code={code} retryable={retryable} reason='{reason}'"
            );
        }
        proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Reject {
            code,
            code_id,
            reason,
        }) => {
            println!("app: got encrypted Reject code={code} id='{code_id}' reason='{reason}'");
        }
        other => {
            println!("app: got unexpected payload: {other:?}");
        }
    }
}
// Fallback stub when `tokio-tungstenite` `connect` feature is not enabled.
#[cfg(not(feature = "connect"))]
fn main() {
    eprintln!("connect_app example requires `tokio-tungstenite` with `connect` feature");
}
