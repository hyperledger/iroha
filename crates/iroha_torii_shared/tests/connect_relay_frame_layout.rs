//! Live TAIRA relay frames re-encode byte-identically with the native Connect codec.
//!
//! `fixtures/connect/relay_frames_v1.json` holds plain Open, Approve and Close frames
//! captured from the live relay. The JavaScript SDK pins the same bytes, so both sides
//! share one wire layout: `[u8; 32]` fields are element-framed (each byte one u64
//! length-prefixed element), `sig_wallet` is a u32 algorithm discriminant followed by an
//! element-framed signature, and the Open `NetworkId` stays a raw 32-byte hash.
use iroha_crypto::Algorithm;
use iroha_data_model::NetworkId;
use iroha_torii_shared::connect::{
    ConnectControlV1, ConnectFrameV1, Constraints, Dir, FrameKind, Role, WalletSignatureV1,
    decode_connect_frame_bare, encode_connect_frame_bare,
};
use norito::json::{self, Value};

fn fixture() -> Value {
    json::from_str(include_str!(
        "../../../fixtures/connect/relay_frames_v1.json"
    ))
    .expect("relay frame fixture JSON")
}

fn hex_field(value: &Value, name: &str) -> Vec<u8> {
    hex::decode(value[name].as_str().expect("hex string")).expect("hex")
}

fn array32(value: &Value, name: &str) -> [u8; 32] {
    hex_field(value, name).try_into().expect("32 bytes")
}

fn element_framed(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| {
            let mut element = 1_u64.to_le_bytes().to_vec();
            element.push(*byte);
            element
        })
        .collect()
}

fn roundtrip(bytes: &[u8]) -> ConnectFrameV1 {
    let frame = decode_connect_frame_bare(bytes).expect("live relay frame decodes");
    assert_eq!(
        encode_connect_frame_bare(&frame).expect("re-encode"),
        bytes,
        "native Connect codec must reproduce the live relay bytes"
    );
    frame
}

#[test]
fn typed_open_frame_encodes_exactly_like_the_live_relay() {
    let fixture = fixture();
    let open = &fixture["open"];
    let bytes = hex_field(open, "hex");
    let network_id: NetworkId = fixture["network_id"]
        .as_str()
        .expect("network id")
        .parse()
        .expect("network id literal");
    let frame = ConnectFrameV1 {
        sid: array32(open, "sid_hex"),
        dir: Dir::AppToWallet,
        seq: 1,
        kind: FrameKind::Control(ConnectControlV1::Open {
            app_pk: array32(open, "app_pk_hex"),
            app_meta: None,
            constraints: Constraints { network_id },
            permissions: None,
        }),
    };
    assert_eq!(encode_connect_frame_bare(&frame).expect("encode"), bytes);
    assert_eq!(roundtrip(&bytes), frame);
    // frame.sid: u64 288, then 32 one-byte elements.
    assert_eq!(&bytes[..8], &288_u64.to_le_bytes());
    assert_eq!(&bytes[8..8 + 288], element_framed(&frame.sid).as_slice());
    let mut raw_network = 32_u64.to_le_bytes().to_vec();
    raw_network.extend_from_slice(network_id.as_bytes());
    assert!(
        bytes
            .windows(raw_network.len())
            .any(|window| window == raw_network)
    );
}

#[test]
fn live_approve_and_close_frames_roundtrip_with_typed_fields() {
    let fixture = fixture();
    let approve = &fixture["approve"];
    let bytes = hex_field(approve, "hex");
    let frame = roundtrip(&bytes);
    assert_eq!(frame.sid, array32(approve, "sid_hex"));
    assert_eq!(frame.dir, Dir::WalletToApp);
    let FrameKind::Control(ConnectControlV1::Approve {
        wallet_pk,
        account_id,
        permissions,
        proof,
        sig_wallet,
    }) = frame.kind
    else {
        panic!("expected Approve");
    };
    assert_eq!(wallet_pk, array32(approve, "wallet_pk_hex"));
    assert_eq!(account_id, approve["account_id"].as_str().expect("account"));
    assert_eq!((permissions, proof), (None, None));
    let signature = hex_field(approve, "signature_hex");
    assert_eq!(
        sig_wallet,
        WalletSignatureV1::from_ed25519_bytes(&signature).expect("ed25519 signature")
    );
    assert_eq!(sig_wallet.algorithm, Algorithm::Ed25519);
    // sig_wallet field: u32 algorithm field, then u64 64 + element-framed bytes.
    let mut expected = 4_u64.to_le_bytes().to_vec();
    expected.extend_from_slice(&0_u32.to_le_bytes());
    expected.extend_from_slice(&(8 + 64 * 9_u64).to_le_bytes());
    expected.extend_from_slice(&64_u64.to_le_bytes());
    expected.extend(element_framed(&signature));
    assert!(bytes.ends_with(&expected));

    let close = &fixture["close"];
    let frame = roundtrip(&hex_field(close, "hex"));
    assert_eq!(
        frame.kind,
        FrameKind::Control(ConnectControlV1::Close {
            who: Role::App,
            code: 4002,
            reason: "connect_transport_closed".to_owned(),
            retryable: false,
        })
    );
}

#[test]
fn raw_fixed_array_layout_is_rejected() {
    let fixture = fixture();
    let open = &fixture["open"];
    let sid = hex_field(open, "sid_hex");
    let bytes = hex_field(open, "hex");
    let mut raw = 32_u64.to_le_bytes().to_vec();
    raw.extend_from_slice(&sid);
    raw.extend_from_slice(&bytes[8 + 288..]);
    assert!(decode_connect_frame_bare(&raw).is_err());
}

/// The encrypted envelope is encoded by the same native Norito layout: inside
/// `SignResultOk`, `WalletSignatureV1` is a u32 algorithm field plus an element-framed
/// signature. JavaScript peers that exchange a u8 algorithm and raw signature bytes inside
/// the AEAD envelope therefore differ from this native encoding.
#[test]
fn native_sign_result_envelope_uses_the_element_framed_signature_layout() {
    use iroha_torii_shared::connect::{
        ConnectPayloadV1, EnvelopeV1, decode_connect_envelope_framed,
        encode_connect_envelope_framed,
    };
    let signature = hex_field(&fixture()["approve"], "signature_hex");
    let envelope = EnvelopeV1 {
        seq: 2,
        payload: ConnectPayloadV1::SignResultOk {
            signature: WalletSignatureV1::from_ed25519_bytes(&signature).expect("signature"),
        },
    };
    let framed = encode_connect_envelope_framed(&envelope).expect("encode envelope");
    assert_eq!(
        decode_connect_envelope_framed(&framed).expect("decode envelope"),
        envelope
    );
    let mut native_signature = 4_u64.to_le_bytes().to_vec();
    native_signature.extend_from_slice(&0_u32.to_le_bytes());
    native_signature.extend_from_slice(&(8 + 64 * 9_u64).to_le_bytes());
    native_signature.extend_from_slice(&64_u64.to_le_bytes());
    native_signature.extend(element_framed(&signature));
    assert!(framed.ends_with(&native_signature));
}
