//! Local QUIC proxy helpers for browser/SDK integrations.
//!
//! The proxy terminates QUIC connections on the operator workstation and relays metadata
//! (certificate, manifest) to browser extensions so they can connect to SoraNet-enabled Torii
//! gateways without handling certificates or guard cache keys directly.
#![allow(unexpected_cfgs)]
use crate::soranet::{GuardCacheKey, GuardCacheKeyError};
#[cfg(feature = "local-quic-proxy")]
use crate::{
    OutboundNetworkPolicy, is_public_ip, resolve_and_validate_host, validate_public_dns_name,
};
use hex::ToHex;
#[cfg(feature = "local-quic-proxy")]
use iroha_telemetry::metrics::global_or_default;
use norito::{NoritoDeserialize, NoritoSerialize, core::DecodeFromSlice};
#[cfg(feature = "local-quic-proxy")]
use norito::{decode_from_bytes, to_bytes};
#[cfg(feature = "local-quic-proxy")]
use quinn::{
    ConnectionError, Endpoint, ServerConfig, VarInt,
    crypto::rustls::QuicServerConfig as QuinnRustlsServerConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
};
use rand::{rand_core::TryCryptoRng, rngs::OsRng};
#[cfg(feature = "local-quic-proxy")]
use rcgen::generate_simple_self_signed;
#[cfg(feature = "local-quic-proxy")]
use sha2::{Digest, Sha256};
#[cfg(feature = "local-quic-proxy")]
use std::net::IpAddr;
#[cfg(all(feature = "local-quic-proxy", unix))]
use std::os::unix::fs::MetadataExt;
#[cfg(feature = "local-quic-proxy")]
use std::path::{Component, Path, PathBuf};
use std::{fmt, net::SocketAddr, str::FromStr, sync::Arc};
#[cfg(feature = "local-quic-proxy")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
#[cfg(feature = "local-quic-proxy")]
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{Mutex, Semaphore, watch},
    task::JoinHandle,
    time::{Duration, timeout},
};
#[cfg(feature = "local-quic-proxy")]
use tracing::info;
#[cfg(feature = "local-quic-proxy")]
use tracing::warn;
#[cfg(feature = "local-quic-proxy")]
use url::{Host, Url};
#[cfg(feature = "local-quic-proxy")]
const PROXY_HANDSHAKE_VERSION: u8 = 1;
#[cfg(feature = "local-quic-proxy")]
const PROXY_ALPN_LABEL: &str = "sorafs-proxy/1";
pub(crate) const PROXY_PROTOCOL_LABEL: &str = "local_quic_proxy";
#[cfg(feature = "local-quic-proxy")]
const PROXY_CAPABILITIES: &[&str] = &[
    "raw-stream",
    "car",
    "tcp-connect",
    "telemetry-v2",
    "cache-tag-v1",
];
const PROXY_SESSION_ID_LEN: usize = 16;
const PROXY_CACHE_TAG_SALT_LEN: usize = 16;
const PROXY_CLIENT_CAPABILITY_LEN: usize = 32;
#[cfg(feature = "local-quic-proxy")]
const PROXY_STREAM_VERSION: u8 = 1;
#[cfg(feature = "local-quic-proxy")]
const PROXY_MAX_FRAME_BYTES: usize = 64 * 1024;
#[cfg(feature = "local-quic-proxy")]
const PROXY_MAX_CONTROL_FIELD_BYTES: usize = 1024;
#[cfg(feature = "local-quic-proxy")]
const PROXY_MAX_CONNECTIONS: usize = 128;
#[cfg(feature = "local-quic-proxy")]
const PROXY_MAX_STREAMS_PER_CONNECTION: u32 = 256;
#[cfg(feature = "local-quic-proxy")]
const PROXY_MAX_LOCAL_FILE_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(feature = "local-quic-proxy")]
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "local-quic-proxy")]
const PROXY_CONTROL_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "local-quic-proxy")]
const PROXY_TRANSFER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(all(
    feature = "local-quic-proxy",
    any(target_os = "macos", target_os = "ios")
))]
const O_NOFOLLOW_FLAG: i32 = 0x2000_0000;
#[cfg(all(
    feature = "local-quic-proxy",
    any(target_os = "linux", target_os = "android")
))]
const O_NOFOLLOW_FLAG: i32 = rustix::fs::OFlags::NOFOLLOW.bits() as i32;
#[cfg(all(
    feature = "local-quic-proxy",
    any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(all(
    feature = "local-quic-proxy",
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!("local-quic-proxy requires a defined no-follow open flag on this Unix target");
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_OK: u8 = 0;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_UNSUPPORTED_SERVICE: u8 = 1;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_MODE_DISABLED: u8 = 2;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_BAD_REQUEST: u8 = 3;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_INTERNAL_ERROR: u8 = 4;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_UNSUPPORTED_VERSION: u8 = 5;
#[cfg(feature = "local-quic-proxy")]
const STREAM_ACK_NOT_IMPLEMENTED: u8 = 7;
#[cfg(feature = "local-quic-proxy")]
const CACHE_TAG_FIELD_SEPARATOR: u8 = 0x1f;
/// Configuration for the local QUIC proxy.
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// Proxy terminates QUIC locally and bridges traffic to SoraNet paths.
    #[norito(rename = "bridge")]
    #[default]
    Bridge,
    /// Proxy only advertises manifest metadata; clients establish SoraNet circuits.
    #[norito(rename = "metadata-only")]
    MetadataOnly,
}
impl ProxyMode {
    /// Returns the canonical label for this proxy mode.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::MetadataOnly => "metadata-only",
        }
    }
    /// Parses an exact canonical proxy mode label (`bridge` or `metadata-only`).
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "bridge" => Some(Self::Bridge),
            "metadata-only" => Some(Self::MetadataOnly),
            _ => None,
        }
    }
}
impl norito::json::FastJsonWrite for ProxyMode {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_string(self.as_str(), out);
    }
}
impl norito::json::JsonDeserialize for ProxyMode {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        ProxyMode::parse(&value)
            .ok_or_else(|| norito::json::Error::Message(format!("invalid proxy_mode `{value}`")))
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        if let Some(label) = value.as_str() {
            return ProxyMode::parse(label).ok_or_else(|| {
                norito::json::Error::Message(format!("invalid proxy_mode `{label}`"))
            });
        }
        Err(norito::json::Error::Message(
            "proxy_mode expects a string".to_owned(),
        ))
    }
}
impl norito::json::JsonObjectKey for ProxyMode {
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        visitor(self.as_str())
    }
}
impl norito::json::JsonObjectKeyOwned for ProxyMode {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        Self::parse(key).ok_or_else(|| {
            norito::json::Error::Message(
                "proxy_mode object key must be `bridge` or `metadata-only`".to_owned(),
            )
        })
    }
}
/// Hex-encoded per-start capability used to authenticate to a local proxy.
///
/// This value is secret bootstrap material. It is exported only through a
/// [`LocalQuicProxyHandle`] or an explicitly requested out-of-band manifest.
#[derive(NoritoSerialize, NoritoDeserialize)]
pub struct ProxyClientCapabilityHex([u8; PROXY_CLIENT_CAPABILITY_LEN]);
impl ProxyClientCapabilityHex {
    #[cfg(feature = "local-quic-proxy")]
    fn from_bytes(bytes: &[u8; PROXY_CLIENT_CAPABILITY_LEN]) -> Self {
        Self(*bytes)
    }
    fn parse(value: String) -> Result<Self, &'static str> {
        if value.len() != PROXY_CLIENT_CAPABILITY_LEN * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            let mut raw = value.into_bytes();
            raw.fill(0);
            std::hint::black_box(raw.as_mut_slice());
            return Err("proxy client capability must be exactly 64 lowercase hex characters");
        }
        let mut bytes = [0_u8; PROXY_CLIENT_CAPABILITY_LEN];
        let decoded = hex::decode_to_slice(&value, &mut bytes);
        let mut raw = value.into_bytes();
        raw.fill(0);
        std::hint::black_box(raw.as_mut_slice());
        if decoded.is_err() {
            bytes.fill(0);
            std::hint::black_box(&mut bytes);
            return Err("proxy client capability contains invalid hex");
        }
        if bytes.iter().all(|byte| *byte == 0) {
            bytes.fill(0);
            std::hint::black_box(&mut bytes);
            return Err("proxy client capability must not be all zero");
        }
        Ok(Self(bytes))
    }
    /// Expose the raw bytes for the first authenticated handshake.
    ///
    /// This is the narrow secret handoff. The caller must avoid diagnostics and
    /// scrub any copy after constructing its handshake frame.
    #[must_use]
    pub fn expose_bytes_for_handshake(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Clone for ProxyClientCapabilityHex {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl fmt::Debug for ProxyClientCapabilityHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyClientCapabilityHex(<redacted>)")
    }
}
impl PartialEq for ProxyClientCapabilityHex {
    fn eq(&self, other: &Self) -> bool {
        blake3::Hash::from_bytes(self.0) == other.0
    }
}
impl Eq for ProxyClientCapabilityHex {}
impl Drop for ProxyClientCapabilityHex {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}
impl norito::json::FastJsonWrite for ProxyClientCapabilityHex {
    fn write_json(&self, out: &mut String) {
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        out.push('"');
        for byte in self.0 {
            out.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
            out.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
        }
        out.push('"');
    }
}
impl norito::json::JsonDeserialize for ProxyClientCapabilityHex {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value = parser.parse_string()?;
        Self::parse(value).map_err(|message| norito::json::Error::Message(message.to_owned()))
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let value = value.as_str().ok_or_else(|| {
            norito::json::Error::Message(
                "proxy client capability must be a lowercase hex string".to_owned(),
            )
        })?;
        Self::parse(value.to_owned())
            .map_err(|message| norito::json::Error::Message(message.to_owned()))
    }
}
impl norito::json::JsonObjectKey for ProxyClientCapabilityHex {
    #[allow(unsafe_code)]
    fn visit_json_key_text<E>(
        &self,
        mut visitor: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            let encoded = [
                LOWER_HEX[usize::from(byte >> 4)],
                LOWER_HEX[usize::from(byte & 0x0f)],
            ];
            // SAFETY: both bytes are selected from the ASCII hexadecimal alphabet.
            visitor(unsafe { core::str::from_utf8_unchecked(&encoded) })?;
        }
        Ok(())
    }
}
impl norito::json::JsonObjectKeyOwned for ProxyClientCapabilityHex {
    fn from_json_key_text(key: &str) -> Result<Self, norito::json::Error> {
        norito::core::reserve_decode_allocation(key.len())
            .map_err(norito::json::Error::from_decode_resource)?;
        Self::parse(key.to_owned())
            .map_err(|message| norito::json::Error::Message(message.to_owned()))
    }
}
#[cfg(feature = "local-quic-proxy")]
struct ProxyClientCapability([u8; PROXY_CLIENT_CAPABILITY_LEN]);
#[cfg(feature = "local-quic-proxy")]
impl ProxyClientCapability {
    fn generate() -> Result<Self, ProxyError> {
        Self::generate_with_rng(&mut OsRng)
    }
    fn generate_with_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, ProxyError> {
        let mut bytes = [0_u8; PROXY_CLIENT_CAPABILITY_LEN];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|error| ProxyError::RandomBytes {
                operation: "generating proxy client capability",
                message: error.to_string(),
            })?;
        if bytes.iter().all(|byte| *byte == 0) {
            bytes.fill(0);
            std::hint::black_box(&mut bytes);
            return Err(ProxyError::RandomBytes {
                operation: "generating proxy client capability",
                message: "entropy source returned all-zero capability material".to_owned(),
            });
        }
        Ok(Self(bytes))
    }
    fn verify(&self, candidate: Option<&[u8; PROXY_CLIENT_CAPABILITY_LEN]>) -> bool {
        candidate.is_some_and(|candidate| blake3::Hash::from_bytes(self.0) == *candidate)
    }
    fn export_hex(&self) -> ProxyClientCapabilityHex {
        ProxyClientCapabilityHex::from_bytes(&self.0)
    }
}
#[cfg(feature = "local-quic-proxy")]
impl fmt::Debug for ProxyClientCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyClientCapability(<redacted>)")
    }
}
#[cfg(feature = "local-quic-proxy")]
impl Drop for ProxyClientCapability {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}
#[derive(
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct LocalQuicProxyConfig {
    /// Loopback address to bind for incoming browser/SDK traffic.
    pub bind_addr: String,
    /// Optional telemetry label used in metrics (defaults to `proxy`).
    #[norito(default)]
    pub telemetry_label: Option<String>,
    /// Optional proxy-local key used for authenticated cache tagging.
    #[norito(default)]
    pub guard_cache_key_hex: Option<String>,
    /// Whether to emit a browser manifest payload in the handshake.
    #[norito(default)]
    pub emit_browser_manifest: bool,
    /// Proxy runtime mode (bridge vs metadata-only).
    #[norito(default)]
    pub proxy_mode: ProxyMode,
    /// Prefer eager circuit creation when a session starts.
    #[norito(default)]
    pub prewarm_circuits: bool,
    /// Maximum number of client streams attached to a single circuit.
    #[norito(default)]
    pub max_streams_per_circuit: Option<u32>,
    /// Optional configured circuit TTL (seconds) surfaced to clients.
    #[norito(default)]
    pub circuit_ttl_hint_secs: Option<u32>,
    /// Optional Norito bridge configuration (filesystem spool).
    #[norito(default)]
    pub norito_bridge: Option<ProxyNoritoBridgeConfig>,
    /// Optional CAR bridge configuration (local cache archives).
    #[norito(default)]
    pub car_bridge: Option<ProxyCarBridgeConfig>,
    /// Optional Kaigi bridge configuration (filesystem spool + policy).
    #[norito(default)]
    pub kaigi_bridge: Option<ProxyKaigiBridgeConfig>,
}
impl Default for LocalQuicProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".into(),
            telemetry_label: None,
            guard_cache_key_hex: None,
            emit_browser_manifest: true,
            proxy_mode: ProxyMode::Bridge,
            prewarm_circuits: true,
            max_streams_per_circuit: Some(64),
            circuit_ttl_hint_secs: Some(300),
            norito_bridge: None,
            car_bridge: None,
            kaigi_bridge: None,
        }
    }
}
impl fmt::Debug for LocalQuicProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalQuicProxyConfig")
            .field("bind_addr", &self.bind_addr)
            .field("telemetry_label", &self.telemetry_label)
            .field(
                "guard_cache_key_hex",
                &self.guard_cache_key_hex.as_ref().map(|_| "<redacted>"),
            )
            .field("emit_browser_manifest", &self.emit_browser_manifest)
            .field("proxy_mode", &self.proxy_mode)
            .field("prewarm_circuits", &self.prewarm_circuits)
            .field("max_streams_per_circuit", &self.max_streams_per_circuit)
            .field("circuit_ttl_hint_secs", &self.circuit_ttl_hint_secs)
            .field("norito_bridge", &self.norito_bridge)
            .field("car_bridge", &self.car_bridge)
            .field("kaigi_bridge", &self.kaigi_bridge)
            .finish()
    }
}
impl Drop for LocalQuicProxyConfig {
    fn drop(&mut self) {
        if let Some(secret) = self.guard_cache_key_hex.take() {
            let mut bytes = secret.into_bytes();
            bytes.fill(0);
            std::hint::black_box(bytes.as_mut_slice());
        }
    }
}
#[derive(
    Debug,
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyNoritoBridgeConfig {
    pub spool_dir: String,
    #[norito(default = "default_norito_bridge_extension")]
    pub extension: Option<String>,
}
fn default_norito_bridge_extension() -> Option<String> {
    Some("norito".to_string())
}
#[derive(
    Debug,
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyCarBridgeConfig {
    pub cache_dir: String,
    #[norito(default = "default_car_bridge_extension")]
    pub extension: Option<String>,
    #[norito(default)]
    pub allow_zst: bool,
}
fn default_car_bridge_extension() -> Option<String> {
    Some("car".to_string())
}
#[derive(
    Debug,
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyKaigiBridgeConfig {
    pub spool_dir: String,
    #[norito(default = "default_kaigi_bridge_extension")]
    pub extension: Option<String>,
    #[norito(default)]
    pub room_policy: Option<String>,
}
fn default_kaigi_bridge_extension() -> Option<String> {
    Some("norito".to_string())
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone, Default)]
struct ProxyBridgeConfig {
    norito: Option<ProxyNoritoBridge>,
    car: Option<ProxyCarBridge>,
    kaigi: Option<ProxyKaigiBridge>,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyBridgeConfig {
    fn from_config(config: &LocalQuicProxyConfig) -> Result<Self, ProxyError> {
        let norito = config
            .norito_bridge
            .as_ref()
            .map(ProxyNoritoBridge::from_config)
            .transpose()
            .map_err(|reason| ProxyError::BridgeConfig {
                service: "norito",
                reason,
            })?;
        let car = config
            .car_bridge
            .as_ref()
            .map(ProxyCarBridge::from_config)
            .transpose()
            .map_err(|reason| ProxyError::BridgeConfig {
                service: "car",
                reason,
            })?;
        let kaigi = config
            .kaigi_bridge
            .as_ref()
            .map(ProxyKaigiBridge::from_config)
            .transpose()
            .map_err(|reason| ProxyError::BridgeConfig {
                service: "kaigi",
                reason,
            })?;
        Ok(Self { norito, car, kaigi })
    }
    fn norito(&self) -> Option<&ProxyNoritoBridge> {
        self.norito.as_ref()
    }
    fn car(&self) -> Option<&ProxyCarBridge> {
        self.car.as_ref()
    }
    fn kaigi(&self) -> Option<&ProxyKaigiBridge> {
        self.kaigi.as_ref()
    }
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone)]
struct ProxyNoritoBridge {
    spool_dir: PathBuf,
    extension: Option<String>,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyNoritoBridge {
    fn from_config(cfg: &ProxyNoritoBridgeConfig) -> Result<Self, String> {
        let spool_dir = cfg.spool_dir.trim();
        if spool_dir.is_empty() {
            return Err("spool directory must not be empty".into());
        }
        let extension = cfg
            .extension
            .as_deref()
            .map(sanitize_extension)
            .transpose()?;
        Ok(Self {
            spool_dir: canonical_bridge_root(Path::new(spool_dir))?,
            extension,
        })
    }
    fn resolve_target(&self, target: &str) -> Result<PathBuf, String> {
        let sanitized = sanitize_relative_target(target)?;
        let mut path = self.spool_dir.join(sanitized);
        if path.extension().is_none()
            && let Some(ext) = &self.extension
        {
            path.set_extension(ext);
        }
        Ok(path)
    }
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone)]
struct ProxyCarBridge {
    cache_dir: PathBuf,
    extension: Option<String>,
    allow_zst: bool,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyCarBridge {
    fn from_config(cfg: &ProxyCarBridgeConfig) -> Result<Self, String> {
        let cache_dir = cfg.cache_dir.trim();
        if cache_dir.is_empty() {
            return Err("cache directory must not be empty".into());
        }
        let extension = cfg
            .extension
            .as_deref()
            .map(sanitize_extension)
            .transpose()?;
        Ok(Self {
            cache_dir: canonical_bridge_root(Path::new(cache_dir))?,
            extension,
            allow_zst: cfg.allow_zst,
        })
    }
    fn resolve_target(&self, target: &str) -> Result<PathBuf, String> {
        let sanitized = sanitize_relative_target(target)?;
        let mut path = self.cache_dir.join(&sanitized);
        if path.extension().is_none()
            && let Some(ext) = &self.extension
        {
            path.set_extension(ext);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && ext.eq_ignore_ascii_case("zst")
            && !self.allow_zst
        {
            return Err("compressed car payloads are disabled".to_string());
        }
        Ok(path)
    }
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone)]
struct ProxyKaigiBridge {
    spool_dir: PathBuf,
    extension: Option<String>,
    room_policy: ProxyKaigiRoomPolicy,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyKaigiBridge {
    fn from_config(cfg: &ProxyKaigiBridgeConfig) -> Result<Self, String> {
        let spool_dir = cfg.spool_dir.trim();
        if spool_dir.is_empty() {
            return Err("spool directory must not be empty".into());
        }
        let extension = cfg
            .extension
            .as_deref()
            .map(sanitize_extension)
            .transpose()?;
        let room_policy = match cfg.room_policy.as_deref() {
            Some(label) => ProxyKaigiRoomPolicy::from_str(label)?,
            None => ProxyKaigiRoomPolicy::Public,
        };
        Ok(Self {
            spool_dir: canonical_bridge_root(Path::new(spool_dir))?,
            extension,
            room_policy,
        })
    }
    fn resolve_target(&self, target: &str) -> Result<PathBuf, String> {
        let path = sanitize_relative_target(target)?;
        let mut resolved = self.spool_dir.clone();
        resolved.push(&path);
        if resolved.extension().is_none()
            && let Some(ext) = &self.extension
        {
            resolved.set_extension(ext);
        }
        Ok(resolved)
    }
    fn room_policy(&self) -> ProxyKaigiRoomPolicy {
        self.room_policy
    }
}
#[cfg(feature = "local-quic-proxy")]
fn sanitize_extension(ext: &str) -> Result<String, String> {
    let trimmed = ext.trim().trim_start_matches('.');
    if trimmed.is_empty()
        || trimmed.len() > 16
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("extension must contain 1-16 ASCII alphanumeric or hyphen bytes".into());
    }
    Ok(trimmed.to_ascii_lowercase())
}
#[cfg(feature = "local-quic-proxy")]
fn canonical_bridge_root(path: &Path) -> Result<PathBuf, String> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(
            "filesystem bridge roots require Unix owner and mode custody enforcement".into(),
        );
    }
    #[cfg(unix)]
    {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("bridge root is unavailable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("bridge root must be a non-symlink directory".into());
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|error| format!("failed to canonicalize bridge root: {error}"))?;
        validate_bridge_ancestor_chain_sync(&canonical)?;
        Ok(canonical)
    }
}
#[cfg(all(feature = "local-quic-proxy", unix))]
#[allow(unsafe_code, reason = "geteuid has no safe standard-library wrapper")]
fn proxy_effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> std::os::raw::c_uint;
    }
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    unsafe { geteuid() }
}
#[cfg(all(feature = "local-quic-proxy", unix))]
fn validate_bridge_ancestor_chain_sync(root: &Path) -> Result<(), String> {
    let effective_uid = proxy_effective_uid();
    let mut ancestors = root.ancestors().map(Path::to_path_buf).collect::<Vec<_>>();
    ancestors.reverse();
    let mut metadata = Vec::with_capacity(ancestors.len());
    for ancestor in &ancestors {
        let observed = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!(
                "failed to inspect bridge-root ancestor `{}`: {error}",
                ancestor.display()
            )
        })?;
        if observed.file_type().is_symlink() || !observed.is_dir() {
            return Err(format!(
                "bridge-root ancestor `{}` must be a direct directory",
                ancestor.display()
            ));
        }
        if observed.uid() != 0 && observed.uid() != effective_uid {
            return Err(format!(
                "bridge-root ancestor `{}` must be owned by root or effective UID {effective_uid}",
                ancestor.display()
            ));
        }
        metadata.push(observed);
    }
    for (index, observed) in metadata.iter().enumerate() {
        if observed.mode() & 0o022 == 0 {
            continue;
        }
        let protected_sticky_boundary = observed.uid() == 0
            && observed.mode() & 0o1000 != 0
            && metadata
                .get(index + 1)
                .is_some_and(|child| child.uid() == effective_uid && child.mode() & 0o022 == 0);
        if !protected_sticky_boundary {
            return Err(format!(
                "bridge-root ancestor `{}` is writable by another principal",
                ancestors[index].display()
            ));
        }
    }
    let root_metadata = metadata
        .last()
        .ok_or_else(|| "bridge root has no filesystem metadata".to_owned())?;
    if root_metadata.uid() != effective_uid || root_metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "bridge root `{}` must be owned by effective UID {effective_uid} and not be group/world writable",
            root.display()
        ));
    }
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
fn sanitize_relative_target(target: &str) -> Result<PathBuf, String> {
    if target.trim().is_empty() {
        return Err("target must not be empty".to_string());
    }
    let path = Path::new(target);
    if path.is_absolute() {
        return Err("absolute paths are not permitted".to_string());
    }
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => sanitized.push(segment),
            Component::CurDir => continue,
            _ => return Err("path traversal is not permitted".to_string()),
        }
    }
    if sanitized.as_os_str().is_empty() {
        return Err("target must not be empty".to_string());
    }
    Ok(sanitized)
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyKaigiRoomPolicy {
    Public,
    Authenticated,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyKaigiRoomPolicy {
    fn from_str(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => Ok(Self::Public),
            "public" => Ok(Self::Public),
            "authenticated" => Ok(Self::Authenticated),
            other => Err(format!(
                "kaigi room policy must be `public` or `authenticated` (got `{other}`)"
            )),
        }
    }
    fn as_label(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Authenticated => "authenticated",
        }
    }
}
impl LocalQuicProxyConfig {
    fn parsed_bind_addr(&self) -> Result<SocketAddr, ProxyError> {
        let bind_addr = SocketAddr::from_str(self.bind_addr.trim()).map_err(|err| {
            ProxyError::BindAddressInvalid(self.bind_addr.clone(), err.to_string())
        })?;
        if !bind_addr.ip().is_loopback() {
            return Err(ProxyError::BindAddressNotLoopback(bind_addr));
        }
        Ok(bind_addr)
    }
    fn guard_cache_key(&self) -> Result<Option<GuardCacheKey>, ProxyError> {
        match self.guard_cache_key_hex.as_deref() {
            Some(hex) => Ok(Some(
                GuardCacheKey::from_hex(hex).map_err(ProxyError::GuardCacheKey)?,
            )),
            None => Ok(None),
        }
    }
    #[cfg(feature = "local-quic-proxy")]
    fn validated_stream_limit(&self) -> Result<u32, ProxyError> {
        let limit = self.max_streams_per_circuit.unwrap_or(64);
        if limit == 0 || limit > PROXY_MAX_STREAMS_PER_CONNECTION {
            return Err(ProxyError::StreamLimit {
                requested: limit,
                maximum: PROXY_MAX_STREAMS_PER_CONNECTION,
            });
        }
        Ok(limit)
    }
}
/// Errors surfaced while starting or running the proxy.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Bind address failed to parse.
    #[error("invalid bind address `{0}`: {1}")]
    BindAddressInvalid(String, String),
    /// Bind address must stay on the local workstation.
    #[error("local QUIC proxy bind address must be loopback (got `{0}`)")]
    BindAddressNotLoopback(SocketAddr),
    /// Guard cache key could not be parsed.
    #[error(transparent)]
    GuardCacheKey(#[from] GuardCacheKeyError),
    /// Local QUIC proxy support was not enabled at compile time.
    #[error(
        "local QUIC proxy support is not compiled in; rebuild with the `local-quic-proxy` feature"
    )]
    Unavailable,
    /// Generating the self-signed certificate failed.
    #[cfg(feature = "local-quic-proxy")]
    #[error("failed to generate proxy certificate: {0}")]
    Certificate(rcgen::Error),
    /// Preparing the proxy private key failed.
    #[error("failed to prepare proxy private key: {0}")]
    PrivateKey(String),
    /// Configuring the QUIC endpoint failed.
    #[error("failed to configure QUIC endpoint: {0}")]
    QuinnConfig(String),
    /// Starting the endpoint failed.
    #[error("failed to start QUIC endpoint: {0}")]
    QuinnEndpoint(String),
    /// Handshake payload failed to serialise/deserialise.
    #[error("handshake error: {0}")]
    Handshake(String),
    /// Application stream handling failed.
    #[error("application stream error: {0}")]
    Stream(String),
    /// A bridge root, extension, or policy was unsafe.
    #[error("invalid {service} bridge configuration: {reason}")]
    BridgeConfig {
        /// Bridge service whose configuration failed.
        service: &'static str,
        /// Stable operator-facing failure reason.
        reason: String,
    },
    /// Per-connection stream concurrency exceeded the hard resource envelope.
    #[error("max_streams_per_circuit {requested} exceeds permitted range 1..={maximum}")]
    StreamLimit {
        /// Configured stream limit.
        requested: u32,
        /// Hard maximum supported by the proxy.
        maximum: u32,
    },
    /// Random bytes required for proxy session material could not be generated.
    #[error("proxy random bytes failed while {operation}: {message}")]
    RandomBytes {
        /// Operation that required entropy.
        operation: &'static str,
        /// Source RNG failure message.
        message: String,
    },
}
/// Runtime handle for a spawned local QUIC proxy.
#[derive(Clone)]
pub struct LocalQuicProxyHandle {
    inner: Arc<LocalQuicProxyInner>,
}
impl LocalQuicProxyHandle {
    /// Address that the proxy listens on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }
    /// PEM-encoded certificate accepted by the proxy.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.inner.certificate_pem
    }
    /// Optional manifest payload for browser extensions.
    pub fn browser_manifest(&self) -> Result<Option<BrowserExtensionManifest>, ProxyError> {
        match self.inner.browser_manifest.as_ref() {
            Some(template) => {
                let manifest = template.preview()?;
                #[cfg(feature = "local-quic-proxy")]
                let manifest = {
                    let mut manifest = manifest;
                    manifest.client_capability_hex =
                        Some(self.inner.client_capability.export_hex());
                    manifest
                };
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }
    /// Export the per-start client capability for an authenticated first handshake.
    ///
    /// Treat the returned value as secret bootstrap material and pass it only
    /// to the local client that owns this handle.
    #[cfg(feature = "local-quic-proxy")]
    #[must_use]
    pub fn export_client_capability(&self) -> ProxyClientCapabilityHex {
        self.inner.client_capability.export_hex()
    }
    /// Runtime mode advertised by the proxy.
    #[must_use]
    pub fn mode(&self) -> ProxyMode {
        self.inner.mode.clone()
    }
    /// Gracefully shuts the proxy down.
    #[cfg(feature = "local-quic-proxy")]
    pub async fn shutdown(&self) {
        if self.inner.shutdown_tx.send(true).is_ok()
            && let Some(handle) = self.inner.join_handle.lock().await.take()
        {
            let _ = handle.await;
        }
    }
    /// Gracefully shuts the proxy down.
    #[cfg(not(feature = "local-quic-proxy"))]
    pub async fn shutdown(&self) {}
}
struct LocalQuicProxyInner {
    /// Keeps the QUIC listener endpoint open for the proxy's lifetime.
    #[cfg(feature = "local-quic-proxy")]
    _endpoint: Endpoint,
    local_addr: SocketAddr,
    certificate_pem: String,
    browser_manifest: Option<BrowserManifestTemplate>,
    mode: ProxyMode,
    #[cfg(feature = "local-quic-proxy")]
    client_capability: Arc<ProxyClientCapability>,
    #[cfg(feature = "local-quic-proxy")]
    shutdown_tx: watch::Sender<bool>,
    #[cfg(feature = "local-quic-proxy")]
    join_handle: Mutex<Option<JoinHandle<()>>>,
}
#[derive(Clone)]
struct BrowserManifestTemplate {
    base: BrowserExtensionManifest,
}
impl BrowserManifestTemplate {
    #[cfg(feature = "local-quic-proxy")]
    fn new(base: BrowserExtensionManifest) -> Self {
        Self { base }
    }
    fn instantiate(&self) -> Result<BrowserExtensionManifest, ProxyError> {
        let mut manifest = self.base.clone();
        manifest.session_id = Some(generate_session_id()?);
        if let Some(cache) = manifest.cache_tagging.as_mut() {
            cache.salt_hex = Some(generate_cache_salt()?);
        }
        Ok(manifest)
    }
    fn preview(&self) -> Result<BrowserExtensionManifest, ProxyError> {
        self.instantiate()
    }
}
#[cfg(feature = "local-quic-proxy")]
fn build_manifest_template(
    config: &LocalQuicProxyConfig,
    local_addr: SocketAddr,
    certificate_pem: &str,
    certificate_der: &[u8],
) -> Option<BrowserManifestTemplate> {
    if !config.emit_browser_manifest {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(certificate_der);
    let fingerprint_hex = hex::encode(hasher.finalize());
    let mut capabilities = Vec::with_capacity(PROXY_CAPABILITIES.len());
    capabilities.extend(PROXY_CAPABILITIES.iter().map(|cap| cap.to_string()));
    let circuit = ProxyCircuitHints {
        ttl_sec: config.circuit_ttl_hint_secs,
        max_streams_per_circuit: config.max_streams_per_circuit,
        prewarm: config.prewarm_circuits,
        reuse_policy: Some("young-first".into()),
    };
    let guard_selection = ProxyGuardSelection {
        guard_set_id: None,
        stickiness: Some("per-origin".into()),
        min_guards: Some(1),
        max_guards: Some(3),
    };
    let cache_tagging = ProxyCacheTagging::default();
    let telemetry_labels = ProxyTelemetryLabels {
        telemetry_label: config.telemetry_label.clone(),
        authority: Some(local_addr.to_string()),
    };
    let telemetry = ProxyTelemetryHints {
        labels: Some(telemetry_labels),
        sampling: Some(ProxyTelemetrySampling {
            traces: Some(0.05),
            metrics: Some(1.0),
        }),
        privacy: Some(ProxyTelemetryPrivacy::new_default()),
    };
    let mut route_hints = Vec::new();
    if let Some(kaigi_bridge) = config.kaigi_bridge.as_ref() {
        let policy_label = kaigi_bridge
            .room_policy
            .as_deref()
            .unwrap_or("public")
            .to_string();
        route_hints.push(ProxyRouteHint {
            policy_id: Some("kaigi-room-policy".into()),
            exit_country: None,
            categories: vec!["kaigi".into(), format!("kaigi.room_policy.{policy_label}")],
        });
    }
    let manifest = BrowserExtensionManifest {
        version: 2,
        authority: local_addr.to_string(),
        certificate_pem: certificate_pem.to_string(),
        cert_fingerprint_hex: Some(fingerprint_hex),
        alpn: Some(PROXY_ALPN_LABEL.to_string()),
        capabilities,
        proxy_mode: config.proxy_mode.clone(),
        session_id: None,
        telemetry_label: config.telemetry_label.clone(),
        client_capability_hex: None,
        circuit: Some(circuit),
        guard_selection: Some(guard_selection),
        route_hints,
        cache_tagging: Some(cache_tagging),
        telemetry_v2: Some(telemetry),
    };
    Some(BrowserManifestTemplate::new(manifest))
}
/// Manifest returned to browser extensions establishing trust with the proxy.
#[derive(
    Debug,
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
)]
pub struct BrowserExtensionManifest {
    /// Manifest schema version.
    pub version: u8,
    /// Authority (host:port) exposed by the proxy.
    pub authority: String,
    /// PEM-encoded certificate clients should trust.
    pub certificate_pem: String,
    /// Optional certificate fingerprint (SHA-256 hex).
    #[norito(default)]
    #[norito(rename = "cert_sha256")]
    pub cert_fingerprint_hex: Option<String>,
    /// ALPN label advertised by the proxy.
    #[norito(default)]
    pub alpn: Option<String>,
    /// Proxy capabilities supported within this release.
    #[norito(default)]
    pub capabilities: Vec<String>,
    /// Operational mode advertised to clients.
    #[norito(default)]
    pub proxy_mode: ProxyMode,
    /// Random session identifier unique per handshake.
    #[norito(default)]
    pub session_id: Option<String>,
    /// Optional telemetry label describing the proxy.
    #[norito(default)]
    pub telemetry_label: Option<String>,
    /// Per-start client capability, present only in out-of-band bootstrap manifests.
    ///
    /// The in-band handshake acknowledgement always omits this field.
    #[norito(default)]
    pub client_capability_hex: Option<ProxyClientCapabilityHex>,
    /// Circuit tuning hints surfaced to clients.
    #[norito(default)]
    pub circuit: Option<ProxyCircuitHints>,
    /// Guard stickiness parameters.
    #[norito(default)]
    pub guard_selection: Option<ProxyGuardSelection>,
    /// Preferred route hints.
    #[norito(default)]
    pub route_hints: Vec<ProxyRouteHint>,
    /// Cache tagging parameters applied by the proxy.
    #[norito(default)]
    pub cache_tagging: Option<ProxyCacheTagging>,
    /// Telemetry configuration hints for clients.
    #[norito(default)]
    pub telemetry_v2: Option<ProxyTelemetryHints>,
}
/// Per-session circuit hints surfaced to clients.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyCircuitHints {
    /// Suggested TTL for circuits in seconds.
    #[norito(default)]
    pub ttl_sec: Option<u32>,
    /// Maximum number of simultaneous streams per circuit.
    #[norito(default)]
    pub max_streams_per_circuit: Option<u32>,
    /// Whether the proxy prewarms circuits.
    #[norito(default)]
    pub prewarm: bool,
    /// Optional reuse policy label (e.g. `young-first`).
    #[norito(default)]
    pub reuse_policy: Option<String>,
}
/// Guard selection preferences exposed to callers.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyGuardSelection {
    /// Identifier describing the guard set in use.
    #[norito(default)]
    pub guard_set_id: Option<String>,
    /// Stickiness policy label (e.g. `per-origin`).
    #[norito(default)]
    pub stickiness: Option<String>,
    /// Minimum number of guards used when bridging sessions.
    #[norito(default)]
    pub min_guards: Option<u32>,
    /// Maximum number of guards used when bridging sessions.
    #[norito(default)]
    pub max_guards: Option<u32>,
}
/// Lightweight route hints surfaced to browser clients.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyRouteHint {
    /// Optional policy identifier.
    #[norito(default)]
    pub policy_id: Option<String>,
    /// Preferred exit country (ISO code).
    #[norito(default)]
    pub exit_country: Option<String>,
    /// Free-form categories describing the route.
    #[norito(default)]
    pub categories: Vec<String>,
}
/// Cache tagging parameters advertised by the proxy.
#[derive(
    Debug,
    Clone,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
    Eq,
)]
pub struct ProxyCacheTagging {
    /// Version of the tagging format.
    pub version: u8,
    /// Algorithm label used when deriving cache tags.
    pub alg: String,
    /// Header name carrying cache tags for HTTP/TCP streams.
    pub tag_header: String,
    /// Salt used when deriving HMAC tags for this session.
    #[norito(default)]
    pub salt_hex: Option<String>,
    /// Services where cache tags are attached.
    #[norito(default)]
    pub attach_on: Vec<String>,
}
impl Default for ProxyCacheTagging {
    fn default() -> Self {
        Self {
            version: 1,
            alg: "HMAC-SHA256-128".into(),
            tag_header: "x-sorafs-cache-tag".into(),
            salt_hex: None,
            attach_on: vec!["car".into(), "norito".into(), "kaigi".into(), "tcp".into()],
        }
    }
}
/// Telemetry hints for browser integrations.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
)]
pub struct ProxyTelemetryHints {
    /// Static labels clients may include when exporting telemetry.
    #[norito(default)]
    pub labels: Option<ProxyTelemetryLabels>,
    /// Sampling configuration for traces and metrics.
    #[norito(default)]
    pub sampling: Option<ProxyTelemetrySampling>,
    /// Privacy-preserving truncation hints.
    #[norito(default)]
    pub privacy: Option<ProxyTelemetryPrivacy>,
}
/// Static telemetry labels.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
)]
pub struct ProxyTelemetryLabels {
    #[norito(default)]
    pub telemetry_label: Option<String>,
    #[norito(default)]
    pub authority: Option<String>,
}
/// Telemetry sampling hints.
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
)]
pub struct ProxyTelemetrySampling {
    #[norito(default)]
    pub traces: Option<f64>,
    #[norito(default)]
    pub metrics: Option<f64>,
}
/// Telemetry privacy hints (low-cardinality fingerprints, etc.).
#[derive(
    Debug,
    Clone,
    Default,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    PartialEq,
)]
pub struct ProxyTelemetryPrivacy {
    #[norito(default)]
    pub fingerprint_prefix_bits: Option<u8>,
    #[norito(default)]
    pub redact_authority: bool,
}
impl ProxyTelemetryPrivacy {
    #[cfg(feature = "local-quic-proxy")]
    fn new_default() -> Self {
        Self {
            fingerprint_prefix_bits: Some(20),
            redact_authority: true,
        }
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyTelemetryHints {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyTelemetryLabels {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyTelemetrySampling {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyTelemetryPrivacy {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for BrowserExtensionManifest {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyCircuitHints {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyGuardSelection {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyRouteHint {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
impl<'a> DecodeFromSlice<'a> for ProxyCacheTagging {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical(bytes)
    }
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone)]
struct ProxySession {
    telemetry_label: String,
    mode: ProxyMode,
    guard_cache_key: Option<Arc<GuardCacheKey>>,
    session_id: Option<String>,
    cache_tags: Option<CacheTagContext>,
    bridge: Arc<ProxyBridgeConfig>,
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Clone)]
struct CacheTagContext {
    alg: String,
    attach_on: Vec<String>,
    salt: Vec<u8>,
}
#[cfg(feature = "local-quic-proxy")]
impl CacheTagContext {
    fn from_cache_tagging(tagging: &ProxyCacheTagging) -> Option<Self> {
        let salt_hex = tagging.salt_hex.as_deref()?;
        let salt = match hex::decode(salt_hex) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    target: "soranet.proxy",
                    ?err,
                    "failed to decode cache tag salt"
                );
                return None;
            }
        };
        let attach_on = tagging
            .attach_on
            .iter()
            .map(|label| label.trim().to_ascii_lowercase())
            .collect();
        Some(Self {
            alg: tagging.alg.clone(),
            attach_on,
            salt,
        })
    }
    fn from_manifest(manifest: &BrowserExtensionManifest) -> Option<Self> {
        let tagging = manifest.cache_tagging.as_ref()?;
        Self::from_cache_tagging(tagging)
    }
    fn supports(&self, service: &str) -> bool {
        if self.attach_on.is_empty() {
            return false;
        }
        self.attach_on.iter().any(|label| label == service)
    }
}
#[cfg(feature = "local-quic-proxy")]
impl ProxySession {
    fn cache_tag_for(
        &self,
        service: ProxyStreamService,
        open_frame: &ProxyStreamOpenV1,
    ) -> Option<String> {
        let context = self.cache_tags.as_ref()?;
        if !context.alg.trim().eq_ignore_ascii_case("HMAC-SHA256-128") {
            return None;
        }
        let guard_key = self.guard_cache_key.as_ref()?;
        let service_label = service.as_label();
        if !context.supports(service_label) {
            return None;
        }
        let mut message = Vec::with_capacity(context.salt.len() + 64);
        message.extend_from_slice(&context.salt);
        append_tag_component(&mut message, Some(service_label));
        append_tag_component(&mut message, open_frame.authority.as_deref());
        append_tag_component(&mut message, open_frame.target.as_deref());
        append_tag_component(&mut message, open_frame.client_id.as_deref());
        append_tag_component(&mut message, open_frame.route_policy_id.as_deref());
        append_tag_component(&mut message, open_frame.exit_country.as_deref());
        append_tag_component(&mut message, self.session_id.as_deref());
        let mac = hmac_sha256_128(guard_key.expose_bytes_for_mac(), &message);
        Some(hex::encode_upper(mac))
    }
}
#[cfg(feature = "local-quic-proxy")]
struct QuicBidirectionalStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}
#[cfg(feature = "local-quic-proxy")]
impl QuicBidirectionalStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
    async fn shutdown(&mut self) {
        let _ = self.send.finish();
        let _ = self.recv.stop(VarInt::from_u32(0));
    }
}
#[cfg(feature = "local-quic-proxy")]
impl AsyncRead for QuicBidirectionalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
#[cfg(feature = "local-quic-proxy")]
impl AsyncWrite for QuicBidirectionalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(len)) => Poll::Ready(Ok(len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
fn append_tag_component(buffer: &mut Vec<u8>, value: Option<&str>) {
    buffer.push(CACHE_TAG_FIELD_SEPARATOR);
    if let Some(raw) = value {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            buffer.extend_from_slice(trimmed.as_bytes());
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
fn hmac_sha256_128(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key_pad = [0u8; BLOCK];
    let mut i_key_pad = [0u8; BLOCK];
    for i in 0..BLOCK {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(message);
    let inner_sum = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_sum);
    let mac = outer.finalize();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&mac[..16]);
    truncated
}
/// Spawn a QUIC proxy bound to the configured address.
#[cfg(feature = "local-quic-proxy")]
pub fn spawn_local_quic_proxy(
    config: LocalQuicProxyConfig,
) -> Result<LocalQuicProxyHandle, ProxyError> {
    let bind_addr = config.parsed_bind_addr()?;
    let guard_cache_key = config.guard_cache_key()?.map(Arc::new);
    let client_capability = Arc::new(ProxyClientCapability::generate()?);
    let stream_limit = config.validated_stream_limit()?;
    let bridge_config = Arc::new(ProxyBridgeConfig::from_config(&config)?);
    let sans = vec!["localhost".to_string(), bind_addr.ip().to_string()];
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(sans).map_err(ProxyError::Certificate)?;
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let private_key = PrivateKeyDer::try_from(signing_key.serialize_der())
        .map_err(|err| ProxyError::PrivateKey(err.to_string()))?;
    let mut tls_config = quinn::rustls::ServerConfig::builder_with_protocol_versions(&[
        &quinn::rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], private_key)
    .map_err(|err| ProxyError::QuinnConfig(err.to_string()))?;
    // Application streams are not replay-safe, so 0-RTT is disabled unconditionally.
    tls_config.max_early_data_size = 0;
    tls_config.alpn_protocols = vec![PROXY_ALPN_LABEL.as_bytes().to_vec()];
    let crypto = QuinnRustlsServerConfig::try_from(Arc::new(tls_config))
        .map_err(|err| ProxyError::QuinnConfig(err.to_string()))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(stream_limit));
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(0));
    server_config.transport = Arc::new(transport_config);
    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|err| ProxyError::QuinnEndpoint(err.to_string()))?;
    let local_addr = endpoint
        .local_addr()
        .map_err(|err| ProxyError::QuinnEndpoint(err.to_string()))?;
    let certificate_pem = cert.pem().to_string();
    let browser_manifest =
        build_manifest_template(&config, local_addr, &certificate_pem, cert_der.as_ref());
    let telemetry_label = config
        .telemetry_label
        .clone()
        .unwrap_or_else(|| "proxy".to_string());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let join_handle = tokio::spawn({
        let guard_cache_key = guard_cache_key.clone();
        let client_capability = client_capability.clone();
        let bridge_config = bridge_config.clone();
        run_accept_loop(
            endpoint.clone(),
            AcceptLoopContext {
                telemetry_label: telemetry_label.clone(),
                manifest_template: browser_manifest.clone(),
                mode: config.proxy_mode.clone(),
                guard_cache_key,
                client_capability,
                bridge_config,
                connection_permits: Arc::new(Semaphore::new(PROXY_MAX_CONNECTIONS)),
            },
            shutdown_rx,
        )
    });
    Ok(LocalQuicProxyHandle {
        inner: Arc::new(LocalQuicProxyInner {
            _endpoint: endpoint,
            local_addr,
            certificate_pem,
            browser_manifest,
            mode: config.proxy_mode.clone(),
            client_capability,
            shutdown_tx,
            join_handle: Mutex::new(Some(join_handle)),
        }),
    })
}
/// Report that local QUIC proxy runtime support was not compiled in.
#[cfg(not(feature = "local-quic-proxy"))]
pub fn spawn_local_quic_proxy(
    config: LocalQuicProxyConfig,
) -> Result<LocalQuicProxyHandle, ProxyError> {
    let _ = config.parsed_bind_addr()?;
    let _ = config.guard_cache_key()?;
    Err(ProxyError::Unavailable)
}
#[cfg(feature = "local-quic-proxy")]
struct AcceptLoopContext {
    telemetry_label: String,
    manifest_template: Option<BrowserManifestTemplate>,
    mode: ProxyMode,
    guard_cache_key: Option<Arc<GuardCacheKey>>,
    client_capability: Arc<ProxyClientCapability>,
    bridge_config: Arc<ProxyBridgeConfig>,
    connection_permits: Arc<Semaphore>,
}
#[cfg(feature = "local-quic-proxy")]
async fn run_accept_loop(
    endpoint: Endpoint,
    context: AcceptLoopContext,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let AcceptLoopContext {
        telemetry_label,
        manifest_template,
        mode,
        guard_cache_key,
        client_capability,
        bridge_config,
        connection_permits,
    } = context;
    loop {
        let connecting_opt = tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_ok() {
                    info!(target: "soranet.proxy", label = telemetry_label, "shutting down local QUIC proxy");
                }
                break;
            }
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = connecting_opt else {
            break;
        };
        let permit = match Arc::clone(&connection_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                incoming.refuse();
                record_transport_event(&telemetry_label, "connection_reject", "capacity");
                continue;
            }
        };
        match incoming.accept() {
            Ok(connecting) => {
                let manifest_template = manifest_template.clone();
                let mode = mode.clone();
                let guard_cache_key = guard_cache_key.clone();
                let client_capability = client_capability.clone();
                let label = telemetry_label.clone();
                let bridge_config = bridge_config.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match connecting.await {
                        Ok(new_conn) => {
                            record_transport_event(&label, "connection_open", "accepted");
                            if let Err(err) = handle_connection(
                                new_conn,
                                manifest_template,
                                mode,
                                guard_cache_key,
                                client_capability,
                                bridge_config,
                                &label,
                            )
                            .await
                            {
                                warn!(target: "soranet.proxy", ?err, label = label, "proxy handshake failed");
                                record_transport_event(&label, "handshake_error", &err.to_string());
                            }
                        }
                        Err(err) => {
                            warn!(target: "soranet.proxy", ?err, label = label, "incoming connection failed");
                            record_transport_event(&label, "connection_error", &err.to_string());
                        }
                    }
                });
            }
            Err(err) => {
                warn!(target: "soranet.proxy", ?err, label = telemetry_label, "incoming connection failed");
                record_transport_event(&telemetry_label, "connection_error", &err.to_string());
            }
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_connection(
    connection: quinn::Connection,
    manifest_template: Option<BrowserManifestTemplate>,
    mode: ProxyMode,
    guard_cache_key: Option<Arc<GuardCacheKey>>,
    client_capability: Arc<ProxyClientCapability>,
    bridge_config: Arc<ProxyBridgeConfig>,
    telemetry_label: &str,
) -> Result<(), ProxyError> {
    let (mut send_stream, mut recv_stream) =
        timeout(PROXY_CONTROL_FRAME_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| ProxyError::Handshake("handshake stream timed out".into()))?
            .map_err(|err| ProxyError::Handshake(err.to_string()))?;
    let mut handshake_bytes = timeout(PROXY_CONTROL_FRAME_TIMEOUT, read_frame(&mut recv_stream))
        .await
        .map_err(|_| ProxyError::Handshake("handshake frame timed out".into()))?
        .map_err(|err| ProxyError::Handshake(err.to_string()))?;
    let decoded_handshake = decode_from_bytes(&handshake_bytes);
    handshake_bytes.fill(0);
    std::hint::black_box(handshake_bytes.as_mut_slice());
    let mut handshake: ProxyHandshakeV1 =
        decoded_handshake.map_err(|err| ProxyError::Handshake(err.to_string()))?;
    if handshake.version != PROXY_HANDSHAKE_VERSION {
        let ack = ProxyHandshakeAckV1 {
            version: PROXY_HANDSHAKE_VERSION,
            accepted: false,
            message: Some("unsupported version".to_string()),
            manifest: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(|err| ProxyError::Handshake(err.to_string()))?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        record_transport_event(telemetry_label, "handshake_reject", "unsupported_version");
        return Ok(());
    }
    let authenticated = client_capability.verify(handshake.client_capability.as_ref());
    if let Some(mut candidate) = handshake.client_capability.take() {
        candidate.fill(0);
        std::hint::black_box(&mut candidate);
    }
    if !authenticated {
        let ack = ProxyHandshakeAckV1 {
            version: PROXY_HANDSHAKE_VERSION,
            accepted: false,
            message: Some("authentication failed".to_string()),
            manifest: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(|err| ProxyError::Handshake(err.to_string()))?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        record_transport_event(telemetry_label, "handshake_reject", "authentication");
        return Ok(());
    }
    if [handshake.client.as_deref(), handshake.user_agent.as_deref()]
        .into_iter()
        .flatten()
        .any(|value| !valid_control_field(value))
    {
        let ack = ProxyHandshakeAckV1 {
            version: PROXY_HANDSHAKE_VERSION,
            accepted: false,
            message: Some("invalid handshake field".to_string()),
            manifest: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(ProxyError::Handshake)?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        record_transport_event(telemetry_label, "handshake_reject", "invalid_field");
        return Ok(());
    }
    record_transport_event(telemetry_label, "handshake_accept", "ok");
    let manifest = match manifest_template.as_ref() {
        Some(template) => Some(template.instantiate()?),
        None => None,
    };
    let mut session_id = manifest.as_ref().and_then(|item| item.session_id.clone());
    let mut cache_tags = manifest.as_ref().and_then(CacheTagContext::from_manifest);
    if cache_tags.is_none() && guard_cache_key.is_some() {
        if session_id.is_none() {
            session_id = Some(generate_session_id()?);
        }
        let fallback_tagging = ProxyCacheTagging {
            salt_hex: Some(generate_cache_salt()?),
            ..ProxyCacheTagging::default()
        };
        cache_tags = CacheTagContext::from_cache_tagging(&fallback_tagging);
    }
    let session = Arc::new(ProxySession {
        telemetry_label: telemetry_label.to_string(),
        mode: mode.clone(),
        guard_cache_key,
        session_id,
        cache_tags,
        bridge: bridge_config,
    });
    let ack = ProxyHandshakeAckV1 {
        version: PROXY_HANDSHAKE_VERSION,
        accepted: true,
        message: None,
        manifest,
    };
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(ProxyError::Handshake)?;
    if let Err(err) = send_stream.finish() {
        record_transport_event(telemetry_label, "handshake_close_error", &err.to_string());
        return Err(ProxyError::Handshake(err.to_string()));
    }
    if matches!(session.mode, ProxyMode::MetadataOnly) {
        record_transport_event(telemetry_label, "bridge_disabled", "metadata_only");
        return Ok(());
    }
    loop {
        match connection.accept_bi().await {
            Ok((stream_send, stream_recv)) => {
                record_transport_event(telemetry_label, "stream_open", "accepted");
                let session = session.clone();
                let label = session.telemetry_label.clone();
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_application_stream(stream_send, stream_recv, session.clone()).await
                    {
                        warn!(target: "soranet.proxy", ?err, label = label, "application stream failed");
                        record_transport_event(&label, "stream_error", &err.to_string());
                    }
                });
            }
            Err(ConnectionError::LocallyClosed) => break,
            Err(ConnectionError::ApplicationClosed { .. }) => break,
            Err(err) => {
                warn!(target: "soranet.proxy", ?err, label = telemetry_label, "stream accept loop terminated");
                record_transport_event(telemetry_label, "stream_accept_error", &err.to_string());
                break;
            }
        }
    }
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, Error)]
enum FrameError {
    #[error("frame length {len} exceeds max {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error("frame read error: {0}")]
    Read(#[from] quinn::ReadExactError),
}
#[cfg(feature = "local-quic-proxy")]
async fn read_frame(stream: &mut quinn::RecvStream) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > PROXY_MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            len,
            max: PROXY_MAX_FRAME_BYTES,
        });
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
#[cfg(feature = "local-quic-proxy")]
async fn write_frame<T: NoritoSerialize>(
    stream: &mut quinn::SendStream,
    payload: &T,
) -> Result<(), String> {
    let bytes = to_bytes(payload).map_err(|err| err.to_string())?;
    let len = bytes.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| err.to_string())?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|err| err.to_string())?;
    stream.flush().await.map_err(|err| err.to_string())?;
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_application_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    session: Arc<ProxySession>,
) -> Result<(), ProxyError> {
    let telemetry_label = session.telemetry_label.as_str();
    let frame_bytes = timeout(PROXY_CONTROL_FRAME_TIMEOUT, read_frame(&mut recv_stream))
        .await
        .map_err(|_| ProxyError::Stream("stream-open frame timed out".into()))?
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    let open_frame: ProxyStreamOpenV1 =
        decode_from_bytes(&frame_bytes).map_err(|err| ProxyError::Stream(err.to_string()))?;
    if open_frame.version != PROXY_STREAM_VERSION {
        record_transport_event(telemetry_label, "stream_reject", "unsupported_version");
        let ack = ProxyStreamAckV1 {
            version: PROXY_STREAM_VERSION,
            code: STREAM_ACK_UNSUPPORTED_VERSION,
            accepted: false,
            message: Some("unsupported version".into()),
            cache_tag_hex: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(ProxyError::Stream)?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        return Ok(());
    }
    if !valid_control_field(&open_frame.service)
        || [
            open_frame.authority.as_deref(),
            open_frame.target.as_deref(),
            open_frame.route_policy_id.as_deref(),
            open_frame.exit_country.as_deref(),
            open_frame.client_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_control_field(value))
    {
        record_transport_event(telemetry_label, "stream_reject", "invalid_field");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_BAD_REQUEST,
                accepted: false,
                message: Some("stream field is oversized or contains control characters".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    }
    let service = ProxyStreamService::from_label(&open_frame.service);
    if matches!(session.mode, ProxyMode::MetadataOnly) {
        record_transport_event(telemetry_label, "stream_reject", "mode_metadata_only");
        let ack = ProxyStreamAckV1 {
            version: PROXY_STREAM_VERSION,
            code: STREAM_ACK_MODE_DISABLED,
            accepted: false,
            message: Some("proxy running in metadata-only mode".into()),
            cache_tag_hex: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(ProxyError::Stream)?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        return Ok(());
    }
    if service == ProxyStreamService::Unknown {
        record_transport_event(telemetry_label, "stream_reject", "unsupported_service");
        let ack = ProxyStreamAckV1 {
            version: PROXY_STREAM_VERSION,
            code: STREAM_ACK_UNSUPPORTED_SERVICE,
            accepted: false,
            message: Some(format!("unsupported service `{}`", open_frame.service)),
            cache_tag_hex: None,
        };
        write_frame(&mut send_stream, &ack)
            .await
            .map_err(ProxyError::Stream)?;
        let _ = send_stream.finish();
        let _ = recv_stream.stop(VarInt::from_u32(0));
        return Ok(());
    }
    match service {
        ProxyStreamService::Tcp => {
            handle_tcp_stream(send_stream, recv_stream, session, open_frame).await
        }
        ProxyStreamService::Norito => {
            handle_norito_stream(send_stream, recv_stream, session, open_frame).await
        }
        ProxyStreamService::Car => {
            handle_car_stream(send_stream, recv_stream, session, open_frame).await
        }
        ProxyStreamService::Kaigi => {
            handle_kaigi_stream(send_stream, recv_stream, session, open_frame).await
        }
        ProxyStreamService::Unknown => unreachable!("unknown service handled earlier"),
    }
}
#[cfg(feature = "local-quic-proxy")]
fn valid_control_field(value: &str) -> bool {
    value.len() <= PROXY_MAX_CONTROL_FIELD_BYTES && !value.chars().any(char::is_control)
}
#[cfg(feature = "local-quic-proxy")]
fn record_transport_event(label: &str, event: &str, reason: &str) {
    let metrics = global_or_default();
    metrics.inc_sorafs_orchestrator_transport_event(label, PROXY_PROTOCOL_LABEL, event, reason);
}
#[cfg(feature = "local-quic-proxy")]
async fn send_failure_ack(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    ack: ProxyStreamAckV1,
) -> Result<(), ProxyError> {
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(ProxyError::Stream)?;
    let _ = send_stream.finish();
    let _ = recv_stream.stop(VarInt::from_u32(0));
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_tcp_stream(
    mut send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
    session: Arc<ProxySession>,
    open_frame: ProxyStreamOpenV1,
) -> Result<(), ProxyError> {
    let telemetry_label = session.telemetry_label.as_str();
    let Some(authority) = open_frame
        .authority
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
    else {
        record_transport_event(telemetry_label, "stream_reject", "tcp_missing_authority");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_BAD_REQUEST,
                accepted: false,
                message: Some("tcp stream requires authority".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let (host, port) = match parse_public_tcp_authority(&authority) {
        Ok(target) => target,
        Err(reason) => {
            record_transport_event(telemetry_label, "stream_reject", "tcp_invalid_authority");
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_BAD_REQUEST,
                    accepted: false,
                    message: Some(format!("TCP authority rejected: {reason}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let addresses =
        match resolve_and_validate_host(&host, port, OutboundNetworkPolicy::PRODUCTION).await {
            Ok(addresses) => addresses,
            Err(error) => {
                record_transport_event(telemetry_label, "stream_reject", "tcp_dns_rejected");
                return send_failure_ack(
                    send_stream,
                    recv_stream,
                    ProxyStreamAckV1 {
                        version: PROXY_STREAM_VERSION,
                        code: STREAM_ACK_BAD_REQUEST,
                        accepted: false,
                        message: Some(format!("TCP authority rejected: {error}")),
                        cache_tag_hex: None,
                    },
                )
                .await;
            }
        };
    let mut tcp_stream = match timeout(
        PROXY_CONNECT_TIMEOUT,
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            record_transport_event(telemetry_label, "stream_reject", "tcp_connect_failed");
            warn!(
                target: "soranet.proxy",
                ?err,
                label = telemetry_label,
                "failed to connect tcp authority"
            );
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_INTERNAL_ERROR,
                    accepted: false,
                    message: Some("failed to connect TCP authority".into()),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
        Err(_) => {
            record_transport_event(telemetry_label, "stream_reject", "tcp_connect_timeout");
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_INTERNAL_ERROR,
                    accepted: false,
                    message: Some("TCP authority connection timed out".into()),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let cache_tag = session.cache_tag_for(ProxyStreamService::Tcp, &open_frame);
    let ack = ProxyStreamAckV1 {
        version: PROXY_STREAM_VERSION,
        code: STREAM_ACK_OK,
        accepted: true,
        message: None,
        cache_tag_hex: cache_tag,
    };
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    let mut quic_stream = QuicBidirectionalStream::new(send_stream, recv_stream);
    match timeout(
        PROXY_TRANSFER_TIMEOUT,
        tokio::io::copy_bidirectional(&mut quic_stream, &mut tcp_stream),
    )
    .await
    {
        Ok(Ok((client_bytes, remote_bytes))) => {
            record_transport_event(telemetry_label, "stream_complete", "tcp_ok");
            info!(
                target: "soranet.proxy",
                label = telemetry_label,
                client_bytes,
                remote_bytes,
                "proxied tcp stream"
            );
        }
        Ok(Err(err)) => {
            record_transport_event(telemetry_label, "stream_error", "tcp_proxy_failed");
            quic_stream.shutdown().await;
            let _ = tcp_stream.shutdown().await;
            return Err(ProxyError::Stream(err.to_string()));
        }
        Err(_) => {
            record_transport_event(telemetry_label, "stream_error", "tcp_transfer_timeout");
            quic_stream.shutdown().await;
            let _ = tcp_stream.shutdown().await;
            return Err(ProxyError::Stream("TCP transfer timed out".into()));
        }
    }
    quic_stream.shutdown().await;
    let _ = tcp_stream.shutdown().await;
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
fn parse_public_tcp_authority(authority: &str) -> Result<(String, u16), String> {
    if authority.is_empty()
        || authority.len() > PROXY_MAX_CONTROL_FIELD_BYTES
        || authority.chars().any(char::is_control)
    {
        return Err("authority is empty, oversized, or contains control characters".into());
    }
    let url = Url::parse(&format!("tcp://{authority}"))
        .map_err(|_| "authority must be a canonical host:port pair".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("credentials, paths, queries, and fragments are not permitted".into());
    }
    let host = match url
        .host()
        .ok_or_else(|| "authority host is missing".to_string())?
    {
        Host::Ipv4(ip) => {
            let ip = IpAddr::V4(ip);
            if !is_public_ip(ip) {
                return Err("authority IP is not publicly routable".into());
            }
            ip.to_string()
        }
        Host::Ipv6(ip) => {
            let ip = IpAddr::V6(ip);
            if !is_public_ip(ip) {
                return Err("authority IP is not publicly routable".into());
            }
            ip.to_string()
        }
        Host::Domain(host) => {
            validate_public_dns_name(host).map_err(|error| error.to_string())?;
            host.to_ascii_lowercase()
        }
    };
    let port = url
        .port()
        .filter(|port| *port != 0)
        .ok_or_else(|| "authority must include a non-zero port".to_string())?;
    Ok((host, port))
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, Error)]
enum BridgeFileError {
    #[error("payload was not found")]
    NotFound,
    #[error("payload path is unsafe or is not a regular file")]
    Unsafe,
    #[error("payload length {length} exceeds hard limit {maximum}")]
    TooLarge { length: u64, maximum: u64 },
    #[error("payload changed while it was being streamed")]
    Changed,
    #[error("payload was truncated while it was being streamed")]
    Truncated,
    #[error("payload I/O failed")]
    Io,
    #[error("payload streaming timed out")]
    Timeout,
}
#[cfg(feature = "local-quic-proxy")]
impl BridgeFileError {
    fn ack_code(&self) -> u8 {
        match self {
            Self::NotFound | Self::Unsafe | Self::TooLarge { .. } => STREAM_ACK_BAD_REQUEST,
            Self::Changed | Self::Truncated | Self::Io | Self::Timeout => STREAM_ACK_INTERNAL_ERROR,
        }
    }
    fn reason(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unsafe => "unsafe_file",
            Self::TooLarge { .. } => "file_too_large",
            Self::Changed => "file_changed",
            Self::Truncated => "file_truncated",
            Self::Io => "file_io",
            Self::Timeout => "file_timeout",
        }
    }
}
#[cfg(all(feature = "local-quic-proxy", unix))]
#[derive(Clone, Copy)]
struct BridgeFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}
#[cfg(all(feature = "local-quic-proxy", unix))]
impl BridgeFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_secs: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_secs: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
}
#[cfg(all(feature = "local-quic-proxy", not(unix)))]
#[derive(Clone)]
struct BridgeFileIdentity {
    length: u64,
    modified: Option<std::time::SystemTime>,
}
#[cfg(all(feature = "local-quic-proxy", not(unix)))]
impl BridgeFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
impl PartialEq for BridgeFileIdentity {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device
                && self.inode == other.inode
                && self.length == other.length
                && self.modified_secs == other.modified_secs
                && self.modified_nanos == other.modified_nanos
                && self.changed_secs == other.changed_secs
                && self.changed_nanos == other.changed_nanos
        }
        #[cfg(not(unix))]
        {
            self.length == other.length && self.modified == other.modified
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
struct OpenBridgeFile {
    file: fs::File,
    path: PathBuf,
    length: u64,
    identity: BridgeFileIdentity,
}
#[cfg(feature = "local-quic-proxy")]
async fn ensure_no_symlink_components(root: &Path, path: &Path) -> Result<(), BridgeFileError> {
    #[cfg(not(unix))]
    {
        let _ = (root, path);
        return Err(BridgeFileError::Unsafe);
    }
    #[cfg(unix)]
    validate_bridge_ancestor_chain_sync(root).map_err(|_| BridgeFileError::Unsafe)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BridgeFileError::Unsafe)?;
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(BridgeFileError::Unsafe);
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(segment) = component else {
            return Err(BridgeFileError::Unsafe);
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).await.map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                BridgeFileError::NotFound
            } else {
                BridgeFileError::Io
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(BridgeFileError::Unsafe);
        }
        #[cfg(unix)]
        if index + 1 < components.len() {
            if !metadata.is_dir()
                || metadata.uid() != proxy_effective_uid()
                || metadata.mode() & 0o022 != 0
            {
                return Err(BridgeFileError::Unsafe);
            }
        } else if !metadata.is_file()
            || metadata.uid() != proxy_effective_uid()
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(BridgeFileError::Unsafe);
        }
        #[cfg(not(unix))]
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(BridgeFileError::Unsafe);
        }
    }
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
async fn open_bridge_file(
    root: &Path,
    path: PathBuf,
    maximum: u64,
) -> Result<OpenBridgeFile, BridgeFileError> {
    ensure_no_symlink_components(root, &path).await?;
    let parent = path.parent().ok_or(BridgeFileError::Unsafe)?;
    let canonical_parent = fs::canonicalize(parent)
        .await
        .map_err(|_| BridgeFileError::Unsafe)?;
    if !canonical_parent.starts_with(root) {
        return Err(BridgeFileError::Unsafe);
    }
    let before = fs::symlink_metadata(&path).await.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            BridgeFileError::NotFound
        } else {
            BridgeFileError::Io
        }
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(BridgeFileError::Unsafe);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW_FLAG);
    let file = options.open(&path).await.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            BridgeFileError::NotFound
        } else {
            BridgeFileError::Unsafe
        }
    })?;
    let opened = file.metadata().await.map_err(|_| BridgeFileError::Io)?;
    let after = fs::symlink_metadata(&path)
        .await
        .map_err(|_| BridgeFileError::Changed)?;
    #[cfg(unix)]
    let custody_changed = [&before, &opened, &after].into_iter().any(|metadata| {
        metadata.uid() != proxy_effective_uid()
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
    });
    #[cfg(not(unix))]
    let custody_changed = true;
    if !opened.is_file()
        || before.file_type().is_symlink()
        || after.file_type().is_symlink()
        || custody_changed
        || BridgeFileIdentity::from_metadata(&before) != BridgeFileIdentity::from_metadata(&opened)
        || BridgeFileIdentity::from_metadata(&opened) != BridgeFileIdentity::from_metadata(&after)
    {
        return Err(BridgeFileError::Changed);
    }
    if opened.len() > maximum {
        return Err(BridgeFileError::TooLarge {
            length: opened.len(),
            maximum,
        });
    }
    Ok(OpenBridgeFile {
        file,
        path,
        length: opened.len(),
        identity: BridgeFileIdentity::from_metadata(&opened),
    })
}
#[cfg(feature = "local-quic-proxy")]
async fn stream_bridge_file_exact(
    opened: &mut OpenBridgeFile,
    send_stream: &mut quinn::SendStream,
) -> Result<u64, BridgeFileError> {
    let mut limited = (&mut opened.file).take(opened.length);
    let bytes = timeout(
        PROXY_TRANSFER_TIMEOUT,
        tokio::io::copy(&mut limited, send_stream),
    )
    .await
    .map_err(|_| BridgeFileError::Timeout)?
    .map_err(|_| BridgeFileError::Io)?;
    if bytes != opened.length {
        return Err(BridgeFileError::Truncated);
    }
    send_stream.flush().await.map_err(|_| BridgeFileError::Io)?;
    verify_bridge_file_unchanged(opened).await?;
    Ok(bytes)
}
#[cfg(feature = "local-quic-proxy")]
async fn verify_bridge_file_unchanged(opened: &OpenBridgeFile) -> Result<(), BridgeFileError> {
    let opened_after = opened
        .file
        .metadata()
        .await
        .map_err(|_| BridgeFileError::Changed)?;
    let path_after = fs::symlink_metadata(&opened.path)
        .await
        .map_err(|_| BridgeFileError::Changed)?;
    if path_after.file_type().is_symlink()
        || BridgeFileIdentity::from_metadata(&opened_after) != opened.identity
        || BridgeFileIdentity::from_metadata(&path_after) != opened.identity
    {
        return Err(BridgeFileError::Changed);
    }
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_norito_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    session: Arc<ProxySession>,
    open_frame: ProxyStreamOpenV1,
) -> Result<(), ProxyError> {
    let telemetry_label = session.telemetry_label.as_str();
    let Some(bridge) = session.bridge.norito() else {
        record_transport_event(telemetry_label, "stream_reject", "norito_bridge_disabled");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_NOT_IMPLEMENTED,
                accepted: false,
                message: Some("norito bridge not configured".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let Some(target) = extract_stream_target(&open_frame) else {
        record_transport_event(telemetry_label, "stream_reject", "norito_missing_target");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_BAD_REQUEST,
                accepted: false,
                message: Some("norito stream requires target".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let path = match bridge.resolve_target(target) {
        Ok(path) => path,
        Err(reason) => {
            record_transport_event(telemetry_label, "stream_reject", "norito_invalid_target");
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_BAD_REQUEST,
                    accepted: false,
                    message: Some(format!("invalid norito target: {reason}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let mut file = match open_bridge_file(&bridge.spool_dir, path, PROXY_MAX_LOCAL_FILE_BYTES).await
    {
        Ok(file) => file,
        Err(error) => {
            record_transport_event(telemetry_label, "stream_reject", error.reason());
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: error.ack_code(),
                    accepted: false,
                    message: Some(format!("norito payload rejected: {error}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let cache_tag = session.cache_tag_for(ProxyStreamService::Norito, &open_frame);
    let ack = ProxyStreamAckV1 {
        version: PROXY_STREAM_VERSION,
        code: STREAM_ACK_OK,
        accepted: true,
        message: None,
        cache_tag_hex: cache_tag,
    };
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    match stream_bridge_file_exact(&mut file, &mut send_stream).await {
        Ok(bytes) => {
            record_transport_event(telemetry_label, "stream_complete", "norito_ok");
            info!(
                target: "soranet.proxy",
                label = telemetry_label,
                bytes,
                "streamed norito payload"
            );
            let _ = send_stream.finish();
            let _ = recv_stream.stop(VarInt::from_u32(0));
            Ok(())
        }
        Err(error) => {
            record_transport_event(telemetry_label, "stream_error", error.reason());
            let _ = send_stream.finish();
            let _ = recv_stream.stop(VarInt::from_u32(0));
            Err(ProxyError::Stream(error.to_string()))
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_kaigi_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    session: Arc<ProxySession>,
    open_frame: ProxyStreamOpenV1,
) -> Result<(), ProxyError> {
    let telemetry_label = session.telemetry_label.as_str();
    let Some(bridge) = session.bridge.kaigi() else {
        record_transport_event(telemetry_label, "stream_reject", "kaigi_bridge_disabled");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_NOT_IMPLEMENTED,
                accepted: false,
                message: Some("kaigi bridge not configured".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let Some(target) = extract_stream_target(&open_frame) else {
        record_transport_event(telemetry_label, "stream_reject", "kaigi_missing_target");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_BAD_REQUEST,
                accepted: false,
                message: Some("kaigi stream requires target".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let path = match bridge.resolve_target(target) {
        Ok(path) => path,
        Err(reason) => {
            record_transport_event(telemetry_label, "stream_reject", "kaigi_invalid_target");
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_BAD_REQUEST,
                    accepted: false,
                    message: Some(format!("invalid kaigi target: {reason}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let mut file = match open_bridge_file(&bridge.spool_dir, path, PROXY_MAX_LOCAL_FILE_BYTES).await
    {
        Ok(file) => file,
        Err(error) => {
            record_transport_event(telemetry_label, "stream_reject", error.reason());
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: error.ack_code(),
                    accepted: false,
                    message: Some(format!("kaigi payload rejected: {error}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let room_policy = bridge.room_policy().as_label().to_string();
    let cache_tag = session.cache_tag_for(ProxyStreamService::Kaigi, &open_frame);
    let ack = ProxyStreamAckV1 {
        version: PROXY_STREAM_VERSION,
        code: STREAM_ACK_OK,
        accepted: true,
        message: Some(format!("room-policy={room_policy}")),
        cache_tag_hex: cache_tag,
    };
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(ProxyError::Stream)?;
    stream_bridge_file_exact(&mut file, &mut send_stream)
        .await
        .map_err(|error| ProxyError::Stream(error.to_string()))?;
    send_stream
        .finish()
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    recv_stream
        .stop(VarInt::from_u32(0))
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    record_transport_event(telemetry_label, "stream_complete", "kaigi_ok");
    Ok(())
}
#[cfg(feature = "local-quic-proxy")]
async fn handle_car_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    session: Arc<ProxySession>,
    open_frame: ProxyStreamOpenV1,
) -> Result<(), ProxyError> {
    let telemetry_label = session.telemetry_label.as_str();
    let Some(bridge) = session.bridge.car() else {
        record_transport_event(telemetry_label, "stream_reject", "car_bridge_disabled");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_NOT_IMPLEMENTED,
                accepted: false,
                message: Some("car bridge not configured".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let Some(target) = extract_stream_target(&open_frame) else {
        record_transport_event(telemetry_label, "stream_reject", "car_missing_target");
        return send_failure_ack(
            send_stream,
            recv_stream,
            ProxyStreamAckV1 {
                version: PROXY_STREAM_VERSION,
                code: STREAM_ACK_BAD_REQUEST,
                accepted: false,
                message: Some("car stream requires target".into()),
                cache_tag_hex: None,
            },
        )
        .await;
    };
    let path = match bridge.resolve_target(target) {
        Ok(path) => path,
        Err(reason) => {
            record_transport_event(telemetry_label, "stream_reject", "car_invalid_target");
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: STREAM_ACK_BAD_REQUEST,
                    accepted: false,
                    message: Some(format!("invalid car target: {reason}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let mut file = match open_bridge_file(&bridge.cache_dir, path, PROXY_MAX_LOCAL_FILE_BYTES).await
    {
        Ok(file) => file,
        Err(error) => {
            record_transport_event(telemetry_label, "stream_reject", error.reason());
            return send_failure_ack(
                send_stream,
                recv_stream,
                ProxyStreamAckV1 {
                    version: PROXY_STREAM_VERSION,
                    code: error.ack_code(),
                    accepted: false,
                    message: Some(format!("car payload rejected: {error}")),
                    cache_tag_hex: None,
                },
            )
            .await;
        }
    };
    let cache_tag = session.cache_tag_for(ProxyStreamService::Car, &open_frame);
    let ack = ProxyStreamAckV1 {
        version: PROXY_STREAM_VERSION,
        code: STREAM_ACK_OK,
        accepted: true,
        message: None,
        cache_tag_hex: cache_tag,
    };
    write_frame(&mut send_stream, &ack)
        .await
        .map_err(|err| ProxyError::Stream(err.to_string()))?;
    match stream_bridge_file_exact(&mut file, &mut send_stream).await {
        Ok(bytes) => {
            record_transport_event(telemetry_label, "stream_complete", "car_ok");
            info!(
                target: "soranet.proxy",
                label = telemetry_label,
                bytes,
                "streamed car archive"
            );
            let _ = send_stream.finish();
            let _ = recv_stream.stop(VarInt::from_u32(0));
            Ok(())
        }
        Err(error) => {
            record_transport_event(telemetry_label, "stream_error", error.reason());
            let _ = send_stream.finish();
            let _ = recv_stream.stop(VarInt::from_u32(0));
            Err(ProxyError::Stream(error.to_string()))
        }
    }
}
#[cfg(feature = "local-quic-proxy")]
fn extract_stream_target(open_frame: &ProxyStreamOpenV1) -> Option<&str> {
    open_frame
        .target
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
fn generate_session_id() -> Result<String, ProxyError> {
    let mut rng = OsRng;
    generate_session_id_with_rng(&mut rng)
}
fn generate_session_id_with_rng<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<String, ProxyError> {
    let mut bytes = [0u8; PROXY_SESSION_ID_LEN];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|err| ProxyError::RandomBytes {
            operation: "generating proxy session id",
            message: err.to_string(),
        })?;
    Ok(bytes.encode_hex::<String>())
}
fn generate_cache_salt() -> Result<String, ProxyError> {
    let mut rng = OsRng;
    generate_cache_salt_with_rng(&mut rng)
}
fn generate_cache_salt_with_rng<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<String, ProxyError> {
    let mut bytes = [0u8; PROXY_CACHE_TAG_SALT_LEN];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|err| ProxyError::RandomBytes {
            operation: "generating proxy cache salt",
            message: err.to_string(),
        })?;
    Ok(bytes.encode_hex::<String>())
}
/// Proxy handshake payload dispatched by clients.
#[cfg(feature = "local-quic-proxy")]
#[derive(NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_orchestrator::proxy::ProxyHandshakeV1")]
struct ProxyHandshakeV1 {
    version: u8,
    #[norito(default)]
    client_capability: Option<[u8; PROXY_CLIENT_CAPABILITY_LEN]>,
    #[norito(default)]
    client: Option<String>,
    #[norito(default)]
    user_agent: Option<String>,
}
#[cfg(feature = "local-quic-proxy")]
impl fmt::Debug for ProxyHandshakeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHandshakeV1")
            .field("version", &self.version)
            .field(
                "client_capability",
                &self.client_capability.as_ref().map(|_| "<redacted>"),
            )
            .field("client", &self.client)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}
#[cfg(feature = "local-quic-proxy")]
impl Drop for ProxyHandshakeV1 {
    fn drop(&mut self) {
        if let Some(capability) = self.client_capability.as_mut() {
            capability.fill(0);
            std::hint::black_box(capability);
        }
    }
}
/// Acknowledgement returned to clients after the handshake completes.
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_orchestrator::proxy::ProxyHandshakeAckV1")]
struct ProxyHandshakeAckV1 {
    version: u8,
    accepted: bool,
    #[norito(default)]
    message: Option<String>,
    #[norito(default)]
    manifest: Option<BrowserExtensionManifest>,
}
/// Stream open frame dispatched per application channel.
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_orchestrator::proxy::ProxyStreamOpenV1")]
struct ProxyStreamOpenV1 {
    version: u8,
    #[norito(default)]
    service: String,
    #[norito(default)]
    authority: Option<String>,
    #[norito(default)]
    target: Option<String>,
    #[norito(default)]
    route_policy_id: Option<String>,
    #[norito(default)]
    exit_country: Option<String>,
    #[norito(default)]
    client_id: Option<String>,
}
/// Stream acknowledgement returned once the proxy routes a request.
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "sorafs_orchestrator::proxy::ProxyStreamAckV1")]
struct ProxyStreamAckV1 {
    version: u8,
    code: u8,
    accepted: bool,
    #[norito(default)]
    message: Option<String>,
    #[norito(default)]
    cache_tag_hex: Option<String>,
}
#[cfg(feature = "local-quic-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyStreamService {
    Tcp,
    Norito,
    Car,
    Kaigi,
    Unknown,
}
#[cfg(feature = "local-quic-proxy")]
impl ProxyStreamService {
    fn from_label(label: &str) -> Self {
        match label.trim().to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "norito" => Self::Norito,
            "car" => Self::Car,
            "kaigi" => Self::Kaigi,
            _ => Self::Unknown,
        }
    }
    fn as_label(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Norito => "norito",
            Self::Car => "car",
            Self::Kaigi => "kaigi",
            Self::Unknown => "unknown",
        }
    }
}
#[cfg(test)]
mod json_key_tests {
    use super::{ProxyClientCapabilityHex, ProxyMode};

    #[test]
    fn proxy_mode_object_keys_use_exact_labels_without_decode_allocation() {
        use norito::json::{JsonObjectKey as _, JsonObjectKeyOwned as _};

        let limits =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        for (mode, label) in [
            (ProxyMode::Bridge, "bridge"),
            (ProxyMode::MetadataOnly, "metadata-only"),
        ] {
            let mut text = String::new();
            mode.visit_json_key_text(|chunk| {
                text.push_str(chunk);
                Ok::<_, core::convert::Infallible>(())
            })
            .expect("infallible mode key visitor");
            assert_eq!(text, label);
            let (decoded, usage) = norito::core::with_decode_limits_measured(limits, || {
                ProxyMode::from_json_key_text(label)
            });
            assert_eq!(
                decoded.expect("mode key requires no allocation budget"),
                mode
            );
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
        for alias in [
            "",
            "metadata",
            "metadata_only",
            "Metadata-Only",
            "BRIDGE",
            " bridge",
            "bridge ",
            "metadata-only\n",
            "unknown",
        ] {
            let (decoded, usage) = norito::core::with_decode_limits_measured(limits, || {
                ProxyMode::from_json_key_text(alias)
            });
            assert!(
                decoded.is_err(),
                "noncanonical mode key accepted: {alias:?}"
            );
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }

    #[test]
    fn proxy_scalar_object_keys_preserve_canonical_text_and_decode_budget() {
        use norito::json::{JsonObjectKey as _, JsonObjectKeyOwned as _};

        let mut mode_text = String::new();
        ProxyMode::MetadataOnly
            .visit_json_key_text(|chunk| {
                mode_text.push_str(chunk);
                Ok::<_, core::convert::Infallible>(())
            })
            .expect("infallible mode key visitor");
        assert_eq!(mode_text, "metadata-only");
        assert_eq!(
            ProxyMode::from_json_key_text(&mode_text).expect("decode proxy mode key"),
            ProxyMode::MetadataOnly
        );

        let literal = format!("01{}", "23".repeat(31));
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (capability, usage) =
            norito::core::with_decode_limits_measured(limits(literal.len()), || {
                ProxyClientCapabilityHex::from_json_key_text(&literal)
            });
        let capability = capability.expect("capability key at exact budget");
        assert_eq!(usage.total_allocated_bytes(), literal.len());
        let mut encoded = String::new();
        capability
            .visit_json_key_text(|chunk| {
                encoded.push_str(chunk);
                Ok::<_, core::convert::Infallible>(())
            })
            .expect("infallible capability key visitor");
        assert_eq!(encoded, literal);

        let (rejected, usage) =
            norito::core::with_decode_limits_measured(limits(literal.len() - 1), || {
                ProxyClientCapabilityHex::from_json_key_text(&literal)
            });
        assert!(matches!(
            rejected,
            Err(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
        assert_eq!(usage.total_allocated_bytes(), 0);
    }
}

#[cfg(all(test, feature = "local-quic-proxy"))]
mod tests {
    use super::*;
    use rand::rand_core::TryRngCore;
    use std::{net::SocketAddr, sync::Arc, time::Duration};
    use tempfile::TempDir;
    use tokio::{io::AsyncWriteExt, task::JoinHandle};
    const TEST_GUARD_KEY: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    #[derive(Debug)]
    struct FailingProxyRng;
    #[derive(Debug)]
    struct ZeroProxyRng;
    #[derive(Debug)]
    struct FailingProxyRngError;
    impl std::fmt::Display for FailingProxyRngError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("failing proxy session RNG")
        }
    }
    impl std::error::Error for FailingProxyRngError {}
    impl TryRngCore for FailingProxyRng {
        type Error = FailingProxyRngError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(FailingProxyRngError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(FailingProxyRngError)
        }
        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
            Err(FailingProxyRngError)
        }
    }
    impl TryRngCore for ZeroProxyRng {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(0);
            Ok(())
        }
    }
    #[test]
    fn tcp_authority_policy_rejects_ssrf_targets() {
        for authority in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.169.254:80",
            "[::1]:443",
            "[fe80::1]:443",
            "localhost:443",
            "relay.local:443",
            "user:secret@relay.example.org:443",
            "relay.example.org:443/path",
            "relay.example.org:443?query=1",
            "relay.example.org",
            "relay.example.org:0",
        ] {
            assert!(
                parse_public_tcp_authority(authority).is_err(),
                "unsafe authority was accepted: {authority}"
            );
        }
        assert_eq!(
            parse_public_tcp_authority("93.184.216.34:443").expect("public IPv4 authority"),
            ("93.184.216.34".into(), 443)
        );
        assert_eq!(
            parse_public_tcp_authority("relay.example.org:443").expect("public DNS authority"),
            ("relay.example.org".into(), 443)
        );
    }
    #[test]
    fn proxy_rejects_unbounded_stream_configuration() {
        let mut zero = LocalQuicProxyConfig::default();
        zero.max_streams_per_circuit = Some(0);
        assert!(matches!(
            zero.validated_stream_limit(),
            Err(ProxyError::StreamLimit { .. })
        ));
        let mut excessive = LocalQuicProxyConfig::default();
        excessive.max_streams_per_circuit = Some(PROXY_MAX_STREAMS_PER_CONNECTION + 1);
        assert!(matches!(
            excessive.validated_stream_limit(),
            Err(ProxyError::StreamLimit { .. })
        ));
    }
    #[test]
    fn proxy_config_debug_redacts_guard_cache_key() {
        let mut config = LocalQuicProxyConfig::default();
        config.guard_cache_key_hex = Some(TEST_GUARD_KEY.into());
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(TEST_GUARD_KEY));
    }
    #[tokio::test]
    async fn bridge_file_open_is_bounded_and_detects_mutation() {
        let root = TempDir::new().expect("tempdir");
        let path = root.path().join("payload.norito");
        tokio::fs::write(&path, b"payload")
            .await
            .expect("write payload");
        assert!(matches!(
            open_bridge_file(root.path(), path.clone(), 3).await,
            Err(BridgeFileError::TooLarge { .. })
        ));
        let opened = open_bridge_file(root.path(), path.clone(), 64)
            .await
            .expect("open regular payload");
        tokio::fs::write(&path, b"short")
            .await
            .expect("truncate payload");
        assert!(matches!(
            verify_bridge_file_unchanged(&opened).await,
            Err(BridgeFileError::Changed)
        ));
    }
    #[tokio::test]
    async fn bridge_file_open_detects_replacement() {
        let root = TempDir::new().expect("tempdir");
        let path = root.path().join("payload.car");
        let replacement = root.path().join("replacement.car");
        tokio::fs::write(&path, b"original")
            .await
            .expect("write payload");
        let opened = open_bridge_file(root.path(), path.clone(), 64)
            .await
            .expect("open regular payload");
        tokio::fs::write(&replacement, b"replaced")
            .await
            .expect("write replacement");
        tokio::fs::rename(&replacement, &path)
            .await
            .expect("replace payload");
        assert!(matches!(
            verify_bridge_file_unchanged(&opened).await,
            Err(BridgeFileError::Changed)
        ));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn bridge_file_open_rejects_symlinks_and_symlink_roots() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = TempDir::new().expect("tempdir");
        let real = root.path().join("real.norito");
        let link = root.path().join("link.norito");
        tokio::fs::write(&real, b"payload")
            .await
            .expect("write payload");
        symlink(&real, &link).expect("create payload symlink");
        assert!(matches!(
            open_bridge_file(root.path(), link, 64).await,
            Err(BridgeFileError::Unsafe)
        ));
        let root_link = root.path().with_extension("link");
        symlink(root.path(), &root_link).expect("create root symlink");
        assert!(canonical_bridge_root(&root_link).is_err());
        std::fs::remove_file(root_link).expect("remove root symlink");

        let writable_root = TempDir::new().expect("writable tempdir");
        std::fs::set_permissions(writable_root.path(), std::fs::Permissions::from_mode(0o777))
            .expect("make root unsafe");
        assert!(canonical_bridge_root(writable_root.path()).is_err());

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o666))
            .expect("make payload unsafe");
        assert!(matches!(
            open_bridge_file(root.path(), real, 64).await,
            Err(BridgeFileError::Unsafe)
        ));
    }
    impl TryCryptoRng for FailingProxyRng {}
    impl TryCryptoRng for ZeroProxyRng {}
    use quinn::{
        ClientConfig, Endpoint, ServerConfig, VarInt,
        crypto::rustls::QuicClientConfig as QuinnRustlsClientConfig,
        crypto::rustls::QuicServerConfig as QuinnRustlsServerConfig,
        rustls::{
            self, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
            client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        },
    };
    fn should_skip_socket_permission(message: &str) -> bool {
        message.contains("Operation not permitted") || message.contains("Permission denied")
    }
    fn spawn_proxy_or_skip(config: LocalQuicProxyConfig) -> Option<LocalQuicProxyHandle> {
        match spawn_local_quic_proxy(config) {
            Ok(handle) => Some(handle),
            Err(ProxyError::QuinnEndpoint(message)) if should_skip_socket_permission(&message) => {
                eprintln!("skipping proxy test (loopback socket unavailable): {message}");
                None
            }
            Err(err) => panic!("spawn proxy: {err}"),
        }
    }
    fn sample_certificate() -> (String, Vec<u8>) {
        let rcgen::CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("generate certificate");
        let cert_pem = cert.pem().to_string();
        let cert_der = cert.der().to_vec();
        (cert_pem, cert_der)
    }
    #[allow(clippy::type_complexity)]
    fn spawn_frame_server_or_skip() -> Option<(
        Endpoint,
        SocketAddr,
        JoinHandle<Result<Vec<u8>, FrameError>>,
    )> {
        let rcgen::CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("generate certificate");
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let private_key =
            PrivateKeyDer::try_from(signing_key.serialize_der()).expect("private key");
        let mut tls_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], private_key)
                .expect("server tls config");
        tls_config.max_early_data_size = u32::MAX;
        tls_config.alpn_protocols = vec![PROXY_ALPN_LABEL.as_bytes().to_vec()];
        let crypto =
            QuinnRustlsServerConfig::try_from(Arc::new(tls_config)).expect("server crypto");
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport = Arc::new(quinn::TransportConfig::default());
        let endpoint = match Endpoint::server(server_config, "127.0.0.1:0".parse().expect("addr")) {
            Ok(endpoint) => endpoint,
            Err(err) if should_skip_socket_permission(&err.to_string()) => {
                eprintln!("skipping frame test (loopback socket unavailable): {err}");
                return None;
            }
            Err(err) => panic!("spawn frame server: {err}"),
        };
        let local_addr = endpoint.local_addr().expect("local addr");
        let endpoint_handle = endpoint.clone();
        let join_handle = tokio::spawn(async move {
            let incoming = endpoint_handle.accept().await.expect("accept incoming");
            let connecting = incoming.accept().expect("accept connection");
            let connection = connecting.await.expect("connect");
            let (_send, mut recv) = connection.accept_bi().await.expect("accept stream");
            read_frame(&mut recv).await
        });
        Some((endpoint, local_addr, join_handle))
    }
    #[test]
    fn manifest_template_populates_expected_fields() {
        let mut config = LocalQuicProxyConfig::default();
        config.telemetry_label = Some("dev-proxy".into());
        config.guard_cache_key_hex = Some(TEST_GUARD_KEY.into());
        config.proxy_mode = ProxyMode::Bridge;
        let (cert_pem, cert_der) = sample_certificate();
        let addr: SocketAddr = "127.0.0.1:4433".parse().expect("addr");
        let template = build_manifest_template(&config, addr, &cert_pem, &cert_der)
            .expect("manifest template");
        let manifest = template.preview().expect("manifest preview");
        let expected_fingerprint = {
            let mut hasher = Sha256::new();
            hasher.update(&cert_der);
            hex::encode(hasher.finalize())
        };
        let expected_caps: Vec<String> = PROXY_CAPABILITIES
            .iter()
            .map(|cap| cap.to_string())
            .collect();
        assert_eq!(manifest.version, 2);
        assert_eq!(manifest.alpn.as_deref(), Some(PROXY_ALPN_LABEL));
        assert_eq!(manifest.capabilities, expected_caps);
        assert_eq!(manifest.proxy_mode, ProxyMode::Bridge);
        assert_eq!(
            manifest.cert_fingerprint_hex.as_deref(),
            Some(expected_fingerprint.as_str())
        );
        assert_eq!(expected_fingerprint.len(), 64);
        let session = manifest.session_id.expect("session id");
        assert_eq!(session.len(), PROXY_SESSION_ID_LEN * 2);
        let cache = manifest.cache_tagging.expect("cache tagging");
        let salt = cache.salt_hex.expect("salt");
        assert_eq!(salt.len(), PROXY_CACHE_TAG_SALT_LEN * 2);
        let rendered = norito::json::to_json_pretty(&template.preview().expect("second preview"))
            .expect("render browser manifest");
        assert!(!rendered.contains(TEST_GUARD_KEY));
        assert!(!rendered.contains("guard_cache_key"));
    }
    #[test]
    fn proxy_session_id_reports_rng_failure() {
        let error =
            generate_session_id_with_rng(&mut FailingProxyRng).expect_err("session RNG failure");
        match error {
            ProxyError::RandomBytes { operation, message } => {
                assert_eq!(operation, "generating proxy session id");
                assert!(message.contains("failing proxy session RNG"));
            }
            other => panic!("expected random bytes error, got {other}"),
        }
    }
    #[test]
    fn proxy_cache_salt_reports_rng_failure() {
        let error =
            generate_cache_salt_with_rng(&mut FailingProxyRng).expect_err("cache salt RNG failure");
        match error {
            ProxyError::RandomBytes { operation, message } => {
                assert_eq!(operation, "generating proxy cache salt");
                assert!(message.contains("failing proxy session RNG"));
            }
            other => panic!("expected random bytes error, got {other}"),
        }
    }
    #[test]
    fn proxy_client_capability_reports_rng_failure() {
        let error = ProxyClientCapability::generate_with_rng(&mut FailingProxyRng)
            .expect_err("client capability RNG failure");
        match error {
            ProxyError::RandomBytes { operation, message } => {
                assert_eq!(operation, "generating proxy client capability");
                assert!(message.contains("failing proxy session RNG"));
            }
            other => panic!("expected random bytes error, got {other}"),
        }
    }
    #[test]
    fn proxy_client_capability_rejects_all_zero_material() {
        let error = ProxyClientCapability::generate_with_rng(&mut ZeroProxyRng)
            .expect_err("all-zero client capability must fail closed");
        assert!(error.to_string().contains("all-zero"));
        assert!(ProxyClientCapabilityHex::parse("00".repeat(32)).is_err());
    }
    #[test]
    fn cache_tag_generation_matches_expected() {
        let mut config = LocalQuicProxyConfig::default();
        config.telemetry_label = Some("dev-proxy".into());
        config.proxy_mode = ProxyMode::Bridge;
        let guard_key = GuardCacheKey::from_bytes([0x11; GuardCacheKey::LENGTH])
            .expect("non-zero guard cache key");
        let (cert_pem, cert_der) = sample_certificate();
        let addr: SocketAddr = "127.0.0.1:9443".parse().expect("addr");
        let template = build_manifest_template(&config, addr, &cert_pem, &cert_der)
            .expect("manifest template");
        let manifest = template.preview().expect("manifest preview");
        let cache_context =
            CacheTagContext::from_manifest(&manifest).expect("cache context present");
        let expected_context = cache_context.clone();
        let bridge_config =
            Arc::new(ProxyBridgeConfig::from_config(&config).expect("valid bridge config"));
        let session = ProxySession {
            telemetry_label: "test".into(),
            mode: ProxyMode::Bridge,
            guard_cache_key: Some(Arc::new(guard_key.clone())),
            session_id: manifest.session_id.clone(),
            cache_tags: Some(cache_context),
            bridge: bridge_config,
        };
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "car".into(),
            authority: Some("torii.dev:8080".into()),
            target: Some("payload.car".into()),
            route_policy_id: Some("policy-alpha".into()),
            exit_country: Some("JP".into()),
            client_id: Some("client-1".into()),
        };
        let actual = session
            .cache_tag_for(ProxyStreamService::Car, &open_frame)
            .expect("cache tag");
        let mut expected_message = Vec::new();
        expected_message.extend_from_slice(&expected_context.salt);
        append_tag_component(&mut expected_message, Some("car"));
        append_tag_component(&mut expected_message, open_frame.authority.as_deref());
        append_tag_component(&mut expected_message, open_frame.target.as_deref());
        append_tag_component(&mut expected_message, open_frame.client_id.as_deref());
        append_tag_component(&mut expected_message, open_frame.route_policy_id.as_deref());
        append_tag_component(&mut expected_message, open_frame.exit_country.as_deref());
        append_tag_component(&mut expected_message, session.session_id.as_deref());
        let expected = hex::encode_upper(hmac_sha256_128(
            guard_key.expose_bytes_for_mac(),
            &expected_message,
        ));
        assert_eq!(actual, expected);
        let tcp_tag = session
            .cache_tag_for(ProxyStreamService::Tcp, &open_frame)
            .expect("tcp cache tag");
        let mut tcp_message = Vec::new();
        tcp_message.extend_from_slice(&expected_context.salt);
        append_tag_component(&mut tcp_message, Some("tcp"));
        append_tag_component(&mut tcp_message, open_frame.authority.as_deref());
        append_tag_component(&mut tcp_message, open_frame.target.as_deref());
        append_tag_component(&mut tcp_message, open_frame.client_id.as_deref());
        append_tag_component(&mut tcp_message, open_frame.route_policy_id.as_deref());
        append_tag_component(&mut tcp_message, open_frame.exit_country.as_deref());
        append_tag_component(&mut tcp_message, session.session_id.as_deref());
        let expected_tcp = hex::encode_upper(hmac_sha256_128(
            guard_key.expose_bytes_for_mac(),
            &tcp_message,
        ));
        assert_eq!(tcp_tag, expected_tcp);
    }
    #[test]
    fn proxy_stream_service_lookup_handles_unknown() {
        assert_eq!(
            ProxyStreamService::from_label("tcp"),
            ProxyStreamService::Tcp
        );
        assert_eq!(
            ProxyStreamService::from_label("Norito"),
            ProxyStreamService::Norito
        );
        assert_eq!(
            ProxyStreamService::from_label("car"),
            ProxyStreamService::Car
        );
        assert_eq!(
            ProxyStreamService::from_label("something"),
            ProxyStreamService::Unknown
        );
    }
    #[test]
    fn extract_stream_target_filters_blanks() {
        let frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "norito".into(),
            authority: None,
            target: Some("  routes/route-alpha  ".into()),
            route_policy_id: None,
            exit_country: None,
            client_id: None,
        };
        assert_eq!(extract_stream_target(&frame), Some("routes/route-alpha"));
        let blank = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "norito".into(),
            authority: None,
            target: Some("   ".into()),
            route_policy_id: None,
            exit_country: None,
            client_id: None,
        };
        assert!(extract_stream_target(&blank).is_none());
        let none_target = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "norito".into(),
            authority: None,
            target: None,
            route_policy_id: None,
            exit_country: None,
            client_id: None,
        };
        assert!(extract_stream_target(&none_target).is_none());
    }
    #[test]
    fn spawn_local_quic_proxy_rejects_non_loopback_bind_addr() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "0.0.0.0:0".into();
        let result = spawn_local_quic_proxy(config);
        match result {
            Err(ProxyError::BindAddressNotLoopback(addr)) => {
                assert_eq!(addr, "0.0.0.0:0".parse().expect("addr"));
            }
            Ok(_) => panic!("non-loopback bind must be rejected"),
            Err(other) => panic!("expected loopback bind rejection, got {other}"),
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn read_frame_rejects_oversized_payload() {
        let Some((server_endpoint, server_addr, server_task)) = spawn_frame_server_or_skip() else {
            return;
        };
        let (client_endpoint, connection) = connect_proxy_client(server_addr).await;
        let (mut send_stream, _recv_stream) = connection.open_bi().await.expect("open stream");
        let oversized_len =
            u32::try_from(PROXY_MAX_FRAME_BYTES + 1).expect("frame length fits u32");
        send_stream
            .write_all(&oversized_len.to_be_bytes())
            .await
            .expect("write frame length");
        send_stream.flush().await.expect("flush frame length");
        send_stream.finish().expect("finish stream");
        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
        match result {
            Err(FrameError::FrameTooLarge { len, max }) => {
                assert_eq!(len, PROXY_MAX_FRAME_BYTES + 1);
                assert_eq!(max, PROXY_MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge error, got {other:?}"),
        }
        connection.close(VarInt::from_u32(0), b"done");
        client_endpoint.wait_idle().await;
        server_endpoint.wait_idle().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_manifest_includes_cache_tagging() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.telemetry_label = Some("dev-proxy".into());
        config.guard_cache_key_hex = Some(TEST_GUARD_KEY.into());
        let Some(proxy) = spawn_proxy_or_skip(config.clone()) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let manifest = handshake_ack
            .manifest
            .expect("handshake should include manifest");
        assert!(
            manifest.client_capability_hex.is_none(),
            "the in-band manifest must not return its authentication capability"
        );
        assert_eq!(manifest.telemetry_label, config.telemetry_label);
        assert_eq!(manifest.proxy_mode, config.proxy_mode);
        let cache = manifest.cache_tagging.expect("cache tagging present");
        let salt = cache.salt_hex.expect("cache salt present");
        assert_eq!(salt.len(), PROXY_CACHE_TAG_SALT_LEN * 2);
        assert!(
            cache.attach_on.iter().any(|label| label == "norito")
                && cache.attach_on.iter().any(|label| label == "car"),
            "expected cache tagging to advertise both norito and car services"
        );
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn stream_rejects_version_mismatch() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.proxy_mode = ProxyMode::Bridge;
        config.emit_browser_manifest = false;
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION.saturating_add(1),
            service: "norito".into(),
            authority: Some("torii.dev:9443".into()),
            target: Some("routes/route-alpha".into()),
            route_policy_id: None,
            exit_country: None,
            client_id: Some("test-client".into()),
        };
        let (mut stream_send, mut stream_recv, stream_ack) =
            open_proxy_stream(&connection, &open_frame).await;
        assert!(!stream_ack.accepted);
        assert_eq!(stream_ack.code, STREAM_ACK_UNSUPPORTED_VERSION);
        let _ = stream_send.finish();
        let _ = stream_recv.stop(VarInt::from_u32(0));
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_rejects_version_mismatch() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.emit_browser_manifest = false;
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let (mut handshake_send, mut handshake_recv) =
            connection.open_bi().await.expect("open handshake stream");
        let handshake = ProxyHandshakeV1 {
            version: PROXY_HANDSHAKE_VERSION.saturating_add(1),
            client_capability: None,
            client: Some("test-client".into()),
            user_agent: Some("orchestrator-test".into()),
        };
        write_frame(&mut handshake_send, &handshake)
            .await
            .expect("write handshake");
        handshake_send.finish().expect("finish handshake send");
        let ack_bytes = read_frame(&mut handshake_recv)
            .await
            .expect("read handshake ack");
        let ack: ProxyHandshakeAckV1 = decode_from_bytes(&ack_bytes).expect("decode handshake ack");
        assert_eq!(ack.version, PROXY_HANDSHAKE_VERSION);
        assert!(!ack.accepted);
        assert_eq!(ack.message.as_deref(), Some("unsupported version"));
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_requires_the_out_of_band_client_capability() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.emit_browser_manifest = true;
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let bootstrap = proxy
            .browser_manifest()
            .expect("bootstrap manifest")
            .expect("manifest enabled");
        assert!(bootstrap.client_capability_hex.is_some());
        let mut capability_hex = hex::encode(
            bootstrap
                .client_capability_hex
                .as_ref()
                .expect("bootstrap capability")
                .expose_bytes_for_handshake(),
        )
        .into_bytes();
        assert!(
            !format!("{bootstrap:?}")
                .as_bytes()
                .windows(capability_hex.len())
                .any(|window| window == capability_hex.as_slice())
        );
        capability_hex.fill(0);
        std::hint::black_box(capability_hex.as_mut_slice());

        let (missing_endpoint, missing_connection) = connect_proxy_client(proxy.local_addr()).await;
        let missing = perform_proxy_handshake_with_capability(&missing_connection, None).await;
        assert!(!missing.accepted);
        assert_eq!(missing.message.as_deref(), Some("authentication failed"));
        assert!(missing.manifest.is_none());
        missing_connection.close(VarInt::from_u32(0), b"done");
        missing_endpoint.wait_idle().await;

        let mut wrong_capability = proxy_client_capability(&proxy);
        wrong_capability[0] ^= 1;
        let (wrong_endpoint, wrong_connection) = connect_proxy_client(proxy.local_addr()).await;
        let wrong =
            perform_proxy_handshake_with_capability(&wrong_connection, Some(wrong_capability))
                .await;
        assert!(!wrong.accepted);
        assert_eq!(wrong.message.as_deref(), Some("authentication failed"));
        assert!(wrong.manifest.is_none());
        wrong_connection.close(VarInt::from_u32(0), b"done");
        wrong_endpoint.wait_idle().await;

        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn norito_bridge_streams_spool_payload() {
        let spool_dir = TempDir::new().expect("tempdir");
        let spool_root = spool_dir.path().join("routes");
        tokio::fs::create_dir_all(&spool_root)
            .await
            .expect("create norito spool");
        let spool_path = spool_root.join("route-alpha.norito");
        tokio::fs::write(&spool_path, b"norito-bytes")
            .await
            .expect("write norito payload");
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.proxy_mode = ProxyMode::Bridge;
        config.emit_browser_manifest = false;
        config.norito_bridge = Some(ProxyNoritoBridgeConfig {
            spool_dir: spool_dir.path().to_string_lossy().into_owned(),
            extension: Some("norito".into()),
        });
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "norito".into(),
            authority: Some("torii.dev:9443".into()),
            target: Some("routes/route-alpha".into()),
            route_policy_id: Some("policy-alpha".into()),
            exit_country: Some("JP".into()),
            client_id: Some("test-client".into()),
        };
        let (mut stream_send, mut stream_recv, stream_ack) =
            open_proxy_stream(&connection, &open_frame).await;
        assert!(stream_ack.accepted);
        assert_eq!(stream_ack.code, STREAM_ACK_OK);
        stream_send.finish().expect("finish stream open");
        let payload = stream_recv
            .read_to_end(16 * 1024 * 1024)
            .await
            .expect("read norito payload");
        assert_eq!(payload, b"norito-bytes");
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn car_bridge_streams_archive() {
        let cache_dir = TempDir::new().expect("tempdir");
        let cache_root = cache_dir.path().join("archives");
        tokio::fs::create_dir_all(&cache_root)
            .await
            .expect("create car cache");
        let car_path = cache_root.join("ledger.car");
        tokio::fs::write(&car_path, b"car-bytes")
            .await
            .expect("write car payload");
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.proxy_mode = ProxyMode::Bridge;
        config.emit_browser_manifest = false;
        config.car_bridge = Some(ProxyCarBridgeConfig {
            cache_dir: cache_dir.path().to_string_lossy().into_owned(),
            extension: Some("car".into()),
            allow_zst: false,
        });
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "car".into(),
            authority: Some("torii.dev:9443".into()),
            target: Some("archives/ledger".into()),
            route_policy_id: Some("policy-alpha".into()),
            exit_country: Some("JP".into()),
            client_id: Some("test-client".into()),
        };
        let (mut stream_send, mut stream_recv, stream_ack) =
            open_proxy_stream(&connection, &open_frame).await;
        assert!(stream_ack.accepted);
        assert_eq!(stream_ack.code, STREAM_ACK_OK);
        stream_send.finish().expect("finish stream open");
        let payload = stream_recv
            .read_to_end(16 * 1024 * 1024)
            .await
            .expect("read car payload");
        assert_eq!(payload, b"car-bytes");
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn kaigi_bridge_streams_spool_payload_with_policy() {
        let spool_dir = TempDir::new().expect("tempdir");
        let spool_root = spool_dir.path().join("kaigi");
        tokio::fs::create_dir_all(&spool_root)
            .await
            .expect("create kaigi spool");
        let spool_path = spool_root.join("room-alpha.norito");
        tokio::fs::write(&spool_path, b"kaigi-bytes")
            .await
            .expect("write kaigi payload");
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.proxy_mode = ProxyMode::Bridge;
        config.emit_browser_manifest = false;
        config.guard_cache_key_hex = Some(TEST_GUARD_KEY.into());
        config.kaigi_bridge = Some(ProxyKaigiBridgeConfig {
            spool_dir: spool_dir.path().to_string_lossy().into_owned(),
            extension: Some("norito".into()),
            room_policy: Some("authenticated".into()),
        });
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "kaigi".into(),
            authority: Some("kaigi.example:9443".into()),
            target: Some("kaigi/room-alpha".into()),
            route_policy_id: Some("policy-kaigi".into()),
            exit_country: Some("SG".into()),
            client_id: Some("kaigi-client".into()),
        };
        let (mut stream_send, mut stream_recv, stream_ack) =
            open_proxy_stream(&connection, &open_frame).await;
        assert!(stream_ack.accepted);
        assert_eq!(stream_ack.code, STREAM_ACK_OK);
        assert_eq!(
            stream_ack.message.as_deref(),
            Some("room-policy=authenticated")
        );
        let cache_tag = stream_ack
            .cache_tag_hex
            .as_ref()
            .expect("kaigi ack should include cache tag");
        assert_eq!(cache_tag.len(), 32);
        stream_send.finish().expect("finish stream open");
        let payload = stream_recv
            .read_to_end(16 * 1024 * 1024)
            .await
            .expect("read kaigi payload");
        assert_eq!(payload, b"kaigi-bytes");
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn tcp_stream_bridge_rejects_loopback_ssrf() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "127.0.0.1:0".into();
        config.proxy_mode = ProxyMode::Bridge;
        config.emit_browser_manifest = false;
        config.guard_cache_key_hex = Some(TEST_GUARD_KEY.into());
        let Some(proxy) = spawn_proxy_or_skip(config) else {
            return;
        };
        let proxy_addr = proxy.local_addr();
        let (endpoint, connection) = connect_proxy_client(proxy_addr).await;
        let handshake_ack = perform_proxy_handshake(&connection, &proxy).await;
        assert!(handshake_ack.accepted);
        let open_frame = ProxyStreamOpenV1 {
            version: PROXY_STREAM_VERSION,
            service: "tcp".into(),
            authority: Some("127.0.0.1:8080".into()),
            target: None,
            route_policy_id: None,
            exit_country: None,
            client_id: Some("browser".into()),
        };
        let (mut stream_send, mut stream_recv, stream_ack) =
            open_proxy_stream(&connection, &open_frame).await;
        assert!(!stream_ack.accepted);
        assert_eq!(stream_ack.code, STREAM_ACK_BAD_REQUEST);
        assert!(stream_ack.cache_tag_hex.is_none());
        let _ = stream_send.finish();
        let _ = stream_recv.stop(VarInt::from_u32(0));
        connection.close(VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;
        proxy.shutdown().await;
    }
    async fn connect_proxy_client(proxy_addr: SocketAddr) -> (Endpoint, quinn::Connection) {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("endpoint");
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(NoCertificateVerification);
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![PROXY_ALPN_LABEL.as_bytes().to_vec()];
        let tls_config = Arc::new(tls_config);
        let crypto =
            QuinnRustlsClientConfig::try_from(Arc::clone(&tls_config)).expect("client crypto");
        let client_config = ClientConfig::new(Arc::new(crypto));
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(proxy_addr, "localhost")
            .expect("connect request");
        let connection = connecting.await.expect("proxy handshake");
        (endpoint, connection)
    }
    fn proxy_client_capability(proxy: &LocalQuicProxyHandle) -> [u8; PROXY_CLIENT_CAPABILITY_LEN] {
        let exported = proxy.export_client_capability();
        let mut capability = [0_u8; PROXY_CLIENT_CAPABILITY_LEN];
        capability.copy_from_slice(exported.expose_bytes_for_handshake());
        capability
    }
    async fn perform_proxy_handshake(
        connection: &quinn::Connection,
        proxy: &LocalQuicProxyHandle,
    ) -> ProxyHandshakeAckV1 {
        perform_proxy_handshake_with_capability(connection, Some(proxy_client_capability(proxy)))
            .await
    }
    async fn perform_proxy_handshake_with_capability(
        connection: &quinn::Connection,
        client_capability: Option<[u8; PROXY_CLIENT_CAPABILITY_LEN]>,
    ) -> ProxyHandshakeAckV1 {
        let (mut handshake_send, mut handshake_recv) =
            connection.open_bi().await.expect("open handshake stream");
        let handshake = ProxyHandshakeV1 {
            version: PROXY_HANDSHAKE_VERSION,
            client_capability,
            client: Some("test-client".into()),
            user_agent: Some("orchestrator-test".into()),
        };
        write_frame(&mut handshake_send, &handshake)
            .await
            .expect("write handshake");
        handshake_send.finish().expect("finish handshake send");
        let ack_bytes = read_frame(&mut handshake_recv)
            .await
            .expect("read handshake ack");
        let ack: ProxyHandshakeAckV1 = decode_from_bytes(&ack_bytes).expect("decode handshake ack");
        assert_eq!(ack.version, PROXY_HANDSHAKE_VERSION);
        let _ = ack.message.as_ref();
        ack
    }
    async fn open_proxy_stream(
        connection: &quinn::Connection,
        open_frame: &ProxyStreamOpenV1,
    ) -> (quinn::SendStream, quinn::RecvStream, ProxyStreamAckV1) {
        let (mut stream_send, mut stream_recv) =
            connection.open_bi().await.expect("open application stream");
        write_frame(&mut stream_send, open_frame)
            .await
            .expect("write stream open");
        let ack_bytes = read_frame(&mut stream_recv).await.expect("read stream ack");
        let ack: ProxyStreamAckV1 = decode_from_bytes(&ack_bytes).expect("decode stream ack");
        assert_eq!(ack.version, PROXY_STREAM_VERSION);
        let _ = ack.message.as_ref();
        (stream_send, stream_recv, ack)
    }
    #[derive(Debug)]
    struct NoCertificateVerification;
    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }
}
#[cfg(all(test, not(feature = "local-quic-proxy")))]
mod tests {
    use super::*;
    #[test]
    fn spawn_local_quic_proxy_reports_disabled_feature() {
        let result = spawn_local_quic_proxy(LocalQuicProxyConfig::default());
        match result {
            Err(ProxyError::Unavailable) => {}
            Ok(_) => panic!("local QUIC proxy must not spawn without the feature"),
            Err(other) => panic!("expected unavailable feature error, got {other}"),
        }
    }
    #[test]
    fn disabled_proxy_still_validates_loopback_binding() {
        let mut config = LocalQuicProxyConfig::default();
        config.bind_addr = "0.0.0.0:0".into();
        let result = spawn_local_quic_proxy(config);
        match result {
            Err(ProxyError::BindAddressNotLoopback(addr)) => {
                assert_eq!(addr, "0.0.0.0:0".parse().expect("addr"));
            }
            Ok(_) => panic!("non-loopback bind must be rejected"),
            Err(other) => panic!("expected loopback bind rejection, got {other}"),
        }
    }
}
