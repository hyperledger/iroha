use crate::{Error, SharedAppState};
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
#[cfg(test)]
use iroha_core::kiso::KisoHandle;
use iroha_core::{
    smartcontracts::isi::vpn::vpn_lease_custody_account_id,
    state::{VPN_SETTLED_RECEIPT_HISTORY_LIMIT as MAX_RECEIPTS_PER_ACCOUNT, WorldReadOnly},
};
#[cfg(test)]
use iroha_crypto::Hash;
use iroha_crypto::{
    Algorithm, HashOf, KeyPair, PrivateKey, PublicKey,
    soranet::{certificate::select_vpn_endpoint, directory::GuardDirectorySnapshotV2},
};
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    asset::AssetDefinitionId,
    isi::{InstructionBox, OpenVpnLeaseEscrow, SettleVpnLease},
    permission::Permission,
    query::error::QueryExecutionFail,
    soranet::vpn::{
        VPN_DEFAULT_TUNNEL_MTU_BYTES, VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1, VpnAddressSlotV1,
        VpnExitClassV1, VpnHelperTicketV1, VpnLeaseRecordV1, VpnLeaseStatusV1, VpnQuoteBodyV1,
        VpnQuotePolicyV1, VpnSessionReceiptV1, VpnSignedQuoteV1, VpnSignedSessionReceiptV1,
        VpnTariffV1, VpnUsageVoucherV1, derive_vpn_address_plan_v1, derive_vpn_address_slot_v1,
        derive_vpn_lease_id_v1, derive_vpn_session_address_plan_v1, derive_vpn_session_id_v1,
        vpn_account_hash_v1 as account_hash, vpn_helper_network_policy_hash_v1,
        vpn_tariff_meter_hash_v1,
    },
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_executor_data_model::permission::soranet::CanIssueSoranetVpnQuote;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::{Numeric, Quantity, RoundingMode};
use iroha_torii_shared::configuration::Configuration;
use mv::storage::StorageReadOnly;
use norito::codec::Encode;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
const SUPPORTED_EXIT_CLASSES: [&str; 3] = ["standard", "low-latency", "high-security"];
const DEFAULT_TUNNEL_ADDRESSES: [&str; 2] = ["10.208.0.2/32", "fd53:7261:6574::2/128"];
// Runtime VPN session state is deliberately bounded independently of the
// number of registered accounts. Quotes are self-contained signed capabilities
// and are never retained here; the WSV lease is authoritative after payment.
// Ordered expiry indexes reclaim cached sessions without scanning.
const VPN_RUNTIME_ACCOUNT_CAPACITY: usize = 4_096;
/// Maximum request body accepted by any first-release VPN mutation route.
pub const VPN_MUTATION_REQUEST_MAX_BYTES_V1: usize = 16 * 1_024;
const VPN_MAX_SIGNED_RELAY_RECEIPT_NORITO_BYTES_V1: usize = 2 * 1_024;
const VPN_MAX_CLIENT_VOUCHER_NORITO_BYTES_V1: usize = 1_024;
/// Immutable VPN relay trust derived from an authenticated guard-directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnRelayTrust {
    /// Exact relay Ed25519 identity advertised by the signed certificate.
    pub relay_id: [u8; 32],
    /// Exact relay ML-DSA-65 identity advertised by the same signed certificate.
    pub relay_mldsa65_public_key: [u8; VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1],
    /// Exact signed QUIC endpoint selected for VPN traffic.
    pub relay_endpoint: String,
    /// Exact TLS DNS name selected for the endpoint.
    pub tls_server_name: String,
    /// Exact leaf SPKI SHA-256 pin selected for the endpoint.
    pub relay_tls_spki_sha256: [u8; 32],
    /// Descriptor commitment authenticated by the relay certificate.
    pub descriptor_commit: [u8; 32],
    /// SHA-256 digest of the canonical relay certificate bundle.
    pub relay_certificate_sha256: [u8; 32],
    /// Externally provisioned digest authenticating the exact directory snapshot.
    pub directory_snapshot_digest: [u8; 32],
    /// Exclusive upper bound on authenticated relay trust, in Unix milliseconds.
    pub valid_until_ms: u64,
}
impl VpnRelayTrust {
    /// Authenticate a directory snapshot and select one exact VPN relay endpoint.
    ///
    /// # Errors
    /// Returns an error if snapshot authentication or freshness fails, the relay
    /// is absent, or its certificate does not authorize a VPN endpoint.
    pub fn from_guard_directory_at(
        snapshot_bytes: &[u8],
        expected_snapshot_digest: [u8; 32],
        relay_id: [u8; 32],
        at_unix: i64,
    ) -> Result<Self, String> {
        let selected = GuardDirectorySnapshotV2::authenticate_relay_bytes_at(
            snapshot_bytes,
            expected_snapshot_digest,
            relay_id,
            at_unix,
        )
        .map_err(|error| format!("VPN guard directory authentication failed: {error}"))?;
        let snapshot_valid_until_unix = selected.snapshot_valid_until_unix;
        let bundle = selected.relay;
        if !bundle.certificate.roles.exit {
            return Err("VPN relay certificate does not authorize the exit role".to_owned());
        }
        let endpoint = select_vpn_endpoint(&bundle.certificate.endpoints)
            .map_err(|error| format!("VPN endpoint selection failed: {error}"))?;
        let canonical_bundle = bundle
            .try_to_cbor()
            .map_err(|error| format!("VPN relay certificate encode failed: {error}"))?;
        let relay_mldsa65_public_key = bundle
            .certificate
            .identity_mldsa65
            .as_slice()
            .try_into()
            .map_err(|_| "VPN relay certificate has an invalid ML-DSA-65 identity width")?;
        let valid_until_unix = snapshot_valid_until_unix.min(bundle.certificate.valid_until);
        let valid_until_ms = u64::try_from(valid_until_unix)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| "VPN relay trust validity exceeds Unix millisecond range".to_owned())?;
        Ok(Self {
            relay_id,
            relay_mldsa65_public_key,
            relay_endpoint: endpoint.quic_multiaddr.clone(),
            tls_server_name: endpoint.tls_server_name.clone(),
            relay_tls_spki_sha256: endpoint.tls_spki_sha256,
            descriptor_commit: bundle.certificate.descriptor_commit,
            relay_certificate_sha256: Sha256::digest(canonical_bundle).into(),
            directory_snapshot_digest: expected_snapshot_digest,
            valid_until_ms,
        })
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnProfileResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnProfileResponseDto {
    pub available: bool,
    pub relay_endpoint: String,
    pub supported_exit_classes: Vec<String>,
    pub default_exit_class: String,
    pub lease_secs: u64,
    pub dns_push_interval_secs: u64,
    pub meter_family: String,
    #[norito(default)]
    pub route_pushes: Vec<String>,
    #[norito(default)]
    pub excluded_routes: Vec<String>,
    #[norito(default)]
    pub dns_servers: Vec<String>,
    #[norito(default)]
    pub tunnel_addresses: Vec<String>,
    pub mtu_bytes: u64,
    pub display_billing_label: String,
    pub operator_account_id: String,
    pub lease_fee: Quantity,
    pub settlement_grace_secs: u64,
    pub flow_label_bits: u8,
    pub padding_budget_ms: u16,
    pub relay_id_hex: String,
    pub relay_mldsa65_public_key_hex: String,
    pub descriptor_commit_hex: String,
    pub tls_server_name: String,
    pub relay_tls_spki_sha256_hex: String,
    pub relay_certificate_sha256_hex: String,
    pub directory_snapshot_digest_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnQuoteCreateRequestDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
#[norito(deny_unknown_fields)]
pub struct VpnQuoteCreateRequestDto {
    #[norito(default)]
    pub exit_class: String,
    #[norito(default)]
    pub metering_public_key_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnQuoteResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnQuoteResponseDto {
    pub quote_id: String,
    pub lease_id_hex: String,
    pub session_id_hex: String,
    pub payment_reference: String,
    pub account_id: String,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub lease_secs: u64,
    pub quote_expires_at_ms: u64,
    pub fee_asset_id: String,
    pub escrow_account_id: String,
    pub operator_account_id: String,
    pub lease_fee: Quantity,
    pub route_pushes: Vec<String>,
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub tunnel_addresses: Vec<String>,
    pub mtu_bytes: u64,
    pub meter_family: String,
    pub flow_label_bits: u8,
    pub padding_budget_ms: u16,
    pub relay_id_hex: String,
    pub relay_mldsa65_public_key_hex: String,
    pub descriptor_commit_hex: String,
    pub tls_server_name: String,
    pub relay_tls_spki_sha256_hex: String,
    pub relay_certificate_sha256_hex: String,
    pub directory_snapshot_digest_hex: String,
    pub metering_public_key_hex: String,
    pub open_lease_instruction: VpnTxInstructionDto,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnSessionCreateRequestDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
#[norito(deny_unknown_fields)]
pub struct VpnSessionCreateRequestDto {
    #[norito(default)]
    pub exit_class: String,
    #[norito(default)]
    pub quote_id: String,
    #[norito(default)]
    pub payment_tx_hash: String,
    #[norito(default)]
    pub metering_public_key_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnSessionResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnSessionResponseDto {
    pub session_id: String,
    pub account_id: String,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub lease_secs: u64,
    pub expires_at_ms: u64,
    pub connected_at_ms: u64,
    pub meter_family: String,
    pub quote_id: String,
    pub payment_reference: String,
    pub payment_tx_hash: String,
    pub fee_asset_id: String,
    pub escrow_account_id: String,
    pub operator_account_id: String,
    pub lease_fee: Quantity,
    pub flow_label_bits: u8,
    pub padding_budget_ms: u16,
    pub relay_id_hex: String,
    pub relay_mldsa65_public_key_hex: String,
    pub descriptor_commit_hex: String,
    pub tls_server_name: String,
    pub relay_tls_spki_sha256_hex: String,
    pub relay_certificate_sha256_hex: String,
    pub directory_snapshot_digest_hex: String,
    #[norito(default)]
    pub route_pushes: Vec<String>,
    #[norito(default)]
    pub excluded_routes: Vec<String>,
    #[norito(default)]
    pub dns_servers: Vec<String>,
    #[norito(default)]
    pub tunnel_addresses: Vec<String>,
    pub mtu_bytes: u64,
    pub helper_ticket_hex: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnReceiptResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnReceiptResponseDto {
    pub session_id: String,
    pub account_id: String,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub meter_family: String,
    pub connected_at_ms: u64,
    pub disconnected_at_ms: u64,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status: String,
    pub receipt_source: String,
    pub quote_id: String,
    pub payment_tx_hash: String,
    pub fee_asset_id: String,
    pub escrow_account_id: String,
    pub operator_account_id: String,
    pub lease_fee: Quantity,
    pub earned_fee: Quantity,
    pub refunded_fee: Quantity,
    #[norito(default)]
    pub lease_id_hex: String,
    #[norito(default)]
    pub settle_lease_instruction: Option<VpnTxInstructionDto>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnReceiptSubmitRequestDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
#[norito(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "Hex suffixes specify the wire encoding of each independent request field."
)]
pub struct VpnReceiptSubmitRequestDto {
    pub relay_receipt_hex: String,
    pub client_voucher_hex: String,
    #[norito(default)]
    pub lease_id_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnTxInstructionDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnTxInstructionDto {
    pub wire_id: String,
    pub payload_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::vpn::VpnReceiptListResponseDto")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    norito::derive::NoritoSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoDeserialize,
    PartialEq,
    Eq,
)]
pub struct VpnReceiptListResponseDto {
    #[norito(default)]
    pub items: Vec<VpnReceiptResponseDto>,
    pub total: u64,
}
#[derive(Debug, Clone)]
pub struct VpnSessionRecord {
    pub session_id: String,
    pub lease_id: [u8; 32],
    pub account_id: AccountId,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub lease_secs: u64,
    pub expires_at_ms: u64,
    pub connected_at_ms: u64,
    pub meter_family: String,
    pub quote_id: String,
    pub payment_reference: String,
    pub payment_tx_hash: String,
    pub fee_asset_id: String,
    pub escrow_account_id: AccountId,
    pub operator_account_id: AccountId,
    pub lease_fee: Quantity,
    pub tariff: VpnTariffV1,
    pub flow_label_bits: u8,
    pub padding_budget_ms: u16,
    pub relay_id: [u8; 32],
    pub relay_mldsa65_public_key: [u8; VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1],
    pub descriptor_commit: [u8; 32],
    pub tls_server_name: String,
    pub relay_tls_spki_sha256: [u8; 32],
    pub relay_certificate_sha256: [u8; 32],
    pub directory_snapshot_digest: [u8; 32],
    #[cfg(test)]
    pub relay_trust_valid_until_ms: u64,
    pub metering_public_key: PublicKey,
    pub route_pushes: Vec<String>,
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub tunnel_addresses: Vec<String>,
    pub mtu_bytes: u64,
    pub helper_ticket_hex: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
#[derive(Debug, Clone)]
pub struct VpnReceiptRecord {
    pub session_id: String,
    pub account_id: AccountId,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub meter_family: String,
    pub connected_at_ms: u64,
    pub disconnected_at_ms: u64,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status: String,
    pub receipt_source: String,
    pub quote_id: String,
    pub payment_tx_hash: String,
    pub fee_asset_id: String,
    pub escrow_account_id: AccountId,
    pub operator_account_id: AccountId,
    pub lease_fee: Quantity,
    pub earned_fee: Quantity,
    pub refunded_fee: Quantity,
    pub lease_id_hex: String,
    pub settle_lease_instruction: Option<VpnTxInstructionDto>,
}
#[derive(Debug, Clone)]
pub struct VpnQuoteRecord {
    pub quote_id: String,
    pub lease_id: [u8; 32],
    pub session_id: [u8; 16],
    pub signed_quote: VpnSignedQuoteV1,
    pub account_id: AccountId,
    pub exit_class: String,
    pub relay_endpoint: String,
    pub lease_secs: u64,
    pub quote_expires_at_ms: u64,
    pub payment_reference: String,
    pub fee_asset_id: String,
    pub escrow_account_id: AccountId,
    pub operator_account_id: AccountId,
    pub lease_fee: Quantity,
    pub tariff: VpnTariffV1,
    pub settlement_grace_ms: u64,
    pub metering_public_key: PublicKey,
    pub route_pushes: Vec<String>,
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub tunnel_addresses: Vec<String>,
    pub mtu_bytes: u64,
    pub meter_family: String,
    pub flow_label_bits: u8,
    pub padding_budget_ms: u16,
    pub relay_id: [u8; 32],
    pub relay_mldsa65_public_key: [u8; VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1],
    pub descriptor_commit: [u8; 32],
    pub tls_server_name: String,
    pub relay_tls_spki_sha256: [u8; 32],
    pub relay_certificate_sha256: [u8; 32],
    pub directory_snapshot_digest: [u8; 32],
    pub relay_trust_valid_until_ms: u64,
}
/// Reverse/expiry indexes, in-flight reservations, and the VPN session-cache bound.
///
/// The enclosing `vpn_state_lock` protects these indexes together with every
/// mutation of `vpn_sessions` and `vpn_used_payments`. Keeping the indexes
/// behind the same lock makes replacement, expiry, and exact removal atomic
/// without requiring request-time scans of the record maps.
#[derive(Debug)]
pub struct VpnRuntimeState {
    session_ids_by_account: HashMap<AccountId, String>,
    session_expirations: BTreeSet<(u64, String)>,
    settling_session_ids: HashSet<String>,
    session_capacity: usize,
    #[cfg(test)]
    session_account_lookups: usize,
    #[cfg(test)]
    settlement_reservations: usize,
}
impl Default for VpnRuntimeState {
    fn default() -> Self {
        Self {
            session_ids_by_account: HashMap::new(),
            session_expirations: BTreeSet::new(),
            settling_session_ids: HashSet::new(),
            session_capacity: VPN_RUNTIME_ACCOUNT_CAPACITY,
            #[cfg(test)]
            session_account_lookups: 0,
            #[cfg(test)]
            settlement_reservations: 0,
        }
    }
}
#[cfg(test)]
impl VpnRuntimeState {
    fn with_session_capacity(session_capacity: usize) -> Self {
        Self {
            session_capacity,
            ..Self::default()
        }
    }
}
fn now_ms() -> u64 {
    system_time_ms(SystemTime::now())
}
fn system_time_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}
fn conversion_error(message: impl Into<String>) -> Error {
    Error::Query(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
        message.into(),
    )))
}
fn not_permitted_error(message: impl Into<String>) -> Error {
    Error::Query(ValidationFail::NotPermitted(message.into()))
}
fn ensure_vpn_operator_ticket_signer(private_key: &PrivateKey) -> Result<(), Error> {
    if private_key.algorithm() != Algorithm::Ed25519 {
        return Err(not_permitted_error(
            "vpn operator quote and helper-ticket signing key must use Ed25519",
        ));
    }
    Ok(())
}
fn vpn_operator_ticket_signer<'a>(
    app: &'a SharedAppState,
    operator_account_id: &AccountId,
) -> Result<&'a KeyPair, Error> {
    let signer = app.vpn_operator_signer.as_ref().ok_or_else(|| {
        not_permitted_error("dedicated VPN operator signer is not configured on this Torii node")
    })?;
    ensure_vpn_operator_ticket_signer(signer.private_key())?;
    let signer_account_id = AccountId::new(signer.public_key().clone());
    if &signer_account_id != operator_account_id {
        return Err(not_permitted_error(
            "vpn operator account must match this Torii node's dedicated quote and helper-ticket signing key",
        ));
    }
    Ok(signer)
}
fn inconsistent_vpn_state(message: impl Into<String>) -> Error {
    Error::AppServiceUnavailable {
        code: "vpn_state_inconsistent",
        message: message.into(),
    }
}
fn normalize_exit_class(value: &str, default_value: &str) -> Result<String, Error> {
    let candidate = if value.trim().is_empty() {
        default_value.trim()
    } else {
        value.trim()
    };
    let parsed = VpnExitClassV1::try_from_label(candidate).map_err(|err| {
        conversion_error(format!(
            "exit_class must be one of {} ({err})",
            SUPPORTED_EXIT_CLASSES.join(", ")
        ))
    })?;
    Ok(parsed.as_label().to_owned())
}
fn default_tunnel_addresses() -> Vec<String> {
    DEFAULT_TUNNEL_ADDRESSES
        .iter()
        .map(|item| (*item).to_owned())
        .collect()
}
fn build_profile_at(
    dto: &Configuration,
    trust: Option<&VpnRelayTrust>,
    operator_signer_available: bool,
    current_ms: u64,
) -> VpnProfileResponseDto {
    let vpn = &dto.network.soranet_vpn;
    let trust = trust.filter(|trust| {
        vpn.enabled
            && operator_signer_available
            && vpn
                .lease_secs
                .checked_mul(1_000)
                .and_then(|duration_ms| current_ms.checked_add(duration_ms))
                .is_some_and(|lease_end_ms| lease_end_ms <= trust.valid_until_ms)
    });
    let relay_endpoint = trust
        .map(|trust| trust.relay_endpoint.clone())
        .unwrap_or_default();
    let default_exit_class = vpn.exit_class.trim().to_owned();
    let supported_exit_classes = SUPPORTED_EXIT_CLASSES
        .iter()
        .map(|item| (*item).to_owned())
        .collect::<Vec<_>>();
    VpnProfileResponseDto {
        available: trust.is_some(),
        relay_endpoint,
        supported_exit_classes,
        default_exit_class: default_exit_class.clone(),
        lease_secs: vpn.lease_secs,
        dns_push_interval_secs: vpn.dns_push_interval_secs,
        meter_family: vpn.meter_family.clone(),
        route_pushes: vpn.route_pushes.clone(),
        excluded_routes: vpn.excluded_routes.clone(),
        dns_servers: vpn.dns_servers.clone(),
        tunnel_addresses: default_tunnel_addresses(),
        mtu_bytes: u64::from(VPN_DEFAULT_TUNNEL_MTU_BYTES),
        display_billing_label: format!(
            "{default_exit_class} · {} · {} XOR",
            vpn.meter_family, vpn.lease_fee
        ),
        operator_account_id: vpn.operator_account_id.clone(),
        lease_fee: vpn.lease_fee.clone(),
        settlement_grace_secs: vpn.settlement_grace_secs,
        flow_label_bits: vpn.flow_label_bits,
        padding_budget_ms: vpn.padding_budget_ms,
        relay_id_hex: trust
            .map(|trust| hex::encode(trust.relay_id))
            .unwrap_or_default(),
        relay_mldsa65_public_key_hex: trust
            .map(|trust| hex::encode(trust.relay_mldsa65_public_key))
            .unwrap_or_default(),
        descriptor_commit_hex: trust
            .map(|trust| hex::encode(trust.descriptor_commit))
            .unwrap_or_default(),
        tls_server_name: trust
            .map(|trust| trust.tls_server_name.clone())
            .unwrap_or_default(),
        relay_tls_spki_sha256_hex: trust
            .map(|trust| hex::encode(trust.relay_tls_spki_sha256))
            .unwrap_or_default(),
        relay_certificate_sha256_hex: trust
            .map(|trust| hex::encode(trust.relay_certificate_sha256))
            .unwrap_or_default(),
        directory_snapshot_digest_hex: trust
            .map(|trust| hex::encode(trust.directory_snapshot_digest))
            .unwrap_or_default(),
    }
}
fn require_signed_request(
    app: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<AccountId, Error> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(app) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error);
            }
        };

    match crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    )? {
        Some(verified) => Ok(verified.account),
        None => Err(not_permitted_error("signed account headers are required")),
    }
}
fn decode_hex_32(raw: &str, field: &str) -> Result<[u8; 32], Error> {
    let normalized = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if normalized.len() != 64 {
        return Err(conversion_error(format!("{field} must decode to 32 bytes")));
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(normalized, &mut decoded)
        .map_err(|err| conversion_error(format!("{field}: {err}")))?;
    Ok(decoded)
}
fn parse_metering_public_key(raw: &str) -> Result<PublicKey, Error> {
    let normalized = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if normalized.is_empty() {
        return Err(conversion_error(
            "metering_public_key_hex must not be empty",
        ));
    }
    PublicKey::from_hex(Algorithm::Ed25519, normalized).map_err(|err| {
        conversion_error(format!(
            "metering_public_key_hex must be an Ed25519 public key hex payload: {err}"
        ))
    })
}
fn public_key_payload_hex(public_key: &PublicKey) -> Result<String, Error> {
    let (_, payload) = public_key
        .try_to_bytes()
        .map_err(|err| conversion_error(format!("metering public key is malformed: {err}")))?;
    Ok(hex::encode(payload))
}
fn xor_asset_definition_id() -> AssetDefinitionId {
    let domain =
        DomainId::parse_fully_qualified("universal.universal").expect("static XOR domain id");
    let name = Name::from_str("xor").expect("static XOR asset name");
    AssetDefinitionId::derive_from_components(domain, name)
}
fn parse_profile_account_id(raw: &str, field: &str) -> Result<AccountId, Error> {
    AccountId::parse_encoded(raw.trim())
        .map_err(|err| conversion_error(format!("{field} must be a canonical account id: {err}")))
}
fn active_fee_per_minute(lease_fee: &Quantity, lease_secs: u64) -> Result<Quantity, Error> {
    if lease_secs == 0 {
        return Err(conversion_error("vpn lease_secs must be greater than zero"));
    }
    lease_fee
        .try_mul_div_decimal_round(
            &Numeric::from(60_u64),
            &Numeric::from(lease_secs),
            9,
            RoundingMode::Ceil,
        )
        .map_err(|err| conversion_error(format!("vpn tariff arithmetic failed: {err}")))
}
fn vpn_tariff_for_lease(lease_fee: &Quantity, lease_secs: u64) -> Result<VpnTariffV1, Error> {
    Ok(VpnTariffV1 {
        lease_fee: lease_fee.clone(),
        active_fee_per_minute: active_fee_per_minute(lease_fee, lease_secs)?,
        ingress_fee_per_mib: Quantity::zero(),
        egress_fee_per_mib: Quantity::zero(),
    })
}
fn build_helper_ticket_hex(
    record: &VpnSessionRecord,
    expires_at_ms: u64,
    issuer_private_key: &PrivateKey,
) -> Result<String, Error> {
    let session_id = parse_vpn_session_id_hex(&record.session_id)?;
    let address_plan = derive_vpn_session_address_plan_v1(session_id);
    VpnHelperTicketV1 {
        session_id,
        quote_id: decode_hex_32(&record.quote_id, "quote_id")?,
        lease_id: record.lease_id,
        account_hash: account_hash(&record.account_id),
        relay_id: record.relay_id,
        payment_tx_hash: decode_hex_32(&record.payment_tx_hash, "payment_tx_hash")?,
        metering_public_key: record.metering_public_key.clone(),
        tariff: record.tariff.clone(),
        client_ipv4_address: address_plan.client_ipv4_address,
        client_ipv6_address: address_plan.client_ipv6_address,
        network_policy_hash: vpn_helper_network_policy_hash_v1(
            &record.relay_endpoint,
            &record.relay_id,
            &record.relay_mldsa65_public_key,
            &record.descriptor_commit,
            &record.tls_server_name,
            &record.relay_tls_spki_sha256,
            &record.relay_certificate_sha256,
            &record.directory_snapshot_digest,
            record.padding_budget_ms,
            &record.route_pushes,
            &record.excluded_routes,
            &record.dns_servers,
            &record.tunnel_addresses,
            record.mtu_bytes,
        ),
        valid_after_ms: record.connected_at_ms,
        expires_at_ms,
    }
    .try_to_hex(issuer_private_key)
    .map_err(|err| conversion_error(format!("invalid vpn helper ticket: {err}")))
}
fn build_quote_id(
    network_id: &iroha_data_model::NetworkId,
    account_id: &AccountId,
    metering_public_key: &PublicKey,
    exit_class: &str,
    nonce: &str,
    current_ms: u64,
) -> [u8; 32] {
    fn update_framed(hasher: &mut blake3::Hasher, value: &[u8]) {
        let length =
            u64::try_from(value.len()).expect("VPN quote-id components are bounded below u64::MAX");
        hasher.update(&length.to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = blake3::Hasher::new_derive_key("iroha.soranet.vpn.quote-id.v1");
    update_framed(&mut hasher, network_id.as_bytes());
    update_framed(&mut hasher, &account_id.encode());
    update_framed(&mut hasher, &metering_public_key.encode());
    update_framed(&mut hasher, exit_class.as_bytes());
    update_framed(&mut hasher, nonce.as_bytes());
    hasher.update(&current_ms.to_be_bytes());
    *hasher.finalize().as_bytes()
}
fn tx_instr_from_box(boxed: InstructionBox) -> VpnTxInstructionDto {
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(&boxed)
        .expect("instruction must have a canonical V1 wire identifier and Norito frame");
    VpnTxInstructionDto {
        wire_id: wire_id.to_owned(),
        payload_hex: hex::encode(framed),
    }
}
fn settle_lease_instruction(
    lease_id: [u8; 32],
    relay_receipt: VpnSignedSessionReceiptV1,
    voucher: VpnUsageVoucherV1,
) -> VpnTxInstructionDto {
    let instruction: InstructionBox = SettleVpnLease::new(lease_id, relay_receipt, voucher).into();
    tx_instr_from_box(instruction)
}
fn validate_quote_record_projection(
    record: &VpnQuoteRecord,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<(), Error> {
    record.signed_quote.verify().map_err(|error| {
        inconsistent_vpn_state(format!("stored VPN quote signature is invalid: {error}"))
    })?;
    let body = &record.signed_quote.body;
    let policy = &body.policy;
    let quote_id = hex::encode(body.quote_id);
    if &body.network_id != expected_network_id {
        return Err(inconsistent_vpn_state(
            "stored VPN quote belongs to a different exact network",
        ));
    }
    let canonical_lease_id =
        derive_vpn_lease_id_v1(&body.network_id, body.quote_id, &body.client_account_id);
    let canonical_session_id = derive_vpn_session_id_v1(
        &body.network_id,
        body.quote_id,
        &body.client_account_id,
        body.address_slot,
    );
    let signed_fee_asset_id = body.asset_definition.to_string();
    let signed_exit_class = policy.exit_class.as_label();
    if body.lease_id != canonical_lease_id || body.session_id != canonical_session_id {
        return Err(inconsistent_vpn_state(
            "stored VPN quote contains non-canonical lease or session identifiers",
        ));
    }
    macro_rules! require_projection {
        ($label:literal, $record_value:expr, $signed_value:expr) => {
            if $record_value != $signed_value {
                return Err(inconsistent_vpn_state(concat!(
                    "stored VPN quote ",
                    $label,
                    " projection differs from the signed quote"
                )));
            }
        };
    }
    require_projection!("quote id", &record.quote_id, &quote_id);
    require_projection!("payment reference", &record.payment_reference, &quote_id);
    require_projection!("lease id", &record.lease_id, &body.lease_id);
    require_projection!("session id", &record.session_id, &body.session_id);
    require_projection!("client", &record.account_id, &body.client_account_id);
    require_projection!(
        "operator",
        &record.operator_account_id,
        &body.operator_account_id
    );
    require_projection!(
        "metering key",
        &record.metering_public_key,
        &body.metering_public_key
    );
    require_projection!("tariff", &record.tariff, &body.tariff);
    require_projection!("lease fee", &record.lease_fee, &body.tariff.lease_fee);
    require_projection!("fee asset", &record.fee_asset_id, &signed_fee_asset_id);
    require_projection!(
        "quote expiry",
        &record.quote_expires_at_ms,
        &body.expires_at_ms
    );
    require_projection!(
        "settlement grace",
        &record.settlement_grace_ms,
        &body.settlement_grace_ms
    );
    if record.exit_class != signed_exit_class {
        return Err(inconsistent_vpn_state(
            "stored VPN quote exit class projection differs from the signed quote",
        ));
    }
    require_projection!(
        "relay endpoint",
        &record.relay_endpoint,
        &policy.relay_endpoint
    );
    require_projection!("lease duration", &record.lease_secs, &policy.lease_secs);
    require_projection!(
        "escrow",
        &record.escrow_account_id,
        &policy.escrow_account_id
    );
    require_projection!("meter family", &record.meter_family, &policy.meter_family);
    require_projection!("routes", &record.route_pushes, &policy.route_pushes);
    require_projection!(
        "excluded routes",
        &record.excluded_routes,
        &policy.excluded_routes
    );
    require_projection!("DNS", &record.dns_servers, &policy.dns_servers);
    require_projection!(
        "tunnel addresses",
        &record.tunnel_addresses,
        &policy.tunnel_addresses
    );
    require_projection!("MTU", &record.mtu_bytes, &policy.mtu_bytes);
    require_projection!(
        "flow label",
        &record.flow_label_bits,
        &policy.flow_label_bits
    );
    require_projection!(
        "padding budget",
        &record.padding_budget_ms,
        &policy.padding_budget_ms
    );
    require_projection!("relay id", &record.relay_id, &policy.relay_id);
    require_projection!(
        "relay ML-DSA-65 identity",
        &record.relay_mldsa65_public_key,
        &policy.relay_mldsa65_public_key
    );
    require_projection!(
        "descriptor commitment",
        &record.descriptor_commit,
        &policy.descriptor_commit
    );
    require_projection!(
        "TLS server name",
        &record.tls_server_name,
        &policy.tls_server_name
    );
    require_projection!(
        "TLS SPKI",
        &record.relay_tls_spki_sha256,
        &policy.relay_tls_spki_sha256
    );
    require_projection!(
        "relay certificate",
        &record.relay_certificate_sha256,
        &policy.relay_certificate_sha256
    );
    require_projection!(
        "directory snapshot",
        &record.directory_snapshot_digest,
        &policy.directory_snapshot_digest
    );
    require_projection!(
        "relay trust expiry",
        &record.relay_trust_valid_until_ms,
        &policy.relay_trust_valid_until_ms
    );
    Ok(())
}
fn quote_record_from_lease(
    lease: &VpnLeaseRecordV1,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<VpnQuoteRecord, Error> {
    let signed_quote = &lease.signed_quote;
    let body = &signed_quote.body;
    let policy = &body.policy;
    let expected_address_slot = derive_vpn_address_slot_v1(body.quote_id);
    if lease.lease_id != body.lease_id
        || lease.session_id != body.session_id
        || lease.quote_id != body.quote_id
        || lease.client_account_id != body.client_account_id
        || lease.operator_account_id != body.operator_account_id
        || lease.metering_public_key != body.metering_public_key
        || lease.asset_definition != body.asset_definition
        || lease.lease_fee != body.tariff.lease_fee
        || lease.custody_account_id != policy.escrow_account_id
        || lease.relay_id != policy.relay_id
        || lease.tariff != body.tariff
        || lease.quote_policy != *policy
        || lease.address_slot != body.address_slot
        || body.address_slot != expected_address_slot
        || lease.expires_at_ms != body.expires_at_ms
        || lease.settlement_grace_ms != body.settlement_grace_ms
        || lease.opened_at_ms < body.valid_after_ms
        || lease.opened_at_ms >= body.expires_at_ms
    {
        return Err(inconsistent_vpn_state(
            "consensus VPN lease differs from its retained signed quote",
        ));
    }
    let quote_id = hex::encode(body.quote_id);
    let record = VpnQuoteRecord {
        quote_id: quote_id.clone(),
        lease_id: body.lease_id,
        session_id: body.session_id,
        signed_quote: signed_quote.clone(),
        account_id: body.client_account_id.clone(),
        exit_class: policy.exit_class.as_label().to_owned(),
        relay_endpoint: policy.relay_endpoint.clone(),
        lease_secs: policy.lease_secs,
        quote_expires_at_ms: body.expires_at_ms,
        payment_reference: quote_id,
        fee_asset_id: body.asset_definition.to_string(),
        escrow_account_id: policy.escrow_account_id.clone(),
        operator_account_id: body.operator_account_id.clone(),
        lease_fee: body.tariff.lease_fee.clone(),
        tariff: body.tariff.clone(),
        settlement_grace_ms: body.settlement_grace_ms,
        metering_public_key: body.metering_public_key.clone(),
        route_pushes: policy.route_pushes.clone(),
        excluded_routes: policy.excluded_routes.clone(),
        dns_servers: policy.dns_servers.clone(),
        tunnel_addresses: policy.tunnel_addresses.clone(),
        mtu_bytes: policy.mtu_bytes,
        meter_family: policy.meter_family.clone(),
        flow_label_bits: policy.flow_label_bits,
        padding_budget_ms: policy.padding_budget_ms,
        relay_id: policy.relay_id,
        relay_mldsa65_public_key: policy.relay_mldsa65_public_key,
        descriptor_commit: policy.descriptor_commit,
        tls_server_name: policy.tls_server_name.clone(),
        relay_tls_spki_sha256: policy.relay_tls_spki_sha256,
        relay_certificate_sha256: policy.relay_certificate_sha256,
        directory_snapshot_digest: policy.directory_snapshot_digest,
        relay_trust_valid_until_ms: policy.relay_trust_valid_until_ms,
    };
    validate_quote_record_projection(&record, expected_network_id)?;
    Ok(record)
}
fn open_lease_instruction(
    record: &VpnQuoteRecord,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<VpnTxInstructionDto, Error> {
    validate_quote_record_projection(record, expected_network_id)?;
    let instruction: InstructionBox = OpenVpnLeaseEscrow::new(record.signed_quote.clone()).into();
    Ok(tx_instr_from_box(instruction))
}
fn ensure_vpn_quote_operator_authorized(
    app: &SharedAppState,
    operator_account_id: &AccountId,
) -> Result<(), Error> {
    let required_permission: Permission = CanIssueSoranetVpnQuote.into();
    let world = app.state.world_view();
    let direct = world
        .account_permissions_iter(operator_account_id)
        .map_err(|error| {
            not_permitted_error(format!(
                "cannot resolve configured VPN operator authority: {error}"
            ))
        })?
        .any(|permission| permission == &required_permission);
    let through_role = world
        .account_roles_iter(operator_account_id)
        .any(|role_id| {
            world.roles().get(role_id).is_some_and(|role| {
                role.permissions()
                    .any(|permission| permission == &required_permission)
            })
        });
    if direct || through_role {
        Ok(())
    } else {
        Err(not_permitted_error(
            "configured VPN operator does not hold CanIssueSoranetVpnQuote",
        ))
    }
}
fn settlement_lease_id_from_request_or_index(
    request: &VpnReceiptSubmitRequestDto,
    indexed_lease_id: [u8; 32],
) -> Result<([u8; 32], String), Error> {
    let lease_id_hex = request.lease_id_hex.trim();
    if lease_id_hex.is_empty() {
        return Ok((indexed_lease_id, hex::encode(indexed_lease_id)));
    }
    let lease_id = decode_hex_32(lease_id_hex, "lease_id_hex")?;
    if lease_id != indexed_lease_id {
        return Err(not_permitted_error(
            "lease_id_hex does not match the consensus-indexed VPN session",
        ));
    }
    Ok((lease_id, hex::encode(lease_id)))
}
fn quote_response_from_record(
    record: &VpnQuoteRecord,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<VpnQuoteResponseDto, Error> {
    let open_lease_instruction = open_lease_instruction(record, expected_network_id)?;
    Ok(VpnQuoteResponseDto {
        quote_id: record.quote_id.clone(),
        lease_id_hex: hex::encode(record.lease_id),
        session_id_hex: hex::encode(record.session_id),
        payment_reference: record.payment_reference.clone(),
        account_id: record.account_id.to_string(),
        exit_class: record.exit_class.clone(),
        relay_endpoint: record.relay_endpoint.clone(),
        lease_secs: record.lease_secs,
        quote_expires_at_ms: record.quote_expires_at_ms,
        fee_asset_id: record.fee_asset_id.clone(),
        escrow_account_id: record.escrow_account_id.to_string(),
        operator_account_id: record.operator_account_id.to_string(),
        lease_fee: record.lease_fee.clone(),
        route_pushes: record.route_pushes.clone(),
        excluded_routes: record.excluded_routes.clone(),
        dns_servers: record.dns_servers.clone(),
        tunnel_addresses: record.tunnel_addresses.clone(),
        mtu_bytes: record.mtu_bytes,
        meter_family: record.meter_family.clone(),
        flow_label_bits: record.flow_label_bits,
        padding_budget_ms: record.padding_budget_ms,
        relay_id_hex: hex::encode(record.relay_id),
        relay_mldsa65_public_key_hex: hex::encode(record.relay_mldsa65_public_key),
        descriptor_commit_hex: hex::encode(record.descriptor_commit),
        tls_server_name: record.tls_server_name.clone(),
        relay_tls_spki_sha256_hex: hex::encode(record.relay_tls_spki_sha256),
        relay_certificate_sha256_hex: hex::encode(record.relay_certificate_sha256),
        directory_snapshot_digest_hex: hex::encode(record.directory_snapshot_digest),
        metering_public_key_hex: public_key_payload_hex(&record.metering_public_key)?,
        open_lease_instruction,
    })
}
fn response_from_record(record: &VpnSessionRecord) -> VpnSessionResponseDto {
    VpnSessionResponseDto {
        session_id: record.session_id.clone(),
        account_id: record.account_id.to_string(),
        exit_class: record.exit_class.clone(),
        relay_endpoint: record.relay_endpoint.clone(),
        lease_secs: record.lease_secs,
        expires_at_ms: record.expires_at_ms,
        connected_at_ms: record.connected_at_ms,
        meter_family: record.meter_family.clone(),
        quote_id: record.quote_id.clone(),
        payment_reference: record.payment_reference.clone(),
        payment_tx_hash: record.payment_tx_hash.clone(),
        fee_asset_id: record.fee_asset_id.clone(),
        escrow_account_id: record.escrow_account_id.to_string(),
        operator_account_id: record.operator_account_id.to_string(),
        lease_fee: record.lease_fee.clone(),
        flow_label_bits: record.flow_label_bits,
        padding_budget_ms: record.padding_budget_ms,
        relay_id_hex: hex::encode(record.relay_id),
        relay_mldsa65_public_key_hex: hex::encode(record.relay_mldsa65_public_key),
        descriptor_commit_hex: hex::encode(record.descriptor_commit),
        tls_server_name: record.tls_server_name.clone(),
        relay_tls_spki_sha256_hex: hex::encode(record.relay_tls_spki_sha256),
        relay_certificate_sha256_hex: hex::encode(record.relay_certificate_sha256),
        directory_snapshot_digest_hex: hex::encode(record.directory_snapshot_digest),
        route_pushes: record.route_pushes.clone(),
        excluded_routes: record.excluded_routes.clone(),
        dns_servers: record.dns_servers.clone(),
        tunnel_addresses: record.tunnel_addresses.clone(),
        mtu_bytes: record.mtu_bytes,
        helper_ticket_hex: record.helper_ticket_hex.clone(),
        bytes_in: record.bytes_in,
        bytes_out: record.bytes_out,
        status: "active".to_owned(),
    }
}
fn receipt_response_from_record(record: &VpnReceiptRecord) -> VpnReceiptResponseDto {
    VpnReceiptResponseDto {
        session_id: record.session_id.clone(),
        account_id: record.account_id.to_string(),
        exit_class: record.exit_class.clone(),
        relay_endpoint: record.relay_endpoint.clone(),
        meter_family: record.meter_family.clone(),
        connected_at_ms: record.connected_at_ms,
        disconnected_at_ms: record.disconnected_at_ms,
        duration_ms: record.duration_ms,
        bytes_in: record.bytes_in,
        bytes_out: record.bytes_out,
        status: record.status.clone(),
        receipt_source: record.receipt_source.clone(),
        quote_id: record.quote_id.clone(),
        payment_tx_hash: record.payment_tx_hash.clone(),
        fee_asset_id: record.fee_asset_id.clone(),
        escrow_account_id: record.escrow_account_id.to_string(),
        operator_account_id: record.operator_account_id.to_string(),
        lease_fee: record.lease_fee.clone(),
        earned_fee: record.earned_fee.clone(),
        refunded_fee: record.refunded_fee.clone(),
        lease_id_hex: record.lease_id_hex.clone(),
        settle_lease_instruction: record.settle_lease_instruction.clone(),
    }
}
fn build_pending_settlement_receipt_record(
    record: &VpnSessionRecord,
    signed_relay_receipt: &VpnSignedSessionReceiptV1,
    voucher: &VpnUsageVoucherV1,
    lease_id: [u8; 32],
    lease_id_hex: String,
) -> Result<VpnReceiptRecord, Error> {
    let relay_receipt = &signed_relay_receipt.receipt;
    let connected_at_ms = relay_receipt.started_at_ms.max(record.connected_at_ms);
    let disconnected_at_ms = relay_receipt.ended_at_ms;
    let duration_ms = relay_receipt
        .ended_at_ms
        .saturating_sub(relay_receipt.started_at_ms);
    let earned_fee = if relay_receipt.earned_fee > record.lease_fee {
        record.lease_fee.clone()
    } else {
        relay_receipt.earned_fee.clone()
    };
    let refunded_fee = record
        .lease_fee
        .checked_sub(&earned_fee)
        .map_err(|err| conversion_error(format!("vpn refund arithmetic failed: {err}")))?;
    Ok(VpnReceiptRecord {
        session_id: record.session_id.clone(),
        account_id: record.account_id.clone(),
        exit_class: record.exit_class.clone(),
        relay_endpoint: record.relay_endpoint.clone(),
        meter_family: record.meter_family.clone(),
        connected_at_ms,
        disconnected_at_ms,
        duration_ms,
        bytes_in: relay_receipt.ingress_bytes,
        bytes_out: relay_receipt.egress_bytes,
        status: "settlement_pending".to_owned(),
        receipt_source: "relay".to_owned(),
        quote_id: record.quote_id.clone(),
        payment_tx_hash: record.payment_tx_hash.clone(),
        fee_asset_id: record.fee_asset_id.clone(),
        escrow_account_id: record.escrow_account_id.clone(),
        operator_account_id: record.operator_account_id.clone(),
        lease_fee: record.lease_fee.clone(),
        earned_fee,
        refunded_fee,
        lease_id_hex,
        settle_lease_instruction: Some(settle_lease_instruction(
            lease_id,
            signed_relay_receipt.clone(),
            voucher.clone(),
        )),
    })
}
#[cfg(test)]
fn store_receipt(app: &SharedAppState, receipt: VpnReceiptRecord) {
    let key = receipt.account_id.clone();
    let mut entry = app.vpn_receipts.entry(key).or_default();
    entry.insert(0, receipt);
    if entry.len() > MAX_RECEIPTS_PER_ACCOUNT {
        entry.truncate(MAX_RECEIPTS_PER_ACCOUNT);
    }
}
fn lock_vpn_runtime(app: &SharedAppState) -> std::sync::MutexGuard<'_, VpnRuntimeState> {
    app.vpn_state_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[cfg(test)]
fn remove_session_by_id_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    session_id: &str,
) -> Option<VpnSessionRecord> {
    let record = app
        .vpn_sessions
        .get(session_id)
        .map(|entry| entry.clone())?;
    remove_session_record_locked(app, state, &record)
}
fn remove_session_record_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    expected: &VpnSessionRecord,
) -> Option<VpnSessionRecord> {
    let removed = app
        .vpn_sessions
        .remove(&expected.session_id)
        .map(|(_, record)| record);
    let account_key = &expected.account_id;
    if state
        .session_ids_by_account
        .get(account_key)
        .is_some_and(|indexed_id| indexed_id == &expected.session_id)
    {
        state.session_ids_by_account.remove(account_key);
    }
    state
        .session_expirations
        .remove(&(expected.expires_at_ms, expected.session_id.clone()));
    app.vpn_used_payments.remove(&expected.payment_tx_hash);
    if let Some(record) = removed.as_ref() {
        app.vpn_used_payments.remove(&record.payment_tx_hash);
    }
    removed
}

fn remove_session_candidate_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    expected: &VpnSessionRecord,
) -> bool {
    let Some(current) = app
        .vpn_sessions
        .get(&expected.session_id)
        .map(|entry| entry.clone())
    else {
        return false;
    };
    if current.lease_id != expected.lease_id {
        return false;
    }
    remove_session_record_locked(app, state, &current).is_some()
}

fn reclaim_expired_sessions_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    current_ms: u64,
) {
    let mut reserved_expirations = Vec::new();
    while let Some((expires_at_ms, session_id)) = state
        .session_expirations
        .first()
        .filter(|(expires_at_ms, _)| *expires_at_ms <= current_ms)
        .cloned()
    {
        state
            .session_expirations
            .remove(&(expires_at_ms, session_id.clone()));
        let Some(record) = app.vpn_sessions.get(&session_id).map(|entry| entry.clone()) else {
            continue;
        };
        if record.expires_at_ms != expires_at_ms {
            continue;
        }
        if state.settling_session_ids.contains(&session_id) {
            // Keep the entry out of the ordered set during this sweep so later
            // expired sessions can still be reclaimed. Restoring it afterward
            // preserves expiry tracking if the wall clock moves backward before
            // the reservation drop path runs.
            reserved_expirations.push((expires_at_ms, session_id));
            continue;
        }
        let _ = remove_session_record_locked(app, state, &record);
    }
    state.session_expirations.extend(reserved_expirations);
}
fn session_for_account_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    account_id: &AccountId,
) -> Option<VpnSessionRecord> {
    #[cfg(test)]
    {
        state.session_account_lookups += 1;
    }
    let session_id = state.session_ids_by_account.get(account_id)?.clone();
    let record = app.vpn_sessions.get(&session_id).map(|entry| entry.clone());
    match record {
        Some(record) if &record.account_id == account_id => Some(record),
        _ => {
            // Self-heal only the authenticated account's stale reverse entry.
            state.session_ids_by_account.remove(account_id);
            None
        }
    }
}
fn expire_session_record_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    record: &VpnSessionRecord,
    current_ms: u64,
) -> bool {
    if record.expires_at_ms > current_ms {
        return false;
    }
    if state.settling_session_ids.contains(&record.session_id) {
        return true;
    }
    let _ = remove_session_record_locked(app, state, record);
    true
}
fn expire_session_for_account_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    account_id: &AccountId,
    current_ms: u64,
) {
    let Some(record) = session_for_account_locked(app, state, account_id) else {
        return;
    };
    let _ = expire_session_record_locked(app, state, &record, current_ms);
}
fn session_by_id_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    session_id: &str,
    current_ms: u64,
) -> Option<VpnSessionRecord> {
    let record = app
        .vpn_sessions
        .get(session_id)
        .map(|entry| entry.clone())?;
    if expire_session_record_locked(app, state, &record, current_ms) {
        return None;
    }
    Some(record)
}
fn reserve_session_settlement_locked(
    state: &mut VpnRuntimeState,
    session_id: &str,
) -> Result<(), Error> {
    if state.settling_session_ids.contains(session_id) {
        return Err(not_permitted_error(
            "vpn session receipt settlement is already in progress",
        ));
    }
    if state.settling_session_ids.len() >= state.session_capacity {
        return Err(not_permitted_error(
            "vpn runtime settlement capacity is exhausted",
        ));
    }
    state.settling_session_ids.insert(session_id.to_owned());
    #[cfg(test)]
    {
        state.settlement_reservations = state.settlement_reservations.saturating_add(1);
    }
    Ok(())
}
struct VpnSettlementReservation {
    app: SharedAppState,
    session_id: String,
    active: bool,
}
impl VpnSettlementReservation {
    fn reserve(app: &SharedAppState, session_id: String) -> Result<Self, Error> {
        {
            let mut state = lock_vpn_runtime(app);
            reserve_session_settlement_locked(&mut state, &session_id)?;
        }
        Ok(Self {
            app: app.clone(),
            session_id,
            active: true,
        })
    }
}
impl Drop for VpnSettlementReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = lock_vpn_runtime(&self.app);
        state.settling_session_ids.remove(&self.session_id);
        if let Some(record) = self
            .app
            .vpn_sessions
            .get(&self.session_id)
            .map(|entry| entry.clone())
        {
            let _ = expire_session_record_locked(&self.app, &mut state, &record, now_ms());
        }
    }
}
fn insert_session_locked(
    app: &SharedAppState,
    state: &mut VpnRuntimeState,
    record: VpnSessionRecord,
    current_ms: u64,
) -> Result<bool, Error> {
    reclaim_expired_sessions_locked(app, state, current_ms);
    let existing = session_for_account_locked(app, state, &record.account_id);
    if let Some(existing) = existing.as_ref()
        && existing.lease_id == record.lease_id
        && existing.session_id == record.session_id
        && existing.payment_tx_hash == record.payment_tx_hash
    {
        return Ok(true);
    }
    if existing.is_none() && state.session_ids_by_account.len() >= state.session_capacity {
        // The process-local session map is only an optimization. A paid,
        // consensus-indexed lease must remain usable when this cache is full;
        // GET reconstructs the same session directly from WSV.
        return Ok(false);
    }
    if let Some(collision) = app.vpn_sessions.get(&record.session_id) {
        if collision.account_id != record.account_id || collision.lease_id != record.lease_id {
            return Err(not_permitted_error(
                "vpn session identifier collides with another account",
            ));
        }
    }
    if let Some(existing) = existing {
        if state.settling_session_ids.contains(&existing.session_id) {
            return Err(not_permitted_error(
                "vpn session receipt settlement is in progress",
            ));
        }
        let _ = remove_session_record_locked(app, state, &existing);
    }
    app.vpn_used_payments
        .insert(record.payment_tx_hash.clone(), ());
    state
        .session_ids_by_account
        .insert(record.account_id.clone(), record.session_id.clone());
    state
        .session_expirations
        .insert((record.expires_at_ms, record.session_id.clone()));
    app.vpn_sessions.insert(record.session_id.clone(), record);
    Ok(true)
}
fn list_receipts_for_account(
    app: &SharedAppState,
    account_id: &AccountId,
) -> Result<Vec<VpnReceiptResponseDto>, Error> {
    let mut records = app
        .vpn_receipts
        .get(account_id)
        .map(|entry| entry.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let world = app.state.world_view();
    let indexed_leases = world.vpn_settled_leases_by_account().get(account_id);
    for (settled_at_ms, lease_id) in indexed_leases
        .into_iter()
        .flat_map(|leases| leases.iter().rev())
    {
        let lease = world.vpn_leases().get(lease_id).ok_or_else(|| {
            inconsistent_vpn_state(format!(
                "settled VPN receipt index references missing lease {}",
                hex::encode(lease_id)
            ))
        })?;
        if &lease.client_account_id != account_id
            || lease.status != VpnLeaseStatusV1::Settled
            || lease.settled_at_ms != Some(*settled_at_ms)
            || lease.lease_id != *lease_id
        {
            return Err(inconsistent_vpn_state(format!(
                "settled VPN receipt index entry does not match lease {}",
                hex::encode(lease_id)
            )));
        }
        let lease_id_hex = hex::encode(lease.lease_id);
        let record = receipt_record_from_settled_lease(lease)?.ok_or_else(|| {
            inconsistent_vpn_state(format!(
                "settled VPN receipt index references incomplete lease {lease_id_hex}"
            ))
        })?;
        // Committed WSV terminal state is authoritative over any process-local
        // pending projection for the same lease.
        records.retain(|cached| cached.lease_id_hex != lease_id_hex);
        records.push(record);
    }
    records.sort_by(|left, right| right.disconnected_at_ms.cmp(&left.disconnected_at_ms));
    records.truncate(MAX_RECEIPTS_PER_ACCOUNT);
    Ok(records.iter().map(receipt_response_from_record).collect())
}
fn committed_transaction_by_hash(
    app: &SharedAppState,
    payment_tx_hash: &str,
) -> Result<(SignedTransaction, u64), Error> {
    let target: HashOf<TransactionEntrypoint> = payment_tx_hash
        .trim()
        .parse()
        .map_err(|_| conversion_error("payment_tx_hash must be a transaction hash"))?;
    let Some(height) = app.state.committed_entrypoint_height(&target) else {
        #[cfg(test)]
        if app.state.committed_height() == 0 {
            return Err(not_permitted_error(
                "test VPN payment bypass is disabled without a quote-bound hash",
            ));
        }
        return Err(not_permitted_error(
            "vpn payment transaction is not committed",
        ));
    };
    let height_u64 = u64::try_from(height.get())
        .map_err(|_| conversion_error("payment transaction height exceeds u64"))?;
    // HTTP observation: authenticate the payment carrier through State/checkpoint ancestry
    // under this request's owner, retained through the membership recheck below.
    let original = crate::read_pipeline_execution_carrier(app, height)?;
    let found = original
        .owner
        .scope(|| -> Result<Option<SignedTransaction>, Error> {
            let mut found = None;
            for (entrypoint_hash, tx, result) in
                crate::canonical_history::signed_calls(original.carrier.block())
                    .map_err(|error| conversion_error(error.to_string()))?
            {
                if !crate::signed_transaction_carrier_matches_indexed_identity(
                    &entrypoint_hash,
                    tx,
                    &target,
                ) {
                    continue;
                }
                if found.is_some() {
                    return Err(not_permitted_error(
                        "VPN payment has duplicate Network sources",
                    ));
                }
                if result.is_err() {
                    return Err(not_permitted_error(
                        "vpn payment transaction did not commit successfully",
                    ));
                }
                found = Some(tx.clone());
            }
            Ok(found)
        })?;
    if app.state.committed_entrypoint_height(&target) != Some(height) {
        return Err(not_permitted_error(
            "VPN payment membership changed during authentication",
        ));
    }
    drop(original);
    found.map(|tx| (tx, height_u64)).ok_or_else(|| {
        not_permitted_error("vpn payment transaction was indexed but not found in its block")
    })
}

fn open_lease_matches_quote(
    open: &OpenVpnLeaseEscrow,
    quote: &VpnQuoteRecord,
) -> Result<bool, Error> {
    open.quote.verify().map_err(|error| {
        conversion_error(format!("payment VPN quote signature is invalid: {error}"))
    })?;
    Ok(open.quote == quote.signed_quote)
}

fn canonical_signed_transaction_hash(tx: &SignedTransaction) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(tx.hash().as_ref());
    bytes
}

fn verify_vpn_payment(
    app: &SharedAppState,
    lease: &VpnLeaseRecordV1,
    quote: &VpnQuoteRecord,
    payment_tx_hash: &str,
) -> Result<[u8; 32], Error> {
    validate_quote_record_projection(quote, app.state.network_id_ref())?;
    let payment_hash = payment_tx_hash.trim();
    if payment_hash.is_empty() {
        return Err(conversion_error("payment_tx_hash must not be empty"));
    }
    let requested_payment_hash = decode_hex_32(payment_hash, "payment_tx_hash")?;
    #[cfg(test)]
    if app.state.committed_height() == 0
        && requested_payment_hash == lease.open_tx_hash
        && requested_payment_hash == lease.quote_id
    {
        return Ok(requested_payment_hash);
    }
    #[cfg(not(test))]
    let _ = requested_payment_hash;
    let (tx, _) = committed_transaction_by_hash(app, payment_hash)?;
    let canonical_payment_hash = canonical_signed_transaction_hash(&tx);
    if canonical_payment_hash != lease.open_tx_hash {
        return Err(not_permitted_error(
            "vpn payment transaction does not match the consensus VPN lease opening",
        ));
    }
    if tx.authority() != &quote.account_id {
        return Err(not_permitted_error(
            "vpn payment transaction authority does not match signed account",
        ));
    }
    let mut matched = false;
    for instruction in tx.instructions().explicit_instructions() {
        let Some(open) = instruction.as_any().downcast_ref::<OpenVpnLeaseEscrow>() else {
            continue;
        };
        if open_lease_matches_quote(open, quote)? {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err(not_permitted_error(
            "vpn payment transaction must explicitly open the quoted native XOR VPN lease escrow",
        ));
    }
    if lease.status != VpnLeaseStatusV1::Active
        || lease.signed_quote != quote.signed_quote
        || lease.client_account_id != quote.account_id
        || lease.lease_id != quote.lease_id
        || lease.session_id != quote.session_id
        || lease.open_tx_hash != canonical_payment_hash
    {
        return Err(not_permitted_error(
            "vpn payment does not resolve to the exact active consensus VPN lease",
        ));
    }
    Ok(canonical_payment_hash)
}
fn decode_norito_hex<T: norito::codec::Decode>(
    raw: &str,
    field: &str,
    max_encoded_bytes: usize,
) -> Result<T, Error> {
    let max_hex_len = max_encoded_bytes
        .checked_mul(2)
        .expect("VPN evidence byte limits fit in usize hexadecimal lengths");
    if raw.len() > max_hex_len {
        return Err(conversion_error(format!(
            "{field} exceeds the V1 limit of {max_encoded_bytes} decoded bytes"
        )));
    }
    if raw.is_empty()
        || !raw.len().is_multiple_of(2)
        || !raw
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(conversion_error(format!(
            "{field} must be non-empty even-length lowercase hexadecimal without a prefix or whitespace"
        )));
    }
    let bytes = hex::decode(raw).map_err(|err| conversion_error(format!("{field}: {err}")))?;
    let mut cursor = bytes.as_slice();
    let decoded = norito::codec::Decode::decode(&mut cursor)
        .map_err(|err| conversion_error(format!("{field} is not valid Norito: {err}")))?;
    if !cursor.is_empty() {
        return Err(conversion_error(format!(
            "{field} has trailing bytes after Norito payload"
        )));
    }
    Ok(decoded)
}
fn parse_vpn_session_id_hex(session_id: &str) -> Result<[u8; 16], Error> {
    if session_id.len() != 32
        || !session_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(conversion_error(
            "session_id must be exactly 32 lowercase hexadecimal characters",
        ));
    }
    let mut decoded = [0u8; 16];
    hex::decode_to_slice(session_id, &mut decoded)
        .map_err(|error| conversion_error(format!("session_id is invalid: {error}")))?;
    Ok(decoded)
}
fn active_paid_lease_for_session(
    app: &SharedAppState,
    account_id: &AccountId,
    quote_id: [u8; 32],
    current_ms: u64,
) -> Result<(VpnLeaseRecordV1, VpnQuoteRecord), Error> {
    let network_id = *app.state.network_id_ref();
    let address_slot = derive_vpn_address_slot_v1(quote_id);
    let expected_lease_id = derive_vpn_lease_id_v1(&network_id, quote_id, account_id);
    let expected_session_id =
        derive_vpn_session_id_v1(&network_id, quote_id, account_id, address_slot);
    let lease = {
        let world = app.state.world_view();
        let account_lease_id = world.vpn_active_lease_by_account().get(account_id).copied();
        let address_lease_id = world
            .vpn_active_lease_by_address_slot()
            .get(&address_slot)
            .copied();
        if account_lease_id != Some(expected_lease_id)
            || address_lease_id != Some(expected_lease_id)
        {
            return Err(not_permitted_error(
                "vpn quote has no exact active consensus-indexed paid lease",
            ));
        }
        let lease = world.vpn_leases().get(&expected_lease_id).ok_or_else(|| {
            inconsistent_vpn_state(
                "active VPN account/address indexes reference a missing native VPN lease",
            )
        })?;
        if lease.lease_id != expected_lease_id
            || lease.session_id != expected_session_id
            || lease.quote_id != quote_id
            || &lease.client_account_id != account_id
            || lease.address_slot != address_slot
        {
            return Err(inconsistent_vpn_state(
                "active VPN account/address indexes differ from the retained native VPN lease",
            ));
        }
        lease.clone()
    };
    if lease.status != VpnLeaseStatusV1::Active || lease.expires_at_ms <= current_ms {
        return Err(not_permitted_error(
            "vpn quote's consensus-indexed paid lease is not active",
        ));
    }
    let quote = quote_record_from_lease(&lease, &network_id)?;
    let trust = app.vpn_relay_trust.as_deref().ok_or_else(|| {
        not_permitted_error("vpn relay trust is not configured on this Torii node")
    })?;
    ensure_lease_matches_authenticated_trust(&lease, trust)?;
    Ok((lease, quote))
}
fn revalidate_unchanged_paid_lease(
    app: &SharedAppState,
    account_id: &AccountId,
    quote_id: [u8; 32],
    expected_lease: &VpnLeaseRecordV1,
    expected_quote: &VpnQuoteRecord,
    current_ms: u64,
) -> Result<VpnLeaseRecordV1, Error> {
    let (lease, quote) = active_paid_lease_for_session(app, account_id, quote_id, current_ms)?;
    if &lease != expected_lease || quote.signed_quote != expected_quote.signed_quote {
        return Err(not_permitted_error(
            "vpn consensus lease changed during session admission",
        ));
    }
    Ok(lease)
}
fn active_lease_record_from_wsv(
    app: &SharedAppState,
    session_id: [u8; 16],
    current_ms: u64,
) -> Result<Option<VpnLeaseRecordV1>, Error> {
    let slot = VpnAddressSlotV1::from_session_id(session_id);
    let lease_record = {
        let world = app.state.world_view();
        let Some(lease_id) = world.vpn_active_lease_by_address_slot().get(&slot).copied() else {
            return Ok(None);
        };
        let lease = world.vpn_leases().get(&lease_id).ok_or_else(|| {
            inconsistent_vpn_state("active VPN address slot references a missing native VPN lease")
        })?;
        if lease.lease_id != lease_id {
            return Err(inconsistent_vpn_state(
                "active VPN address-slot index key differs from the retained VPN lease id",
            ));
        }
        if lease.session_id != session_id {
            return Err(inconsistent_vpn_state(
                "active VPN address slot references a different session id",
            ));
        }
        lease.clone()
    };
    if lease_record.status != VpnLeaseStatusV1::Active || lease_record.expires_at_ms <= current_ms {
        return Ok(None);
    }
    let trust = app.vpn_relay_trust.as_deref().ok_or_else(|| {
        not_permitted_error("vpn relay trust is not configured on this Torii node")
    })?;
    ensure_lease_matches_authenticated_trust(&lease_record, trust)?;
    Ok(Some(lease_record))
}
struct AuthorizedVpnSettlementContext {
    lease_id: [u8; 32],
    lease_id_hex: String,
    session: VpnSessionRecord,
}
fn validate_authorized_vpn_settlement(
    app: &SharedAppState,
    request: &VpnReceiptSubmitRequestDto,
    signed_account: &AccountId,
    signed_relay_receipt: &VpnSignedSessionReceiptV1,
    voucher: &VpnUsageVoucherV1,
    current_ms: u64,
) -> Result<AuthorizedVpnSettlementContext, Error> {
    let receipt_session_id = signed_relay_receipt.receipt.session_id;
    let slot = VpnAddressSlotV1::from_session_id(receipt_session_id);
    // Resolve both the active-session index and lease from one point-in-time
    // view. This lookup is O(1), and imported VPN leases have already passed
    // the protocol's fixed structural and encoded-size bounds.
    let (indexed_lease_id, lease_record) = {
        let world = app.state.world_view();
        let indexed_lease_id = *world
            .vpn_active_lease_by_address_slot()
            .get(&slot)
            .ok_or_else(|| {
                not_permitted_error(
                    "vpn receipt does not match an active consensus-indexed VPN session",
                )
            })?;
        let lease_record = world.vpn_leases().get(&indexed_lease_id).ok_or_else(|| {
            inconsistent_vpn_state("active VPN session index references a missing native VPN lease")
        })?;
        if lease_record.lease_id != indexed_lease_id {
            return Err(inconsistent_vpn_state(
                "active VPN session index key differs from the retained VPN lease id",
            ));
        }
        if lease_record.session_id != receipt_session_id {
            return Err(not_permitted_error(
                "vpn receipt does not match an active consensus-indexed VPN session",
            ));
        }
        (indexed_lease_id, lease_record.clone())
    };

    // An exact authenticated operator match must precede all settlement
    // reservation state. Otherwise any registered account can transiently
    // consume the global/per-session settlement capacity for another lease.
    if signed_account != &lease_record.operator_account_id {
        return Err(not_permitted_error(
            "vpn receipt submission must be signed by the configured operator account",
        ));
    }
    let (lease_id, lease_id_hex) =
        settlement_lease_id_from_request_or_index(request, indexed_lease_id)?;
    if lease_record.status != VpnLeaseStatusV1::Active {
        return Err(not_permitted_error("vpn lease is not active"));
    }
    if current_ms >= lease_record.refund_available_at_ms() {
        return Err(not_permitted_error(
            "vpn lease settlement grace window expired",
        ));
    }
    if signed_relay_receipt.receipt.ended_at_ms > current_ms
        || voucher.body.issued_at_ms > current_ms
    {
        return Err(not_permitted_error(
            "vpn receipt and voucher must not be dated in the future",
        ));
    }
    let session = session_record_from_lease(&lease_record)?;
    verify_relay_receipt_for_session(&session, signed_relay_receipt, voucher)?;
    Ok(AuthorizedVpnSettlementContext {
        lease_id,
        lease_id_hex,
        session,
    })
}
fn session_id_hex_from_lease(record: &VpnLeaseRecordV1) -> String {
    hex::encode(record.session_id)
}
fn ensure_lease_matches_authenticated_trust(
    record: &VpnLeaseRecordV1,
    trust: &VpnRelayTrust,
) -> Result<(), Error> {
    let policy = &record.quote_policy;
    let trust_expiry_matches = policy.relay_trust_valid_until_ms == trust.valid_until_ms;
    if record.relay_id != trust.relay_id
        || policy.relay_id != trust.relay_id
        || policy.relay_mldsa65_public_key != trust.relay_mldsa65_public_key
        || policy.relay_endpoint != trust.relay_endpoint
        || policy.descriptor_commit != trust.descriptor_commit
        || policy.tls_server_name != trust.tls_server_name
        || policy.relay_tls_spki_sha256 != trust.relay_tls_spki_sha256
        || policy.relay_certificate_sha256 != trust.relay_certificate_sha256
        || policy.directory_snapshot_digest != trust.directory_snapshot_digest
        || !trust_expiry_matches
        || record.expires_at_ms > trust.valid_until_ms
    {
        return Err(not_permitted_error(
            "persisted VPN lease does not match the authenticated relay trust",
        ));
    }
    Ok(())
}
fn session_record_from_lease(record: &VpnLeaseRecordV1) -> Result<VpnSessionRecord, Error> {
    let policy = &record.quote_policy;
    if record.relay_id != policy.relay_id {
        return Err(not_permitted_error(
            "vpn lease relay id does not match its authenticated quote policy",
        ));
    }
    if record.expires_at_ms > policy.relay_trust_valid_until_ms {
        return Err(not_permitted_error(
            "vpn relay trust does not cover the complete persisted lease",
        ));
    }
    Ok(VpnSessionRecord {
        session_id: session_id_hex_from_lease(record),
        lease_id: record.lease_id,
        account_id: record.client_account_id.clone(),
        exit_class: policy.exit_class.as_label().to_owned(),
        relay_endpoint: policy.relay_endpoint.clone(),
        lease_secs: policy.lease_secs,
        expires_at_ms: record.expires_at_ms,
        connected_at_ms: record.opened_at_ms,
        meter_family: policy.meter_family.clone(),
        quote_id: hex::encode(record.quote_id),
        payment_reference: hex::encode(record.quote_id),
        payment_tx_hash: hex::encode(record.open_tx_hash),
        fee_asset_id: policy.fee_asset_id.clone(),
        escrow_account_id: policy.escrow_account_id.clone(),
        operator_account_id: record.operator_account_id.clone(),
        lease_fee: record.lease_fee.clone(),
        tariff: record.tariff.clone(),
        flow_label_bits: policy.flow_label_bits,
        padding_budget_ms: policy.padding_budget_ms,
        relay_id: policy.relay_id,
        relay_mldsa65_public_key: policy.relay_mldsa65_public_key,
        descriptor_commit: policy.descriptor_commit,
        tls_server_name: policy.tls_server_name.clone(),
        relay_tls_spki_sha256: policy.relay_tls_spki_sha256,
        relay_certificate_sha256: policy.relay_certificate_sha256,
        directory_snapshot_digest: policy.directory_snapshot_digest,
        #[cfg(test)]
        relay_trust_valid_until_ms: policy.relay_trust_valid_until_ms,
        metering_public_key: record.metering_public_key.clone(),
        route_pushes: policy.route_pushes.clone(),
        excluded_routes: policy.excluded_routes.clone(),
        dns_servers: policy.dns_servers.clone(),
        tunnel_addresses: policy.tunnel_addresses.clone(),
        mtu_bytes: policy.mtu_bytes,
        helper_ticket_hex: String::new(),
        bytes_in: 0,
        bytes_out: 0,
    })
}
fn active_session_record_from_lease(
    app: &SharedAppState,
    lease_record: &VpnLeaseRecordV1,
) -> Result<VpnSessionRecord, Error> {
    let mut record = session_record_from_lease(lease_record)?;
    let operator_signer = vpn_operator_ticket_signer(app, &record.operator_account_id)?;
    record.helper_ticket_hex =
        build_helper_ticket_hex(&record, record.expires_at_ms, operator_signer.private_key())?;
    Ok(record)
}
fn receipt_record_from_settled_lease(
    record: &VpnLeaseRecordV1,
) -> Result<Option<VpnReceiptRecord>, Error> {
    if record.status != VpnLeaseStatusV1::Settled {
        return Ok(None);
    }
    let Some(signed_relay_receipt) = record.settled_relay_receipt.as_ref() else {
        return Ok(None);
    };
    let Some(voucher) = record.settled_client_voucher.as_ref() else {
        return Ok(None);
    };
    let verified_earned_fee = record
        .verify_settlement_evidence(signed_relay_receipt, voucher)
        .map_err(|error| {
            inconsistent_vpn_state(format!(
                "settled VPN lease retained invalid two-party settlement evidence: {error}"
            ))
        })?;
    if record.relay_receipt_hash != Some(signed_relay_receipt.hash())
        || record.client_voucher_hash != Some(voucher.hash())
        || record.highest_voucher_sequence != voucher.body.sequence
        || record.earned_fee != verified_earned_fee
    {
        return Err(inconsistent_vpn_state(
            "settled VPN lease fields do not match its retained two-party settlement evidence",
        ));
    }
    let accounted_fee = record
        .earned_fee
        .checked_add(&record.refunded_fee)
        .map_err(|error| {
            inconsistent_vpn_state(format!(
                "settled VPN lease fee accounting overflows: {error}"
            ))
        })?;
    if accounted_fee != record.lease_fee {
        return Err(inconsistent_vpn_state(
            "settled VPN lease does not conserve its escrowed fee",
        ));
    }
    let relay_receipt = &signed_relay_receipt.receipt;
    let session = session_record_from_lease(record)?;
    let connected_at_ms = relay_receipt.started_at_ms.max(record.opened_at_ms);
    let disconnected_at_ms = record.settled_at_ms.unwrap_or(relay_receipt.ended_at_ms);
    let duration_ms = relay_receipt
        .ended_at_ms
        .saturating_sub(relay_receipt.started_at_ms);
    Ok(Some(VpnReceiptRecord {
        session_id: session.session_id,
        account_id: session.account_id,
        exit_class: session.exit_class,
        relay_endpoint: session.relay_endpoint,
        meter_family: session.meter_family,
        connected_at_ms,
        disconnected_at_ms,
        duration_ms,
        bytes_in: relay_receipt.ingress_bytes,
        bytes_out: relay_receipt.egress_bytes,
        status: "settled".to_owned(),
        receipt_source: "wsv".to_owned(),
        quote_id: session.quote_id,
        payment_tx_hash: session.payment_tx_hash,
        fee_asset_id: session.fee_asset_id,
        escrow_account_id: session.escrow_account_id,
        operator_account_id: session.operator_account_id,
        lease_fee: record.lease_fee.clone(),
        earned_fee: record.earned_fee.clone(),
        refunded_fee: record.refunded_fee.clone(),
        lease_id_hex: hex::encode(record.lease_id),
        settle_lease_instruction: None,
    }))
}
fn verify_relay_receipt_for_session(
    record: &VpnSessionRecord,
    signed_relay_receipt: &VpnSignedSessionReceiptV1,
    voucher: &VpnUsageVoucherV1,
) -> Result<(), Error> {
    signed_relay_receipt.verify().map_err(|error| {
        not_permitted_error(format!(
            "vpn relay receipt signature verification failed: {error}"
        ))
    })?;
    let relay_receipt = &signed_relay_receipt.receipt;
    let expected_session_id = parse_vpn_session_id_hex(&record.session_id)?;
    if relay_receipt.session_id != expected_session_id
        || voucher.body.session_id != expected_session_id
    {
        return Err(not_permitted_error(
            "vpn receipt session id does not match the active session",
        ));
    }
    let expected_quote_id = decode_hex_32(&record.quote_id, "quote_id")?;
    if relay_receipt.quote_id != expected_quote_id || voucher.body.quote_id != expected_quote_id {
        return Err(not_permitted_error(
            "vpn receipt quote id does not match the active session",
        ));
    }
    let expected_payment_hash = decode_hex_32(&record.payment_tx_hash, "payment_tx_hash")?;
    if relay_receipt.payment_tx_hash != expected_payment_hash {
        return Err(not_permitted_error(
            "vpn receipt payment hash does not match the active session",
        ));
    }
    let expected_account_hash = account_hash(&record.account_id);
    if relay_receipt.account_hash != expected_account_hash {
        return Err(not_permitted_error(
            "vpn receipt account hash does not match the active session",
        ));
    }
    let expected_relay_id = record.relay_id;
    if relay_receipt.relay_id != expected_relay_id || voucher.body.relay_id != expected_relay_id {
        return Err(not_permitted_error(
            "vpn receipt relay id does not match the configured relay",
        ));
    }
    if relay_receipt.client_voucher_hash != voucher.hash() {
        return Err(not_permitted_error(
            "vpn receipt does not commit to the submitted client voucher",
        ));
    }
    if relay_receipt.highest_voucher_sequence != voucher.body.sequence {
        return Err(not_permitted_error(
            "vpn receipt voucher sequence does not match the submitted voucher",
        ));
    }
    if voucher.client_public_key != record.metering_public_key {
        return Err(not_permitted_error(
            "vpn usage voucher public key does not match the session",
        ));
    }
    voucher
        .verify()
        .map_err(|err| not_permitted_error(format!("vpn usage voucher signature failed: {err}")))?;
    let active_ms = relay_receipt
        .ended_at_ms
        .checked_sub(relay_receipt.started_at_ms)
        .ok_or_else(|| not_permitted_error("vpn receipt service interval is inverted"))?;
    if !voucher.body.authorizes(
        relay_receipt.ingress_bytes,
        relay_receipt.egress_bytes,
        active_ms,
    ) {
        return Err(not_permitted_error(
            "vpn receipt usage exceeds the submitted prepaid voucher ceilings",
        ));
    }
    let expected_uptime_secs = u32::try_from(active_ms.div_ceil(1_000))
        .map_err(|_| not_permitted_error("vpn receipt active time exceeds receipt range"))?;
    if relay_receipt.uptime_secs != expected_uptime_secs {
        return Err(not_permitted_error(
            "vpn receipt uptime must equal its observed service interval rounded up",
        ));
    }
    if voucher.body.issued_at_ms > relay_receipt.ended_at_ms {
        return Err(not_permitted_error(
            "vpn receipt ends before the highest prepaid voucher was issued",
        ));
    }
    let expected_exit_class = VpnExitClassV1::try_from_label(&record.exit_class)
        .map_err(|error| conversion_error(error.to_string()))?;
    if relay_receipt.exit_class != expected_exit_class {
        return Err(not_permitted_error(
            "vpn receipt exit class does not match the signed session",
        ));
    }
    if relay_receipt.cover_bytes != 0 {
        return Err(not_permitted_error(
            "vpn settlement receipt must not carry unauthenticated cover telemetry",
        ));
    }
    if relay_receipt.meter_hash != vpn_tariff_meter_hash_v1(&record.tariff) {
        return Err(not_permitted_error(
            "vpn receipt meter hash does not match the signed tariff",
        ));
    }
    if relay_receipt.started_at_ms < record.connected_at_ms
        || relay_receipt.ended_at_ms > record.expires_at_ms
    {
        return Err(not_permitted_error(
            "vpn receipt service interval falls outside the signed session",
        ));
    }
    if voucher.body.issued_at_ms < record.connected_at_ms
        || voucher.body.issued_at_ms >= record.expires_at_ms
    {
        return Err(not_permitted_error(
            "vpn voucher issuance timestamp falls outside the signed session",
        ));
    }
    let expected_earned_fee = session_earned_fee(record, relay_receipt, voucher)?;
    if relay_receipt.earned_fee != expected_earned_fee {
        return Err(not_permitted_error(
            "vpn receipt earned fee does not match the session tariff",
        ));
    }
    Ok(())
}
fn session_earned_fee(
    record: &VpnSessionRecord,
    relay_receipt: &VpnSessionReceiptV1,
    voucher: &VpnUsageVoucherV1,
) -> Result<Quantity, Error> {
    let active_ms = relay_receipt
        .ended_at_ms
        .checked_sub(relay_receipt.started_at_ms)
        .ok_or_else(|| not_permitted_error("vpn receipt service interval is inverted"))?;
    if !voucher.body.authorizes(
        relay_receipt.ingress_bytes,
        relay_receipt.egress_bytes,
        active_ms,
    ) {
        return Err(not_permitted_error(
            "vpn receipt usage exceeds the submitted prepaid voucher ceilings",
        ));
    }
    record
        .tariff
        .fee_for_usage(
            relay_receipt.ingress_bytes,
            relay_receipt.egress_bytes,
            active_ms,
        )
        .map_err(|err| conversion_error(format!("vpn tariff arithmetic failed: {err}")))
}
pub async fn handle_get_vpn_profile(app: SharedAppState) -> Result<Response, Error> {
    let dto = app.kiso.get_dto().await?;
    Ok(crate::utils::JsonBody(build_profile_at(
        &dto,
        app.vpn_relay_trust.as_deref(),
        app.vpn_operator_signer.is_some(),
        now_ms(),
    ))
    .into_response())
}
pub async fn handle_create_vpn_quote(
    app: SharedAppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Error> {
    let account_id = require_signed_request(&app, headers, method, uri, body)?;
    let request: VpnQuoteCreateRequestDto = norito::json::from_slice(body)
        .map_err(|err| conversion_error(format!("invalid vpn quote create payload: {err}")))?;
    let dto = app.kiso.get_dto().await?;
    let current_ms = now_ms();
    let profile = build_profile_at(
        &dto,
        app.vpn_relay_trust.as_deref(),
        app.vpn_operator_signer.is_some(),
        current_ms,
    );
    if !profile.available {
        if dto.network.soranet_vpn.enabled && app.vpn_operator_signer.is_none() {
            return Err(not_permitted_error(
                "vpn operator signer is not configured on this Torii node",
            ));
        }
        if dto.network.soranet_vpn.enabled && app.vpn_relay_trust.is_some() {
            return Err(not_permitted_error(
                "authenticated relay trust does not cover the complete VPN lease",
            ));
        }
        return Err(not_permitted_error("vpn is disabled on this Torii node"));
    }
    let trust = app.vpn_relay_trust.as_deref().ok_or_else(|| {
        not_permitted_error("vpn relay trust is not configured on this Torii node")
    })?;
    let exit_class = normalize_exit_class(&request.exit_class, &profile.default_exit_class)?;
    let operator_account_id =
        parse_profile_account_id(&profile.operator_account_id, "operator_account_id")?;
    let operator_signer = vpn_operator_ticket_signer(&app, &operator_account_id)?;
    ensure_vpn_quote_operator_authorized(&app, &operator_account_id)?;
    let metering_public_key = parse_metering_public_key(&request.metering_public_key_hex)?;
    let nonce = headers
        .get(crate::HEADER_NONCE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("vpn-quote");
    let network_id = *app.state.network_id_ref();
    let quote_id_bytes = build_quote_id(
        &network_id,
        &account_id,
        &metering_public_key,
        &exit_class,
        nonce,
        current_ms,
    );
    let quote_id = hex::encode(quote_id_bytes);
    let address_slot = derive_vpn_address_slot_v1(quote_id_bytes);
    let lease_id = derive_vpn_lease_id_v1(&network_id, quote_id_bytes, &account_id);
    let session_id =
        derive_vpn_session_id_v1(&network_id, quote_id_bytes, &account_id, address_slot);
    let address_plan = derive_vpn_address_plan_v1(address_slot);
    let lease_duration_ms = profile
        .lease_secs
        .checked_mul(1_000)
        .ok_or_else(|| conversion_error("vpn lease duration overflows milliseconds"))?;
    let quote_expires_at_ms = current_ms
        .checked_add(lease_duration_ms)
        .ok_or_else(|| conversion_error("vpn lease expiry exceeds Unix millisecond range"))?;
    if quote_expires_at_ms > trust.valid_until_ms {
        return Err(not_permitted_error(
            "authenticated relay trust does not cover the complete VPN lease",
        ));
    }
    let tariff = vpn_tariff_for_lease(&profile.lease_fee, profile.lease_secs)?;
    let settlement_grace_ms = profile
        .settlement_grace_secs
        .checked_mul(1_000)
        .ok_or_else(|| conversion_error("vpn settlement grace overflows milliseconds"))?;
    let asset_definition = xor_asset_definition_id();
    let escrow_account_id = vpn_lease_custody_account_id(&network_id, &lease_id, &asset_definition);
    if escrow_account_id == operator_account_id {
        return Err(not_permitted_error(
            "vpn protocol custody account must differ from the relay operator",
        ));
    }
    let quote_policy = VpnQuotePolicyV1 {
        exit_class: VpnExitClassV1::try_from_label(&exit_class)
            .map_err(|error| conversion_error(error.to_string()))?,
        relay_endpoint: profile.relay_endpoint.clone(),
        relay_id: trust.relay_id,
        relay_mldsa65_public_key: trust.relay_mldsa65_public_key,
        descriptor_commit: trust.descriptor_commit,
        tls_server_name: trust.tls_server_name.clone(),
        relay_tls_spki_sha256: trust.relay_tls_spki_sha256,
        relay_certificate_sha256: trust.relay_certificate_sha256,
        directory_snapshot_digest: trust.directory_snapshot_digest,
        relay_trust_valid_until_ms: trust.valid_until_ms,
        lease_secs: profile.lease_secs,
        meter_family: profile.meter_family.clone(),
        fee_asset_id: asset_definition.to_string(),
        escrow_account_id: escrow_account_id.clone(),
        route_pushes: profile.route_pushes.clone(),
        excluded_routes: profile.excluded_routes.clone(),
        dns_servers: profile.dns_servers.clone(),
        tunnel_addresses: address_plan.client_tunnel_addresses.clone(),
        mtu_bytes: profile.mtu_bytes,
        flow_label_bits: profile.flow_label_bits,
        padding_budget_ms: profile.padding_budget_ms,
    };
    let signed_quote = VpnSignedQuoteV1::try_sign(
        VpnQuoteBodyV1 {
            network_id,
            quote_id: quote_id_bytes,
            lease_id,
            session_id,
            address_slot,
            client_account_id: account_id.clone(),
            operator_account_id: operator_account_id.clone(),
            metering_public_key: metering_public_key.clone(),
            asset_definition,
            tariff: tariff.clone(),
            policy: quote_policy,
            valid_after_ms: current_ms,
            expires_at_ms: quote_expires_at_ms,
            settlement_grace_ms,
        },
        operator_signer.private_key(),
    )
    .map_err(|error| conversion_error(format!("cannot sign canonical VPN quote: {error}")))?;
    let record = VpnQuoteRecord {
        quote_id: quote_id.clone(),
        lease_id,
        session_id,
        signed_quote,
        account_id,
        exit_class,
        relay_endpoint: profile.relay_endpoint,
        lease_secs: profile.lease_secs,
        quote_expires_at_ms,
        payment_reference: quote_id.clone(),
        fee_asset_id: xor_asset_definition_id().to_string(),
        escrow_account_id,
        operator_account_id,
        lease_fee: profile.lease_fee,
        tariff,
        settlement_grace_ms,
        metering_public_key,
        route_pushes: profile.route_pushes,
        excluded_routes: profile.excluded_routes,
        dns_servers: profile.dns_servers,
        tunnel_addresses: address_plan.client_tunnel_addresses,
        mtu_bytes: profile.mtu_bytes,
        meter_family: profile.meter_family,
        flow_label_bits: profile.flow_label_bits,
        padding_budget_ms: profile.padding_budget_ms,
        relay_id: trust.relay_id,
        relay_mldsa65_public_key: trust.relay_mldsa65_public_key,
        descriptor_commit: trust.descriptor_commit,
        tls_server_name: trust.tls_server_name.clone(),
        relay_tls_spki_sha256: trust.relay_tls_spki_sha256,
        relay_certificate_sha256: trust.relay_certificate_sha256,
        directory_snapshot_digest: trust.directory_snapshot_digest,
        relay_trust_valid_until_ms: trust.valid_until_ms,
    };
    let response = quote_response_from_record(&record, &network_id)?;
    Ok((StatusCode::CREATED, crate::utils::JsonBody(response)).into_response())
}
pub async fn handle_create_vpn_session(
    app: SharedAppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Error> {
    let account_id = require_signed_request(&app, headers, method, uri, body)?;
    let request: VpnSessionCreateRequestDto = norito::json::from_slice(body)
        .map_err(|err| conversion_error(format!("invalid vpn session create payload: {err}")))?;
    let dto = app.kiso.get_dto().await?;
    let vpn = &dto.network.soranet_vpn;
    if !vpn.enabled {
        return Err(not_permitted_error("vpn is disabled on this Torii node"));
    }
    let current_ms = now_ms();
    if request.quote_id.trim().is_empty() {
        return Err(conversion_error("quote_id must not be empty"));
    }
    let quote_id = decode_hex_32(&request.quote_id, "quote_id")?;
    let exit_class = normalize_exit_class(&request.exit_class, &vpn.exit_class)?;
    let metering_public_key = parse_metering_public_key(&request.metering_public_key_hex)?;
    if request.payment_tx_hash.trim().is_empty() {
        return Err(conversion_error("payment_tx_hash must not be empty"));
    }
    let payment_tx_hash = hex::encode(decode_hex_32(&request.payment_tx_hash, "payment_tx_hash")?);
    // Resolve both consensus indexes and the retained lease from one WSV view.
    // The signed quote is reconstructed from that durable lease, so unpaid
    // quote issuance consumes no process-local capacity and works across nodes.
    let (lease, quote) = active_paid_lease_for_session(&app, &account_id, quote_id, current_ms)?;
    if quote.exit_class != exit_class {
        return Err(not_permitted_error(
            "vpn quote exit class does not match session request",
        ));
    }
    if metering_public_key != quote.metering_public_key {
        return Err(not_permitted_error(
            "vpn session metering key does not match the quoted native lease",
        ));
    }
    let canonical_payment_tx_hash = verify_vpn_payment(&app, &lease, &quote, &payment_tx_hash)?;
    // Transaction resolution can overlap a consensus transition. Re-read both
    // active indexes after it and issue a helper ticket only for the unchanged,
    // still-active durable lease.
    let admission_ms = now_ms();
    let final_lease =
        revalidate_unchanged_paid_lease(&app, &account_id, quote_id, &lease, &quote, admission_ms)?;
    let record = active_session_record_from_lease(&app, &final_lease)?;
    if record.payment_tx_hash != hex::encode(canonical_payment_tx_hash) {
        return Err(inconsistent_vpn_state(
            "consensus VPN lease payment projection differs from its committed transaction",
        ));
    }
    let response = response_from_record(&record);
    let mut vpn_state = lock_vpn_runtime(&app);
    let _cached = insert_session_locked(&app, &mut vpn_state, record, admission_ms)?;
    Ok((StatusCode::CREATED, crate::utils::JsonBody(response)).into_response())
}
pub async fn handle_get_vpn_session(
    app: SharedAppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    session_id: &str,
) -> Result<Response, Error> {
    let account_id = require_signed_request(&app, headers, method, uri, &[])?;
    let current_ms = now_ms();
    let session_id_bytes = parse_vpn_session_id_hex(session_id)?;
    let cached_record = {
        let mut vpn_state = lock_vpn_runtime(&app);
        session_by_id_locked(&app, &mut vpn_state, session_id, current_ms)
    };
    // WSV is authoritative for lease lifecycle. Keep its snapshot outside the
    // runtime-cache lock, then conditionally evict only the candidate observed
    // before that snapshot so a concurrent replacement cannot be removed.
    let active_lease = active_lease_record_from_wsv(&app, session_id_bytes, current_ms)?;
    let record = match (cached_record.as_ref(), active_lease.as_ref()) {
        (Some(cached), Some(lease)) if cached.lease_id == lease.lease_id => cached.clone(),
        (cached, None) => {
            if let Some(cached) = cached {
                let mut vpn_state = lock_vpn_runtime(&app);
                let _ = remove_session_candidate_locked(&app, &mut vpn_state, cached);
            }
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        (cached, Some(lease)) => {
            if let Some(cached) = cached {
                let mut vpn_state = lock_vpn_runtime(&app);
                let _ = remove_session_candidate_locked(&app, &mut vpn_state, cached);
            }
            active_session_record_from_lease(&app, lease)?
        }
    };
    if record.account_id != account_id {
        return Err(not_permitted_error(
            "vpn session belongs to a different account",
        ));
    }
    Ok(crate::utils::JsonBody(response_from_record(&record)).into_response())
}
pub async fn handle_list_vpn_receipts(
    app: SharedAppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Response, Error> {
    let account_id = require_signed_request(&app, headers, method, uri, &[])?;
    {
        let mut vpn_state = lock_vpn_runtime(&app);
        expire_session_for_account_locked(&app, &mut vpn_state, &account_id, now_ms());
    }
    // Receipt projection can read bounded WSV indexes after the short runtime
    // mutation critical section has completed.
    let items = list_receipts_for_account(&app, &account_id)?;
    let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
    Ok(crate::utils::JsonBody(VpnReceiptListResponseDto { items, total }).into_response())
}
pub async fn handle_submit_vpn_receipt(
    app: SharedAppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Error> {
    let signed_account = require_signed_request(&app, headers, method, uri, body)?;
    let request: VpnReceiptSubmitRequestDto = norito::json::from_slice(body)
        .map_err(|err| conversion_error(format!("invalid vpn receipt payload: {err}")))?;
    let relay_receipt: VpnSignedSessionReceiptV1 = decode_norito_hex(
        &request.relay_receipt_hex,
        "relay_receipt_hex",
        VPN_MAX_SIGNED_RELAY_RECEIPT_NORITO_BYTES_V1,
    )?;
    let voucher: VpnUsageVoucherV1 = decode_norito_hex(
        &request.client_voucher_hex,
        "client_voucher_hex",
        VPN_MAX_CLIENT_VOUCHER_NORITO_BYTES_V1,
    )?;
    let preflight = validate_authorized_vpn_settlement(
        &app,
        &request,
        &signed_account,
        &relay_receipt,
        &voucher,
        now_ms(),
    )?;
    let session_id_hex = preflight.session.session_id.clone();
    let preflight_lease_id = preflight.lease_id;
    let _settlement = VpnSettlementReservation::reserve(&app, session_id_hex.clone())?;
    // Reservation state cannot make the WSV immutable. Re-resolve the exact
    // authoritative lease and revalidate both signatures and all evidence
    // after reservation so a concurrent lifecycle transition cannot be used
    // to build an instruction from stale preflight state. Consensus performs
    // the final lifecycle check when the returned instruction is submitted.
    let authoritative = validate_authorized_vpn_settlement(
        &app,
        &request,
        &signed_account,
        &relay_receipt,
        &voucher,
        now_ms(),
    )?;
    if authoritative.lease_id != preflight_lease_id {
        return Err(not_permitted_error(
            "vpn session lease changed while settlement was being reserved",
        ));
    }
    let receipt = build_pending_settlement_receipt_record(
        &authoritative.session,
        &relay_receipt,
        &voucher,
        authoritative.lease_id,
        authoritative.lease_id_hex,
    )?;
    // Validation only prepares a canonical settlement instruction. The active
    // session and receipt projection remain consensus-derived until that
    // instruction commits; reporting "settled" here would create a false
    // local state and permit duplicate provisional receipts.
    Ok((
        StatusCode::CREATED,
        crate::utils::JsonBody(receipt_response_from_record(&receipt)),
    )
        .into_response())
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    include!("vpn_tests.rs");
}
