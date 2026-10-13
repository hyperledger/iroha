//! Native SoraNet VPN lease escrow instruction handlers.
use super::{Error, Execute, asset::isi::assert_numeric_spec_with};
use crate::smartcontracts::isi::helpers::ensure_custody_account;
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use eyre::Result;
use iroha_crypto::{
    Algorithm, derive_non_signing_ed25519_public_key,
    soranet::certificate::{validate_quic_multiaddr, validate_tls_server_name},
};
#[cfg(test)]
use iroha_crypto::{Hash, HashOf, KeyPair};
#[cfg(test)]
use iroha_data_model::soranet::vpn::{
    VpnSessionReceiptV1, VpnUsageVoucherBodyV1, vpn_account_hash_v1 as account_hash,
    vpn_tariff_meter_hash_v1,
};
#[cfg(test)]
use iroha_data_model::{IntoKeyValue, account::Account};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::vpn::{OpenVpnLeaseEscrow, RefundExpiredVpnLease, SettleVpnLease},
    prelude::*,
    soranet::vpn::{
        VPN_DEFAULT_TUNNEL_MTU_BYTES, VpnLeaseRecordV1, VpnLeaseStatusV1, VpnQuoteBodyV1,
        VpnQuotePolicyV1, VpnSignedQuoteV1, VpnSignedSessionReceiptV1, VpnUsageVoucherV1,
        derive_vpn_address_plan_v1, derive_vpn_lease_id_v1, derive_vpn_session_id_v1,
    },
    transaction::SignedTransaction,
};
use iroha_executor_data_model::permission::soranet::CanIssueSoranetVpnQuote;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::codec::Encode;
use std::{net::IpAddr, str::FromStr};
/// Exact VPN purpose carried by a one-shot numeric movement capability.
pub(in crate::smartcontracts::isi) enum VerifiedVpnNumericPurpose {
    Funding {
        lease_id: [u8; 32],
        authority: AccountId,
    },
    Settlement {
        lease_id: [u8; 32],
        authority: AccountId,
    },
    Refund {
        lease_id: [u8; 32],
        authority: AccountId,
    },
}
/// Non-reusable proof that VPN admission selected an exact atomic movement batch.
pub(in crate::smartcontracts::isi) struct VerifiedVpnNumericBatch {
    purpose: VerifiedVpnNumericPurpose,
    legs: Vec<(AssetId, AssetId, Quantity)>,
}
impl VerifiedVpnNumericBatch {
    fn new(purpose: VerifiedVpnNumericPurpose, legs: Vec<(AssetId, AssetId, Quantity)>) -> Self {
        Self { purpose, legs }
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (VerifiedVpnNumericPurpose, Vec<(AssetId, AssetId, Quantity)>) {
        (self.purpose, self.legs)
    }
}
const VPN_LEASE_CUSTODY_ACCOUNT_DOMAIN: &str = "iroha-soranet-vpn-lease-v1";
const VPN_MAX_SIGNED_QUOTE_BYTES_V1: usize = 32 * 1024;
const VPN_MAX_RELAY_ENDPOINT_BYTES_V1: usize = 1_024;
const VPN_MAX_TLS_SERVER_NAME_BYTES_V1: usize = 253;
const VPN_MAX_METER_FAMILY_BYTES_V1: usize = 128;
const VPN_MAX_ROUTE_ENTRIES_V1: usize = 64;
const VPN_MAX_ROUTE_BYTES_V1: usize = 128;
const VPN_MAX_DNS_ENTRIES_V1: usize = 8;
const VPN_MAX_DNS_BYTES_V1: usize = 64;
const VPN_ED25519_SIGNATURE_BYTES_V1: usize = 64;
fn validation_err(message: impl Into<String>) -> Error {
    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
        message.into().into(),
    )
}
fn ensure_non_zero_32(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if *value == [0u8; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(())
}
fn ensure_non_zero_16(label: &str, value: &[u8; 16]) -> Result<(), String> {
    if *value == [0u8; 16] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(())
}
fn ensure_positive(value: &Quantity) -> Result<(), String> {
    if value.is_zero() {
        return Err("vpn lease fee must be positive".to_owned());
    }
    Ok(())
}
fn ensure_relay_trust_covers_lease(
    relay_id: &[u8; 32],
    quote_policy: &VpnQuotePolicyV1,
    expires_at_ms: u64,
) -> Result<(), String> {
    if &quote_policy.relay_id != relay_id {
        return Err("vpn quote policy relay id must match the lease relay id".to_owned());
    }
    if expires_at_ms > quote_policy.relay_trust_valid_until_ms {
        return Err("vpn relay trust must remain valid for the complete lease".to_owned());
    }
    Ok(())
}
fn ensure_non_zero_policy_commitment(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if *value == [0_u8; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(())
}
fn ensure_bounded_canonical_text(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must be non-empty, unpadded, control-free UTF-8 of at most {max_bytes} bytes"
        ));
    }
    Ok(())
}
fn ensure_bounded_canonical_text_list(
    label: &str,
    values: &[String],
    minimum_items: usize,
    maximum_items: usize,
    maximum_item_bytes: usize,
) -> Result<(), String> {
    if !(minimum_items..=maximum_items).contains(&values.len()) {
        return Err(format!(
            "{label} must contain {minimum_items}..={maximum_items} entries"
        ));
    }
    for (index, value) in values.iter().enumerate() {
        ensure_bounded_canonical_text(label, value, maximum_item_bytes)?;
        if values[..index].iter().any(|previous| previous == value) {
            return Err(format!("{label} must not contain duplicate entries"));
        }
    }
    Ok(())
}

// Keep the parsed IPv4/IPv6 networks inline: this private validation fact is
// short-lived and allocation-free, while the address widths naturally differ.
#[allow(variant_size_differences)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalVpnCidrV1 {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

fn parse_canonical_vpn_cidr(label: &str, value: &str) -> Result<CanonicalVpnCidrV1, String> {
    let (address_text, prefix_text) = value
        .split_once('/')
        .filter(|(_, prefix)| !prefix.contains('/'))
        .ok_or_else(|| format!("{label} entry `{value}` must be an IP-address/prefix CIDR"))?;
    let address = address_text
        .parse::<IpAddr>()
        .map_err(|error| format!("{label} entry `{value}` has an invalid IP address: {error}"))?;
    if address.to_string() != address_text {
        return Err(format!(
            "{label} entry `{value}` must use the canonical IP address spelling"
        ));
    }
    let prefix = prefix_text.parse::<u8>().map_err(|error| {
        format!("{label} entry `{value}` has an invalid decimal prefix: {error}")
    })?;
    if prefix.to_string() != prefix_text {
        return Err(format!(
            "{label} entry `{value}` must use the canonical decimal prefix"
        ));
    }
    match address {
        IpAddr::V4(address) => {
            if prefix > 32 {
                return Err(format!(
                    "{label} entry `{value}` prefix exceeds the IPv4 maximum of 32"
                ));
            }
            let raw = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = raw & mask;
            if raw != network {
                return Err(format!(
                    "{label} entry `{value}` must have all host bits cleared"
                ));
            }
            Ok(CanonicalVpnCidrV1::V4 { network, prefix })
        }
        IpAddr::V6(address) => {
            if prefix > 128 {
                return Err(format!(
                    "{label} entry `{value}` prefix exceeds the IPv6 maximum of 128"
                ));
            }
            let raw = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = raw & mask;
            if raw != network {
                return Err(format!(
                    "{label} entry `{value}` must have all host bits cleared"
                ));
            }
            Ok(CanonicalVpnCidrV1::V6 { network, prefix })
        }
    }
}

fn parse_canonical_vpn_cidr_list(
    label: &str,
    values: &[String],
    minimum_items: usize,
) -> Result<Vec<CanonicalVpnCidrV1>, String> {
    ensure_bounded_canonical_text_list(
        label,
        values,
        minimum_items,
        VPN_MAX_ROUTE_ENTRIES_V1,
        VPN_MAX_ROUTE_BYTES_V1,
    )?;
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let cidr = parse_canonical_vpn_cidr(label, value)?;
        if parsed.contains(&cidr) {
            return Err(format!(
                "{label} must not contain semantically duplicate entries"
            ));
        }
        parsed.push(cidr);
    }
    Ok(parsed)
}

fn validate_canonical_vpn_dns_servers(values: &[String]) -> Result<(), String> {
    const LABEL: &str = "vpn quote DNS resolvers";
    ensure_bounded_canonical_text_list(
        LABEL,
        values,
        1,
        VPN_MAX_DNS_ENTRIES_V1,
        VPN_MAX_DNS_BYTES_V1,
    )?;
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let address = value
            .parse::<IpAddr>()
            .map_err(|error| format!("{LABEL} entry `{value}` is not an IP literal: {error}"))?;
        if address.to_string() != *value {
            return Err(format!(
                "{LABEL} entry `{value}` must use the canonical IP literal spelling"
            ));
        }
        if address.is_unspecified()
            || address.is_multicast()
            || matches!(address, IpAddr::V4(address) if address == std::net::Ipv4Addr::BROADCAST)
        {
            return Err(format!(
                "{LABEL} entry `{value}` must be a unicast resolver address"
            ));
        }
        if parsed.contains(&address) {
            return Err(format!(
                "{LABEL} must not contain semantically duplicate entries"
            ));
        }
        parsed.push(address);
    }
    Ok(())
}

fn ensure_canonical_quote_policy(
    body: &VpnQuoteBodyV1,
    custody_account_id: &AccountId,
) -> Result<(), String> {
    let policy = &body.policy;
    ensure_non_zero_32("vpn relay id", &policy.relay_id)?;
    iroha_crypto::PublicKey::from_bytes(Algorithm::MlDsa, &policy.relay_mldsa65_public_key)
        .map_err(|error| format!("vpn relay ML-DSA-65 identity is invalid: {error}"))?;
    ensure_non_zero_policy_commitment(
        "vpn relay descriptor commitment",
        &policy.descriptor_commit,
    )?;
    ensure_non_zero_policy_commitment("vpn relay TLS SPKI pin", &policy.relay_tls_spki_sha256)?;
    ensure_non_zero_policy_commitment(
        "vpn relay certificate commitment",
        &policy.relay_certificate_sha256,
    )?;
    ensure_non_zero_policy_commitment(
        "vpn directory snapshot commitment",
        &policy.directory_snapshot_digest,
    )?;
    ensure_bounded_canonical_text(
        "vpn quote relay endpoint",
        &policy.relay_endpoint,
        VPN_MAX_RELAY_ENDPOINT_BYTES_V1,
    )?;
    validate_quic_multiaddr(&policy.relay_endpoint)
        .map_err(|error| format!("vpn quote relay endpoint is invalid: {error}"))?;
    ensure_bounded_canonical_text(
        "vpn quote TLS server name",
        &policy.tls_server_name,
        VPN_MAX_TLS_SERVER_NAME_BYTES_V1,
    )?;
    validate_tls_server_name(&policy.tls_server_name)
        .map_err(|error| format!("vpn quote TLS server name is invalid: {error}"))?;
    ensure_bounded_canonical_text(
        "vpn quote meter family",
        &policy.meter_family,
        VPN_MAX_METER_FAMILY_BYTES_V1,
    )?;
    let route_pushes = parse_canonical_vpn_cidr_list("vpn quote routes", &policy.route_pushes, 1)?;
    let excluded_routes =
        parse_canonical_vpn_cidr_list("vpn quote excluded routes", &policy.excluded_routes, 0)?;
    validate_canonical_vpn_dns_servers(&policy.dns_servers)?;
    // V1 intentionally permits a more-specific exclusion below a pushed
    // default route. Only exact normalized network/prefix equality is
    // contradictory and therefore rejected across the two ordered lists.
    if route_pushes
        .iter()
        .any(|route| excluded_routes.contains(route))
    {
        return Err("vpn quote included and excluded route sets must be disjoint".to_owned());
    }
    if policy.flow_label_bits != 24 {
        return Err("vpn quote flow-label width must be 24 bits".to_owned());
    }
    if policy.mtu_bytes != u64::from(VPN_DEFAULT_TUNNEL_MTU_BYTES) {
        return Err(format!(
            "vpn quote MTU must be {VPN_DEFAULT_TUNNEL_MTU_BYTES} bytes"
        ));
    }
    if policy.padding_budget_ms == 0 {
        return Err("vpn quote padding budget must be greater than zero".to_owned());
    }
    if !body.address_slot.is_valid() {
        return Err("vpn quote address slot is outside the V1 pool".to_owned());
    }
    let expected_addresses = derive_vpn_address_plan_v1(body.address_slot);
    if policy.tunnel_addresses != expected_addresses.client_tunnel_addresses {
        return Err("vpn quote tunnel addresses do not match its typed address slot".to_owned());
    }
    if policy.fee_asset_id != body.asset_definition.to_string() {
        return Err(
            "vpn quote fee asset label does not match its typed asset definition".to_owned(),
        );
    }
    if &policy.escrow_account_id != custody_account_id {
        return Err(
            "vpn quote escrow account does not match deterministic protocol custody".to_owned(),
        );
    }
    let lease_duration_ms = body
        .expires_at_ms
        .checked_sub(body.valid_after_ms)
        .ok_or_else(|| "vpn quote expiry precedes its validity start".to_owned())?;
    let expected_duration_ms = policy
        .lease_secs
        .checked_mul(1_000)
        .ok_or_else(|| "vpn quote lease duration overflows milliseconds".to_owned())?;
    if lease_duration_ms != expected_duration_ms || policy.lease_secs == 0 {
        return Err(
            "vpn quote policy duration does not match its signed validity interval".to_owned(),
        );
    }
    ensure_relay_trust_covers_lease(&policy.relay_id, policy, body.expires_at_ms)
}

/// Validate deterministic V1 quote invariants without consulting historical state.
///
/// Signature validity, operator permission, exact-network binding, transaction
/// authority, and current-time admission remain caller responsibilities.
pub(crate) fn validate_static_vpn_quote(quote: &VpnSignedQuoteV1) -> Result<AccountId, String> {
    let signature_bytes = quote.signature.payload().len();
    if signature_bytes != VPN_ED25519_SIGNATURE_BYTES_V1 {
        return Err(format!(
            "vpn quote signature has {signature_bytes} bytes; expected {VPN_ED25519_SIGNATURE_BYTES_V1}"
        ));
    }
    let body = &quote.body;
    ensure_non_zero_32("vpn quote id", &body.quote_id)?;
    ensure_non_zero_32("vpn lease id", &body.lease_id)?;
    ensure_non_zero_16("vpn session id", &body.session_id)?;
    let expected_lease_id =
        derive_vpn_lease_id_v1(&body.network_id, body.quote_id, &body.client_account_id);
    if body.lease_id != expected_lease_id {
        return Err("vpn lease id is not the canonical network/client/quote derivation".to_owned());
    }
    let expected_session_id = derive_vpn_session_id_v1(
        &body.network_id,
        body.quote_id,
        &body.client_account_id,
        body.address_slot,
    );
    if body.session_id != expected_session_id {
        return Err(
            "vpn session id is not the canonical network/client/quote/slot derivation".to_owned(),
        );
    }
    if body.settlement_grace_ms == 0
        || body
            .expires_at_ms
            .checked_add(body.settlement_grace_ms)
            .is_none()
    {
        return Err("vpn quote settlement grace must be non-zero and timestamp-safe".to_owned());
    }
    ensure_xor_asset(&body.asset_definition)?;
    ensure_positive(&body.tariff.lease_fee)?;
    if body.metering_public_key.try_algorithm() != Ok(Algorithm::Ed25519) {
        return Err(
            "vpn metering public key must use Ed25519 for the V1 helper-ticket format".to_owned(),
        );
    }
    let custody =
        vpn_lease_custody_account_id(&body.network_id, &body.lease_id, &body.asset_definition)
            .map_err(|error| format!("vpn quote custody derivation failed: {error}"))?;
    ensure_canonical_quote_policy(body, &custody)?;
    // Only count the encoded envelope after every variable-width field has a
    // protocol bound. `encoded_len` streams into a sink and does not allocate a
    // duplicate quote-sized buffer.
    let quote_size = quote.encoded_len();
    if quote_size > VPN_MAX_SIGNED_QUOTE_BYTES_V1 {
        return Err(format!(
            "vpn signed quote has {quote_size} bytes; maximum is {VPN_MAX_SIGNED_QUOTE_BYTES_V1}"
        ));
    }
    Ok(custody)
}
fn vpn_quote_operator_is_authorized<W: WorldReadOnly>(
    operator_account_id: &AccountId,
    world: &W,
) -> Result<bool, Error> {
    let required_permission: Permission = CanIssueSoranetVpnQuote.into();
    Ok(world
        .account_permissions_iter(operator_account_id)?
        .into_iter()
        .any(|permission| permission == &required_permission)
        || world
            .account_roles_iter(operator_account_id)
            .any(|role_id| {
                world.roles().get(role_id).is_some_and(|role| {
                    role.permissions()
                        .any(|permission| permission == &required_permission)
                })
            }))
}
fn verify_operator_quote(
    quote: &VpnSignedQuoteV1,
    authority: &AccountId,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<AccountId, Error> {
    // The V1 helper ticket uses the quote operator as its fixed-width Ed25519
    // issuer, so consensus must not admit a quote from another key algorithm.
    if quote
        .body
        .operator_account_id
        .try_signatory()
        .is_some_and(|public_key| public_key.try_algorithm() != Ok(Algorithm::Ed25519))
    {
        return Err(validation_err(
            "vpn quote operator issuer must use Ed25519 for the V1 helper-ticket format",
        ));
    }
    let custody = validate_static_vpn_quote(quote).map_err(validation_err)?;
    quote.verify().map_err(|error| {
        validation_err(format!("vpn operator quote signature is invalid: {error}"))
    })?;
    let body = &quote.body;
    if !vpn_quote_operator_is_authorized(&body.operator_account_id, &state_transaction.world)? {
        return Err(validation_err(
            "vpn quote signer does not hold CanIssueSoranetVpnQuote",
        ));
    }
    if &body.network_id != state_transaction.network_id() {
        return Err(validation_err(
            "vpn quote is bound to a different exact network",
        ));
    }
    if &body.client_account_id != authority {
        return Err(validation_err(
            "vpn quote client account does not match transaction authority",
        ));
    }
    let now_ms = state_transaction.block_unix_timestamp_ms();
    if now_ms < body.valid_after_ms || now_ms >= body.expires_at_ms {
        return Err(validation_err("vpn quote is not currently valid"));
    }
    Ok(custody)
}
fn hash_to_bytes(hash: &iroha_crypto::HashOf<SignedTransaction>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    bytes
}
fn xor_asset_definition_id() -> AssetDefinitionId {
    let domain =
        DomainId::parse_fully_qualified("universal.universal").expect("static XOR domain id");
    let name = Name::from_str("xor").expect("static XOR asset name");
    AssetDefinitionId::derive_from_components(domain, name)
}
fn ensure_xor_asset(asset_definition: &AssetDefinitionId) -> Result<(), String> {
    let expected = xor_asset_definition_id();
    if asset_definition != &expected {
        return Err(format!("vpn lease fee asset must be XOR ({expected})"));
    }
    Ok(())
}
/// Derive the deterministic protocol custody account for a VPN lease.
///
/// # Errors
/// This derivation is infallible and currently always returns `Ok`.
pub fn vpn_lease_custody_account_id(
    network_id: &iroha_data_model::NetworkId,
    lease_id: &[u8; 32],
    asset_definition: &AssetDefinitionId,
) -> Result<AccountId, Error> {
    let asset_definition = asset_definition.to_string();
    let public_key = derive_non_signing_ed25519_public_key(
        VPN_LEASE_CUSTODY_ACCOUNT_DOMAIN.as_bytes(),
        &[network_id.as_bytes(), lease_id, asset_definition.as_bytes()],
    );
    Ok(AccountId::new(public_key))
}
fn transfer_numeric_asset_for_vpn(
    state_transaction: &mut StateTransaction<'_, '_>,
    authorization: VerifiedVpnNumericBatch,
) -> Result<(), Error> {
    crate::smartcontracts::isi::asset::isi::execute_verified_vpn_numeric_batch(
        state_transaction,
        authorization,
    )
}
fn custody_asset(record: &VpnLeaseRecordV1) -> AssetId {
    AssetId::new(
        record.asset_definition.clone(),
        record.custody_account_id.clone(),
    )
}
fn client_asset(record: &VpnLeaseRecordV1) -> AssetId {
    AssetId::new(
        record.asset_definition.clone(),
        record.client_account_id.clone(),
    )
}
/// Return whether an account is still bound by a funded active VPN lease.
///
/// Rekeying or unregistering such an account would invalidate the signed
/// client binding and make the eventual escrow refund undeliverable.
pub(crate) fn is_active_vpn_client<W: WorldReadOnly>(world: &W, account_id: &AccountId) -> bool {
    world
        .vpn_active_lease_by_account()
        .get(account_id)
        .is_some()
}
fn operator_asset(record: &VpnLeaseRecordV1) -> AssetId {
    AssetId::new(
        record.asset_definition.clone(),
        record.operator_account_id.clone(),
    )
}
fn verify_vpn_settlement(
    record: &VpnLeaseRecordV1,
    signed_receipt: &VpnSignedSessionReceiptV1,
    voucher: &VpnUsageVoucherV1,
) -> Result<Quantity, Error> {
    record
        .verify_settlement_evidence(signed_receipt, voucher)
        .map_err(|error| validation_err(error.to_string()))
}
fn refund_active_vpn_lease(
    mut record: VpnLeaseRecordV1,
    authority: &AccountId,
    now_ms: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if record.status != VpnLeaseStatusV1::Active {
        return Err(validation_err("vpn lease is not active"));
    }
    if now_ms < record.refund_available_at_ms() {
        return Err(validation_err("vpn lease refund is not available yet"));
    }
    let escrow_asset = custody_asset(&record);
    let destination = client_asset(&record);
    transfer_numeric_asset_for_vpn(
        state_transaction,
        VerifiedVpnNumericBatch::new(
            VerifiedVpnNumericPurpose::Refund {
                lease_id: record.lease_id,
                authority: authority.clone(),
            },
            vec![(escrow_asset, destination, record.lease_fee.clone())],
        ),
    )?;
    record.status = VpnLeaseStatusV1::Refunded;
    record.refunded_at_ms = Some(now_ms);
    record.refunded_fee = record.lease_fee.clone();
    state_transaction
        .world
        .put_vpn_lease(record)
        .map_err(validation_err)?;
    Ok(())
}
fn release_expired_vpn_claims_for_quote(
    body: &VpnQuoteBodyV1,
    authority: &AccountId,
    now_ms: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if let Some(existing_lease_id) = state_transaction
        .world
        .vpn_active_lease_by_account
        .get(&body.client_account_id)
        .copied()
    {
        let record = state_transaction
            .world
            .vpn_leases
            .get(&existing_lease_id)
            .cloned()
            .ok_or_else(|| validation_err("vpn active-account index is stale"))?;
        refund_active_vpn_lease(record, authority, now_ms, state_transaction)?;
    }
    if let Some(existing_lease_id) = state_transaction
        .world
        .vpn_active_lease_by_address_slot
        .get(&body.address_slot)
        .copied()
    {
        let record = state_transaction
            .world
            .vpn_leases
            .get(&existing_lease_id)
            .cloned()
            .ok_or_else(|| validation_err("vpn active-address index is stale"))?;
        refund_active_vpn_lease(record, authority, now_ms, state_transaction)?;
    }
    Ok(())
}
impl Execute for OpenVpnLeaseEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let quote = self.quote;
        let body = &quote.body;
        let custody = verify_operator_quote(&quote, authority, state_transaction)?;
        if state_transaction
            .world
            .vpn_leases
            .get(&body.lease_id)
            .is_some()
        {
            return Err(validation_err("vpn lease already exists"));
        }
        let spec = state_transaction
            .numeric_spec_for(&body.asset_definition)
            .map_err(Error::from)?;
        assert_numeric_spec_with(body.tariff.lease_fee.as_numeric(), spec)?;
        state_transaction.world.account(authority)?;
        state_transaction.world.account(&body.operator_account_id)?;
        state_transaction
            .world
            .asset_definition(&body.asset_definition)?;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        release_expired_vpn_claims_for_quote(body, authority, now_ms, state_transaction)?;
        if state_transaction
            .world
            .vpn_active_lease_by_account
            .get(&body.client_account_id)
            .is_some()
        {
            return Err(validation_err(
                "vpn client account already has an active lease",
            ));
        }
        if state_transaction
            .world
            .vpn_active_lease_by_address_slot
            .get(&body.address_slot)
            .is_some()
        {
            return Err(validation_err("vpn address slot is already claimed"));
        }
        let open_tx_hash = state_transaction
            .current_tx_hash
            .as_ref()
            .map(hash_to_bytes)
            .ok_or_else(|| validation_err("vpn lease opening requires a transaction hash"))?;
        let client_asset = AssetId::new(body.asset_definition.clone(), authority.clone());
        let custody_asset = AssetId::new(body.asset_definition.clone(), custody.clone());
        let custody_created = ensure_custody_account(&custody, state_transaction)?;
        let transfer_result = transfer_numeric_asset_for_vpn(
            state_transaction,
            VerifiedVpnNumericBatch::new(
                VerifiedVpnNumericPurpose::Funding {
                    lease_id: body.lease_id,
                    authority: authority.clone(),
                },
                vec![(client_asset, custody_asset, body.tariff.lease_fee.clone())],
            ),
        );
        if transfer_result.is_err() && custody_created {
            state_transaction.world.accounts.remove(custody.clone());
        }
        transfer_result?;
        let record = VpnLeaseRecordV1 {
            lease_id: body.lease_id,
            session_id: body.session_id,
            quote_id: body.quote_id,
            client_account_id: authority.clone(),
            operator_account_id: body.operator_account_id.clone(),
            metering_public_key: body.metering_public_key.clone(),
            asset_definition: body.asset_definition.clone(),
            lease_fee: body.tariff.lease_fee.clone(),
            custody_account_id: custody,
            relay_id: body.policy.relay_id,
            tariff: body.tariff.clone(),
            quote_policy: body.policy.clone(),
            address_slot: body.address_slot,
            signed_quote: quote.clone(),
            open_tx_hash,
            status: VpnLeaseStatusV1::Active,
            opened_at_ms: now_ms,
            expires_at_ms: body.expires_at_ms,
            settlement_grace_ms: body.settlement_grace_ms,
            settled_at_ms: None,
            refunded_at_ms: None,
            highest_voucher_sequence: 0,
            client_voucher_hash: None,
            settled_client_voucher: None,
            relay_receipt_hash: None,
            settled_relay_receipt: None,
            earned_fee: Quantity::zero(),
            refunded_fee: Quantity::zero(),
        };
        state_transaction
            .world
            .put_vpn_lease(record)
            .map_err(validation_err)?;
        Ok(())
    }
}
impl Execute for SettleVpnLease {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .vpn_leases
            .get(&self.lease_id)
            .cloned()
        else {
            return Err(validation_err("vpn lease not found"));
        };
        if record.status != VpnLeaseStatusV1::Active {
            return Err(validation_err("vpn lease is not active"));
        }
        if &record.operator_account_id != authority {
            return Err(validation_err("only vpn operator may settle lease"));
        }
        let now_ms = state_transaction.block_unix_timestamp_ms();
        if now_ms >= record.refund_available_at_ms() {
            return Err(validation_err("vpn lease settlement grace window expired"));
        }
        if self.relay_receipt.receipt.ended_at_ms > now_ms
            || self.client_voucher.body.issued_at_ms > now_ms
        {
            return Err(validation_err(
                "vpn settlement receipt and voucher must not be dated in the future",
            ));
        }
        let earned_fee = verify_vpn_settlement(&record, &self.relay_receipt, &self.client_voucher)?;
        let refund_fee = record
            .lease_fee
            .checked_sub(&earned_fee)
            .map_err(|err| validation_err(format!("vpn refund arithmetic failed: {err}")))?;
        let escrow_asset = custody_asset(&record);
        let mut legs = Vec::new();
        if !earned_fee.is_zero() {
            let operator_asset = operator_asset(&record);
            legs.push((escrow_asset.clone(), operator_asset, earned_fee.clone()));
        }
        if !refund_fee.is_zero() {
            let client_asset = client_asset(&record);
            legs.push((escrow_asset, client_asset, refund_fee.clone()));
        }
        transfer_numeric_asset_for_vpn(
            state_transaction,
            VerifiedVpnNumericBatch::new(
                VerifiedVpnNumericPurpose::Settlement {
                    lease_id: record.lease_id,
                    authority: authority.clone(),
                },
                legs,
            ),
        )?;
        record.status = VpnLeaseStatusV1::Settled;
        record.settled_at_ms = Some(now_ms);
        record.highest_voucher_sequence = self.client_voucher.body.sequence;
        record.client_voucher_hash = Some(self.client_voucher.hash());
        record.settled_client_voucher = Some(self.client_voucher);
        record.relay_receipt_hash = Some(self.relay_receipt.hash());
        record.settled_relay_receipt = Some(self.relay_receipt);
        record.earned_fee = earned_fee;
        record.refunded_fee = refund_fee;
        state_transaction
            .world
            .put_vpn_lease(record)
            .map_err(validation_err)?;
        Ok(())
    }
}
impl Execute for RefundExpiredVpnLease {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(record) = state_transaction
            .world
            .vpn_leases
            .get(&self.lease_id)
            .cloned()
        else {
            return Err(validation_err("vpn lease not found"));
        };
        let now_ms = state_transaction.block_unix_timestamp_ms();
        refund_active_vpn_lease(record, authority, now_ms, state_transaction)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::LaneConfig;
    use iroha_primitives::numeric::Numeric;
    fn nano_quantity(nanos: u64) -> Quantity {
        Quantity::from_canonical_numeric(Numeric::new(u128::from(nanos), 9))
            .expect("test nano-XOR value is a valid quantity")
    }
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("VPN fixture key generation should succeed")
    }
    fn relay_keypair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519)
            .expect("VPN relay fixture key generation should succeed")
    }
    fn operator_keypair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x74; 32], Algorithm::Ed25519)
            .expect("VPN operator fixture key generation should succeed")
    }
    fn sign_relay_receipt(receipt: VpnSessionReceiptV1) -> VpnSignedSessionReceiptV1 {
        VpnSignedSessionReceiptV1::try_sign(receipt, relay_keypair().private_key())
            .expect("VPN relay fixture receipt should sign")
    }
    fn resign_relay_receipt(receipt: &mut VpnSignedSessionReceiptV1) {
        receipt.relay_signature = sign_relay_receipt(receipt.receipt.clone()).relay_signature;
    }
    fn resign_operator_quote(record: &mut VpnLeaseRecordV1) {
        record.signed_quote = VpnSignedQuoteV1::try_sign(
            record.signed_quote.body.clone(),
            operator_keypair().private_key(),
        )
        .expect("VPN operator fixture quote should re-sign");
    }
    fn vpn_test_state() -> crate::state::State {
        crate::state::State::new_for_testing(
            crate::state::World::new(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        )
    }
    fn vpn_test_block_header() -> iroha_data_model::block::BlockHeader {
        iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).expect("VPN test block height is non-zero"),
            None,
            None,
            0,
            0,
        )
    }
    fn vpn_test_network_id(seed: u8) -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([seed; Hash::LENGTH]),
            ),
        )
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn xor_asset_check_accepts_canonical_xor_id() {
        ensure_xor_asset(&xor_asset_definition_id()).expect("canonical XOR asset id");
    }
    #[test]
    fn vpn_lease_custody_account_id_is_stable_without_a_public_signing_seed() {
        let network_id = vpn_test_network_id(0x21);
        let asset_definition = xor_asset_definition_id();
        let lease_id = [0x11; 32];
        let first = vpn_lease_custody_account_id(&network_id, &lease_id, &asset_definition)
            .expect("custody account derivation succeeds");
        let second = vpn_lease_custody_account_id(&network_id, &lease_id, &asset_definition)
            .expect("custody account derivation is repeatable");
        assert_eq!(first, second);
        let mut different_lease_id = lease_id;
        different_lease_id[0] ^= 0x01;
        let different =
            vpn_lease_custody_account_id(&network_id, &different_lease_id, &asset_definition)
                .expect("different custody account derivation succeeds");
        assert_ne!(first, different);
        let different_network =
            vpn_lease_custody_account_id(&vpn_test_network_id(0x22), &lease_id, &asset_definition)
                .expect("different exact-network custody derivation succeeds");
        assert_ne!(first, different_network);
        let mut public_seed_material = Vec::new();
        public_seed_material.extend_from_slice(VPN_LEASE_CUSTODY_ACCOUNT_DOMAIN.as_bytes());
        public_seed_material.extend_from_slice(network_id.as_bytes());
        public_seed_material.extend_from_slice(&lease_id);
        public_seed_material.extend_from_slice(asset_definition.to_string().as_bytes());
        let public_seed: [u8; Hash::LENGTH] = Hash::new(public_seed_material).into();
        let public_seed_keypair = KeyPair::try_from_seed(public_seed.to_vec(), Algorithm::Ed25519)
            .expect("public seed derives");
        assert_ne!(
            first,
            AccountId::new(public_seed_keypair.public_key().clone()),
            "VPN custody must not expose a signing key through public seed derivation"
        );
    }
    fn settlement_record_and_voucher(
        mut voucher_body: VpnUsageVoucherBodyV1,
    ) -> (
        VpnLeaseRecordV1,
        VpnSignedSessionReceiptV1,
        VpnUsageVoucherV1,
    ) {
        let key_pair = checked_keypair();
        let client_account_id = AccountId::new(key_pair.public_key().clone());
        let operator_key = operator_keypair();
        let operator_account_id = AccountId::new(operator_key.public_key().clone());
        let relay_key = relay_keypair();
        let (relay_algorithm, relay_public_key) = relay_key
            .public_key()
            .try_to_bytes()
            .expect("relay fixture key is valid");
        assert_eq!(relay_algorithm, Algorithm::Ed25519);
        voucher_body.relay_id.copy_from_slice(relay_public_key);
        let network_id = vpn_test_network_id(0x31);
        let address_slot = iroha_data_model::soranet::vpn::VpnAddressSlotV1::new(23)
            .expect("fixture address slot");
        let lease_id = iroha_data_model::soranet::vpn::derive_vpn_lease_id_v1(
            &network_id,
            voucher_body.quote_id,
            &client_account_id,
        );
        voucher_body.session_id = iroha_data_model::soranet::vpn::derive_vpn_session_id_v1(
            &network_id,
            voucher_body.quote_id,
            &client_account_id,
            address_slot,
        );
        voucher_body.sequence = 9;
        let voucher = VpnUsageVoucherV1::try_sign(voucher_body, key_pair.private_key())
            .expect("vpn usage voucher fixture should sign");
        let tariff = iroha_data_model::soranet::vpn::VpnTariffV1 {
            lease_fee: nano_quantity(1_000),
            active_fee_per_minute: nano_quantity(60),
            ingress_fee_per_mib: nano_quantity(100),
            egress_fee_per_mib: nano_quantity(200),
        };
        let asset_definition = xor_asset_definition_id();
        let custody_account_id =
            vpn_lease_custody_account_id(&network_id, &lease_id, &asset_definition)
                .expect("derive fixture custody");
        let address_plan = iroha_data_model::soranet::vpn::derive_vpn_address_plan_v1(address_slot);
        let quote_policy = iroha_data_model::soranet::vpn::VpnQuotePolicyV1 {
            exit_class: iroha_data_model::soranet::vpn::VpnExitClassV1::Standard,
            relay_endpoint: "/dns/relay.example/udp/9443/quic".to_owned(),
            relay_id: voucher.body.relay_id,
            relay_mldsa65_public_key: [0x12;
                iroha_data_model::soranet::vpn::VPN_RELAY_MLDSA65_PUBLIC_KEY_BYTES_V1],
            descriptor_commit: [0x22; 32],
            tls_server_name: "relay.example".to_owned(),
            relay_tls_spki_sha256: [0xAB; 32],
            relay_certificate_sha256: [0x33; 32],
            directory_snapshot_digest: [0x66; 32],
            relay_trust_valid_until_ms: 10_000,
            lease_secs: 9,
            meter_family: "soranet.vpn.standard".to_owned(),
            fee_asset_id: asset_definition.to_string(),
            escrow_account_id: custody_account_id.clone(),
            route_pushes: vec!["0.0.0.0/0".to_owned()],
            excluded_routes: Vec::new(),
            dns_servers: vec!["1.1.1.1".to_owned()],
            tunnel_addresses: address_plan.client_tunnel_addresses,
            mtu_bytes: u64::from(iroha_data_model::soranet::vpn::VPN_DEFAULT_TUNNEL_MTU_BYTES),
            flow_label_bits: 24,
            padding_budget_ms: 15,
        };
        let signed_quote = VpnSignedQuoteV1::try_sign(
            VpnQuoteBodyV1 {
                network_id,
                quote_id: voucher.body.quote_id,
                lease_id,
                session_id: voucher.body.session_id,
                address_slot,
                client_account_id: client_account_id.clone(),
                operator_account_id: operator_account_id.clone(),
                metering_public_key: key_pair.public_key().clone(),
                asset_definition: asset_definition.clone(),
                tariff: tariff.clone(),
                policy: quote_policy.clone(),
                valid_after_ms: 1_000,
                expires_at_ms: 10_000,
                settlement_grace_ms: 1_000,
            },
            operator_key.private_key(),
        )
        .expect("sign fixture VPN quote");
        let receipt = VpnSessionReceiptV1 {
            session_id: voucher.body.session_id,
            quote_id: voucher.body.quote_id,
            payment_tx_hash: [0x44; 32],
            account_hash: account_hash(&client_account_id),
            relay_id: voucher.body.relay_id,
            ingress_bytes: voucher.body.ingress_bytes,
            egress_bytes: voucher.body.egress_bytes,
            cover_bytes: 0,
            uptime_secs: u32::try_from(voucher.body.active_ms.div_ceil(1_000))
                .expect("fixture active time fits receipt"),
            started_at_ms: voucher.body.issued_at_ms - voucher.body.active_ms,
            ended_at_ms: voucher.body.issued_at_ms,
            exit_class: iroha_data_model::soranet::vpn::VpnExitClassV1::Standard,
            meter_hash: vpn_tariff_meter_hash_v1(&tariff),
            earned_fee: tariff
                .fee_ceiling(&voucher.body)
                .expect("test tariff arithmetic succeeds"),
            highest_voucher_sequence: voucher.body.sequence,
            client_voucher_hash: voucher.hash(),
        };
        let record = VpnLeaseRecordV1 {
            lease_id,
            session_id: voucher.body.session_id,
            quote_id: voucher.body.quote_id,
            client_account_id,
            operator_account_id,
            metering_public_key: key_pair.public_key().clone(),
            asset_definition,
            lease_fee: tariff.lease_fee.clone(),
            custody_account_id,
            relay_id: voucher.body.relay_id,
            tariff,
            quote_policy,
            address_slot,
            signed_quote,
            open_tx_hash: [0x44; 32],
            status: VpnLeaseStatusV1::Active,
            opened_at_ms: voucher.body.issued_at_ms - voucher.body.active_ms,
            expires_at_ms: 10_000,
            settlement_grace_ms: 1_000,
            settled_at_ms: None,
            refunded_at_ms: None,
            highest_voucher_sequence: 0,
            client_voucher_hash: None,
            settled_client_voucher: None,
            relay_receipt_hash: None,
            settled_relay_receipt: None,
            earned_fee: Quantity::zero(),
            refunded_fee: Quantity::zero(),
        };
        (record, sign_relay_receipt(receipt), voucher)
    }
    #[test]
    fn settlement_verifies_voucher_and_recomputes_tariff() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 1_048_576,
            egress_bytes: 1,
            active_ms: 1_500,
            issued_at_ms: 3_000,
        };
        let (record, mut receipt, voucher) = settlement_record_and_voucher(body);
        receipt.receipt.ingress_bytes = 524_288;
        receipt.receipt.started_at_ms = receipt.receipt.started_at_ms.saturating_add(500);
        let active_ms = receipt.receipt.ended_at_ms - receipt.receipt.started_at_ms;
        receipt.receipt.uptime_secs =
            u32::try_from(active_ms.div_ceil(1_000)).expect("fixture uptime");
        receipt.receipt.earned_fee = record
            .tariff
            .fee_for_usage(
                receipt.receipt.ingress_bytes,
                receipt.receipt.egress_bytes,
                active_ms,
            )
            .expect("actual usage fee");
        resign_relay_receipt(&mut receipt);
        assert_eq!(
            verify_vpn_settlement(&record, &receipt, &voucher).expect("settlement valid"),
            receipt.receipt.earned_fee
        );
    }
    #[test]
    fn open_vpn_lease_admission_rejects_non_ed25519_operator_issuer() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x23; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (mut record, _, _) = settlement_record_and_voucher(body);
        let non_ed25519_operator = KeyPair::try_random_with_algorithm(Algorithm::Secp256k1)
            .expect("secp256k1 fixture key generation succeeds");
        record.signed_quote.body.operator_account_id =
            AccountId::new(non_ed25519_operator.public_key().clone());
        let authority = record.client_account_id.clone();

        let state = vpn_test_state();
        let mut block = state.block(vpn_test_block_header());
        let mut transaction = block.transaction();
        let error = OpenVpnLeaseEscrow::new(record.signed_quote)
            .execute(&authority, &mut transaction)
            .expect_err("consensus must reject a non-Ed25519 quote operator");
        assert!(
            error.to_string().contains(
                "vpn quote operator issuer must use Ed25519 for the V1 helper-ticket format"
            ),
            "unexpected admission error: {error}"
        );
    }
    #[test]
    fn settlement_rejects_relay_overclaim() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 1_048_576,
            egress_bytes: 1,
            active_ms: 1_500,
            issued_at_ms: 3_000,
        };
        let (record, mut receipt, voucher) = settlement_record_and_voucher(body);
        receipt.receipt.earned_fee = receipt
            .receipt
            .earned_fee
            .checked_add(&nano_quantity(1))
            .expect("test overclaim remains representable");
        resign_relay_receipt(&mut receipt);
        assert!(verify_vpn_settlement(&record, &receipt, &voucher).is_err());

        receipt.receipt.earned_fee = record
            .lease_fee
            .checked_add(&nano_quantity(1))
            .expect("fixture over-escrow fee remains representable");
        resign_relay_receipt(&mut receipt);
        let error = verify_vpn_settlement(&record, &receipt, &voucher)
            .expect_err("relay receipt may never claim more than escrow");
        assert!(error.to_string().contains("exceeds the escrowed lease fee"));
    }
    #[test]
    fn settlement_rejects_receipt_interval_beyond_prepaid_time_ceiling() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 1_500,
            issued_at_ms: 3_000,
        };
        let (record, mut receipt, voucher) = settlement_record_and_voucher(body);
        receipt.receipt.started_at_ms = receipt.receipt.started_at_ms.saturating_sub(1);
        resign_relay_receipt(&mut receipt);
        let error = verify_vpn_settlement(&record, &receipt, &voucher)
            .expect_err("receipt time beyond prepaid credit must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the signed prepaid voucher ceilings")
        );
    }
    #[test]
    fn settlement_rejects_uncommitted_receipt_telemetry() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 1_000,
            issued_at_ms: 3_000,
        };
        let (record, receipt, voucher) = settlement_record_and_voucher(body);
        let mut cover_claim = receipt.clone();
        cover_claim.receipt.cover_bytes = 1;
        resign_relay_receipt(&mut cover_claim);
        assert!(verify_vpn_settlement(&record, &cover_claim, &voucher).is_err());
        let mut meter_substitution = receipt;
        meter_substitution.receipt.meter_hash[0] ^= 1;
        resign_relay_receipt(&mut meter_substitution);
        assert!(verify_vpn_settlement(&record, &meter_substitution, &voucher).is_err());
    }
    #[test]
    fn settlement_rejects_tampered_or_wrong_key_relay_receipt() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x24; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 1,
            egress_bytes: 2,
            active_ms: 1_000,
            issued_at_ms: 3_000,
        };
        let (record, receipt, voucher) = settlement_record_and_voucher(body);
        let mut tampered = receipt.clone();
        tampered.receipt.egress_bytes = tampered.receipt.egress_bytes.saturating_add(1);
        let error = verify_vpn_settlement(&record, &tampered, &voucher)
            .expect_err("tampered relay receipt must fail before settlement accounting");
        assert!(error.to_string().contains("relay receipt signature"));

        let wrong_key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
            .expect("wrong relay fixture key generation should succeed");
        let mut wrong_key_body = receipt.receipt.clone();
        let (_, wrong_relay_id) = wrong_key
            .public_key()
            .try_to_bytes()
            .expect("wrong relay fixture key is valid");
        wrong_key_body.relay_id.copy_from_slice(wrong_relay_id);
        let wrong_key_receipt =
            VpnSignedSessionReceiptV1::try_sign(wrong_key_body, wrong_key.private_key())
                .expect("wrong relay fixture signs its own identity");
        let mut substituted = receipt;
        substituted.relay_signature = wrong_key_receipt.relay_signature;
        let error = verify_vpn_settlement(&record, &substituted, &voucher)
            .expect_err("another relay's signature must not authorize settlement");
        assert!(error.to_string().contains("relay receipt signature"));
    }
    #[test]
    fn relay_trust_must_cover_complete_lease() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0x11; 16],
            quote_id: [0x22; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (record, _, _) = settlement_record_and_voucher(body);
        ensure_relay_trust_covers_lease(
            &record.relay_id,
            &record.quote_policy,
            record.expires_at_ms,
        )
        .expect("trust valid through the exclusive lease end is accepted");
        let error = ensure_relay_trust_covers_lease(
            &record.relay_id,
            &record.quote_policy,
            record.expires_at_ms + 1,
        )
        .expect_err("trust expiring before the lease must be rejected");
        assert!(error.clone().contains("complete lease"));
    }
    #[test]
    fn canonical_quote_policy_rejects_unsigned_address_and_economic_projections() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0x81; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (record, _, _) = settlement_record_and_voucher(body);
        ensure_canonical_quote_policy(&record.signed_quote.body, &record.custody_account_id)
            .expect("exact signed quote policy is canonical");
        let mut wrong_address = record.signed_quote.body.clone();
        wrong_address.policy.tunnel_addresses = vec!["10.0.0.2/30".to_owned()];
        assert!(ensure_canonical_quote_policy(&wrong_address, &record.custody_account_id).is_err());
        let mut wrong_fee_asset = record.signed_quote.body.clone();
        wrong_fee_asset.policy.fee_asset_id = "other#universal.universal".to_owned();
        assert!(
            ensure_canonical_quote_policy(&wrong_fee_asset, &record.custody_account_id).is_err()
        );
        let mut missing_trust = record.signed_quote.body.clone();
        missing_trust.policy.directory_snapshot_digest = [0_u8; 32];
        assert!(ensure_canonical_quote_policy(&missing_trust, &record.custody_account_id).is_err());
        let mut invalid_mldsa_identity = record.signed_quote.body.clone();
        invalid_mldsa_identity
            .policy
            .relay_mldsa65_public_key
            .fill(0);
        assert!(
            ensure_canonical_quote_policy(&invalid_mldsa_identity, &record.custody_account_id)
                .is_err()
        );
        let mut oversized_endpoint = record.signed_quote.body.clone();
        oversized_endpoint.policy.relay_endpoint = "x".repeat(VPN_MAX_RELAY_ENDPOINT_BYTES_V1 + 1);
        assert!(
            ensure_canonical_quote_policy(&oversized_endpoint, &record.custody_account_id).is_err()
        );
        let mut too_many_routes = record.signed_quote.body.clone();
        too_many_routes.policy.route_pushes = (0..=VPN_MAX_ROUTE_ENTRIES_V1)
            .map(|index| format!("10.0.{index}.0/24"))
            .collect();
        assert!(
            ensure_canonical_quote_policy(&too_many_routes, &record.custody_account_id).is_err()
        );
        let mut duplicate_route = record.signed_quote.body.clone();
        duplicate_route.policy.route_pushes = vec!["0.0.0.0/0".to_owned(); 2];
        assert!(
            ensure_canonical_quote_policy(&duplicate_route, &record.custody_account_id).is_err()
        );
        let mut zero_padding = record.signed_quote.body.clone();
        zero_padding.policy.padding_budget_ms = 0;
        assert!(ensure_canonical_quote_policy(&zero_padding, &record.custody_account_id).is_err());
    }
    #[test]
    fn quote_preflight_bounds_variable_fields_before_crypto_encoding() {
        let source = include_str!("vpn.rs");
        let static_validator = source
            .split_once("pub(crate) fn validate_static_vpn_quote")
            .expect("static quote validator remains defined")
            .1
            .split_once("fn vpn_quote_operator_is_authorized")
            .expect("static quote validator remains bounded by the next function")
            .0;
        let policy_bounds = static_validator
            .find("ensure_canonical_quote_policy")
            .expect("static validator retains structural policy bounds");
        let counted_size = static_validator
            .find("quote.encoded_len()")
            .expect("static validator retains allocation-free encoded-size counting");
        assert!(
            policy_bounds < counted_size,
            "variable policy fields must be bounded before encoded-size counting"
        );
        assert!(
            !static_validator.contains("quote.encode()"),
            "static quote preflight must not allocate a duplicate encoded envelope"
        );

        let admission = source
            .split_once("fn verify_operator_quote")
            .expect("quote admission remains defined")
            .1
            .split_once("fn hash_to_bytes")
            .expect("quote admission remains bounded by the next function")
            .0;
        assert!(
            admission
                .find("validate_static_vpn_quote")
                .expect("admission retains static preflight")
                < admission
                    .find("quote.verify()")
                    .expect("admission retains signature verification"),
            "admission must bound the body before signature verification encodes it"
        );

        let state_source = include_str!("../../state/vpn_lease_validation.rs");
        let projection = state_source
            .split_once("fn validate_vpn_lease_quote_projection")
            .expect("state quote projection remains defined")
            .1;
        assert!(
            projection
                .find("validate_static_vpn_quote")
                .expect("state rebuild retains static preflight")
                < projection
                    .find(".verify()")
                    .expect("state rebuild retains signature verification"),
            "state rebuild must bound the body before signature verification encodes it"
        );
    }
    #[test]
    fn vpn_quote_operator_authority_accepts_only_leaf_permission_directly_or_via_role() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0x82; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (record, _, _) = settlement_record_and_voucher(body);
        let operator = record.operator_account_id.clone();
        let state = vpn_test_state();
        let mut block = state.block(vpn_test_block_header());
        let mut transaction = block.transaction();
        let account = Account::new(operator.clone()).build(&operator);
        let (id, value) = account.into_key_value();
        transaction.world.accounts.insert(id, value);
        assert!(
            !vpn_quote_operator_is_authorized(&operator, &transaction.world)
                .expect("registered operator lookup")
        );
        let required: Permission = CanIssueSoranetVpnQuote.into();
        transaction.world.account_permissions.insert(
            operator.clone(),
            std::collections::BTreeSet::from([required.clone()]),
        );
        assert!(
            vpn_quote_operator_is_authorized(&operator, &transaction.world)
                .expect("direct issuer lookup")
        );
        transaction
            .world
            .account_permissions
            .remove(operator.clone());
        let role_id: RoleId = "soranet_vpn_quote_issuer".parse().expect("role id");
        let role = Role::new(role_id.clone(), operator.clone())
            .add_permission(required)
            .build(&operator);
        transaction.world.roles.insert(role_id.clone(), role);
        transaction.world.account_roles.insert(
            crate::role::RoleIdWithOwner::new(operator.clone(), role_id),
            (),
        );
        assert!(
            vpn_quote_operator_is_authorized(&operator, &transaction.world)
                .expect("role issuer lookup")
        );
    }
    #[test]
    fn active_address_slot_index_rejects_exact_historical_quote_collision_pair() {
        let mut quote_0009 = [0_u8; 32];
        quote_0009[31] = 0x09;
        let mut quote_0198 = [0_u8; 32];
        quote_0198[30..].copy_from_slice(&[0x01, 0x98]);
        let voucher_body = |quote_id| VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id,
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (first, _, _) = settlement_record_and_voucher(voucher_body(quote_0009));
        let (second, _, _) = settlement_record_and_voucher(voucher_body(quote_0198));
        assert_ne!(first.client_account_id, second.client_account_id);
        assert_eq!(first.address_slot, second.address_slot);
        let world = crate::state::World::new();
        let mut block = world.block();
        let mut transaction =
            block.transaction_without_telemetry(LaneConfig::default(), /* block height */ 1);
        transaction
            .put_vpn_lease(first)
            .expect("first typed address claim is available");
        let error = transaction
            .put_vpn_lease(second)
            .expect_err("second active lease must not alias the same address slot");
        assert!(error.contains("address slot"), "unexpected error: {error}");
    }
    #[test]
    fn active_account_index_releases_only_on_terminal_transition() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0x91; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (active, _, _) = settlement_record_and_voucher(body);
        let mut terminal = active.clone();
        terminal.status = VpnLeaseStatusV1::Refunded;
        terminal.refunded_at_ms = Some(11_000);
        terminal.refunded_fee = terminal.lease_fee.clone();
        let state = vpn_test_state();
        let mut block = state.block(vpn_test_block_header());
        let mut transaction = block.transaction();
        transaction
            .world
            .put_vpn_lease(active.clone())
            .expect("active lease is indexed");
        assert!(is_active_vpn_client(
            &transaction.world,
            &active.client_account_id
        ));
        assert_eq!(
            transaction
                .world
                .vpn_active_lease_by_account
                .get(&active.client_account_id),
            Some(&active.lease_id)
        );
        transaction
            .world
            .put_vpn_lease(terminal)
            .expect("terminal transition releases active claims");
        assert!(
            transaction
                .world
                .vpn_active_lease_by_account
                .get(&active.client_account_id)
                .is_none()
        );
        assert!(
            transaction
                .world
                .vpn_active_lease_by_address_slot
                .get(&active.address_slot)
                .is_none()
        );
        assert!(!is_active_vpn_client(
            &transaction.world,
            &active.client_account_id
        ));
        let error = transaction
            .world
            .put_vpn_lease(active)
            .expect_err("terminal VPN lease must not be resurrected");
        assert!(error.contains("terminal status back to active"));
    }
    #[test]
    fn vpn_state_rejects_a_retained_quote_field_substitution() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0xA1; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (mut forged, _, _) = settlement_record_and_voucher(body);
        let mut impossible_open = forged.clone();
        impossible_open.opened_at_ms = impossible_open.expires_at_ms;
        forged.signed_quote.body.policy.descriptor_commit[0] ^= 1;
        let world = crate::state::World::new();
        let mut block = world.block();
        let mut transaction =
            block.transaction_without_telemetry(LaneConfig::default(), /* block height */ 1);
        let error = transaction
            .put_vpn_lease(forged)
            .expect_err("retained quote substitution must fail before indexing");
        assert!(
            error.contains("invalid operator quote"),
            "unexpected error: {error}"
        );
        let error = transaction
            .put_vpn_lease(impossible_open)
            .expect_err("lease opening outside the signed interval must fail");
        assert!(
            error.contains("opened outside"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn vpn_state_revalidates_all_static_quote_invariants() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0xA3; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            active_ms: 0,
            issued_at_ms: 2_000,
        };
        let (canonical, _, _) = settlement_record_and_voucher(body);
        let insert_fresh = |record| {
            let world = crate::state::World::new();
            let mut block = world.block();
            let mut transaction = block
                .transaction_without_telemetry(LaneConfig::default(), /* block height */ 1);
            transaction.put_vpn_lease(record).map(|_| ())
        };
        insert_fresh(canonical.clone()).expect("canonical quote must rebuild");
        let assert_rejected = |record, expected: &str| {
            let error = insert_fresh(record).expect_err("invalid static quote must be rejected");
            assert!(
                error.contains(expected),
                "expected `{expected}` in quote validation error, got: {error}"
            );
        };

        let mut duplicate_route = canonical.clone();
        duplicate_route.signed_quote.body.policy.route_pushes = vec!["0.0.0.0/0".to_owned(); 2];
        duplicate_route.quote_policy = duplicate_route.signed_quote.body.policy.clone();
        resign_operator_quote(&mut duplicate_route);
        assert_rejected(duplicate_route, "routes must not contain duplicate entries");

        let mut overlapping_route = canonical.clone();
        overlapping_route.signed_quote.body.policy.excluded_routes = vec!["0.0.0.0/0".to_owned()];
        overlapping_route.quote_policy = overlapping_route.signed_quote.body.policy.clone();
        resign_operator_quote(&mut overlapping_route);
        assert_rejected(overlapping_route, "route sets must be disjoint");

        let mut duplicate_dns = canonical.clone();
        duplicate_dns.signed_quote.body.policy.dns_servers = vec!["1.1.1.1".to_owned(); 2];
        duplicate_dns.quote_policy = duplicate_dns.signed_quote.body.policy.clone();
        resign_operator_quote(&mut duplicate_dns);
        assert_rejected(
            duplicate_dns,
            "DNS resolvers must not contain duplicate entries",
        );

        let mut invalid_endpoint = canonical.clone();
        invalid_endpoint.signed_quote.body.policy.relay_endpoint = "relay.example:9443".to_owned();
        invalid_endpoint.quote_policy = invalid_endpoint.signed_quote.body.policy.clone();
        resign_operator_quote(&mut invalid_endpoint);
        assert_rejected(invalid_endpoint, "relay endpoint is invalid");

        let mut invalid_tls_name = canonical.clone();
        invalid_tls_name.signed_quote.body.policy.tls_server_name = "Relay.Example".to_owned();
        invalid_tls_name.quote_policy = invalid_tls_name.signed_quote.body.policy.clone();
        resign_operator_quote(&mut invalid_tls_name);
        assert_rejected(invalid_tls_name, "TLS server name is invalid");

        let mut route_with_host_bits = canonical.clone();
        route_with_host_bits.signed_quote.body.policy.route_pushes = vec!["10.0.0.1/24".to_owned()];
        route_with_host_bits.quote_policy = route_with_host_bits.signed_quote.body.policy.clone();
        resign_operator_quote(&mut route_with_host_bits);
        assert_rejected(route_with_host_bits, "host bits cleared");

        let mut noncanonical_route = canonical.clone();
        noncanonical_route.signed_quote.body.policy.route_pushes =
            vec!["2001:0db8::/32".to_owned()];
        noncanonical_route.quote_policy = noncanonical_route.signed_quote.body.policy.clone();
        resign_operator_quote(&mut noncanonical_route);
        assert_rejected(noncanonical_route, "canonical IP address spelling");

        let mut noncanonical_prefix = canonical.clone();
        noncanonical_prefix.signed_quote.body.policy.route_pushes = vec!["10.0.0.0/024".to_owned()];
        noncanonical_prefix.quote_policy = noncanonical_prefix.signed_quote.body.policy.clone();
        resign_operator_quote(&mut noncanonical_prefix);
        assert_rejected(noncanonical_prefix, "canonical decimal prefix");

        let mut invalid_dns = canonical.clone();
        invalid_dns.signed_quote.body.policy.dns_servers = vec!["one.one.one.one".to_owned()];
        invalid_dns.quote_policy = invalid_dns.signed_quote.body.policy.clone();
        resign_operator_quote(&mut invalid_dns);
        assert_rejected(invalid_dns, "is not an IP literal");

        for resolver in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "ff02::1"] {
            let mut non_unicast_dns = canonical.clone();
            non_unicast_dns.signed_quote.body.policy.dns_servers = vec![resolver.to_owned()];
            non_unicast_dns.quote_policy = non_unicast_dns.signed_quote.body.policy.clone();
            resign_operator_quote(&mut non_unicast_dns);
            assert_rejected(non_unicast_dns, "unicast resolver address");
        }

        let mut noncanonical_dns = canonical.clone();
        noncanonical_dns.signed_quote.body.policy.dns_servers = vec!["2001:0db8::1".to_owned()];
        noncanonical_dns.quote_policy = noncanonical_dns.signed_quote.body.policy.clone();
        resign_operator_quote(&mut noncanonical_dns);
        assert_rejected(noncanonical_dns, "canonical IP literal spelling");

        let mut intentional_subnet_exclusion = canonical.clone();
        intentional_subnet_exclusion
            .signed_quote
            .body
            .policy
            .excluded_routes = vec!["10.0.0.0/8".to_owned()];
        intentional_subnet_exclusion.quote_policy = intentional_subnet_exclusion
            .signed_quote
            .body
            .policy
            .clone();
        resign_operator_quote(&mut intentional_subnet_exclusion);
        insert_fresh(intentional_subnet_exclusion)
            .expect("a subnet exclusion below a pushed default route remains valid");

        let mut wrong_flow_width = canonical.clone();
        wrong_flow_width.signed_quote.body.policy.flow_label_bits = 23;
        wrong_flow_width.quote_policy = wrong_flow_width.signed_quote.body.policy.clone();
        resign_operator_quote(&mut wrong_flow_width);
        assert_rejected(wrong_flow_width, "flow-label width must be 24 bits");

        let mut wrong_mtu = canonical.clone();
        wrong_mtu.signed_quote.body.policy.mtu_bytes = u64::from(VPN_DEFAULT_TUNNEL_MTU_BYTES) + 1;
        wrong_mtu.quote_policy = wrong_mtu.signed_quote.body.policy.clone();
        resign_operator_quote(&mut wrong_mtu);
        assert_rejected(wrong_mtu, "quote MTU must be 1280 bytes");

        let mut zero_padding = canonical.clone();
        zero_padding.signed_quote.body.policy.padding_budget_ms = 0;
        zero_padding.quote_policy = zero_padding.signed_quote.body.policy.clone();
        resign_operator_quote(&mut zero_padding);
        assert_rejected(zero_padding, "padding budget must be greater than zero");

        let mut control_character = canonical.clone();
        control_character
            .signed_quote
            .body
            .policy
            .tls_server_name
            .push('\n');
        control_character.quote_policy = control_character.signed_quote.body.policy.clone();
        resign_operator_quote(&mut control_character);
        assert_rejected(control_character, "control-free UTF-8");

        let mut oversized_tls_name = canonical.clone();
        oversized_tls_name.signed_quote.body.policy.tls_server_name =
            "x".repeat(VPN_MAX_TLS_SERVER_NAME_BYTES_V1 + 1);
        oversized_tls_name.quote_policy = oversized_tls_name.signed_quote.body.policy.clone();
        resign_operator_quote(&mut oversized_tls_name);
        assert_rejected(oversized_tls_name, "at most 253 bytes");

        let mut oversized_quote = canonical.clone();
        oversized_quote.signed_quote.body.policy.relay_endpoint =
            "x".repeat(VPN_MAX_SIGNED_QUOTE_BYTES_V1 + 1);
        oversized_quote.quote_policy = oversized_quote.signed_quote.body.policy.clone();
        resign_operator_quote(&mut oversized_quote);
        assert_rejected(oversized_quote, "at most 1024 bytes");

        let mut oversized_signature = canonical.clone();
        oversized_signature.signed_quote.signature =
            iroha_crypto::Signature::from_bytes(&vec![0_u8; VPN_MAX_SIGNED_QUOTE_BYTES_V1 + 1]);
        assert_rejected(oversized_signature, "vpn quote signature has");

        let mut non_xor_fee = canonical.clone();
        let non_xor_asset = AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("universal.universal")
                .expect("fixture domain should parse"),
            Name::from_str("other").expect("fixture asset name should parse"),
        );
        let non_xor_custody = vpn_lease_custody_account_id(
            &non_xor_fee.signed_quote.body.network_id,
            &non_xor_fee.lease_id,
            &non_xor_asset,
        )
        .expect("fixture custody derivation should succeed");
        non_xor_fee.signed_quote.body.asset_definition = non_xor_asset.clone();
        non_xor_fee.signed_quote.body.policy.fee_asset_id = non_xor_asset.to_string();
        non_xor_fee.signed_quote.body.policy.escrow_account_id = non_xor_custody.clone();
        non_xor_fee.asset_definition = non_xor_asset;
        non_xor_fee.custody_account_id = non_xor_custody;
        non_xor_fee.quote_policy = non_xor_fee.signed_quote.body.policy.clone();
        resign_operator_quote(&mut non_xor_fee);
        assert_rejected(non_xor_fee, "fee asset must be XOR");

        let mut zero_fee = canonical;
        zero_fee.signed_quote.body.tariff.lease_fee = Quantity::zero();
        zero_fee.tariff = zero_fee.signed_quote.body.tariff.clone();
        zero_fee.lease_fee = Quantity::zero();
        resign_operator_quote(&mut zero_fee);
        assert_rejected(zero_fee, "lease fee must be positive");
    }
    #[test]
    fn vpn_state_revalidates_terminal_receipt_and_timeout_boundaries() {
        let body = VpnUsageVoucherBodyV1 {
            session_id: [0_u8; 16],
            quote_id: [0xA2; 32],
            relay_id: [0x33; 32],
            sequence: 0,
            ingress_bytes: 1_024,
            egress_bytes: 2_048,
            active_ms: 1_000,
            issued_at_ms: 2_000,
        };
        let (active, receipt, voucher) = settlement_record_and_voucher(body);
        let mut settled = active.clone();
        settled.status = VpnLeaseStatusV1::Settled;
        settled.settled_at_ms = Some(receipt.receipt.ended_at_ms);
        settled.highest_voucher_sequence = voucher.body.sequence;
        settled.client_voucher_hash = Some(voucher.hash());
        settled.settled_client_voucher = Some(voucher.clone());
        settled.relay_receipt_hash = Some(receipt.hash());
        settled.settled_relay_receipt = Some(receipt);
        settled.earned_fee = settled
            .settled_relay_receipt
            .as_ref()
            .expect("settled fixture receipt")
            .receipt
            .earned_fee
            .clone();
        settled.refunded_fee = settled
            .lease_fee
            .checked_sub(&settled.earned_fee)
            .expect("fixture fee conservation");
        let insert_fresh = |record| {
            let world = crate::state::World::new();
            let mut block = world.block();
            let mut transaction = block
                .transaction_without_telemetry(LaneConfig::default(), /* block height */ 1);
            transaction.put_vpn_lease(record).map(|_| ())
        };
        insert_fresh(settled.clone()).expect("canonical settled lease must rebuild");
        let mut wrong_account = settled.clone();
        let wrong_account_receipt_hash = {
            let wrong_account_receipt = wrong_account
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            wrong_account_receipt.receipt.account_hash[0] ^= 1;
            resign_relay_receipt(wrong_account_receipt);
            wrong_account_receipt.hash()
        };
        wrong_account.relay_receipt_hash = Some(wrong_account_receipt_hash);
        assert!(
            insert_fresh(wrong_account)
                .expect_err("receipt account substitution must fail")
                .contains("retained settlement evidence")
        );
        let mut wrong_class = settled.clone();
        let wrong_class_receipt_hash = {
            let wrong_class_receipt = wrong_class
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            wrong_class_receipt.receipt.exit_class =
                iroha_data_model::soranet::vpn::VpnExitClassV1::HighSecurity;
            resign_relay_receipt(wrong_class_receipt);
            wrong_class_receipt.hash()
        };
        wrong_class.relay_receipt_hash = Some(wrong_class_receipt_hash);
        assert!(
            insert_fresh(wrong_class)
                .expect_err("receipt class substitution must fail")
                .contains("retained settlement evidence")
        );
        let mut wrong_meter = settled.clone();
        let wrong_meter_hash = {
            let receipt = wrong_meter
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            receipt.receipt.meter_hash[0] ^= 1;
            resign_relay_receipt(receipt);
            receipt.hash()
        };
        wrong_meter.relay_receipt_hash = Some(wrong_meter_hash);
        assert!(
            insert_fresh(wrong_meter)
                .expect_err("receipt meter substitution must fail")
                .contains("meter hash")
        );
        let mut wrong_uptime = settled.clone();
        let wrong_uptime_hash = {
            let receipt = wrong_uptime
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            receipt.receipt.uptime_secs = receipt.receipt.uptime_secs.saturating_add(1);
            resign_relay_receipt(receipt);
            receipt.hash()
        };
        wrong_uptime.relay_receipt_hash = Some(wrong_uptime_hash);
        assert!(
            insert_fresh(wrong_uptime)
                .expect_err("noncanonical receipt uptime must fail")
                .contains("uptime")
        );
        let mut cover_claim = settled.clone();
        let cover_claim_hash = {
            let receipt = cover_claim
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            receipt.receipt.cover_bytes = 1;
            resign_relay_receipt(receipt);
            receipt.hash()
        };
        cover_claim.relay_receipt_hash = Some(cover_claim_hash);
        assert!(
            insert_fresh(cover_claim)
                .expect_err("settlement cover telemetry must fail")
                .contains("cover telemetry")
        );
        let mut wrong_fee = settled.clone();
        let inflated_fee = wrong_fee
            .earned_fee
            .checked_add(&nano_quantity(1))
            .expect("fixture fee inflation remains representable");
        let wrong_fee_hash = {
            let receipt = wrong_fee
                .settled_relay_receipt
                .as_mut()
                .expect("settled fixture receipt");
            receipt.receipt.earned_fee = inflated_fee.clone();
            resign_relay_receipt(receipt);
            receipt.hash()
        };
        wrong_fee.relay_receipt_hash = Some(wrong_fee_hash);
        wrong_fee.earned_fee = inflated_fee;
        wrong_fee.refunded_fee = wrong_fee
            .lease_fee
            .checked_sub(&wrong_fee.earned_fee)
            .expect("fixture fee conservation");
        assert!(
            insert_fresh(wrong_fee)
                .expect_err("receipt tariff overclaim must fail")
                .contains("earned fee")
        );
        let mut missing_voucher = settled.clone();
        missing_voucher.settled_client_voucher = None;
        assert!(
            insert_fresh(missing_voucher)
                .expect_err("settled lease without full client evidence must fail")
                .contains("no retained client voucher")
        );
        let mut forged_voucher = settled.clone();
        forged_voucher
            .settled_client_voucher
            .as_mut()
            .expect("settled fixture voucher")
            .body
            .ingress_bytes += 1;
        assert!(
            insert_fresh(forged_voucher)
                .expect_err("tampered retained client voucher must fail")
                .contains("voucher signature")
        );
        let mut late_settlement = settled;
        late_settlement.settled_at_ms = Some(late_settlement.refund_available_at_ms());
        assert!(
            insert_fresh(late_settlement)
                .expect_err("settlement at the refund boundary must fail")
                .contains("retained receipt")
        );
        let mut early_refund = active;
        early_refund.status = VpnLeaseStatusV1::Refunded;
        early_refund.refunded_at_ms = Some(early_refund.refund_available_at_ms() - 1);
        early_refund.refunded_fee = early_refund.lease_fee.clone();
        assert!(
            insert_fresh(early_refund)
                .expect_err("refund before the settlement window closes must fail")
                .contains("terminal state")
        );
    }
}
