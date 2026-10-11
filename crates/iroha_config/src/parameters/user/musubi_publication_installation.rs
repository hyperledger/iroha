//! Complete explicit publication installation intent; parsing performs no secret or network I/O.

use super::*;

/// All-or-none original publication identity, private-file selection and bounded pin spending.
///
/// Empty configuration leaves publication uninstalled. Identity and pin fields are all required;
/// the independent readback timeout defaults only within that complete selection. Partial
/// configuration is an error, never a request to generate credentials, replace a session or
/// initialize missing durable history.
#[derive(Debug, Clone, ReadConfig, Default)]
pub struct MusubiPublicationInstallation {
    /// Exact original genesis-derived network.
    pub network_id: Option<NetworkId>,
    /// Exact nonzero seed ProviderId as 64 lowercase hexadecimal characters.
    pub seed_provider_hex: Option<String>,
    /// Canonical provider-owner account, independently checked by native receipt validation.
    pub ingress_broker: Option<String>,
    /// Original nonzero pin session as 64 lowercase hexadecimal characters.
    pub pin_session_hex: Option<String>,
    /// Original owner-private broker credential; parser never reads it.
    pub broker_key_file: Option<WithOrigin<PathBuf>>,
    /// Original owner-private paid-pin credential; parser never reads it.
    pub pin_key_file: Option<WithOrigin<PathBuf>>,
    /// Exact canonical DNS name of the original server certificate.
    pub tls_server_name: Option<String>,
    /// Original DER server certificate.
    pub tls_certificate_file: Option<WithOrigin<PathBuf>>,
    /// Original DER server private key.
    pub tls_private_key_file: Option<WithOrigin<PathBuf>>,
    /// Original DER trust root, without global trust-store modification.
    pub tls_root_certificate_file: Option<WithOrigin<PathBuf>>,
    /// Per-discovery budget in milliseconds, default 30 seconds and bounded to 1..=120_000.
    /// Independent of caller request timeouts and the paid-pin authorization interval.
    pub readback_request_timeout_ms: Option<u64>,
    /// New-operation interval, at most one hour and additionally capped by signed caller expiry.
    pub pin_authorization_window_ms: Option<u64>,
    /// Positive Check count, at most sixteen, under the unchanged operation authorization.
    pub pin_max_check_rounds: Option<u16>,
    /// Exact native Nexus fee asset.
    pub pin_fee_asset: Option<AssetDefinitionId>,
    /// Positive per-transaction Nexus ceiling; does not cap native-priced pin principal.
    pub pin_per_transaction_fee_limit: Option<Quantity>,
    /// Aggregate Nexus ceiling covering the selected per-transaction ceiling.
    pub pin_total_fee_limit: Option<Quantity>,
}

impl MusubiPublicationInstallation {
    pub(super) fn parse(
        self,
        emitter: &mut Emitter<ParseError>,
    ) -> Option<actual::MusubiPublicationInstallation> {
        let any = [
            self.network_id.is_some(),
            self.seed_provider_hex.is_some(),
            self.ingress_broker.is_some(),
            self.pin_session_hex.is_some(),
            self.broker_key_file.is_some(),
            self.pin_key_file.is_some(),
            self.tls_server_name.is_some(),
            self.tls_certificate_file.is_some(),
            self.tls_private_key_file.is_some(),
            self.tls_root_certificate_file.is_some(),
            self.readback_request_timeout_ms.is_some(),
            self.pin_authorization_window_ms.is_some(),
            self.pin_max_check_rounds.is_some(),
            self.pin_fee_asset.is_some(),
            self.pin_per_transaction_fee_limit.is_some(),
            self.pin_total_fee_limit.is_some(),
        ]
        .into_iter()
        .any(|present| present);
        if !any {
            return None;
        }
        match self.complete() {
            Ok(selected) => Some(selected),
            Err(message) => {
                emitter.emit(
                    Report::new(ParseError::InvalidMusubiPublicationConfig)
                        .attach(format!("musubi_publication.installation: {message}")),
                );
                None
            }
        }
    }

    fn complete(self) -> core::result::Result<actual::MusubiPublicationInstallation, &'static str> {
        let network_id = required(self.network_id)?;
        let seed_provider = ProviderId::new(nonzero_hex(required(self.seed_provider_hex)?)?);
        let raw_broker = required(self.ingress_broker)?;
        let ingress_broker = AccountId::parse_encoded(&raw_broker)
            .map_err(|_| "broker must be one canonical domainless account")?;
        if ingress_broker.to_string() != raw_broker || network_id.as_bytes()[31] & 1 != 1 {
            return Err("network or canonical broker identity differs");
        }
        let pin_session = nonzero_hex(required(self.pin_session_hex)?)?;
        let tls_server_name = required(self.tls_server_name)?;
        if !canonical_dns_name(&tls_server_name) {
            return Err("TLS server name must be canonical lowercase DNS");
        }
        let broker_key_file = private_path(&required(self.broker_key_file)?)?;
        let pin_key_file = private_path(&required(self.pin_key_file)?)?;
        let tls_certificate_file = private_path(&required(self.tls_certificate_file)?)?;
        let tls_private_key_file = private_path(&required(self.tls_private_key_file)?)?;
        let tls_root_certificate_file = private_path(&required(self.tls_root_certificate_file)?)?;
        let readback_request_timeout_ms = self
            .readback_request_timeout_ms
            .unwrap_or(defaults::musubi_publication::READBACK_REQUEST_TIMEOUT_MS);
        if !(1..=defaults::musubi_publication::MAX_READBACK_REQUEST_TIMEOUT_MS)
            .contains(&readback_request_timeout_ms)
        {
            return Err("readback request timeout must be within 1..=120_000 milliseconds");
        }
        let pin_authorization_window_ms = required(self.pin_authorization_window_ms)?;
        let pin_max_check_rounds = required(self.pin_max_check_rounds)?;
        let pin_fee_asset = required(self.pin_fee_asset)?;
        let pin_per_transaction_fee_limit = required(self.pin_per_transaction_fee_limit)?;
        let pin_total_fee_limit = required(self.pin_total_fee_limit)?;
        if !(1..=3_600_000).contains(&pin_authorization_window_ms)
            || !(1..=16).contains(&pin_max_check_rounds)
            || pin_per_transaction_fee_limit.is_zero()
            || pin_total_fee_limit < pin_per_transaction_fee_limit
        {
            return Err("finite pin interval, Check count or Nexus ceilings are invalid");
        }
        Ok(actual::MusubiPublicationInstallation {
            network_id,
            seed_provider,
            ingress_broker,
            pin_session,
            broker_key_file,
            pin_key_file,
            tls_server_name,
            tls_certificate_file,
            tls_private_key_file,
            tls_root_certificate_file,
            readback_request_timeout_ms,
            pin_authorization_window_ms,
            pin_max_check_rounds,
            pin_fee_asset,
            pin_per_transaction_fee_limit,
            pin_total_fee_limit,
        })
    }
}

fn required<T>(value: Option<T>) -> core::result::Result<T, &'static str> {
    value.ok_or("all installation fields are required together")
}
fn nonzero_hex(value: String) -> core::result::Result<[u8; 32], &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("provider and session must be 64 lowercase hexadecimal characters");
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "invalid original hexadecimal identity")?;
    if bytes == [0; 32] {
        return Err("provider and session must be nonzero");
    }
    Ok(bytes)
}
fn private_path(value: &WithOrigin<PathBuf>) -> core::result::Result<PathBuf, &'static str> {
    if value.value().as_os_str().is_empty() {
        return Err("original private file paths must not be empty");
    }
    Ok(value.resolve_relative_path())
}
fn canonical_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests;
