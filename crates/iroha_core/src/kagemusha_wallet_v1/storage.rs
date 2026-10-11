//! Canonical bounded ledger table records. One typed key selects one exact Norito schema;
//! there are no fallback decoders or mutable account-metadata authority records.
use super::*;

pub(super) const REGISTRATION: u8 = 1;
pub(super) const WALLET: u8 = 2;
pub(super) const ISSUANCE: u8 = 3;
pub(super) const UNLOAD: u8 = 4;
pub(super) const FEE: u8 = 5;
pub(super) const CERTIFICATE: u8 = 6;
pub(super) const CREDENTIAL: u8 = 7;
pub(super) const REQUEST: u8 = 8;

/// Historical issuer-certified credential, retained by its credential digest.
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::CredentialRecord")]
pub struct CredentialRecord {
    /// Canonical credential.
    pub credential: KagemushaWalletCredentialV1,
    /// Exact issuer certificate set.
    pub certificates: KagemushaWalletCertificateSetV1,
}

pub(super) fn key(kind: u8, scheme: Digest, owner: Digest) -> KagemushaWalletLedgerKeyV1 {
    KagemushaWalletLedgerKeyV1::from_parts(kind, scheme, owner, [0; 32])
}
pub(super) fn issuance_key(
    scheme: Digest,
    wallet: Digest,
    request: Digest,
) -> KagemushaWalletLedgerKeyV1 {
    entry_key(ISSUANCE, scheme, wallet, request)
}
pub(super) fn entry_key(
    kind: u8,
    scheme: Digest,
    owner: Digest,
    entry: Digest,
) -> KagemushaWalletLedgerKeyV1 {
    KagemushaWalletLedgerKeyV1::from_parts(kind, scheme, owner, entry)
}
pub(super) fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>> {
    norito::to_bytes(value).map_err(|_| Error::Binding)
}
pub(super) fn decode<T>(bytes: &[u8], cap: usize) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.len() > cap {
        return Err(Error::Binding);
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(cap))
        .map_err(|_| Error::Binding)
}

/// Validate one restored row's exact key/schema/bindings before trusting a snapshot.
///
/// # Errors
/// Rejects unknown tags, oversized/noncanonical values, nonzero unused keys, or mismatched
/// identities. Signature/proof admission belongs to the original atomic execution, and the
/// enclosing snapshot must be authenticated against the finalized World state commitment.
pub fn validate_row(key: &KagemushaWalletLedgerKeyV1, bytes: &[u8]) -> Result<()> {
    let (kind, scheme, owner, entry) = &key.components();
    if *scheme == [0; 32] || *owner == [0; 32] || (*kind != ISSUANCE && *entry != [0; 32]) {
        return Err(Error::Binding);
    }
    match *kind {
        super::event_evidence::KIND => {
            let value: super::event_evidence::KagemushaLoadEventPathV1 =
                decode(bytes, super::event_evidence::CAP)?;
            value.validate(key)
        }
        super::artifacts::KIND => {
            let value: super::artifacts::VerifierInstallation =
                decode(bytes, super::artifacts::CAP)?;
            value.validate(key)
        }
        REGISTRATION => {
            let value: Registration = decode(bytes, bytes.len())?;
            value.require(scheme, owner)
        }
        WALLET => {
            let value: WalletRecord = decode(bytes, WALLET_CAP)?;
            if value.asset == [0; 32]
                || (value.phase == Phase::Abandoned
                    && (value.activation != [0; 32] || value.next_load != 0))
                || (value.phase != Phase::Abandoned && value.activation == [0; 32])
            {
                return Err(Error::Binding);
            }
            Ok(())
        }
        ISSUANCE => {
            let value: Issuance = decode(bytes, bytes.len())?;
            value.body.validate()?;
            if value.command.scheme != *scheme
                || value.command.wallet != *owner
                || value.command.request_id != *entry
                || *entry == [0; 32]
                || value.body.scheme_id != *scheme
                || value.body.wallet_id != *owner
                || value.command.amount != value.body.amount
                || value.command.asset != value.body.asset_digest
                || value.command.ordinal != value.body.ordinal
                || value.command.request_id != value.body.request_id
                || kagemusha_wallet_account_digest_v1(&value.payer)?
                    != value.body.payer_account_digest
            {
                return Err(Error::Binding);
            }
            match &value.command.charge {
                Some(charge) => {
                    charge.quote.validate()?;
                    charge.quote.require_terms(
                        KagemushaWalletChargeKindV1::Load,
                        &value.body.wallet_id,
                        value.body.ordinal,
                        value.body.amount,
                        value.body.online_charge,
                    )?;
                    if charge.quote.body.scheme_id != *scheme
                        || charge.quote.body.asset_digest != value.body.asset_digest
                        || charge.quote.charge_quote_digest() != value.body.charge_quote
                        || kagemusha_wallet_account_digest_v1(&charge.beneficiary)?
                            != charge.quote.body.beneficiary_account_digest
                    {
                        return Err(Error::Binding);
                    }
                }
                None if value.body.online_charge == 0 && value.body.charge_quote == [0; 32] => {}
                None => return Err(Error::Binding),
            }
            Ok(())
        }
        UNLOAD | FEE => {
            let value: KagemushaWalletPayoutRecordV1 = decode(bytes, PAYOUT_CAP)?;
            let expected = if *kind == UNLOAD {
                KagemushaWalletPayoutKeyV1::Unload(*owner)
            } else {
                KagemushaWalletPayoutKeyV1::Fee(*owner)
            };
            if value.key != expected
                || value.source == [0; 32]
                || value.transaction == [0; 32]
                || value.amount == 0
            {
                return Err(Error::Binding);
            }
            Ok(())
        }
        CERTIFICATE => {
            let value: KagemushaWalletSignerCertificateV1 =
                decode(bytes, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1)?;
            value.validate()?;
            if value.body.scheme_id != *scheme || value.certificate_digest() != *owner {
                return Err(Error::Binding);
            }
            Ok(())
        }
        CREDENTIAL => {
            let value: CredentialRecord = decode(bytes, CREDENTIAL_CAP)?;
            value.credential.validate()?;
            value.certificates.validate()?;
            if value.credential.body.scheme_id != *scheme
                || value.credential.credential_digest() != *owner
            {
                return Err(Error::Binding);
            }
            Ok(())
        }
        REQUEST => {
            let value: KagemushaWalletRequestV1 =
                decode(bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1)?;
            value.validate()?;
            if value.body.scheme_id != *scheme || value.request_digest() != *owner {
                return Err(Error::Binding);
            }
            Ok(())
        }
        RESERVE => {
            let value: ReserveOwner = decode(bytes, 256)?;
            if *scheme != custody_namespace() || value.scheme == [0; 32] || value.asset == [0; 32] {
                return Err(Error::Binding);
            }
            Ok(())
        }
        RESERVE_ACCOUNT | RESERVE_ASSET => {
            let references: u64 = decode(bytes, 128)?;
            if *scheme != custody_namespace() || references == 0 {
                return Err(Error::Binding);
            }
            Ok(())
        }
        _ => Err(Error::Binding),
    }
}

// Fixed-record bounds use their component schemas. Registration and issuance include full
// canonical AccountId controllers, whose admission budget belongs to the enclosing node
// transaction/snapshot reader; decoding those rows uses the already bounded input length,
// rather than imposing an unsupported small-account restriction. No proof cap is inferred.
pub(super) const WALLET_CAP: usize = 512;
pub(super) const PAYOUT_CAP: usize = 512;
pub(super) const CREDENTIAL_CAP: usize =
    KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1 + KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1 + 1024;

pub(super) const RESERVE: u8 = 9;
pub(super) const RESERVE_ACCOUNT: u8 = 10;
pub(super) const RESERVE_ASSET: u8 = 11;

#[derive(Clone, Copy, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::ReserveOwner")]
pub(super) struct ReserveOwner {
    pub scheme: Digest,
    pub asset: Digest,
}
fn custody_namespace() -> Digest {
    *iroha_crypto::Hash::new(b"iroha:kagemusha:ledger-custody-index:v1\0").as_ref()
}
pub(super) fn reserve_key(
    id: &iroha_data_model::asset::AssetId,
) -> Result<KagemushaWalletLedgerKeyV1> {
    let encoded = encode(id)?;
    let digest =
        *iroha_crypto::Hash::new_from_chunks(&[b"iroha:kagemusha:reserve-asset:v1\0", &encoded])
            .as_ref();
    Ok(key(RESERVE, custody_namespace(), digest))
}
pub(super) fn reserve_account_key(account: &AccountId) -> Result<KagemushaWalletLedgerKeyV1> {
    Ok(key(
        RESERVE_ACCOUNT,
        custody_namespace(),
        kagemusha_wallet_account_digest_v1(account)?,
    ))
}
pub(super) fn reserve_definition_key(
    definition: &iroha_data_model::asset::AssetDefinitionId,
) -> Result<KagemushaWalletLedgerKeyV1> {
    let encoded = encode(definition)?;
    let digest = *iroha_crypto::Hash::new_from_chunks(&[
        b"iroha:kagemusha:reserve-definition:v1\0",
        &encoded,
    ])
    .as_ref();
    Ok(key(RESERVE_ASSET, custody_namespace(), digest))
}

/// Reference counts are permanent positive counters; no deletion path exists.
pub(super) fn is_reference_key(key: &KagemushaWalletLedgerKeyV1) -> bool {
    matches!(key.components().0, RESERVE_ACCOUNT | RESERVE_ASSET)
}

/// Validate one complete snapshot generation, including the permanent reserve indexes.
/// The caller's lookup must refer to exactly the same generation as the iterator. Only
/// registration reference counts are accumulated; historical issuance/proof bytes are not cloned.
pub(crate) fn validate_snapshot<'a>(
    rows: impl Iterator<Item = (&'a KagemushaWalletLedgerKeyV1, &'a Vec<u8>)>,
    lookup: impl Fn(&KagemushaWalletLedgerKeyV1) -> Option<&'a [u8]>,
) -> Result<()> {
    let mut expected = std::collections::BTreeMap::<KagemushaWalletLedgerKeyV1, u64>::new();
    let mut actual_count = 0_usize;
    for (row_key, bytes) in rows {
        validate_row(row_key, bytes)?;
        let (kind, scheme, asset, _) = row_key.components();
        match kind {
            super::artifacts::KIND => {
                let value: super::artifacts::VerifierInstallation =
                    decode(bytes, super::artifacts::CAP)?;
                let registration_key = key(REGISTRATION, scheme, value.authorizing_asset);
                let encoded = lookup(&registration_key).ok_or(Error::Unavailable)?;
                validate_row(&registration_key, encoded)?;
                let registration: Registration = decode(encoded, encoded.len())?;
                value.require_registration(&registration)?;
            }
            ISSUANCE => {
                let issuance: Issuance = decode(bytes, bytes.len())?;
                let path_key = super::event_evidence::key(issuance.body.receipt_digest()?);
                let path_bytes = lookup(&path_key).ok_or(Error::Unavailable)?;
                validate_row(&path_key, path_bytes)?;
                let path: super::event_evidence::KagemushaLoadEventPathV1 =
                    decode(path_bytes, super::event_evidence::CAP)?;
                if path.height() != issuance.body.block_height {
                    return Err(Error::Binding);
                }
                let registration_key = key(REGISTRATION, scheme, issuance.body.asset_digest);
                let encoded = lookup(&registration_key).ok_or(Error::Unavailable)?;
                validate_row(&registration_key, encoded)?;
                let wallet_key = key(WALLET, scheme, issuance.body.wallet_id);
                let encoded = lookup(&wallet_key).ok_or(Error::Unavailable)?;
                validate_row(&wallet_key, encoded)?;
                let wallet: WalletRecord = decode(encoded, WALLET_CAP)?;
                if wallet.asset != issuance.body.asset_digest
                    || wallet.next_load <= issuance.body.ordinal
                {
                    return Err(Error::Binding);
                }
            }
            REGISTRATION => {
                let registration: Registration = decode(bytes, bytes.len())?;
                let reserve = reserve_key(&super::custody::reserve_id(&registration))?;
                let encoded = lookup(&reserve).ok_or(Error::Unavailable)?;
                validate_row(&reserve, encoded)?;
                let owner: ReserveOwner = decode(encoded, 256)?;
                if owner.scheme != scheme || owner.asset != asset {
                    return Err(Error::Binding);
                }
                for index in [
                    reserve_account_key(&registration.reserve)?,
                    reserve_definition_key(&registration.asset.asset)?,
                ] {
                    let count = expected.entry(index).or_default();
                    *count = count.checked_add(1).ok_or(Error::Overflow)?;
                }
            }
            RESERVE => {
                let owner: ReserveOwner = decode(bytes, 256)?;
                let registration_key = key(REGISTRATION, owner.scheme, owner.asset);
                let encoded = lookup(&registration_key).ok_or(Error::Unavailable)?;
                validate_row(&registration_key, encoded)?;
                let registration: Registration = decode(encoded, encoded.len())?;
                if reserve_key(&super::custody::reserve_id(&registration))? != *row_key {
                    return Err(Error::Binding);
                }
            }
            RESERVE_ACCOUNT | RESERVE_ASSET => {
                actual_count = actual_count.checked_add(1).ok_or(Error::Overflow)?
            }
            _ => {}
        }
    }
    if actual_count != expected.len() {
        return Err(Error::Binding);
    }
    for (key, expected_count) in expected {
        let count: u64 = decode(lookup(&key).ok_or(Error::Unavailable)?, 128)?;
        if count != expected_count {
            return Err(Error::Binding);
        }
    }
    Ok(())
}
