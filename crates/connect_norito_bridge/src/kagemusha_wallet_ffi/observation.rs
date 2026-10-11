//! Closed copies from the admitted Native owner. No foreign receipt or source authority.
use super::*;
use exports::{input, output};
const METADATA_MAGIC: &[u8; 8] = b"KWMDV1\0\0";
const OUTPUT_MAGIC: &[u8; 8] = b"KWROV1\0\0";
const ACCOUNT_MAX: usize = 4096;
const ASSET_MAX: usize = 1024;

fn metadata(value: &state::NativeWalletMetadataV1) -> Result<Vec<u8>> {
    if value.account_original.is_empty()
        || value.account_original.len() > ACCOUNT_MAX
        || value.asset_original.is_empty()
        || value.asset_original.len() > ASSET_MAX
        || value.asset_scale > KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1
        || [
            value.scheme_id,
            value.wallet_id,
            value.asset_digest,
            value.account_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(Failure::code(INTERNAL));
    }
    let mut out =
        Vec::with_capacity(148 + value.account_original.len() + value.asset_original.len());
    out.extend_from_slice(METADATA_MAGIC);
    out.extend_from_slice(&value.asset_scale.to_le_bytes());
    for digest in [
        value.scheme_id,
        value.wallet_id,
        value.asset_digest,
        value.account_digest,
    ] {
        out.extend_from_slice(&digest);
    }
    out.extend_from_slice(&(value.account_original.len() as u32).to_le_bytes());
    out.extend_from_slice(&(value.asset_original.len() as u32).to_le_bytes());
    out.extend_from_slice(&value.account_original);
    out.extend_from_slice(&value.asset_original);
    Ok(out)
}
fn released(value: &state::NativeReleasedOutputV1) -> Result<Vec<u8>> {
    let (kind, peer) = value
        .peer
        .as_ref()
        .map_or((0, &[][..]), |(kind, bytes)| (*kind, &bytes[..]));
    let expected = match value.kind {
        KagemushaWalletOperationKindV1::Send => 3,
        KagemushaWalletOperationKindV1::Receive => 4,
        _ => 0,
    };
    if value.operation_id == [0; 32]
        || value.original.is_empty()
        || value.original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        || peer.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        || kind != expected
        || (kind == 0) != peer.is_empty()
        || (kind == 3 && peer != value.original)
    {
        return Err(Failure::code(INTERNAL));
    }
    let mut out = Vec::with_capacity(66 + value.original.len() + peer.len());
    out.extend_from_slice(OUTPUT_MAGIC);
    out.push(value.kind.tag());
    out.extend_from_slice(&value.operation_id);
    out.extend_from_slice(&value.sequence.to_le_bytes());
    out.extend_from_slice(&(value.original.len() as u32).to_le_bytes());
    out.push(kind);
    out.extend_from_slice(&(peer.len() as u32).to_le_bytes());
    out.extend_from_slice(&value.original);
    out.extend_from_slice(peer);
    Ok(out)
}
fn prepared_load(value: &state::NativePreparedLedgerLoadV1) -> Result<Vec<u8>> {
    if [
        value.request_id,
        value.scheme_id,
        value.wallet_id,
        value.asset_digest,
        value.payer_account_digest,
    ]
    .contains(&[0; 32])
        || value.amount == 0
        || value.online_charge != 0
        || value.instruction_original.is_empty()
        || value.instruction_original.len() > state::LEDGER_INSTRUCTION_MAX_BYTES_V1
    {
        return Err(Failure::code(INTERNAL));
    }
    let mut bytes = Vec::with_capacity(220 + value.instruction_original.len());
    bytes.extend_from_slice(b"KWLPV1\0\0");
    for id in [
        value.request_id,
        value.scheme_id,
        value.wallet_id,
        value.asset_digest,
        value.payer_account_digest,
    ] {
        bytes.extend_from_slice(&id);
    }
    for amount in [value.ordinal, value.amount, value.online_charge] {
        bytes.extend_from_slice(&amount.to_le_bytes());
    }
    bytes.extend_from_slice(&(value.instruction_original.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&value.instruction_original);
    Ok(bytes)
}
fn require_identity(selector: u32, identity: &[u8]) -> Result<()> {
    match selector {
        0 if identity.is_empty() => Ok(()),
        1..=3 if identity.len() == 32 && identity != [0; 32] => Ok(()),
        _ => Err(Failure::code(INVALID)),
    }
}
impl<P: advance::KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send> NativeWallet<P, S> {
    pub(super) fn observe_inner(&mut self, selector: u32, identity: &[u8]) -> Result<Response> {
        require_identity(selector, identity)?;
        let (kind, bytes) = match selector {
            0 => (12, metadata(&self.wallet.metadata()?)?),
            1 | 2 => {
                let id = identity.try_into().map_err(|_| Failure::code(INVALID))?;
                let value = if selector == 1 {
                    self.wallet.released_request(id)?
                } else {
                    self.wallet.released_output(id)?
                };
                (12, released(&value)?)
            }
            3 => {
                let id = identity.try_into().map_err(|_| Failure::code(INVALID))?;
                match self.wallet.recover_ledger_load(id)? {
                    Some(value) => (12, prepared_load(&value)?),
                    None => (12, b"KWLNV1\0\0".to_vec()),
                }
            }
            _ => return Err(Failure::code(INVALID)),
        };
        Ok(Response {
            kind,
            bytes,
            ..Response::default()
        })
    }
}
/// Shared C/JNI observation dispatch under the same custody and deletion gate.
pub(crate) fn observe(handle: u64, selector: u32, identity: &[u8]) -> Result<Response> {
    require_identity(selector, identity)?;
    with_wallet(handle, true, |wallet| wallet.observe(selector, identity))
}

/// Read bounded original DATA from the same admitted owner, without a monetary action.
/// Metadata0 has no identity; Request1, Operation2 and preparedLoad3 use nonzero32.
/// All observations return generic original DATA kind12 with zero sequence/detail.
/// The selected API domain fixes the exact frame: KWMDV1 metadata, KWROV1 output,
/// KWLPV1 prepared Load, or exactly KWLNV1\0\0 for absent prepared Load only.
/// None is a monetary completion, permit, or custody-absence verdict.
/// # Safety
/// Input pointers must be initialized for their stated lengths; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_observe_v1(
    handle: u64,
    selector: u32,
    identity: *const u8,
    identity_length: usize,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            let identity = input(identity, identity_length, 32)?;
            observe(handle, selector, identity)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_observation_dispatch_rejects_invalid_data_before_unknown_owner() {
        assert_eq!(observe(0, 0, &[]).unwrap_err().status, CLOSED);
        for selector in 1..=3 {
            assert_eq!(observe(0, selector, &[1; 32]).unwrap_err().status, CLOSED);
            assert_eq!(observe(0, selector, &[0; 32]).unwrap_err().status, INVALID);
        }
        assert_eq!(observe(0, 4, &[]).unwrap_err().status, INVALID);
    }
    #[test]
    fn observation_rejects_unused_identity_and_nonclosed_selectors() {
        assert!(require_identity(0, &[]).is_ok());
        for selector in [1, 2, 3] {
            assert!(require_identity(selector, &[1; 32]).is_ok());
            for input in [&[][..], &[0; 32][..], &[1; 31][..], &[1; 33][..]] {
                assert!(require_identity(selector, input).is_err());
            }
        }
        assert!(require_identity(0, &[1; 32]).is_err());
        for selector in [4, 5, 17, u32::MAX] {
            assert!(require_identity(selector, &[]).is_err());
        }
    }
    #[test]
    fn release_projection_preserves_exact_originals_and_refuses_cross_family_peer() {
        // Copyable projection DATA only, not a Native completion fixture.
        let mut value = state::NativeReleasedOutputV1 {
            operation_id: [7; 32],
            kind: KagemushaWalletOperationKindV1::Send,
            sequence: u128::MAX,
            original: vec![1, 2, 3],
            peer: Some((3, vec![1, 2, 3])),
        };
        let frame = released(&value).unwrap();
        assert_eq!(&frame[..8], OUTPUT_MAGIC);
        assert_eq!(&frame[9..41], &[7; 32]);
        assert_eq!(&frame[41..57], &u128::MAX.to_le_bytes());
        assert_eq!(&frame[66..], &[1, 2, 3, 1, 2, 3]);
        value.peer = Some((4, vec![1, 2, 3]));
        assert!(released(&value).is_err());
        value.peer = Some((3, vec![1, 2, 4]));
        assert!(released(&value).is_err());
        value.kind = KagemushaWalletOperationKindV1::Unload;
        assert!(released(&value).is_err());
        value.peer = None;
        assert!(released(&value).is_ok());
    }
}

fn account_original(literal: &[u8]) -> Result<Vec<u8>> {
    use iroha_data_model::account::address::AccountAddress;
    if literal.is_empty() || literal.len() > 4096 {
        return Err(Failure::code(INVALID));
    }
    let text = std::str::from_utf8(literal).map_err(|_| Failure::code(INVALID))?;
    // Pure original codec: validate the exact literal's embedded discriminant, checksum
    // and canonical presentation without changing process-global network selection.
    // The admitted owner separately binds this AccountId digest to its signed Request.
    let account = AccountAddress::parse_encoded(text, None)
        .and_then(|address| address.to_account_id())
        .map_err(|_| Failure::code(INVALID))?;
    let frame = norito::encode_canonical(&account).map_err(|_| Failure::code(INTERNAL))?;
    if frame.is_empty() || frame.len() > ACCOUNT_MAX {
        return Err(Failure::code(INVALID));
    }
    Ok(frame)
}
/// Encode one canonical account literal with Rust's actual full AccountId canonical frame.
/// This pure codec gives no account ownership, receiver binding or operation authority.
/// # Safety
/// literal must be initialized for length bytes and out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_account_original_v1(
    literal: *const u8,
    length: usize,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            let literal = input(literal, length, 4096)?;
            Ok(Response {
                kind: 12,
                bytes: account_original(literal)?,
                ..Response::default()
            })
        })
    }
}

fn account_display(original: &[u8], prefix: u16) -> Result<Vec<u8>> {
    use iroha_data_model::account::{AccountId, address::AccountAddress};
    if original.is_empty() || original.len() > ACCOUNT_MAX {
        return Err(Failure::code(INVALID));
    }
    let account: AccountId = norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    )
    .map_err(|_| Failure::code(INVALID))?;
    let address = AccountAddress::from_account_id(&account).map_err(|_| Failure::code(INVALID))?;
    let text = address
        .to_i105_for_discriminant(prefix)
        .map_err(|_| Failure::code(INVALID))?;
    if text.is_empty() || text.len() > 4096 {
        return Err(Failure::code(INVALID));
    }
    Ok(text.into_bytes())
}
/// Pure exact full AccountId frame to I105 display under an independently selected prefix.
/// The prefix affects presentation only and grants no network, account or wallet authority.
/// # Safety
/// original must be initialized for length bytes and out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_account_display_v1(
    original: *const u8,
    length: usize,
    prefix: u16,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            let original = input(original, length, ACCOUNT_MAX)?;
            Ok(Response {
                kind: 12,
                bytes: account_display(original, prefix)?,
                ..Response::default()
            })
        })
    }
}

#[cfg(test)]
mod account_tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::account::{AccountId, address::AccountAddress};
    #[test]
    fn account_codec_roundtrips_full_actual_frame_and_refuses_bare_payload_or_trailing_data() {
        let key = KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).unwrap();
        let account = AccountId::new(key.public_key().clone());
        let expected = norito::encode_canonical(&account).unwrap();
        let literal = AccountAddress::from_account_id(&account)
            .unwrap()
            .to_i105_for_discriminant(369)
            .unwrap();
        assert_eq!(account_original(literal.as_bytes()).unwrap(), expected);
        assert_eq!(account_display(&expected, 369).unwrap(), literal.as_bytes());
        let changed_prefix = account_display(&expected, 42).unwrap();
        assert_ne!(changed_prefix, literal.as_bytes());
        assert_eq!(account_original(&changed_prefix).unwrap(), expected);
        let mut trailing = expected.clone();
        trailing.push(0);
        assert!(account_display(&trailing, 369).is_err());
        assert!(account_display(&expected[1..], 369).is_err());
        assert!(account_original(format!(" {literal}").as_bytes()).is_err());
        assert!(account_original(format!("{literal} ").as_bytes()).is_err());
        assert!(account_original(format!("{literal}@foreign.domain").as_bytes()).is_err());
        assert!(account_original(b"not-an-account").is_err());
        assert!(account_original(&[0xff]).is_err());
    }
}
