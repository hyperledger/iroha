//! Externally signed wallet-self selective query for one committed transaction.

use std::{num::NonZeroU64, ptr, slice};

use iroha_crypto::{Algorithm, Hash, HashOf, Signature, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    query::{
        CommittedTransaction, CommittedTxFilters, QueryItemKind, QueryRequest,
        QueryRequestWithAuthority, QuerySignature, QueryWithParams, SignedQuery,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
        transaction::prelude::FindTransactions,
    },
    transaction::TransactionEntrypoint,
};
use iroha_version::codec::EncodeVersioned as _;
use libc::{c_int, c_uchar, c_ulong};
use norito::codec::Encode as _;

const ERR_COMMITTED_QUERY: c_int = -509;
const QUERY_TIME_TO_LIVE_MS: u64 = 100_000;
const MAX_AUTHORITY_BYTES: usize = 1024;
const MAX_SIGNED_QUERY_BYTES: usize = 16 * 1024;

pub(crate) fn exact_query_payload(
    network_id: NetworkId,
    authority: AccountId,
    transaction_hash: HashOf<TransactionEntrypoint>,
    creation_time_ms: u64,
    nonce: [u8; 32],
) -> Result<QueryRequestWithAuthority, String> {
    if creation_time_ms == 0 || nonce == [0; 32] {
        return Err("query creation time and nonce must be nonzero".into());
    }
    let signer = authority
        .try_signatory()
        .ok_or("query authority must have one signer")?;
    if signer.algorithm() != Algorithm::Ed25519 {
        return Err("query signer must be Ed25519".into());
    }
    let predicate = CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
        authority_eq: Some(authority.clone()),
        entry_eq: Some(transaction_hash),
        ..CommittedTxFilters::default()
    });
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: FindTransactions::new().encode(),
        item: QueryItemKind::CommittedTransaction,
        predicate_bytes: predicate.encode(),
        selector_bytes: SelectorTuple::<CommittedTransaction>::default().encode(),
        params: QueryParams::default(),
    });
    if let QueryRequest::Start(ref query) = request {
        let scoped = query
            .exact_transaction_read_authority_with_limits(norito::canonical_decode_limits(
                query.predicate_bytes.len(),
            ))
            .map_err(|error| format!("exact query scope rejected: {error}"))?;
        if scoped.as_ref() != Some(&authority) {
            return Err("query is not an exact self transaction read".into());
        }
    }
    Ok(request.with_authority(
        network_id,
        authority,
        creation_time_ms,
        NonZeroU64::new(QUERY_TIME_TO_LIVE_MS).expect("fixed nonzero query TTL"),
        nonce,
    ))
}

pub(crate) fn query_payload_hash(payload: &QueryRequestWithAuthority) -> [u8; 32] {
    *HashOf::new(payload).as_ref()
}

pub(crate) fn finalize_query(
    payload: QueryRequestWithAuthority,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if signature_bytes.len() != 64 {
        return Err("query signature must be exactly 64 bytes".into());
    }
    iroha_crypto::ed25519_parse_signature(signature_bytes)
        .map_err(|_| "query signature is not canonical Ed25519")?;
    let signed = SignedQuery {
        signature: QuerySignature(SignatureOf::from_signature(Signature::from_bytes(
            signature_bytes,
        ))),
        payload,
    };
    signed
        .verify_signature()
        .map_err(|error| format!("wallet query signature failed: {error}"))?;
    let wire = signed.encode_versioned();
    if wire.is_empty() || wire.len() > MAX_SIGNED_QUERY_BYTES {
        return Err("signed query exceeds its native bound".into());
    }
    Ok(wire)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Mirrors the bounded C pointer/length argument pairs."
)]
unsafe fn read_query_args(
    network_id_ptr: *const c_uchar,
    network_id_len: c_ulong,
    authority_ptr: *const c_uchar,
    authority_len: c_ulong,
    transaction_hash_ptr: *const c_uchar,
    transaction_hash_len: c_ulong,
    creation_time_ms: u64,
    nonce_ptr: *const c_uchar,
    nonce_len: c_ulong,
) -> Result<QueryRequestWithAuthority, String> {
    if network_id_ptr.is_null()
        || authority_ptr.is_null()
        || transaction_hash_ptr.is_null()
        || nonce_ptr.is_null()
        || network_id_len != 32
        || transaction_hash_len != 32
        || nonce_len != 32
        || authority_len == 0
        || authority_len as usize > MAX_AUTHORITY_BYTES
    {
        return Err("invalid selective query argument".into());
    }
    let network_bytes: [u8; 32] = unsafe { slice::from_raw_parts(network_id_ptr, 32) }
        .try_into()
        .map_err(|_| "invalid network byte length")?;
    let transaction_bytes: [u8; 32] = unsafe { slice::from_raw_parts(transaction_hash_ptr, 32) }
        .try_into()
        .map_err(|_| "invalid transaction hash length")?;
    let nonce: [u8; 32] = unsafe { slice::from_raw_parts(nonce_ptr, 32) }
        .try_into()
        .map_err(|_| "invalid nonce length")?;
    if network_bytes[31] & 1 == 0 || transaction_bytes[31] & 1 == 0 {
        return Err("network and transaction hashes must be marked".into());
    }
    let account = std::str::from_utf8(unsafe {
        slice::from_raw_parts(authority_ptr, authority_len as usize)
    })
    .map_err(|_| "query authority must be UTF-8")?;
    if account.trim() != account {
        return Err("query authority is not canonical".into());
    }
    let authority = AccountId::parse_encoded(account)
        .map_err(|_| "query authority is not a canonical encoded account")?;
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed(
        network_bytes,
    )));
    let transaction_hash = HashOf::from_untyped_unchecked(Hash::prehashed(transaction_bytes));
    exact_query_payload(
        network_id,
        authority,
        transaction_hash,
        creation_time_ms,
        nonce,
    )
}

/// Exact current wallet-self query prehash for an external Ed25519 signer.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_committed_transaction_query_payload_hash_v1(
    network_id_ptr: *const c_uchar,
    network_id_len: c_ulong,
    authority_ptr: *const c_uchar,
    authority_len: c_ulong,
    transaction_hash_ptr: *const c_uchar,
    transaction_hash_len: c_ulong,
    creation_time_ms: u64,
    nonce_ptr: *const c_uchar,
    nonce_len: c_ulong,
    out_hash_32: *mut c_uchar,
) -> c_int {
    if !out_hash_32.is_null() {
        unsafe { ptr::write_bytes(out_hash_32, 0, 32) };
    }
    let result = std::panic::catch_unwind(|| unsafe {
        if out_hash_32.is_null() {
            return Err("null output hash".to_owned());
        }
        let payload = read_query_args(
            network_id_ptr,
            network_id_len,
            authority_ptr,
            authority_len,
            transaction_hash_ptr,
            transaction_hash_len,
            creation_time_ms,
            nonce_ptr,
            nonce_len,
        )?;
        Ok::<_, String>(query_payload_hash(&payload))
    });
    let Ok(Ok(hash)) = result else {
        return ERR_COMMITTED_QUERY;
    };
    unsafe { ptr::copy_nonoverlapping(hash.as_ptr(), out_hash_32, 32) };
    0
}

/// Finalize the same single-use signed query from the wallet's external
/// Ed25519 signature. The account signer and exact query prehash are verified.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_committed_transaction_query_finalize_v1(
    network_id_ptr: *const c_uchar,
    network_id_len: c_ulong,
    authority_ptr: *const c_uchar,
    authority_len: c_ulong,
    transaction_hash_ptr: *const c_uchar,
    transaction_hash_len: c_ulong,
    creation_time_ms: u64,
    nonce_ptr: *const c_uchar,
    nonce_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
    out_signed_query_ptr: *mut *mut c_uchar,
    out_signed_query_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out_signed_query_ptr, out_signed_query_len);
    let result = std::panic::catch_unwind(|| unsafe {
        if signature_ptr.is_null()
            || signature_len != 64
            || out_signed_query_ptr.is_null()
            || out_signed_query_len.is_null()
        {
            return Err("invalid signed query output or signature".to_owned());
        }
        let payload = read_query_args(
            network_id_ptr,
            network_id_len,
            authority_ptr,
            authority_len,
            transaction_hash_ptr,
            transaction_hash_len,
            creation_time_ms,
            nonce_ptr,
            nonce_len,
        )?;
        finalize_query(payload, slice::from_raw_parts(signature_ptr, 64))
    });
    let Ok(Ok(wire)) = result else {
        return ERR_COMMITTED_QUERY;
    };
    if unsafe { super::write_bytes(out_signed_query_ptr, out_signed_query_len, &wire) }.is_err() {
        return ERR_COMMITTED_QUERY;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::block::BlockHeader;
    use iroha_version::codec::DecodeVersioned as _;

    fn fixture() -> (KeyPair, NetworkId, AccountId, HashOf<TransactionEntrypoint>) {
        let key = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519).unwrap();
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"current query network"),
        ));
        let account = AccountId::new(key.public_key().clone());
        let transaction_hash = HashOf::from_untyped_unchecked(Hash::new(b"committed query target"));
        (key, network, account, transaction_hash)
    }

    #[test]
    fn exact_wallet_query_requires_matching_external_signature_and_current_scope() {
        let (key, network, account, transaction_hash) = fixture();
        let nonce = [0x79; 32];
        let payload =
            exact_query_payload(network, account.clone(), transaction_hash, 1_234_567, nonce)
                .unwrap();
        let hash = query_payload_hash(&payload);
        let signature = Signature::try_new(key.private_key(), &hash).unwrap();
        let wire = finalize_query(payload, signature.payload()).unwrap();
        let signed = SignedQuery::decode_all_versioned(&wire).unwrap();
        signed.verify_signature().unwrap();
        assert_eq!(signed.authority(), &account);
        assert_eq!(signed.payload.network_id(), network);
        let QueryRequest::Start(query) = signed.request() else {
            panic!("expected exact current iterable query");
        };
        assert_eq!(query.item, QueryItemKind::CommittedTransaction);
        assert_eq!(query.params, QueryParams::default());
        assert_eq!(
            query
                .exact_transaction_read_authority_with_limits(norito::canonical_decode_limits(
                    query.predicate_bytes.len(),
                ))
                .unwrap(),
            Some(account.clone()),
        );

        let other_key = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519).unwrap();
        let wrong_signer = Signature::try_new(other_key.private_key(), &hash).unwrap();
        assert!(
            finalize_query(
                exact_query_payload(network, account.clone(), transaction_hash, 1_234_567, nonce)
                    .unwrap(),
                wrong_signer.payload(),
            )
            .is_err()
        );
        let other_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"wrong query network")),
        );
        let altered_network = exact_query_payload(
            other_network,
            account.clone(),
            transaction_hash,
            1_234_567,
            nonce,
        )
        .unwrap();
        assert_ne!(query_payload_hash(&altered_network), hash);
        assert!(finalize_query(altered_network, signature.payload()).is_err());
        let other_transaction = HashOf::from_untyped_unchecked(Hash::new(b"wrong transaction"));
        let altered_transaction = exact_query_payload(
            network,
            account.clone(),
            other_transaction,
            1_234_567,
            nonce,
        )
        .unwrap();
        assert_ne!(query_payload_hash(&altered_transaction), hash);
        assert!(finalize_query(altered_transaction, signature.payload()).is_err());
        assert!(
            exact_query_payload(network, account, transaction_hash, 1_234_567, [0; 32]).is_err()
        );
    }
}
