//! JNI projection of the same native selective-inclusion verifier used by Swift.

use super::{
    CONNECT_NORITO_BRIDGE_ABI_VERSION, NetworkId, catch_unwind_to_java,
    read_java_byte_array_bounded, throw_java_illegal_argument, throw_java_illegal_state,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId, block::BlockHeader, query::QueryRequestWithAuthority,
    transaction::TransactionEntrypoint,
};
use jni::{objects::JByteArray, sys::jobjectArray};

use crate::committed_transaction_inclusion::{
    MAX_CHAIN_JSON_BYTES, MAX_RESPONSE_BYTES, VerifiedCommittedTransaction, candidate_block_hash,
    verify_committed_transaction_inclusion, verify_exact_successful_committed_transaction,
};
use crate::committed_transaction_query::{exact_query_payload, finalize_query, query_payload_hash};

fn java_query_payload(
    network_id: &[u8],
    authority: &[u8],
    transaction_hash: &[u8],
    creation_time_ms: jni::sys::jlong,
    nonce: &[u8],
) -> Result<QueryRequestWithAuthority, String> {
    let network: [u8; 32] = network_id
        .try_into()
        .map_err(|_| "networkId must be exactly 32 bytes")?;
    let transaction: [u8; 32] = transaction_hash
        .try_into()
        .map_err(|_| "transactionHash must be exactly 32 bytes")?;
    let nonce: [u8; 32] = nonce
        .try_into()
        .map_err(|_| "queryNonce must be exactly 32 bytes")?;
    if network[31] & 1 == 0 || transaction[31] & 1 == 0 {
        return Err("networkId and transactionHash must be marked hashes".into());
    }
    let account = std::str::from_utf8(authority).map_err(|_| "query authority must be UTF-8")?;
    if account.trim() != account {
        return Err("query authority is not canonical".into());
    }
    let authority = AccountId::parse_encoded(account)
        .map_err(|_| "query authority is not a canonical encoded account")?;
    let creation_time_ms = u64::try_from(creation_time_ms)
        .ok()
        .filter(|value| *value != 0)
        .ok_or("query creationTimeMs must be positive")?;
    exact_query_payload(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(network),
        )),
        authority,
        HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed(transaction)),
        creation_time_ms,
        nonce,
    )
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeCommittedTransactionQueryPayloadHash(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    network_id: JByteArray<'_>,
    authority: JByteArray<'_>,
    transaction_hash: JByteArray<'_>,
    creation_time_ms: jni::sys::jlong,
    nonce: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(network) = read_java_byte_array_bounded(&mut env, &network_id, "networkId", 32) else {
        return std::ptr::null_mut();
    };
    let Some(authority) = read_java_byte_array_bounded(&mut env, &authority, "authority", 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(transaction) =
        read_java_byte_array_bounded(&mut env, &transaction_hash, "transactionHash", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(nonce) = read_java_byte_array_bounded(&mut env, &nonce, "queryNonce", 32) else {
        return std::ptr::null_mut();
    };
    let Some(result) =
        catch_unwind_to_java(&mut env, "committed transaction query prehash", || {
            java_query_payload(&network, &authority, &transaction, creation_time_ms, &nonce)
                .map(|payload| query_payload_hash(&payload))
        })
    else {
        return std::ptr::null_mut();
    };
    let hash = match result {
        Ok(hash) => hash,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error);
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&hash) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_java_illegal_state(
                &mut env,
                format!("query prehash allocation failed: {error}"),
            );
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeFinalizeCommittedTransactionQuery(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    network_id: JByteArray<'_>,
    authority: JByteArray<'_>,
    transaction_hash: JByteArray<'_>,
    creation_time_ms: jni::sys::jlong,
    nonce: JByteArray<'_>,
    signature: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(network) = read_java_byte_array_bounded(&mut env, &network_id, "networkId", 32) else {
        return std::ptr::null_mut();
    };
    let Some(authority) = read_java_byte_array_bounded(&mut env, &authority, "authority", 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(transaction) =
        read_java_byte_array_bounded(&mut env, &transaction_hash, "transactionHash", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(nonce) = read_java_byte_array_bounded(&mut env, &nonce, "queryNonce", 32) else {
        return std::ptr::null_mut();
    };
    let Some(signature) = read_java_byte_array_bounded(&mut env, &signature, "querySignature", 64)
    else {
        return std::ptr::null_mut();
    };
    let Some(result) =
        catch_unwind_to_java(&mut env, "committed transaction query finalization", || {
            let payload =
                java_query_payload(&network, &authority, &transaction, creation_time_ms, &nonce)?;
            finalize_query(payload, &signature)
        })
    else {
        return std::ptr::null_mut();
    };
    let wire = match result {
        Ok(wire) => wire,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error);
            return std::ptr::null_mut();
        }
    };
    match env.byte_array_from_slice(&wire) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_java_illegal_state(&mut env, format!("signed query allocation failed: {error}"));
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeVerifierContractVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeCandidateBlockHash(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    response: JByteArray<'_>,
    transaction_hash: JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let Some(response) = read_java_byte_array_bounded(
        &mut env,
        &response,
        "committedTransactionResponse",
        MAX_RESPONSE_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(transaction) =
        read_java_byte_array_bounded(&mut env, &transaction_hash, "transactionHash", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(result) = catch_unwind_to_java(&mut env, "candidate block hash", || {
        let transaction: [u8; 32] = transaction
            .try_into()
            .map_err(|_| "transactionHash must be exactly 32 bytes".to_owned())?;
        if transaction[31] & 1 == 0 {
            return Err("transactionHash must be a marked hash".into());
        }
        candidate_block_hash(
            &response,
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed(transaction)),
        )
    }) else {
        return std::ptr::null_mut();
    };
    let hash = match result {
        Ok(value) => value,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error);
            return std::ptr::null_mut();
        }
    };
    let Some(hash) = hash else {
        // A canonical, empty committed-transaction page is a pending read.
        return std::ptr::null_mut();
    };
    match env.byte_array_from_slice(&hash) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_java_illegal_state(
                &mut env,
                format!("candidate block-hash allocation failed: {error}"),
            );
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeVerifyCommittedTransactionInclusion(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    response: JByteArray<'_>,
    chain_json: JByteArray<'_>,
    network_id: JByteArray<'_>,
    expected_chain: JByteArray<'_>,
    trusted_checkpoint: JByteArray<'_>,
    transaction_hash: JByteArray<'_>,
) -> jobjectArray {
    let Some(response) = read_java_byte_array_bounded(
        &mut env,
        &response,
        "committedTransactionResponse",
        MAX_RESPONSE_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(chain_json) = read_java_byte_array_bounded(
        &mut env,
        &chain_json,
        "nativeFinalityProofChainJson",
        MAX_CHAIN_JSON_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(network_id) = read_java_byte_array_bounded(&mut env, &network_id, "networkId", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(label) =
        read_java_byte_array_bounded(&mut env, &expected_chain, "expectedChain", 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env,
        &trusted_checkpoint,
        "trustedCheckpoint",
        iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(transaction_hash) =
        read_java_byte_array_bounded(&mut env, &transaction_hash, "transactionHash", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(result) = catch_unwind_to_java(&mut env, "committed transaction inclusion", || {
        let network_bytes: [u8; 32] = network_id
            .try_into()
            .map_err(|_| "networkId must be exactly 32 bytes".to_owned())?;
        let transaction_bytes: [u8; 32] = transaction_hash
            .try_into()
            .map_err(|_| "transactionHash must be exactly 32 bytes".to_owned())?;
        if network_bytes[31] & 1 == 0 || transaction_bytes[31] & 1 == 0 {
            return Err("networkId and transactionHash must be marked hashes".to_owned());
        }
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(network_bytes)),
        );
        let transaction_hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(
            Hash::prehashed(transaction_bytes),
        );
        let label =
            std::str::from_utf8(&label).map_err(|_| "expectedChain is not UTF-8".to_owned())?;
        verify_committed_transaction_inclusion(
            &response,
            &chain_json,
            network_id,
            label,
            &checkpoint,
            transaction_hash,
        )
    }) else {
        return std::ptr::null_mut();
    };
    let verified = match result {
        Ok(value) => value,
        Err(error) => {
            throw_java_illegal_argument(&mut env, error);
            return std::ptr::null_mut();
        }
    };
    verified_to_java(&mut env, verified)
}

/// Verify exact retained authorization bytes and successful native execution through the same
/// independently selected checkpoint used by the general inclusion verifier.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_client_CommittedTransactionInclusionBridge_nativeVerifyExactSuccessfulCommittedTransaction(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    response: JByteArray<'_>,
    chain_json: JByteArray<'_>,
    network_id: JByteArray<'_>,
    expected_chain: JByteArray<'_>,
    trusted_checkpoint: JByteArray<'_>,
    original_signed_transaction: JByteArray<'_>,
) -> jobjectArray {
    let Some(response) = read_java_byte_array_bounded(
        &mut env,
        &response,
        "committedTransactionResponse",
        MAX_RESPONSE_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(chain_json) = read_java_byte_array_bounded(
        &mut env,
        &chain_json,
        "nativeFinalityProofChainJson",
        MAX_CHAIN_JSON_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(network_id) = read_java_byte_array_bounded(&mut env, &network_id, "networkId", 32)
    else {
        return std::ptr::null_mut();
    };
    let Some(label) =
        read_java_byte_array_bounded(&mut env, &expected_chain, "expectedChain", 1024)
    else {
        return std::ptr::null_mut();
    };
    let Some(checkpoint) = read_java_byte_array_bounded(
        &mut env,
        &trusted_checkpoint,
        "trustedCheckpoint",
        iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(original) = read_java_byte_array_bounded(
        &mut env,
        &original_signed_transaction,
        "originalSignedTransaction",
        4 * 1024 * 1024,
    ) else {
        return std::ptr::null_mut();
    };
    let Some(result) = catch_unwind_to_java(&mut env, "exact successful transaction inclusion", || {
        let network_bytes: [u8; 32] = network_id
            .try_into()
            .map_err(|_| "networkId must be exactly 32 bytes".to_owned())?;
        if network_bytes[31] & 1 == 0 {
            return Err("networkId must be a marked hash".to_owned());
        }
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(network_bytes)),
        );
        let label =
            std::str::from_utf8(&label).map_err(|_| "expectedChain is not UTF-8".to_owned())?;
        verify_exact_successful_committed_transaction(
            &response,
            &chain_json,
            network_id,
            label,
            &checkpoint,
            &original,
        )
    }) else {
        return std::ptr::null_mut();
    };
    match result {
        Ok(verified) => verified_to_java(&mut env, verified),
        Err(error) => {
            throw_java_illegal_argument(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

fn verified_to_java(env: &mut jni::JNIEnv<'_>, verified: VerifiedCommittedTransaction) -> jobjectArray {
    let fields = [
        verified.row,
        verified.output_hash.to_vec(),
        verified.block_hash.to_vec(),
        verified.block_height.to_be_bytes().to_vec(),
        vec![u8::from(verified.result_ok)],
        verified.checkpoint,
    ];
    let array = (|| {
        let byte_array_class = env.find_class("[B")?;
        let array = env.new_object_array(6, byte_array_class, jni::objects::JObject::null())?;
        for (index, field) in fields.iter().enumerate() {
            let value = env.byte_array_from_slice(field)?;
            env.set_object_array_element(&array, index as i32, &value)?;
        }
        Ok::<_, jni::errors::Error>(array.into_raw())
    })();
    match array {
        Ok(array) => array,
        Err(error) => {
            throw_java_illegal_state(
                env,
                format!("committed inclusion result allocation failed: {error}"),
            );
            std::ptr::null_mut()
        }
    }
}
