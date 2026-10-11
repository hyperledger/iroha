#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativePublicKeyFromPrivate(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    algorithm_code: jni::sys::jint,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_native_public_key_from_private(&mut env, algorithm_code, private_key)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeSignerContractRevision(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    native_signer_jni_contract_revision() as jni::sys::jint
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeKeypairFromSeed(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    algorithm_code: jni::sys::jint,
    seed: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    java_native_keypair_from_seed(&mut env, algorithm_code, seed)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeSignDetached(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    algorithm_code: jni::sys::jint,
    private_key: jni::objects::JByteArray<'_>,
    message: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_native_sign_detached(&mut env, algorithm_code, private_key, message)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeVerifyDetached(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    algorithm_code: jni::sys::jint,
    public_key: jni::objects::JByteArray<'_>,
    message: jni::objects::JByteArray<'_>,
    signature: jni::objects::JByteArray<'_>,
) -> jni::sys::jboolean {
    java_native_verify_detached(&mut env, algorithm_code, public_key, message, signature)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeAccountReadPermissionMultisigPayloadHash(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    network_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JByteArray<'_>,
    reporting_account: jni::objects::JByteArray<'_>,
    change: jni::sys::jint,
    creation_time_ms: jni::sys::jlong,
    fee_payment_json: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_native_account_read_permission_multisig_payload_hash(
        &mut env,
        network_id,
        authority,
        reporting_account,
        change,
        creation_time_ms,
        fee_payment_json,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeFinalizeAccountReadPermissionMultisig(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    network_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JByteArray<'_>,
    reporting_account: jni::objects::JByteArray<'_>,
    change: jni::sys::jint,
    creation_time_ms: jni::sys::jlong,
    fee_payment_json: jni::objects::JByteArray<'_>,
    signature: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    java_native_finalize_account_read_permission_multisig(
        &mut env,
        network_id,
        authority,
        reporting_account,
        change,
        creation_time_ms,
        fee_payment_json,
        signature,
    )
}
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_nativeEncodeRegisterZkAssetSignedTransaction(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    algorithm_code: jni::sys::jint,
    network_id: jni::objects::JByteArray<'_>,
    chain_discriminant: jni::sys::jint,
    authority: jni::objects::JByteArray<'_>,
    creation_time_ms: jni::sys::jlong,
    ttl_ms: jni::sys::jlong,
    ttl_present: jni::sys::jboolean,
    asset: jni::objects::JByteArray<'_>,
    vk_unshield: jni::objects::JByteArray<'_>,
    vk_unshield_present: jni::sys::jboolean,
    private_key: jni::objects::JByteArray<'_>,
    fee_payment_json: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    java_native_encode_register_zk_asset_signed_transaction(
        &mut env,
        algorithm_code,
        network_id,
        chain_discriminant,
        authority,
        creation_time_ms,
        ttl_ms,
        ttl_present,
        asset,
        vk_unshield,
        vk_unshield_present,
        private_key,
        fee_payment_json,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeHasGovernanceDagSymbols(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jboolean {
    jni::sys::JNI_TRUE
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeHasGovernanceLogNodeSymbols(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jboolean {
    jni::sys::JNI_TRUE
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeHasFixtureBundleSymbols(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jboolean {
    jni::sys::JNI_TRUE
}
/// Reports that the Kotlin/JVM ABI contains appeal-finance validator symbols.
///
/// # Safety
/// The JVM must supply valid JNI references for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeHasAppealFinanceSymbols(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jboolean {
    jni::sys::JNI_TRUE
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateOrderbookPayloadJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_orderbook_payload_json(
        &mut env,
        kind,
        payload,
        label,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidatePopPayloadJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_pop_payload_json(&mut env, kind, payload, label, generated_at)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateHedgingPayloadJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_hedging_payload_json(
        &mut env,
        kind,
        payload,
        label,
        generated_at,
    )
}
/// JNI entrypoint for Kotlin/JVM appeal-finance `CancelAssetLock` validation.
///
/// # Safety
/// The JVM must supply valid JNI references for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateAppealFinanceCancelAssetLockJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json(
        &mut env,
        payload,
        label,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateFixtureBundleJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kinds: jni::objects::JByteArray<'_>,
    payloads: jni::objects::JObjectArray<'_>,
    labels: jni::objects::JObjectArray<'_>,
    now: jni::sys::jlong,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_fixture_bundle_json(
        &mut env,
        kinds,
        payloads,
        labels,
        now,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateGovernanceLogNodeJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    expected_node_cid: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_governance_log_node_json(
        &mut env,
        payload,
        label,
        expected_node_cid,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateGovernanceDagBlockJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    expected_block_cid: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_governance_dag_block_json(
        &mut env,
        payload,
        label,
        expected_block_cid,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidateGovernanceDagHeadChainJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    head: jni::objects::JByteArray<'_>,
    head_label: jni::objects::JByteArray<'_>,
    blocks: jni::objects::JObjectArray<'_>,
    block_labels: jni::objects::JObjectArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_governance_dag_head_chain_json(
        &mut env,
        head,
        head_label,
        blocks,
        block_labels,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeSignOrderbookPayload(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_sign_orderbook_payload(&mut env, kind, payload, private_key)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeDeriveOrderbookOrderId(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    owner_account: jni::objects::JByteArray<'_>,
    nonce: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_derive_orderbook_order_id(&mut env, owner_account, nonce)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeBuildSignedOrderbookOrderRequest(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    order_id: jni::objects::JByteArray<'_>,
    side: jni::sys::jint,
    tier: jni::sys::jint,
    price_per_gib: jni::objects::JByteArray<'_>,
    quantity_gib: jni::sys::jlong,
    remaining_gib: jni::sys::jlong,
    owner_account: jni::objects::JByteArray<'_>,
    provider_id: jni::objects::JByteArray<'_>,
    expiry_unix: jni::sys::jlong,
    nonce: jni::sys::jlong,
    maker_fee_bps: jni::sys::jint,
    taker_fee_bps: jni::sys::jint,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_build_signed_orderbook_order_request(
        &mut env,
        JavaSorafsOrderbookOrderRequestArrays {
            order_id,
            side,
            tier,
            price_per_gib,
            quantity_gib,
            remaining_gib,
            owner_account,
            provider_id,
            expiry_unix,
            nonce,
            maker_fee_bps,
            taker_fee_bps,
            private_key,
        },
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeBuildSignedOrderbookOrderCancel(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    order_id: jni::objects::JByteArray<'_>,
    owner_account: jni::objects::JByteArray<'_>,
    reason: jni::sys::jint,
    nonce: jni::sys::jlong,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_build_signed_orderbook_order_cancel(
        &mut env,
        order_id,
        owner_account,
        reason,
        nonce,
        private_key,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeBuildSignedOrderbookSettlementReceipt(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    receipt_id: jni::objects::JByteArray<'_>,
    channel_id: jni::objects::JByteArray<'_>,
    trade_id: jni::objects::JByteArray<'_>,
    range_start: jni::sys::jlong,
    range_end: jni::sys::jlong,
    chunk_hash: jni::objects::JByteArray<'_>,
    bytes_delivered: jni::sys::jlong,
    xor_debited: jni::objects::JByteArray<'_>,
    provider_credit: jni::objects::JByteArray<'_>,
    fee_amount: jni::objects::JByteArray<'_>,
    issued_at_unix: jni::sys::jlong,
    private_key: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_build_signed_orderbook_settlement_receipt(
        &mut env,
        JavaSorafsOrderbookSettlementReceiptArrays {
            receipt_id,
            channel_id,
            trade_id,
            range_start,
            range_end,
            chunk_hash,
            bytes_delivered,
            xor_debited,
            provider_credit,
            fee_amount,
            issued_at_unix,
            private_key,
        },
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidatePdpPayloadJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    kind: jni::sys::jint,
    payload: jni::objects::JByteArray<'_>,
    label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_pdp_payload_json(&mut env, kind, payload, label, generated_at)
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidatePdpCommitmentChallengeJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    commitment: jni::objects::JByteArray<'_>,
    commitment_label: jni::objects::JByteArray<'_>,
    challenge: jni::objects::JByteArray<'_>,
    challenge_label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_pdp_commitment_challenge_json(
        &mut env,
        commitment,
        commitment_label,
        challenge,
        challenge_label,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidatePdpChallengeProofJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    challenge: jni::objects::JByteArray<'_>,
    challenge_label: jni::objects::JByteArray<'_>,
    proof: jni::objects::JByteArray<'_>,
    proof_label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_pdp_challenge_proof_json(
        &mut env,
        challenge,
        challenge_label,
        proof,
        proof_label,
        generated_at,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_sorafs_SorafsReferenceValidators_nativeValidatePdpBundleJson(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    commitment: jni::objects::JByteArray<'_>,
    commitment_label: jni::objects::JByteArray<'_>,
    challenge: jni::objects::JByteArray<'_>,
    challenge_label: jni::objects::JByteArray<'_>,
    proof: jni::objects::JByteArray<'_>,
    proof_label: jni::objects::JByteArray<'_>,
    generated_at: jni::sys::jlong,
) -> jni::sys::jbyteArray {
    java_sorafs_reference_validate_pdp_bundle_json(
        &mut env,
        JavaSorafsPdpBundleArrays {
            commitment,
            commitment_label,
            challenge,
            challenge_label,
            proof,
            proof_label,
        },
        generated_at,
    )
}

// Canonical privacy JNI exports are owned only by the Kotlin SDK.
/// Return the native bridge ABI version for Kotlin/JVM privacy callers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}
/// Return this binary's canonical compiled privacy profile catalog.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeCompiledProfileCatalog(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jbyteArray {
    java_native_privacy_compiled_profile_catalog(&mut env)
}
/// Validate a canonical compiled privacy profile catalog for Kotlin/JVM callers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeValidateCompiledProfileCatalog(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    archive: jni::objects::JByteArray<'_>,
) -> jni::sys::jint {
    java_native_privacy_validate_compiled_profile_catalog(&mut env, archive)
}
/// Validate a Torii Exact12 capability manifest for the Kotlin/JVM SDK.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeValidateExact12CapabilityManifestForNetworkV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    archive: jni::objects::JByteArray<'_>,
    expected_network: jni::objects::JByteArray<'_>,
) -> jni::sys::jint {
    java_native_privacy_validate_exact12_capability_manifest(&mut env, archive, expected_network)
}
/// Inspect one validated Torii Exact12 manifest and compare all local profile tuples.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeInspectExact12CapabilityManifest(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    archive: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    java_native_privacy_inspect_exact12_capability_manifest(&mut env, archive)
}
/// Require active committed admission and exact local tuple equality for Kotlin/JVM.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeRequireExact12CapabilityTupleForNetworkV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    archive: jni::objects::JByteArray<'_>,
    protocol_index: jni::sys::jint,
    expected_network: jni::objects::JByteArray<'_>,
) -> jni::sys::jboolean {
    java_native_privacy_require_exact12_capability_tuple(
        &mut env,
        archive,
        protocol_index,
        expected_network,
    )
}
/// Validate a canonical retained submit-proof instruction against committed Kotlin/JVM admission.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeValidateExact12SubmitProofConstructionForNetworkV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    manifest_archive: jni::objects::JByteArray<'_>,
    protocol_index: jni::sys::jint,
    instruction_archive: jni::objects::JByteArray<'_>,
    expected_network: jni::objects::JByteArray<'_>,
) -> jni::sys::jboolean {
    java_native_privacy_validate_exact12_submit_proof_construction(
        &mut env,
        manifest_archive,
        protocol_index,
        instruction_archive,
        expected_network,
    )
}
/// Return the canonical exact-12 privacy fixture bundle to the Kotlin/JVM SDK.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeExact12FixtureBundle(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jbyteArray {
    java_native_privacy_exact12_fixture_bundle(&mut env)
}
/// Validate an exact-12 privacy fixture bundle for the Kotlin/JVM SDK.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_nativeValidateExact12FixtureBundle(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    archive: jni::objects::JByteArray<'_>,
) -> jni::sys::jint {
    java_native_privacy_validate_exact12_fixture_bundle(&mut env, archive)
}

fn clear_parliament_jni_exception(env: &mut jni::JNIEnv<'_>) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

fn read_parliament_jni_bytes(
    env: &mut jni::JNIEnv<'_>,
    value: &jni::objects::JByteArray<'_>,
    maximum: usize,
) -> Option<Vec<u8>> {
    let length = usize::try_from(env.get_array_length(value).ok()?).ok()?;
    if length == 0 || length > maximum {
        return None;
    }
    env.convert_byte_array(value).ok()
}

fn read_parliament_jni_trust_anchor(
    env: &mut jni::JNIEnv<'_>,
    value: &jni::objects::JByteArray<'_>,
) -> Option<[u8; CONNECT_NORITO_PARLIAMENT_TIMED_OVN_TRUST_ANCHOR_BYTES_V1]> {
    read_parliament_jni_bytes(
        env,
        value,
        CONNECT_NORITO_PARLIAMENT_TIMED_OVN_TRUST_ANCHOR_BYTES_V1,
    )?
    .try_into()
    .ok()
}

fn read_parliament_jni_authority(
    env: &mut jni::JNIEnv<'_>,
    value: &jni::objects::JString<'_>,
) -> Option<String> {
    let java = env.get_string(value).ok()?;
    let authority = java.to_str().ok()?;
    if authority.is_empty()
        || authority.len() > super::parliament_timed_ovn_ffi::AUTHORITY_UTF8_MAX_BYTES_V1
    {
        return None;
    }
    Some(authority.to_owned())
}

// JNI uses distinct byte-array components, never a new wire codec. The first is
// diagnostic metadata or the public record; the second is the canonical checkpoint.
fn parliament_jni_components(
    env: &mut jni::JNIEnv<'_>,
    expected_first_bytes: usize,
    body: impl FnOnce(&mut jni::JNIEnv<'_>) -> Option<(Vec<u8>, Vec<u8>)>,
) -> jni::sys::jobjectArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (first, checkpoint) = body(env)?;
        if first.len() != expected_first_bytes
            || checkpoint.is_empty()
            || checkpoint.len() > iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES
        {
            return None;
        }
        let bytes_class = env.find_class("[B").ok()?;
        let output = env
            .new_object_array(2, bytes_class, jni::objects::JObject::null())
            .ok()?;
        let first = env.byte_array_from_slice(&first).ok()?;
        let checkpoint = env.byte_array_from_slice(&checkpoint).ok()?;
        env.set_object_array_element(&output, 0, first).ok()?;
        env.set_object_array_element(&output, 1, checkpoint).ok()?;
        Some(output.into_raw())
    }))
    .ok()
    .flatten();
    result.unwrap_or_else(|| {
        clear_parliament_jni_exception(env);
        std::ptr::null_mut()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeBridgeAbiVersion(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jint {
    CONNECT_NORITO_BRIDGE_ABI_VERSION as jni::sys::jint
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeVerifyCastingProofV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    proof_response: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
    expected_ballot_attempt_id: jni::objects::JByteArray<'_>,
) -> jni::sys::jbyteArray {
    let checkpoint = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof_response = read_parliament_jni_bytes(
            &mut env,
            &proof_response,
            CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1,
        )?;
        let network_id = read_parliament_jni_trust_anchor(&mut env, &network_id)?;
        let trusted_checkpoint = read_parliament_jni_bytes(
            &mut env,
            &trusted_checkpoint,
            iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
        )?;
        let expected_ballot_attempt_id =
            read_parliament_jni_trust_anchor(&mut env, &expected_ballot_attempt_id)?;
        super::parliament_timed_ovn_ffi::verified_terminal_casting_proof_v1(
            &proof_response,
            network_id,
            &trusted_checkpoint,
            expected_ballot_attempt_id,
        )
        .ok()
        .map(|page| page.promoted_checkpoint)
    }))
    .ok()
    .flatten();
    if let Some(checkpoint) = checkpoint
        && let Ok(array) = env.byte_array_from_slice(&checkpoint)
    {
        return array.into_raw();
    }
    clear_parliament_jni_exception(&mut env);
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeVerifyCastingProofPageV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    proof_response: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
    expected_ballot_attempt_id: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    parliament_jni_components(
        &mut env,
        CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_PAGE_SUMMARY_BYTES_V1,
        |env| {
            let proof_response = read_parliament_jni_bytes(
                env,
                &proof_response,
                CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1,
            )?;
            let network_id = read_parliament_jni_trust_anchor(env, &network_id)?;
            let trusted_checkpoint = read_parliament_jni_bytes(
                env,
                &trusted_checkpoint,
                iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
            )?;
            let expected_ballot_attempt_id =
                read_parliament_jni_trust_anchor(env, &expected_ballot_attempt_id)?;
            super::parliament_timed_ovn_ffi::verified_casting_proof_page_v1(
                &proof_response,
                network_id,
                &trusted_checkpoint,
                expected_ballot_attempt_id,
            )
            .ok()
            .map(|page| {
                (
                    page.diagnostic_summary_bytes_v1().to_vec(),
                    page.promoted_checkpoint,
                )
            })
        },
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeRegistrationFromProofV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    proof_response: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
    expected_ballot_attempt_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JString<'_>,
    seed: jni::objects::JByteArray<'_>,
) -> jni::sys::jobjectArray {
    parliament_jni_components(
        &mut env,
        iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1,
        |env| {
            let proof_response = read_parliament_jni_bytes(
                env,
                &proof_response,
                CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1,
            )?;
            let network_id = read_parliament_jni_trust_anchor(env, &network_id)?;
            let trusted_checkpoint = read_parliament_jni_bytes(
                env,
                &trusted_checkpoint,
                iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
            )?;
            let expected_ballot_attempt_id =
                read_parliament_jni_trust_anchor(env, &expected_ballot_attempt_id)?;
            let page = super::parliament_timed_ovn_ffi::verified_terminal_casting_proof_v1(
                &proof_response,
                network_id,
                &trusted_checkpoint,
                expected_ballot_attempt_id,
            )
            .ok()?;
            let casting_context = page.casting_context.as_ref()?;
            let authority = read_parliament_jni_authority(env, &authority)?;
            // Never copy the Java seed until every proof/archive check succeeds.
            let seed_bytes = Zeroizing::new(read_parliament_jni_bytes(
                env,
                &seed,
                CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1,
            )?);
            if seed_bytes.len() != CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1 {
                return None;
            }
            let mut seed =
                Zeroizing::new([0_u8; CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1]);
            seed.copy_from_slice(&seed_bytes);
            super::parliament_timed_ovn_ffi::registration_from_verified_context_v1(
                casting_context,
                &authority,
                &seed,
            )
            .ok()
            .map(|record| (record, page.promoted_checkpoint))
        },
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_nativeBallotFromProofV1(
    mut env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    proof_response: jni::objects::JByteArray<'_>,
    network_id: jni::objects::JByteArray<'_>,
    trusted_checkpoint: jni::objects::JByteArray<'_>,
    expected_ballot_attempt_id: jni::objects::JByteArray<'_>,
    authority: jni::objects::JString<'_>,
    seed: jni::objects::JByteArray<'_>,
    choice: jni::sys::jint,
) -> jni::sys::jobjectArray {
    parliament_jni_components(
        &mut env,
        iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1,
        |env| {
            let choice = u8::try_from(choice).ok().filter(|choice| *choice <= 2)?;
            let proof_response = read_parliament_jni_bytes(
                env,
                &proof_response,
                CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1,
            )?;
            let network_id = read_parliament_jni_trust_anchor(env, &network_id)?;
            let trusted_checkpoint = read_parliament_jni_bytes(
                env,
                &trusted_checkpoint,
                iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
            )?;
            let expected_ballot_attempt_id =
                read_parliament_jni_trust_anchor(env, &expected_ballot_attempt_id)?;
            let page = super::parliament_timed_ovn_ffi::verified_terminal_casting_proof_v1(
                &proof_response,
                network_id,
                &trusted_checkpoint,
                expected_ballot_attempt_id,
            )
            .ok()?;
            let casting_context = page.casting_context.as_ref()?;
            let authority = read_parliament_jni_authority(env, &authority)?;
            // Never copy the Java seed until every proof/archive check succeeds.
            let seed_bytes = Zeroizing::new(read_parliament_jni_bytes(
                env,
                &seed,
                CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1,
            )?);
            if seed_bytes.len() != CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1 {
                return None;
            }
            let mut seed =
                Zeroizing::new([0_u8; CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1]);
            seed.copy_from_slice(&seed_bytes);
            super::parliament_timed_ovn_ffi::ballot_from_verified_context_v1(
                casting_context,
                &authority,
                &seed,
                choice,
            )
            .ok()
            .map(|record| (record, page.promoted_checkpoint))
        },
    )
}
