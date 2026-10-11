# Iroha KAGEMUSHA Wallet SDK — consumer ProGuard/R8 rules

# KAGEMUSHA wallet Advance provider platform handle (G2). JNI ignores Kotlin visibility, so the
# Rust `KagemushaWalletPlatformV1` adapter calls its private upcalls and reads the internal result
# objects by name; app code has no public route to them.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidPlatformV1 {
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyProbeV1 keyProbe(byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyGenerationV1 keyGenerate(byte[], byte[], int);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidSignatureV1 keySign(byte[], byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidRemoveV1 keyDelete(byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidAttestationChainV1 attestationChain(byte[]);
    private int anchorPolicyTag();
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletNativeReplyV1 nativeCall(int, byte[], byte[], int);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidUnavailableV1 storageState();
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidCustodyRootV1 custodyRoot();
}
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidUnavailableV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyProbeV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyGenerationV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidSecurityLevelV1 { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidSignatureV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidRemoveV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidAttestationChainV1** { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidCustodyRootV1** { *; }

-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletNativeReplyV1 { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletNativeV1 { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletCallV1 { *; }

# Rust constructs the typed snapshot holder by its literal name and constructor descriptor.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletSnapshotReplyV1 { *; }

# Rust constructs the distinct reviewed-operation result holder by its literal class name.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletReviewReplyV1 { *; }

# Native Load transport decoding; DATA binding only, no wallet or monetary permission.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletLoadOriginalNativeV1 { *; }

# Original installation loader; Native authenticates its immutable application trust root.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletInstalledRuntimeNativeV1 { *; }

# Rust constructs bounded observation DATA through its dedicated JNI reply domain.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletObservationNativeV1 { *; }
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletObservationReplyV1 { *; }
