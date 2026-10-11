# Iroha KAGEMUSHA Wallet SDK — consumer ProGuard/R8 rules

# KAGEMUSHA wallet Advance provider platform handle (G2). JNI ignores Kotlin visibility, so the
# Rust `KagemushaWalletPlatformV1` adapter calls its private upcalls and reads the internal result
# objects by name; app code has no public route to them.
# TODO(G2-bridge): the Rust JNI adapter that binds these names has not landed in
# connect_norito_bridge yet; keep this block in lockstep with it when it does.
-keep class org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidPlatformV1 {
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyProbeV1 keyProbe(byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidKeyGenerationV1 keyGenerate(byte[], byte[], int);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidSignatureV1 keySign(byte[], byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidRemoveV1 keyDelete(byte[]);
    private org.hyperledger.iroha.sdk.offline.wallet.KagemushaWalletAndroidAttestationChainV1 attestationChain(byte[]);
    private int anchorPolicyTag();
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
