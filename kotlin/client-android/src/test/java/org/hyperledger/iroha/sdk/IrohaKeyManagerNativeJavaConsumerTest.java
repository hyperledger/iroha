package org.hyperledger.iroha.sdk;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.hyperledger.iroha.sdk.crypto.IrohaHash;
import org.hyperledger.iroha.sdk.crypto.MlDsaPrivateKey;
import org.hyperledger.iroha.sdk.crypto.MlDsaPublicKey;
import org.hyperledger.iroha.sdk.crypto.NativeSignerBridge;
import org.hyperledger.iroha.sdk.crypto.Signer;
import org.hyperledger.iroha.sdk.crypto.SigningAlgorithm;
import org.hyperledger.iroha.sdk.crypto.keystore.KeySecurityPreference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

/** Requires a freshly built host JNI bridge; absence is a failure, never a skipped native claim. */
@Tag("host-native")
class IrohaKeyManagerNativeJavaConsumerTest {
    @Test
    void mlDsaManagerGeneratesLoadsAndSignsThroughItsSoftwareProvider() throws Exception {
        assertTrue(NativeSignerBridge.isNativeAvailable(), "fresh connect_norito_bridge ABI 29 is required");
        IrohaKeyManager manager = IrohaKeyManager.withSoftwareProvider(SigningAlgorithm.ML_DSA);
        KeyPair pair = manager.generateOrLoad("ml-dsa", KeySecurityPreference.SOFTWARE_ONLY);
        assertEquals(SigningAlgorithm.ML_DSA, manager.signingAlgorithm());
        assertTrue(pair.getPrivate() instanceof MlDsaPrivateKey);
        assertTrue(pair.getPublic() instanceof MlDsaPublicKey);
        KeyPair loaded = manager.generateOrLoad("ml-dsa", KeySecurityPreference.SOFTWARE_ONLY);
        assertArrayEquals(pair.getPublic().getEncoded(), loaded.getPublic().getEncoded());
        Signer signer = manager.signerForAlias("ml-dsa", KeySecurityPreference.SOFTWARE_ONLY);
        byte[] message = "hello-ml-dsa".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signer.sign(message);
        assertTrue(NativeSignerBridge.verifyDetached(
                SigningAlgorithm.ML_DSA, signer.publicKey(), IrohaHash.prehash(message), signature));
    }
}
