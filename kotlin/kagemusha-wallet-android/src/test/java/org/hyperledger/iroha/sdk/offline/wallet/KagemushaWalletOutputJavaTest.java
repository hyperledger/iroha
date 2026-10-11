package org.hyperledger.iroha.sdk.offline.wallet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Java source consumes canonical Kotlin projection classes, with no second codec. */
class KagemushaWalletOutputJavaTest {
    @Test void metadataRetainsCopiesForJavaCallers() {
        ByteBuffer frame = ByteBuffer.allocate(150).order(ByteOrder.LITTLE_ENDIAN);
        frame.put("KWMDV1\0\0".getBytes(StandardCharsets.US_ASCII)).putInt(28);
        byte[] identity = new byte[128]; java.util.Arrays.fill(identity, (byte) 7);
        frame.put(identity).putInt(1).putInt(1).put((byte) 11).put((byte) 12);
        KagemushaWalletMetadataV1 result = new KagemushaWalletMetadataV1(frame.array());
        java.util.Arrays.fill(frame.array(), (byte) 0);
        assertEquals(28, result.getAssetScale());
        assertArrayEquals(new byte[]{11}, result.accountOriginal());
        result.assetOriginal()[0] = 0;
        assertArrayEquals(new byte[]{12}, result.assetOriginal());
        assertTrue(result.toString().contains("[REDACTED]"));
    }
}
