// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
package org.hyperledger.iroha.sdk.offline;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.hyperledger.iroha.sdk.client.JsonParser;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Java source calls the canonical Kotlin middleware owner; no duplicate implementation. */
public class KagemushaEligibilityJavaTest {
    private static byte[] hex(Object value) {
        String text = (String) value;
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(text.substring(2*i, 2*i+2), 16);
        return bytes;
    }
    @Test public void eachProviderCanInjectCurrentLookupAndExistingSignerFromJava() throws Exception {
        File root = new File(".").getCanonicalFile();
        File fixture;
        do {
            fixture = new File(root, "fixtures/kagemusha/enrollment_eligibility_template_v1_vectors.json");
            if (fixture.isFile()) break;
            root = root.getParentFile();
            assertNotNull(root, "Rust eligibility fixture required");
        } while (true);
        Map<?, ?> vectors = (Map<?, ?>) JsonParser.parse(new String(Files.readAllBytes(fixture.toPath()), StandardCharsets.UTF_8));
        for (String authority : new String[] {"bank", "scheme-operator"}) {
        Map<?, ?> row = ((List<?>) vectors.get("cases")).stream().map(value -> (Map<?, ?>) value)
            .filter(value -> authority.equals(value.get("authority")) && "approved-unfrozen".equals(value.get("decision")))
            .findFirst().orElseThrow(() -> new AssertionError("provider vector required"));
        KagemushaEnrollmentEligibilityV1.PolicyTemplate template = KagemushaEnrollmentEligibilityV1.decodeTemplate(hex(row.get("template_hex")));
        AtomicInteger reads = new AtomicInteger();
        byte[] response = KagemushaEnrollmentEligibilityV1.answer(template, hex(row.get("observation_hex")),
            () -> BigInteger.valueOf(1100),
            (asset, selected, request) -> {
                assertArrayEquals(hex(row.get("asset_hex")), asset.originalBytes());
                reads.incrementAndGet();
                assertEquals(authority.equals("bank") ? KagemushaEnrollmentEligibilityV1.Authority.BANK :
                    KagemushaEnrollmentEligibilityV1.Authority.SCHEME_OPERATOR, selected.getAuthority());
                assertEquals(32, selected.scopeDigest().length);
                assertEquals(32, request.accountDigest().length);
                return new KagemushaEnrollmentEligibilityV1.Current(true, false, BigInteger.ONE, BigInteger.valueOf(1100));
            }, message -> {
                assertArrayEquals(hex(row.get("signing_message_hex")), message);
                return hex(row.get("signature_hex"));
            });
        assertArrayEquals(hex(row.get("response_hex")), response);
        assertEquals(1, reads.get());
        }
    }
}
