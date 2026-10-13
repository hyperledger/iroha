package org.hyperledger.iroha.sdk.tx.norito

import kotlin.test.Test

class SignedAttachmentsCodecTest {
    @Test fun `canonical frame ceiling accepts exactly the limit`() = SignedAttachmentsCodecAssertions.aggregateFrameBoundaryIsExact()
    @Test fun `Rust carrier frames and all statement digests agree`() = SignedAttachmentsCodecAssertions.canonicalRustFramesAndDigests()
    @Test fun `carrier plans reject allocation bounds before encoding`() = SignedAttachmentsCodecAssertions.carrierSizePreflightRejectsBeforeProofEncoding()
}
