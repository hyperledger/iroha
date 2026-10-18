package org.hyperledger.iroha.sdk.tx

import kotlin.test.Test

/** Shared Rust vectors run through the canonical Kotlin payload API and mandatory native admission. */
class SignedAttachmentVectorsTest {
    @Test fun `all typed privacy protocols have canonical direct and batch intent projections`() = SignedAttachmentPayloadAssertions.typedPrivacyProjections()
    @Test fun `proved executable normalizes outputs and binds code`() = SignedAttachmentPayloadAssertions.provedExecutableBindings()
    @Test fun `carrier construction and rebinding preserve the proof free intent`() = SignedAttachmentPayloadAssertions.carrierConstructionAndRebinding()
    @Test fun `attachment free vector round trips byte for byte`() = SignedAttachmentPayloadAssertions.attachmentFreeRoundtrips()
    @Test fun `attachment bearing vectors decode and re-encode byte for byte`() = SignedAttachmentPayloadAssertions.acceptedPayloadsAndDigests()
    @Test fun `all rejected Rust vectors fail transaction admission`() = SignedAttachmentPayloadAssertions.rejectedPayloads()
    @Test fun `native action registry equals authoritative Rust inventory`() = SignedAttachmentPayloadAssertions.nativeRegistryMatches()
    @Test fun `canonical non iroha native actions round trip and aliases are refused`() = SignedAttachmentPayloadAssertions.nonIrohaNativeOperationsRoundtrip()
}
