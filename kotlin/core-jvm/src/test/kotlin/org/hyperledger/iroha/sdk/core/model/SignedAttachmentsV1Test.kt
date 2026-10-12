package org.hyperledger.iroha.sdk.core.model

import kotlin.test.Test

class SignedAttachmentsV1Test {
    @Test fun `Java source consumes the Kotlin model`() = SignedAttachmentsJavaCalls.verify()
    @Test fun `digest values are bounded and defensive`() = SignedAttachmentsModelAssertions.digestsAreDistinctDefensiveValues()
    @Test fun `lists reject counts before allocation`() = SignedAttachmentsModelAssertions.listsCheckBoundsBeforeReadingAndAreDefensive()
    @Test fun `content ownership rejects substitutions omissions and duplicates`() = SignedAttachmentsModelAssertions.occurrenceContentsAndReferencesAreAdmittedExactly()
    @Test fun `closed variants and primitive bounds are enforced`() = SignedAttachmentsModelAssertions.closedBindingsAndPrimitiveBoundsAreEnforced()
}
