package org.hyperledger.iroha.sdk.offline.wallet

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

/** Cleanup fault seam only: these resources contain no Native IDs or financial capabilities. */
class KagemushaWalletCleanupQuarantineV1Test {
    private class Resource : KagemushaWalletCleanupResourceV1 {
        var calls=0;var released=false;var failure:Throwable?=null
        override fun cleanupReleased()=released
        override fun retryCleanup(){calls++;failure?.let{throw it};released=true}
    }
    @Test fun `ordinary check never retries or erases a failed resource`() {
        val quarantine=KagemushaWalletCleanupQuarantineV1();val resource=Resource();val failure=IllegalStateException("provider busy")
        quarantine.retain(resource,failure)
        repeat(2){assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.requireReleased()})}
        assertEquals(0,resource.calls)
    }
    @Test fun `explicit retry retains failure until real release acknowledgment`() {
        val quarantine=KagemushaWalletCleanupQuarantineV1();val resource=Resource();val failure=IllegalStateException("close failed")
        resource.failure=failure;quarantine.retain(resource,failure)
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.retry()})
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.requireReleased()})
        resource.failure=null;quarantine.retry();quarantine.requireReleased();assertEquals(2,resource.calls)
    }
    @Test fun `retry visits every retained resource once despite duplicate failures`() {
        val quarantine=KagemushaWalletCleanupQuarantineV1();val first=Resource();val second=Resource();val failure=IllegalStateException("first")
        first.failure=failure;quarantine.retain(first,failure);quarantine.retain(first,failure);quarantine.retain(second,IllegalStateException("second"))
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.retry()})
        assertEquals(1,first.calls);assertEquals(1,second.calls)
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.requireReleased()})
        first.failure=null;quarantine.retry();quarantine.requireReleased();assertEquals(1,second.calls)
    }    @Test fun `shared throwable cannot stop a third cleanup retry`() {
        val quarantine=KagemushaWalletCleanupQuarantineV1();val first=Resource();val second=Resource();val third=Resource()
        val failure=IllegalStateException("shared provider failure");first.failure=failure;second.failure=failure
        for(resource in listOf(first,second,third))quarantine.retain(resource,failure)
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.retry()})
        assertEquals(1,first.calls);assertEquals(1,second.calls);assertEquals(1,third.calls)
        assertSame(failure,assertFailsWith<IllegalStateException>{quarantine.requireReleased()})
        first.failure=null;second.failure=null;quarantine.retry();quarantine.requireReleased();assertEquals(1,third.calls)
    }

}
