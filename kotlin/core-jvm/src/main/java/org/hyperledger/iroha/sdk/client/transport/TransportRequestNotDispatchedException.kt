package org.hyperledger.iroha.sdk.client.transport

/**
 * A transport adapter refused a request before handing it to its backend.
 *
 * Emit this signal only when the request has never been dispatched: neither the backend nor any
 * network operation may have been invoked. A synchronous throw alone does not establish this
 * guarantee. Failures after dispatch, including cancellation and I/O failures, must retain their
 * ordinary failure type because the transaction outcome may be unknown.
 *
 * Transaction submission preserves [originalFailure] so a pre-dispatch cancellation remains a
 * cancellation instead of being reported as an ambiguous transaction outcome.
 */
class TransportRequestNotDispatchedException(
    val originalFailure: Exception,
) : RuntimeException("Transport request was refused before dispatch", originalFailure)
