package org.hyperledger.iroha.sdk.client.stream

import java.net.URLEncoder
import org.hyperledger.iroha.sdk.client.collections.AccountHistoryRow
import org.hyperledger.iroha.sdk.json.Json
import org.hyperledger.iroha.sdk.json.JsonObject

/**
 * Listener for `GET /v1/accounts/{account_id}/history/sse` (`specs/torii/streaming.md`).
 *
 * The feed is live-only: once [onOpen] runs, read the first account-history page and
 * deduplicate by [AccountHistoryRow.id]; together the stream and that page leave no gap.
 */
interface AccountHistoryStreamListener {
    /** A connection was established; rows committed before it must be read from history. */
    fun onOpen() {}

    /** One new movement, in ascending (block height, block index, movement index) order. */
    fun onMovement(row: AccountHistoryRow)

    /** Torii ended the stream with a terminal `stream_error` (for example `stream_lagged`). */
    fun onStreamError(error: ToriiStreamException) {}

    /** The stream ended normally. */
    fun onClosed() {}

    /** The stream failed (transport, HTTP error such as `invalid_filter`, or a malformed frame). */
    fun onError(error: Throwable) {}
}

/** Event name of one account-history row frame. */
internal const val ACCOUNT_HISTORY_MOVEMENT_EVENT = "movement"

/** Path of the live account-history stream for [accountId] (an I105 literal or alias). */
internal fun accountHistoryStreamPath(accountId: String): String {
    require(accountId.isNotBlank()) { "accountId must not be blank" }
    return "/v1/accounts/${URLEncoder.encode(accountId, "UTF-8")}/history/sse"
}

/** Whether [rawPath] is a live account-history stream, which has no replay log either. */
internal fun isAccountHistoryStreamRawPath(rawPath: String?): Boolean {
    if (rawPath == null || !rawPath.startsWith("/v1/accounts/") || !rawPath.endsWith("/history/sse")) {
        return false
    }
    val account = rawPath.removePrefix("/v1/accounts/").removeSuffix("/history/sse")
    return account.isNotEmpty() && '/' !in account
}

/**
 * Adapts raw SSE frames to [listener]: `movement` frames decode as [AccountHistoryRow], a
 * terminal `stream_error` reaches [AccountHistoryStreamListener.onStreamError], and frames with
 * other names are ignored so a server can add event kinds. A `movement` payload that is not a
 * history row fails the stream instead of being skipped.
 */
internal fun accountHistoryFrames(listener: AccountHistoryStreamListener): ToriiEventStreamListener =
    object : ToriiEventStreamListener {
        override fun onOpen() = listener.onOpen()

        override fun onEvent(event: ServerSentEvent) {
            val terminal = event.terminalStreamError()
            if (terminal != null) {
                listener.onStreamError(terminal)
                return
            }
            if (event.event != ACCOUNT_HISTORY_MOVEMENT_EVENT) return
            val row = Json.parse(event.data) as? JsonObject
                ?: throw IllegalArgumentException("account-history movement data must be a JSON object")
            listener.onMovement(AccountHistoryRow.fromJson(row))
        }

        override fun onClosed() = listener.onClosed()

        override fun onError(error: Throwable) = listener.onError(error)
    }
