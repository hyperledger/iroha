# App API routed-read HTTP admission

All 46 first-release `ToriiReadEndpointV1` public handlers share one outer HTTP
admission corridor. Before a request body is polled, Torii waits within the
bounded query admission queue for the smallest query-fanout owner whose limits
admit the request target and declared body (256 KiB, 2 MiB and 16 MiB phase
units below `torii.query_fanout_max_working_set_bytes`, then that ceiling; an
undeclared length takes the ceiling). The same reservation is adopted by
downstream single-route and fanout execution and remains owned by the final
response body. When a limit derived from the owner refuses the read, the
corridor releases it, waits for the next owner and serves the read again from
its retained body; only the ceiling owner's refusal reaches the client. Owners
below the ceiling do not book the proxy-candidate allowance, so a read routed to
another validator moves to the ceiling owner before any candidate is resolved.

The corridor counts the complete parsed request target (scheme and authority for
absolute form, plus path and query) and body against the route-body phase. It
rejects duplicate or non-canonical `Content-Length`, `Content-Length` combined
with `Transfer-Encoding`, trailers, and any body framing on bodyless routes.
Bodyless streams are still drained through end-of-stream under the same deadline,
so a lying zero length cannot smuggle a DATA frame. Unknown-length streams are
limited by bytes and the absolute deadline. A non-empty body is collected into
one exact-capacity owner-backed buffer; an empty body uses the static empty
`Bytes` representation after the stream has completed. JSON is lexically
preflighted before measured typed decoding. Form queries use a separate exact
expanded-JSON phase before entering the typed decode scope.

The current Torii listener is HTTP/1 only. Its adapter exposes at most 8 KiB per
socket read, which is the source bound used for Hyper DATA-frame accounting; no
HTTP/2 listener path is enabled. Listener pre-authentication and the configured
API token run before routed-read admission. Routes that additionally require a
canonical account body signature verify it after the bounded body has been
collected under the fanout reservation, but before any typed extractor or
handler executes.

Canonical V1 request authentication also rejects ambiguous duplicate singleton
headers and applies the same limits in HTTP and direct verifier calls: at most
64 decoded query pairs, 64 KiB of raw query text, a 32-byte HTTP method token,
a 64 KiB percent-encoded path, printable-ASCII nonces of 1–256 bytes, and a
36 KiB direct account/alias literal. The direct identity cap
bounds grouped I105 conversion work; larger controller policies use the bounded
witness form, which permits at most 64 signatures in a 768 KiB decoded canonical
Norito frame. Individual signatures are capped by the largest V1 algorithm
payload.

`X-Iroha-Account` transports a canonical account identity as ASCII lowercase
`0x` plus its canonical `AccountAddress` bytes; an exact active ASCII account
alias is carried unchanged. Account ids in data models and signed JSON bodies
remain canonical I105. This header-only spelling avoids relying on Unicode HTTP
field-value behavior, which differs across browsers, proxies, and SDK stacks.

Timestamp headers are canonical unsigned decimal integers: signs, leading
zeroes, fractional or exponent notation, and surrounding whitespace are
rejected before signature verification.

`torii.app_api_routed_read_body_read_timeout_ms` is the absolute deadline for
collecting one admitted routed-read body. Its default is `10000` milliseconds;
zero is rejected during configuration parsing. Timeout and capacity failures
release the reservation only after their response body is dropped.
