# P2P admission, queues and metrics

## Mandatory first-release records

After the identity handshake, `NetworkBase` selects a provisional connection
using the complete identity-authenticated session hash. Only connection ids
already reserved by its listener or dialer can enter this bounded owner. Both
endpoints prefer the same full hash; local direction, compact-prefix ties and
relay roles do not define another arbitration policy. Exact configured outbound
hub identity proof remains independent of the selected transport.

The selected connection receives a non-cloneable reader permit before
`Pool::bind`. A replacement cancels its predecessor and waits for actual I/O and
source-ledger destruction. It does not wait for old delivered work: those guards
retain the same strong PeerId partitions and exact byte/count reservations.
Pending replacements never hold another reader. Stale Connected/Terminated
notices cannot publish or retire a different connection generation. The physical
release channel is independent of the service mailbox and dispatch-worker drain.

Identity, permission wait, `peer/receive_credit/negotiation.rs` geometry exchange
and the Connected handoff share the original authentication deadline. Geometry
uses canonical `GeometryOfferV1` records.
Each offer binds nine semantic class ordinals, counts, byte partitions, native
frame maxima and Norito writer flags. Both independently valid offers are
bound into directional authority; outgoing maxima use their per-class minima.
Different valid geometries can connect. Missing classes, malformed layouts and
unfunded protected maxima fail before application registration. Listener diagnostics
separate Authenticated, PeerEnded and DeadlineElapsed. A completion/early-end
timestamp is captured at the peer boundary, so delayed listener polling cannot
turn an earlier close into a timeout; equality with the deadline is expired. Shipping QUIC
is rejected by `validate_shipping_quic_policy`; it is not an alternate stream.

`RecordHeaderV1` has version, kind, class, binding, sequence and plaintext size.
Kinds are Request, Grant, Data, Ping and Pong. A bounded length prefix precedes
one canonical Norito header, authenticated verbatim as AEAD associated data.
Data carries exactly one canonical peer/relay message; control carries an empty
authenticated body. Directional authority binds network, complete connected
PeerIds, session key identity, transport binding and geometry. Application
class and Topic are separate owners:

| Class | Payload family | Scheduling resource |
| --- | --- | --- |
| Safety | consensus safety messages (`ConsensusSafety` topic) | protected high |
| Lane | ordinary consensus control (`Consensus` topic) | high |
| Payload | consensus bodies and chunks (`ConsensusPayload`/`ConsensusChunk`) | high |
| Control | application control/proxy messages | high |
| BlockSync | ordinary block synchronization | low |
| Low | remaining gossip/health/application traffic | low |

The class is a function of the Topic. Existing Topic caps remain authoritative and
are the class maxima: Safety and Control use the control cap, Lane the consensus cap,
Payload and BlockSync the block-sync cap, Low the largest remaining low cap. Reader
admission requires declared, bounded raw and fully decoded classes to agree.
The connected-peer authentication does not replace relay-origin or consensus
signature/authority validation by the existing consumers.

## Exact retained owners

A Request obtains a receiver-issued Grant only after its source, scratch,
dispatch byte and count reservations exist. A matching plaintext Data header
transfers that exact reservation to the unique reader solely to allocate the
bounded ciphertext. AEAD, canonical decode and semantic agreement precede
application delivery. Failed tags fence the reader; they cannot release an
unspent grant early. Every transferred guard remains with subscriber and final
consumer work, including retained gossip and supervised proxy work.

Request/Grant/Ping/Pong use fixed, independently precharged transport cells,
not application Control or Low grants. Remote Ping requests retain a two-token
burst and one-token refill per half idle interval. An exact authenticated Pong
retires the sole outstanding local probe without spending remote Ping credit.
Unknown, duplicate and substituted Pongs fail. Grant/control progress never waits
on a data credit it must release. One bounded record scheduler gives each high
class two ranks and each low class one rank. FIFO remains within each semantic
source/class; ordinary work is serviced after its retained predecessor releases.
This removes application-backpressure blockage on an honest ordered stream. It
cannot bypass earlier bytes that the sender/network never delivers.

Let `H`/`L` be configured high/low byte budgets, `P` the existing per-PeerId
progress reserve and `N` the admitted connection/source bound. Each owner keeps
its existing physical ceiling. High class sublimits partition `H`, and
BlockSync/other Low partition `L`. Private `P` first funds all three physical
allocations for the full Safety maximum plus fixed control cells, then
deterministically divides the residual. Shared class/scratch
saturation does not spend another admitted PeerId's private protected reserve.
Startup rejects insufficient geometry; no extra pool is created to make it fit.
Large ordinary bodies have no claim to a full private protected maximum.

Unspent grants, partial reads, delivered guards and pending writer ACKs retain
strong PeerId ownership. Reconnect reuses that owner; closing a tenure reclaims
only its unspent grants after I/O closes. Old delivered work keeps its original
reservations until physical consumption. Outbound posts likewise reserve
semantic `H`/`L`/`P` bytes before joining a peer FIFO and keep them through flush.

The network actor has four protected classes: Safety, Lane, Payload and BlockSync.
The actor class derives from the actual payload, never caller priority. For each
of `T = 2N` authorized target slots, every class retains 65 FIFO metadata ranks
(260 total). Source and waiter capacities derive from that same class inventory.
Each source may retain up to eight small frames within its existing single-frame
byte cap; the item window never increases that byte cap. A full byte allowance or
item window returns the original ranked ticket until physical ownership releases.
The independent safety and low owners are unchanged.

Physical inbound and daemon subscriber queues partition their existing count
budgets across the semantic classes. Default high count is 8192, low count
32768, post count 2048, and subscriber count 8192. Default byte budgets are
128 MiB high and 64 MiB low. Validated nonzero partitions and checked
arithmetic are mandatory. These are retained-owner bounds,
not measured process RSS; kernel/TLS state, fixed parser storage and application
execution graphs have separate owners and qualification obligations.

TODO: qualify the composed actor/post/record/subscriber/final-consumer path with
native P2P and Core controls and fresh networks. Uncompiled fixtures and source
geometry proofs are not throughput, memory or adversarial-liveness measurements.

### Low-Priority Rate Limiting ([network] settings)

- `low_priority_rate_per_sec` (optional; msgs/sec)
  - Enables per-peer token-bucket for Low-priority traffic (gossip/sync) on both ingress and egress. When unset, disabled.
- `low_priority_burst` (optional; msgs)
  - Bucket burst capacity; defaults to `low_priority_rate_per_sec` when unset.

When enabled, inbound Low-priority frames are dropped before relay dispatch (tx gossip, peer/trust gossip, health/time), and outbound Low-priority posts/broadcast deliveries are throttled per peer. Fixed transport Request/Grant records use their separately precharged cells; they are not application Low traffic. Remote Ping requests have the explicit two-token rate limit; exact correlated Pongs retire locally owned probes. High-priority consensus/control traffic is otherwise unaffected.

### DNS Hostname Refresh ([network] setting)

If your `P2P_PUBLIC_ADDRESS` is a hostname, you can optionally refresh connections on an interval to pick up IP changes:

- `dns_refresh_interval_ms` (optional; disabled if unset)
  - When set, the peer will periodically disconnect and re‑dial hostname‑based peers so the OS resolver can re‑resolve the host name.
  - Recommended values: 300000–600000 (5–10 minutes) depending on your DNS TTL and operational needs.

### P2P Telemetry Metrics

The following gauges are exposed via Prometheus when telemetry is enabled:

- `p2p_dropped_posts`: number of post messages dropped due to a full bounded queue (monotonic).
- `p2p_dropped_broadcasts`: number of broadcast messages dropped due to a full bounded queue (monotonic).
- `p2p_subscriber_queue_full_total`: number of inbound messages dropped because subscriber queues were full.
- `p2p_subscriber_queue_full_by_topic_total{topic="ConsensusSafety|Consensus|ConsensusChunk|Control|BlockSync|TxGossip|PeerGossip|Health|Other"}`: per-topic subscriber-queue drops.
- `p2p_subscriber_unrouted_total`: number of inbound messages dropped because no subscriber matches the topic.
- `p2p_subscriber_unrouted_by_topic_total{topic="ConsensusSafety|Consensus|ConsensusChunk|Control|BlockSync|TxGossip|PeerGossip|Health|Other"}`: per-topic unrouted inbound drops.
- `p2p_queue_depth{priority="Safety|Progress|High|Low"}`: bounded network actor queue depth by scheduling lane.
- `p2p_queue_dropped_total{priority="High|Low",kind="Post|Broadcast"}`: bounded network actor queue drops by priority/kind.
- `p2p_handshake_failures`: number of P2P handshake failures (timeouts, signature/verification errors).
- `soranet_pow_revocation_store_total{reason}`: count of SoraNet PoW revocation-store failures
  (for example, a poisoned store lock, exhausted capacity, or an unwritable snapshot). Alert when
  this rises; the corresponding handshake fails closed and replay protection is never downgraded
  to an in-memory-only fallback.
- `p2p_low_post_throttled_total`: number of Low-priority post messages throttled by per-peer token-buckets.
- `p2p_low_broadcast_throttled_total`: number of Low-priority broadcast deliveries throttled by per-peer token-buckets.
- `p2p_post_overflow_total`: number of per-peer post channel overflows (bounded per-topic channels).
- `p2p_dns_refresh_total`: number of DNS interval-based refresh cycles performed.
- `p2p_dns_ttl_refresh_total`: number of DNS TTL-based refresh cycles performed.
- `p2p_dns_resolution_fail_total`: number of DNS resolution/connection failures for hostname peers.
- `p2p_dns_reconnect_success_total`: number of reconnect successes after refresh cycles.
- `p2p_backoff_scheduled_total`: number of per-address connect backoffs scheduled.
- `p2p_accept_throttled_total`: number of incoming connections rejected by per-IP throttle.
- `p2p_accept_bucket_evictions_total`: number of accept bucket evictions (idle timeout or cap).
- `p2p_accept_buckets_current`: current number of active accept buckets (prefix + per-IP).
- `p2p_accept_prefix_cache_total{result="hit|miss"}`: prefix bucket cache utilisation.
- `p2p_accept_throttle_decisions_total{scope="prefix|ip",decision="allowed|throttled"}`: accept throttle outcomes split by prefix vs per-IP buckets.
- `p2p_incoming_cap_reject_total`: number of incoming connections rejected due to `max_incoming`.
- `p2p_total_cap_reject_total`: number of connections rejected due to `max_total_connections`.
- `p2p_preauth_source_cap_reject_total`: number of accepted unauthenticated TCP or
  address-validated QUIC transports rejected by `preauth_max_connections_per_ip`.
- `p2p_scion_inbound_total`: accepted inbound SCION P2P connections (reserved for future inbound listener support).
- `p2p_scion_outbound_total`: successful outbound SCION-guided P2P connections.

These metrics help identify saturation scenarios and networking issues. Drop counters remain at zero as long as queues keep up with traffic.

Example `/metrics` snippet (Prometheus):

```
# HELP p2p_dropped_posts Number of p2p post messages dropped due to backpressure
# TYPE p2p_dropped_posts gauge
p2p_dropped_posts 0

# HELP p2p_dropped_broadcasts Number of p2p broadcast messages dropped due to backpressure
# TYPE p2p_dropped_broadcasts gauge
p2p_dropped_broadcasts 12

# HELP p2p_subscriber_queue_full_total Number of inbound messages dropped because subscriber queues were full
# TYPE p2p_subscriber_queue_full_total gauge
p2p_subscriber_queue_full_total 3

# HELP p2p_subscriber_queue_full_by_topic_total Per-topic inbound drops caused by full subscriber queues
# TYPE p2p_subscriber_queue_full_by_topic_total gauge
p2p_subscriber_queue_full_by_topic_total{topic="Consensus"} 2

# HELP p2p_subscriber_unrouted_total Number of inbound messages dropped because no subscriber matches the topic
# TYPE p2p_subscriber_unrouted_total gauge
p2p_subscriber_unrouted_total 7

# HELP p2p_subscriber_unrouted_by_topic_total Per-topic inbound drops caused by no matching subscriber
# TYPE p2p_subscriber_unrouted_by_topic_total gauge
p2p_subscriber_unrouted_by_topic_total{topic="Consensus"} 1

# HELP p2p_handshake_failures Number of p2p handshake failures
# TYPE p2p_handshake_failures gauge
p2p_handshake_failures 1

# HELP p2p_dns_refresh_total Number of DNS interval-based refresh cycles performed
# TYPE p2p_dns_refresh_total gauge
p2p_dns_refresh_total 3

# HELP p2p_dns_ttl_refresh_total Number of DNS TTL-based refresh cycles performed
# TYPE p2p_dns_ttl_refresh_total gauge
p2p_dns_ttl_refresh_total 7

# HELP p2p_dns_resolution_fail_total Number of DNS resolution/connection failures for hostname peers
# TYPE p2p_dns_resolution_fail_total gauge
p2p_dns_resolution_fail_total 2

# HELP p2p_dns_reconnect_success_total Number of DNS reconnect successes after refresh cycles
# TYPE p2p_dns_reconnect_success_total gauge
p2p_dns_reconnect_success_total 5

# HELP p2p_backoff_scheduled_total Number of per-address connect backoffs scheduled
# TYPE p2p_backoff_scheduled_total gauge
p2p_backoff_scheduled_total 1

# HELP p2p_accept_throttled_total Number of inbound accepts rejected by per-IP throttle
# TYPE p2p_accept_throttled_total gauge
p2p_accept_throttled_total 0

# HELP p2p_accept_bucket_evictions_total Number of accept throttle bucket evictions (idle or cap)
# TYPE p2p_accept_bucket_evictions_total gauge
p2p_accept_bucket_evictions_total 0

# HELP p2p_accept_buckets_current Current number of active accept throttle buckets (prefix + per-IP)
# TYPE p2p_accept_buckets_current gauge
p2p_accept_buckets_current 0

# HELP p2p_accept_prefix_cache_total Prefix bucket cache hits/misses for accept throttle (label `result` = hit|miss)
# TYPE p2p_accept_prefix_cache_total gauge
p2p_accept_prefix_cache_total{result="hit"} 0
p2p_accept_prefix_cache_total{result="miss"} 4

# HELP p2p_incoming_cap_reject_total Number of inbound accepts rejected by incoming cap
# TYPE p2p_incoming_cap_reject_total gauge
p2p_incoming_cap_reject_total 0

# HELP p2p_total_cap_reject_total Number of connections rejected by total cap
# TYPE p2p_total_cap_reject_total gauge
p2p_total_cap_reject_total 0

# HELP p2p_preauth_source_cap_reject_total Number of accepted unauthenticated transports rejected by the concurrent per-source cap
# TYPE p2p_preauth_source_cap_reject_total gauge
p2p_preauth_source_cap_reject_total 0

# HELP p2p_scion_outbound_total Successful outbound SCION P2P connections
# TYPE p2p_scion_outbound_total gauge
p2p_scion_outbound_total 0
```

### Per-Topic Scheduling

- Outbound traffic is separated into logical topics to avoid head-of-line blocking and to prioritize consensus/control messages:
  - High: `Consensus`, `Control` (biased priority)
  - Low: `BlockSync`, `TxGossip`, `PeerGossip`, `Health`, `Other` (fair scheduling)
- Message payload types implement `iroha_p2p::network::message::ClassifyTopic` to supply their topic. `iroha_core::NetworkMessage` provides the mapping for core messages.
- Inbound and forwarded egress scheduling derive their lanes exclusively from
  that semantic topic. Relay envelopes carry no independent priority field, so
  a remote peer cannot request promotion into a protected queue at either hop.
- A small fairness budget guarantees Low topics make progress during sustained High traffic.

### Proxy Support (HTTP CONNECT / SOCKS5)

- Knobs (`[network]`):
  - `p2p_proxy` (string; optional): outbound proxy URL (e.g., `http://proxy.example.com:8080`, `socks5://proxy.example.com:1080`, or `https://user:pass@proxy.example.com:8443`). Credentials are accepted only on pinned HTTPS.
  - `p2p_proxy_required` (bool; default `false`): when true, require `p2p_proxy` to be set, disallow `p2p_no_proxy` exemptions, and fail startup otherwise. Note: QUIC bypasses the proxy, so `quic_enabled=true` is rejected when `p2p_proxy_required=true`.
  - `p2p_no_proxy` (array of strings): host suffixes to bypass the proxy (e.g., `.example.com`, `localhost`). Must be empty when `p2p_proxy_required=true`.
  - `outbound_dial_allow_cidrs` / `outbound_dial_deny_cidrs` (arrays of CIDRs): constrain every literal or resolved peer and proxy address. Empty allow-lists are unrestricted; deny entries take precedence.
  - `outbound_dial_allow_dns_suffixes` / `outbound_dial_deny_dns_suffixes` (arrays of DNS suffixes): constrain peer and proxy hostnames at DNS label boundaries. Empty allow-lists are unrestricted; deny entries take precedence.
  - `p2p_proxy_tls_verify` (bool; default `true`): must remain true for an `https://` proxy hop.
  - `p2p_proxy_tls_pinned_cert_der_base64` (string; optional): pinned end-entity proxy certificate (DER, base64). Required for every `https://` proxy.
- When `p2p_proxy` is set and the target host is not exempted, the dialer tunnels via:
  - HTTP `CONNECT host:port` for `http://...` / `https://...`
    - `http://...` uses plaintext TCP to the proxy.
    - `https://...` wraps the proxy connection in pinned TLS before issuing `CONNECT`. TLS support is an unconditional part of `iroha_p2p`.
  - SOCKS5 `CONNECT` for `socks5://...` / `socks5h://...`
- Notes:
  - Basic authentication is supported via `user:pass@...` only for an `https://` proxy with an exact leaf-certificate pin. Credentials on HTTP or SOCKS5 are rejected before connecting or writing bytes.
  - HTTP CONNECT authorities are constructed from the typed socket address.
    Hostnames must be ASCII DNS names with valid LDH labels; malformed names
    are rejected before credentials or any other bytes are written to the
    proxy.
  - Proxy exemptions and outbound DNS policy suffixes match only complete DNS labels, so `example.com` never matches `notexample.com`. IPv4-mapped IPv6 literals and mapped-specific (`/96` or narrower) CIDRs are canonicalized to IPv4 for both dial admission and exact-IP proxy exemptions; deny rules additionally retain the original IPv6 match so representation changes cannot weaken them.
  - The outbound policy checks the logical name before lookup and every concrete address returned by the one lookup used for the dial. One lookup may retain at most 64 raw answers; a 65th answer fails the attempt before dialing. TCP, QUIC, SCION-preferred QUIC, SOCKS5, and HTTP(S) CONNECT share the same fail-closed policy.
  - When a CIDR policy applies to a proxied hostname, the node resolves it locally before opening the proxy connection and tunnels to an admitted numeric endpoint. This prevents remote proxy DNS from bypassing the CIDR policy and avoids a second resolution window.
  - Malformed proxy hosts, CIDRs, and DNS suffixes abort startup before listeners are bound.
  - Disabling `p2p_proxy_tls_verify` for an HTTPS proxy is rejected before connecting.
  - Proxies apply only to the mandatory TLS-over-TCP dial. QUIC (UDP) bypasses the proxy; set `quic_enabled=false` and `p2p_proxy_required=true` (with no `p2p_no_proxy` exemptions) if you must force all outbound P2P traffic through a proxy.
  - If no proxy is configured, connections go direct.

### Relay Mode (Hub/Spoke/Assist)

Iroha can optionally use a relay hub to improve reachability when some peers are behind NAT/firewalls or in censored networks. This is an application-level relay (forwarding encrypted frames), not a special Internet routing mechanism.

A relay envelope that a hop may forward carries an end-to-end origin
signature over a domain-separated commitment to the origin, final target, and
canonical application payload. The origin signs at the hand-off to such a hop:
a direct frame addressed to another peer, or a broadcast sent to a relay hub.
First-release node and target identities are BLS-normal, so relay admission
has one fixed 96-byte signature geometry and no per-algorithm verification
branch. Hubs preserve that signature and may only decrement the unsigned
hop-limit (`relay_ttl`). Receivers verify every present signature against the
origin peer key before forwarding or local delivery, and accept a frame whose
origin differs from the authenticated sender only from a relay hub, so
selecting a hub grants routing authority but never grants authority to
impersonate another peer's semantic origin. Only signed frames are forwarded.
A frame that the next hop consumes itself is link-local and carries no origin
signature: the authenticated session (TLS channel binding, the identity-bound
handshake, and the per-direction AEAD binding with per-class sequences)
already proves its sender. A receiver accepts an unsigned frame only when its
origin is the authenticated sender and it targets the receiver or is a
broadcast. TTL is deliberately hop-local rather than cryptographically
monotonic: the shipped forwarder only decrements it, while a Byzantine relay
can still replay a valid envelope or replace its TTL without changing any
signed semantic field.
Ingress and forwarded-egress scheduling derive priority from the authenticated
payload topic; the envelope has no competing priority metadata.
Every receiver clamps that mutable TTL to its own configured `relay_ttl` before
delivery/forwarding decisions. A hub address learned from topology gossip is a
dial candidate, not relay authority: a spoke or assist node grants hub
authority only after its own exact address-and-PeerId dial authenticates a peer
advertising the Hub role. That proof remains pinned until local configuration or
the peer ACL revokes it, and its exact outbound attempt is not suppressed by an
unproven inbound connection for the same identity. Assist and Spoke nodes reserve
one slot below `max_total_connections` while no authenticated hub or exact hub
dial occupies it. Ordinary inbound and outbound connections cannot spend that
slot; only a current address-snapshot entry whose PeerId and address match a
configured hub candidate may do so, and the physical hard cap is never exceeded.
For Assist mode, operators must size `max_total_connections` for the direct
protected-source topology plus the hub. An invalid origin signature or a
mismatch between the signed origin and the authenticated direct sender rejects
and quarantines that exact connection tenure until queued deliveries drain. A
violation without an exact connection tenure is dropped and cannot evict a
replacement session by PeerId alone.

Reliable semantic-progress delivery signs its relay envelope once on first
actor dispatch and retains that exact allocation across direct, broadcast, and
hub-fallback retries. The target cursor, writer-flush receipts, byte lease, and
topology/reply authority remain in one bounded actor-owned item, so retry cannot
repeat BLS signing or create an uncharged payload copy.

- Knobs (`[network]`):
  - `relay_mode` (string; `disabled` | `hub` | `spoke` | `assist`)
    - `disabled`: default; direct peer-to-peer mesh.
    - `hub`: accept inbound peers and forward traffic between them.
    - `spoke`: dial only the hub and rely on forwarding (useful when inbound connectivity is not possible).
    - `assist`: keep direct connections where possible but also keep a hub connection and route via the hub when the target peer is not directly connected.
  - `relay_hub_addresses` (array of socket addr; required for `spoke` and `assist`)
    - Addresses of the hub(s) to dial (peers that run with `relay_mode="hub"`). If multiple are supplied, entries are tried in order and the node may fall back to later hubs if the preferred one is unreachable.
  - `relay_ttl` (u8; default 8)
    - Hop limit for forwarded frames (prevents relay loops).

Recommended deployment pattern:
- Run at least one hub on a stable public address (e.g., a data center node).
- Run constrained nodes as `spoke` so they only need outbound connectivity to the hub.
- Run validators / well-connected peers as `assist` so they can reach spokes without requiring every peer to use a relay.

Example `config.toml` snippets:

```toml
[network]
relay_mode = "hub"
```

```toml
[network]
relay_mode = "spoke"
relay_hub_addresses = ["hub.example.com:1337"]
```

```toml
[network]
relay_mode = "assist"
relay_hub_addresses = ["hub.example.com:1337"]
```

Multi-hub example (censorship/failover):

```toml
[network]
relay_mode = "assist"
relay_hub_addresses = ["hub1.example.com:1337", "hub2.example.com:1337"]
```

### Dialing Strategy (Happy Eyeballs)

- Iroha dials multiple addresses per peer (e.g., hostname, IPv6, IPv4) in parallel with a small stagger so a reachable path wins quickly without waiting for slower/unreachable paths.
- Address preference (default): hostname first, then IPv6, then IPv4.
- Stagger interval: configurable via `[network]` as `happy_eyeballs_stagger_ms` (default 100ms). Increase if you have very large peer lists and want to further reduce burst dials; decrease for faster failover on slow networks.
- Per-address backoff: failed attempts back off independently per address with exponential jitter (up to 5s), avoiding stampedes.
- A failed configured-peer dial retains exactly one pending retry at its backoff deadline. Reconnection therefore does not depend on a later topology update, gossip tick, or outbound application frame.
- Replacing the peer-address snapshot revokes pending retries and backoff state for superseded endpoints; every due retry revalidates its exact `(PeerId, address)` before dialing.
- A later termination from a superseded or differently advertised endpoint cannot restore that endpoint's authority. If the same configured identity still has a current endpoint, the actor schedules that replacement immediately through the normal topology, ACL, validator-roster, hub, and capacity gates.

### SCION Capability Dialing

SCION preference is automatic and capability-driven.

Behavior:
- Each peer advertises `scion_supported` in handshake metadata.
- Peers gossip observed transport capabilities (`scion_supported`) alongside peer-address gossip.
- Outbound dialing prefers SCION only when both peers advertise SCION support.
- If SCION preference fails for a peer, dialing continues with the standard transport strategy.
- Peers without SCION capability use optional QUIC and mandatory TLS; raw TCP and WebSocket are not peer transports.
- Successful SCION-preferred outbound connections increment `p2p_scion_outbound_total`.

There are no `network.scion_*` configuration keys. SCION selection is derived
only from the signed peer-capability exchange; retired configuration keys are
unknown-field errors.

### Example: `[network]` TOML and Feature Flags

Minimal `config.toml` snippet (values shown are defaults tuned for ~20k TPS):

```toml
[network]
# Internal bind address and advertised address
P2P_ADDRESS = "0.0.0.0:1337"
P2P_PUBLIC_ADDRESS = "peer1.example.com:1337"

# Bounded queue capacities
p2p_queue_cap_high = 8192     # consensus/control
p2p_queue_cap_low  = 32768    # gossip/sync
p2p_post_queue_cap = 2048     # per-peer post channel
p2p_subscriber_queue_cap = 8192  # inbound relay subscriber queue

# Other networking parameters (for reference)
block_gossip_size = 4        # fanout cap for block-sync gossip (peer samples and block-sync updates)
block_gossip_period_ms = 10000
block_gossip_max_period_ms = 30000
peer_gossip_period_ms = 1000
peer_gossip_max_period_ms = 30000
transaction_gossip_size = 500 # configurable batch limit; canonical wire ceiling is 512
transaction_gossip_period_ms = 1000
transaction_gossip_resend_ticks = 3
idle_timeout_ms = 60000
preauth_timeout_ms = 30000
preauth_max_connections_per_ip = 8
reply_writer_flush_timeout_ms = 30000
connect_startup_delay_ms = 0
# Trust decay/penalties for gossip senders (decays toward 0)
trust_decay_half_life_ms = 300000  # halve negative scores every 5 minutes
trust_penalty_bad_gossip = 5       # penalty applied per invalid trust gossip
trust_penalty_unknown_peer = 3     # penalty applied when gossip references peers outside topology
trust_min_score = -20              # drop trust gossip at or below this score
```

- Gossip, idle, pre-authentication, and exact reply-writer timeout intervals are clamped to >=100ms
  to prevent zero-duration spin loops.
- `preauth_timeout_ms` is one absolute deadline shared by admission, TLS/QUIC
  setup, required-stream acceptance, and the signed application handshake for
  an accepted transport. It starts when TCP accepts the socket or when QUIC
  completes address validation, before the connection waits for global
  pre-authentication capacity.
  Successful peers are governed only by `idle_timeout_ms` after authentication.
- Mandatory Argon2 work uses separate process-wide outbound mint and inbound
  verification limits. Each outbound handshake admits one primary search;
  additional searches use spare outbound permits and independent random streams.
  Helpers yield before or after an Argon2 evaluation when another primary is
  waiting. A winning credential or handshake cancellation stops the other searches,
  but each running evaluation retains its permit and admission owner until it
  exits. This preserves the configured memory bound across cancellation and
  runtime teardown; puzzle parameters and authentication deadlines are unchanged.
- Each authenticated connection admits a burst of two remote `Ping` requests
  and refills one request credit every `idle_timeout_ms / 2`. Excess requests
  receive no response and do not refresh liveness. An authenticated `Pong` must
  match the sole outstanding local probe and retires it without spending or
  replenishing remote Ping credit. Unknown, duplicate and substituted responses
  fail. Admitted requests, correlated responses and application data refresh
  liveness. Both endpoints can probe every half idle interval without consuming
  each other's response budget; fixed response cells bound amplification.
- `preauth_max_connections_per_ip` caps concurrent accepted-but-unauthenticated
  transports from one canonical source IP (default: 8). One shared reservation
  gate covers TCP and address-validated QUIC, and reserves the source before
  global capacity. IPv4-mapped IPv6 addresses canonicalise to native IPv4;
  native IPv6 addresses otherwise remain exact. The reservation is released
  when authentication completes or the pending connection is cancelled or
  terminated. Operators whose legitimate peers share a NAT may raise the cap,
  but it remains enabled by default. Rejections increment
  `p2p_preauth_source_cap_reject_total` without consuming a global slot.
- `transaction_gossip_size` may be lowered to reduce per-message admission work,
  but cannot exceed 512. The canonical decoder rejects transaction, route, or
  routing-plan sequences above that ceiling before allocating or decoding their
  elements.
- `reply_writer_flush_timeout_ms` is the base timeout for one actor-owned exact
  reply. Its immutable deadline starts on first actor dispatch, before writer
  admission. An observed timeout doubles only that semantic item's next
  attempt, with checked saturation; an ordinary writer close or reconnect
  preserves the attempt, and a complete writer flush resets it. The
  actor-minted flush receipt binds the admitted attempt, and consumers reject
  a receipt whose attempt differs from the retained target. Exponential
  scaling provides qualitative eventual expiry for each finite attempt, not a
  fixed operational wall-clock SLA; a recovered writer may still flush before
  the current deadline.
- Peer-address gossip is change-driven with exponential backoff up to `peer_gossip_max_period_ms`
  (and is throttled when the relay drops inbound frames); block-sync sampling similarly backs off
  up to `block_gossip_max_period_ms` when no progress is observed.
- Transaction gossip pauses when relay backpressure is active (recent subscriber-queue drops) and
  resumes after `transaction_gossip_period_ms * transaction_gossip_resend_ticks` to avoid
  flooding under load.
- `connect_startup_delay_ms` delays outbound dials immediately after startup to reduce
  connection-refused noise when peers come up in waves (localnet or orchestrated rollouts).
- Revision-4 `TimeoutVote` messages (the NEW_VIEW equivalent) are sent to the
  complete frozen committee. Any validator may aggregate the exact
  `q = 2f + 1` equal-vote quorum into a `TimeoutCertificate`.
- Trust scoring is deterministic: scores start at 0, penalties subtract `trust_penalty_bad_gossip`,
  and the debt halves every `trust_decay_half_life_ms` until it reaches 0. In permissioned mode,
  trust gossip that advertises peers outside the current topology applies `trust_penalty_unknown_peer`;
  public (NPoS) mode accepts those reports without penalty. Gossip from peers at or below
  `trust_min_score` is ignored until decay lifts them above the floor. Metrics:
  `p2p_trust_score{peer_id}`, `p2p_trust_penalties_total{reason}`, and
  `p2p_trust_decay_ticks_total{peer_id}`.
- Unknown-peer trust gossip enforcement (permissioned mode): off-topology trust reports trigger a
  warning and increment `p2p_trust_penalties_total{reason="unknown_peer"}`. Scores decay using
  `trust_decay_half_life_ms`; once a sender climbs above `trust_min_score` it is reinstated and
  trust gossip resumes. Public/NPoS overlays skip the penalty so dial sets remain open.
- Trusted peers configured locally remain in the P2P topology even if they are not in the
  world-state topology (e.g., observers). They still receive gossip and block sync but do not
  change the consensus roster.
- Peer-address gossip is accepted only from a current topology member or a
  locally configured peer; runtime trust promotion does not create metadata
  authority. Address votes are narrower: only active validators contribute,
  the complete roster must have exact `3f + 1` geometry (including the local
  node exactly when it is an active validator),
  and a uniquely top-ranked mapping backed by at least `f + 1` distinct
  active-validator reports is required before a non-configured mapping reaches
  the dialer. Conflicting top-count mappings fail closed.
  Honest nodes advertise only their operator-provided startup mappings, never a
  connected peer's self-asserted handshake address, so one Byzantine peer
  cannot manufacture independent echo endorsements. Startup mappings retain
  precedence over all gossip. Before the first committed block, the configured
  validator roster is authoritative. After replay and after every applied block,
  a supervised daemon task publishes the exact committed roster to the gossiper;
  a lagged event receiver reconciles directly from the latest committed state,
  so removed validators lose address-vote authority without a restart.
  A new or rotated non-startup mapping cannot bootstrap from its target's
  handshake claim; at least `f + 1` active validators must be configured with
  the identical mapping and observe that peer online.
- Transport capability metadata is self-authoritative only: a gossiped
  capability entry is accepted only when its subject is the authenticated
  sender. Third-party capability hints cannot force preferred-transport dial
  attempts for another peer; directly observed signed handshake capabilities
  remain available for reconnect scheduling.
- Trust gossip capability: peers advertise `trust_gossip` during the handshake. When a peer sets
  `trust_gossip=false`, it will neither send nor accept trust gossip frames, but regular peer-address
  gossip continues unaffected. The default is `true`, and public (NPoS) deployments should leave it on
  so trust scores propagate network-wide.

#### Trust gossip capability and gating

The trust gossip plane is intentionally separable from peer-address gossip so permissioned networks
can opt out without starving connectivity updates, while public (NPoS) overlays keep trust exchange
wide open. The handshake advertises two booleans that must both be true for trust frames to flow:

- `network.trust_gossip` — local capability knob; defaults to `true`.
- `network.soranet_handshake.trust_gossip` — handshake advertisement; defaults to `true`.

Both flags are AND-ed during the handshake; the resulting capability is stored on the peer handle and
checked on every send/receive. Behaviour matrix:

- **Send:** `NetworkMessage::PeerTrustGossip` is classified into the `TrustGossip` topic. If either
  side disabled the capability, the frame is skipped before queueing, tagged with
  `p2p_trust_gossip_skipped_total{direction="send",reason="local_capability_off|peer_capability_off"}`,
  and a debug log explains why. Peer-address gossip remains on `PeerGossip` and is unaffected by the
  trust toggle.
- **Receive:** trust frames are dropped early when the local node disabled the capability or when the
  connected peer did not negotiate trust support. Drops increment the same skip counter with
  `direction="recv"` labels. Topic caps/backpressure stay unchanged because trust and peer gossip
  still share the existing Low queue and per-topic caps.
- **Relay:** hubs only forward trust frames for peers that negotiated trust support; `relay_ttl` and
  throttles are the same as peer gossip.

Operator guidance:

- Public/NPoS deployments should leave both knobs enabled so trust scores propagate across the overlay
  and observers can scrape `p2p_trust_score`/`p2p_trust_penalties_total`. The skip counter should stay
  at zero in this mode.
- Permissioned/air-gapped overlays can set `network.trust_gossip=false` to suppress trust exchange
  without affecting peer-address gossip or relay caps. Expect `p2p_trust_gossip_skipped_total` to tick
  up when trust frames are attempted; this is expected and indicates the capability gate is working.
- Topic classification and Low-queue throttles are unchanged by the capability: peer-address gossip
  still uses the `PeerGossip` topic and the same caps/backoffs, so disabling trust gossip does not
  starve peer updates.

Network-bound signatures are mandatory. Every inbound and outbound peer
handshake signs one canonical V1 claim containing the BLS-normal node public
key, advertised address, relay/consensus/confidential/crypto/trust
capabilities, configured `NetworkId`, full 256-bit session binding, and the
mandatory TLS/QUIC certificate fingerprint. The network start API requires a `NetworkId`;
changing any advertised claim, replaying it into another session or transport,
or connecting from another network fails signature verification before the peer
can enter the authenticated set or exchange network traffic. The compact
64-bit disambiguator is a diagnostic prefix, not a second selection policy. There is no
feature flag or unbound mode. Only the TLS-over-TCP and QUIC listeners can enter
the `ConnectedFrom` handshake state; each adds its server-certificate fingerprint
to the common signed claim. There is no raw TCP listener or external stream
admission API.

### ACL: Allow/Deny (Keys and CIDRs)

- Keys:
  - `allowlist_only` (bool, default false): when true, only peers whose public keys are listed in `allow_keys` are permitted (outbound dialing and inbound post‑handshake).
  - `allow_keys`: array of peer public keys.
  - `deny_keys`: array of peer public keys to always reject.
- Networks:
  - `allow_cidrs`: list of IPv4/IPv6 CIDRs that are permitted for inbound IPs (e.g., `192.168.1.0/24`, `2001:db8::/32`). A non-empty list gates inbound IPs independently of the peer-key `allowlist_only` switch.
  - `deny_cidrs`: list of IPv4/IPv6 CIDRs rejected for inbound IPs (checked before throttles).
- Invalid CIDR entries fail network startup. A malformed hot-reload update is
  rejected as a unit and leaves the installed ACL unchanged. IPv4-mapped IPv6
  CIDRs with prefixes from `/96` through `/128` are canonicalized to the
  equivalent IPv4 network; broader mapped prefixes are rejected.
- Precedence: `deny_*` takes precedence. CIDR checks apply before per‑IP throttling; key checks apply after handshake (and are also applied to topology for outbound).

### Accept throttle (prefix + per-IP)

- Knobs (`[network]`):
  - `accept_rate_per_prefix_per_sec` / `accept_burst_per_prefix` *(optional)*: prefix-level token bucket (default disabled). Applied before per-IP buckets.
  - `accept_prefix_v4_bits` / `accept_prefix_v6_bits` *(u8; defaults: 24 / 64)*: prefix width used for the prefix bucket key.
  - `accept_rate_per_ip_per_sec` / `accept_burst_per_ip` *(optional)*: per-IP token bucket keyed by full address (/32, /128). Disabled when unset.
  - `max_accept_buckets` *(usize, default: 4096)*: combined cap for active prefix + per-IP buckets (LRU eviction when exceeded).
  - `accept_bucket_idle_ms` *(default: 600000 / 10 minutes)*: idle timeout before buckets are evicted.
- Behaviour:
  - CIDR allowlists still gate access first; allowlisted IPs bypass both prefix and per-IP buckets.
  - Prefix bucket (when enabled) runs before per-IP buckets; a throttled prefix stops evaluation early.
  - Buckets prune idle entries on every evaluation and evict the least-recently-used entry when above `max_accept_buckets`.
  - The cap must retain at least one bucket for each enabled throttle dimension
    (two when both prefix and per-IP throttles are enabled); smaller geometry is
    rejected before listener binding.
- Telemetry:
  - `p2p_accept_buckets_current` gauges active bucket count; `p2p_accept_bucket_evictions_total` tracks idle/LRU evictions.
  - `p2p_accept_prefix_cache_total{result}` surfaces prefix cache hit/miss ratios.
  - `p2p_accept_throttle_decisions_total{scope,decision}` splits allow/throttle outcomes across prefix vs per-IP buckets; `p2p_accept_throttled_total` remains the aggregate throttle counter.

### Optional QUIC Transport

- Build-time: enable `iroha_p2p/quic` to include QUIC support.
- Current shipping status: `[network].quic_enabled = true` is rejected before
  any UDP socket is created. The lockfile resolves patched quinn-proto
  0.11.18; dependency memory and panic fixes do not replace complete
  authenticated-transport, resource and interoperability qualification.
  Mandatory authenticated TLS-over-TCP remains the active P2P transport.
- The QUIC implementation remains dormant shipping material; focused
  local tests exercise bounded DATAGRAM delivery with the patched dependency.
  Complete the abuse and interoperability suites before allowing
  `[network].quic_enabled = true` again.
- Dormant QUIC authentication: nodes use self-signed transport certificates. Rustls verifies
  the TLS `CertificateVerify` proof, then the Iroha identity handshake signs the
  certificate fingerprint together with the active SoraNet session and V5
  transport-delegation binding. A certificate issued by an untrusted root is
  therefore acceptable, but replaying another node's certificate without its
  private key is not.
- Best-effort datagrams are independently fail-closed. The default is
  `[network].quic_datagrams_enabled = false`, and startup rejects an explicit
  `true` before binding sockets. QUIC endpoints advertise no DATAGRAM receive
  support and retain no DATAGRAM send queue; `TxGossip`, `PeerGossip`,
  `TrustGossip`, and `Health` therefore use their reliable-stream fallback.
  - The payload and per-connection buffer knobs remain in the schema for
    requalification but cannot currently enable the extension.
  - Locked `quinn-proto` 0.11.18 charges its private receive and send
    buffers by payload plus fixed `Datagram` overhead, including empty entries.
    Private requalification requires each buffer to hold one maximum payload
    plus that overhead. Shipping DATAGRAM enablement still requires complete
    transport qualification.
  - The dormant P2P ingress still has eager pre-authentication draining,
    exact-size payload compaction, a serialized authentication boundary, and a
    256-entry handoff charged to the process-wide low-priority byte budget.
    These defenses and focused tests remain for transport requalification;
    the dependency-owned pre-poll queue has its own fixed-overhead accounting.

### Mandatory TLS-over-TCP

- TLS-over-TCP is compiled unconditionally; there is no feature or supported build profile that removes it.
- `[network].address` is the TLS 1.3 listener and outbound TCP dials always upgrade to TLS 1.3 with the exact `iroha-p2p/1` ALPN. There is no plaintext listener, retry, or runtime downgrade knob.
- Identity remains authenticated by the canonical V5 application handshake, which binds the certificate fingerprint and configured `NetworkId`; rustls separately verifies possession of the self-signed certificate key.
- Requesting QUIC currently aborts startup because of the locked dependency;
  requesting it without compiled support also remains an error. There is no
  silent downgrade from an explicitly requested transport.

### No WebSocket peer transport

The first release exposes no Torii WebSocket peer route, build feature, dialer,
or external stream adapter. Shipping peer traffic enters through the
process-owned TLS 1.3 listener; dormant QUIC uses the same exact certificate
fingerprint in V5 channel-binding admission.

### First-release SoraNet P2P authentication (V5)

V5 is the only P2P preface accepted in the first release. V4, V3, and every
other version are rejected at the five-byte magic/version header; there is no
version negotiation, compatibility parser, downgrade retry, or legacy
authentication path.

The protocol keeps three mandatory, non-interchangeable identity roles:

- the application/consensus `PeerId` is the BLS-normal node identity;
- the configured dedicated Ed25519 transport identity supplies cheap online proofs;
- a process-lifetime ML-DSA-65 identity supplies the mandatory post-quantum
  online proof.

Network startup consumes the configured Ed25519 identity unchanged, generates
the process-lifetime ML-DSA-65 identity, retains their private keys behind
shared ownership, and signs one canonical Norito
`SoranetTransportCertificateV5` with the BLS-normal node key. The certificate
contains exactly `p2p_preface_version = 5`, `NetworkId`, node `PeerId`, the
32-byte Ed25519 public key, and the 1,952-byte ML-DSA-65 public key. Its BLS
signature uses `iroha:p2p:soranet-transport-certificate:v5|`. The signed
certificate and its
`iroha:p2p:soranet-transport-certificate-digest:v5|` hash are cached for the
life of the network process; an unauthenticated inbound preface never triggers
a new BLS certificate signature. The later encrypted application hello still
uses the node identity as described below.

Every TLS and QUIC stream runs this exact V5 exchange before admission work or
ML-KEM processing:

1. The initiator seeds a CSPRNG from operating-system entropy and generates a
   fresh 32-byte challenge. All-zero and all-identical-byte output fails closed.
   It sends `"I2P2" || 0x05 || challenge || binding_tag || [binding]`: exactly
   70 bytes because tag one must carry the 32-byte TLS/QUIC certificate
   fingerprint. A missing binding is rejected unconditionally.
2. The responder verifies the magic, exact V5 byte, and rejects all-zero or
   all-identical-byte challenges before signing anything. It validates the
   claimed transport binding against the accepted transport and replies with
   `"I2P2" || 0x05` (5 bytes). TLS and QUIC require the exact certificate
   fingerprint; no unbound transport reaches this exchange.
3. The responder constructs a proof statement containing exactly the cached
   certificate digest, fresh challenge, and validated transport
   binding. The Ed25519 transport key signs its canonical encoding under
   `iroha:p2p:soranet-transport-proof:v5|`. The responder combines this fresh
   proof with the cached BLS certificate and sends the canonical Norito frame
   behind a big-endian `u16` length. Empty, non-canonical, or larger-than-4,525
   byte frames are rejected; 4,525 bytes is the exact maximum V5 frame with a
   present binding.
4. The initiator performs bounded canonical decoding and verifies the exact
   V5 certificate version, `NetworkId`, expected `PeerId`, challenge, transport
   binding, key algorithms and lengths, BLS certificate signature, certificate
   digest, and Ed25519 proof. Any failure terminates the connection before an
   admission credential is minted or released and before client-hello or
   ML-KEM work.
5. Both sides hash the complete canonical certificate-plus-proof frame under
   `iroha:p2p:soranet-transport-delegation-binding:v5|`. Admission commits to
   the exact serialized client hello and this full-frame binding under
   `iroha:p2p:soranet-admission:v5|`; a ticket cannot be replayed against a
   different node certificate, challenge, transport, or client hello.

The relay response then carries a mandatory dual-authentication tail: scheme
byte `0x01`, a 64-byte Ed25519 signature, and a 3,309-byte ML-DSA-65 signature.
Both signatures cover one length-delimited SHA3-256 digest containing, in
order, the `soranet.handshake.relay-auth.v1` domain, authentication version,
scheme, selected NK2/NK3 suite, exact client hello, exact signed relay body,
transcript hash, Ed25519 public key, ML-DSA-65 public key, cached certificate
digest, transport ALPN (`iroha-p2p/1`), and TLS server name (`iroha-quic`).
ML-DSA-65 uses the explicit `soranet.handshake.relay-auth.v1` signing context.
The client verifies Ed25519 and then ML-DSA-65 before capability acceptance or ML-KEM decapsulation;
omitting either signature, changing its size, or substituting either certified
key fails the handshake.

The final mutual BLS application hello signs a canonical
`iroha:p2p:identity-binding:v1|` claim over the full session-key hash,
`NetworkId`, complete V5 frame binding, mandatory TLS/QUIC fingerprint, identity
public key, advertised address, and all relay, consensus,
confidential, crypto, and trust capabilities. Thus a captured certificate or
proof cannot authenticate a new challenge, handshake transcript, session, or
transport. The mandatory SoraNet ML-KEM-derived session key remains the sole
P2P content-encryption key.

After AEAD authentication, an encrypted stream frame is one atomic batch. Any
invalid inner header, truncated object, decode failure, topic-cap violation, or
message-count overflow discards the whole batch and closes the peer connection;
decoded prefixes are never delivered from a malformed batch.

After V5 authentication and SoraNet key establishment, hello frames carry
identity, consensus caps, and confidential caps (enabled/assume_valid/backend
plus the `ConfidentialFeatureDigest` containing `vk_set_hash`, `poseidon_params_id`,
`pedersen_params_id`, and `conf_rules_version`). The encrypted payload is
length-prefixed with a `u16`, so metadata larger than `65_535` bytes is rejected
with a deterministic `HandshakeMessageTooLarge` error rather than panicking.

#### Confidential Capability Outcomes

Validator nodes require `confidential.enabled=true`, `assume_valid=false`, the expected verifier backend, and a digest that matches their local registries. Outcomes mirror the matrix in [`confidential_assets.md`](confidential_assets.md#node-capability-negotiation):

| Remote advertisement | Result (validator role) | Operator action |
|----------------------|-------------------------|-----------------|
| `enabled=true`, `assume_valid=false`, backend matches, digest matches | Accepted | Peer enters rotation; no action needed. |
| `enabled=true`, `assume_valid=false`, backend matches, digest stale/missing | Rejected (`HandshakeConfidentialMismatch`) | Apply pending registry/parameter activations or wait for the scheduled `activation_height`. |
| `enabled=true`, `assume_valid=true` | Rejected (`HandshakeConfidentialMismatch`) | Configure the node as an observer or disable `assume_valid`. |
| `enabled=false`, missing fields, or backend differs | Rejected (`HandshakeConfidentialMismatch`) | Upgrade the peer and align backend + digest before reconnecting. |

Observers that intentionally skip verification (`assume_valid=true`) must avoid consensus connections; they can still ingest blocks via Torii/Web APIs but validators drop their P2P handshakes until capabilities match.

### Per-Peer Post Overflow Policy

- Knob: `[network].disconnect_on_post_overflow` (bool, default true)
  - When true (default), if a per-topic bounded post channel overflows for a peer, the connection is dropped.
  - When false, overflowed messages are dropped but the connection stays up. The counter `p2p_post_overflow_total` increments in both cases.

Per-topic metrics (when telemetry enabled):

- `p2p_post_overflow_total{priority="High|Low",topic="ConsensusSafety|Consensus|Control|BlockSync|TxGossip|PeerGossip|Health|Other"}`
- `p2p_subscriber_queue_full_by_topic_total{topic="ConsensusSafety|Consensus|ConsensusChunk|Control|BlockSync|TxGossip|PeerGossip|Health|Other"}`
- `p2p_subscriber_unrouted_by_topic_total{topic="Consensus|Control|BlockSync|TxGossip|PeerGossip|Health|Other"}`

Behavior matrix (bounded queues enabled):

| Setting                          | Effect on overflow                  | Metric updates                         |
|----------------------------------|-------------------------------------|----------------------------------------|
| disconnect_on_post_overflow=true | Disconnect peer; drop pending posts | `p2p_post_overflow_total{topic=..}↑`   |
| disconnect_on_post_overflow=false| Keep connection; drop overflowed    | `p2p_post_overflow_total{topic=..}↑`   |

Because queues are always bounded, overflow counters rise whenever a channel drops messages. Use `disconnect_on_post_overflow` to choose whether to drop the connection or just the overflowing messages.

Actor-owned exact replies are stricter than this best-effort policy. A full
writer queue does not drop the exact occurrence or perform the knob-selected
overflow action: the network actor retains its bounded owner until the writer
flushes or the occurrence reaches `reply_writer_flush_timeout_ms` after its
adaptive scaling. At timeout the actor marks only the bound reply tenure
unwritable, retires only the same connection if it is still current, and
reports `TimedOut`; it never reports a successful flush. A successful full
flush already published by the exact writer is polled first and therefore wins
simultaneous deadline, route-retirement, and connection-replacement
observation. An empty or closed writer completion cannot retain a stale route
or terminate its replacement. Ordinary topology-routed traffic does not
acquire this reply deadline.

### Frame Size Caps

- Global encrypted cap: `[network].max_frame_bytes` (default 17 MiB plus the 28-byte
  ChaCha20-Poly1305 nonce/tag expansion) rejects oversized frames early. The largest topic
  plaintext ceiling remains exactly 17 MiB.
  The limit applies uniformly to authenticated TLS and QUIC accepts and outbound
  dials, with `p2p_frame_cap_violations_total`
  counters incremented whenever an inbound frame is dropped by the topic caps.
  This cap is enforced on encrypted frames, so AEAD overhead (nonce + tag) counts
  toward the limit (currently 28 bytes for ChaCha20-Poly1305). Because the wire
  stream format stores the encrypted-frame body length in a `u32`; its wire ceiling is
  4,294,967,295 bytes. The deterministic runtime/configuration ceiling is
  2,147,483,643 encrypted-body bytes: with the four-byte prefix, the contiguous
  stream buffer remains within `i32::MAX` on both 32-bit and 64-bit hosts.
  Startup and `iroha3d --check-config` reject larger values before binding any
  listener. Before materializing an outbound frame, the sender performs an
  exact counting Norito pass and rejects an oversized result; it then checks
  generic AEAD expansion, the `u32` conversion, and prefix-inclusive queue
  accounting. Incoming stream readers reject lengths above the runtime cap and
  grow their buffer in bounded increments rather than reserving the entire
  unauthenticated declared length. Each authenticated encrypted frame may carry
  at most 32 concatenated inner Norito objects; the receiver rejects object 33
  before measuring or decoding it while preserving the first 32 admitted objects.
- Topic caps (post-decode enforcement, tightened defaults) apply to complete decrypted and authenticated P2P frame bytes:
  - `[network].max_frame_bytes_consensus` (default 17 MiB; caps revision-4
    recovery requests such as `CertifiedBodyRequest` and
    `CommitCertificateRequest`)
  - `[network].max_frame_bytes_control` (default 2 MiB; caps compact revision-4
    `ConsensusSafety` messages such as `Proposal`, `Vote`,
    `QuorumCertificate`, `TimeoutVote`, and `TimeoutCertificate`)
  - `[network].max_frame_bytes_block_sync` (default = 17 MiB plaintext ceiling;
    caps revision-4 `PayloadChunk` and `CertifiedBodyResponse` frames plus
    BlockSync responses; `PayloadManifest` is carried only inside `Proposal`)
  - `[network].max_frame_bytes_tx_gossip` (default 256 KiB)
  - `[network].max_frame_bytes_peer_gossip` (default 64 KiB)
  - `[network].max_frame_bytes_health` (default 32 KiB)
  - `[network].max_frame_bytes_other` (default 128 KiB)

Recommended:
- Keep the global cap at or above the largest expected BlockSync frame.
- Tighten gossip/health caps to minimize attack surface.

### TCP Defaults

- `[network].tcp_nodelay = true` by default to minimize consensus latency.
- `[network].tcp_keepalive_ms = 60000` by default to keep long-lived connections healthy.

### QUIC/TLS Tuning

- TLS: TLS 1.3 and the exact raw-P2P ALPN are unconditional.
- QUIC: configure idle timeout via `[network].quic_max_idle_timeout_ms`.
- QUIC DATAGRAM (best-effort): unavailable in the shipping profile until
  the locked quinn-proto 0.11.18 transport is requalified. Leave
  `[network].quic_datagrams_enabled = false`; an explicit `true` aborts startup.
