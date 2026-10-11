# Torii collection queries

Every Torii collection (domains, accounts, asset definitions, NFTs, RWA lots,
account assets, asset holders, transactions, account transactions, repo
agreements, effective account permissions, subscription plans, subscriptions,
and UAID manifests) is read with one query language and returns one page envelope. The same language is
used by the SDKs, the `iroha` CLI and the event-stream `filter` parameter.
The Rust reference implementation is
[`iroha_torii_shared::list_query`](../../crates/iroha_torii_shared/src/list_query/mod.rs);
shared golden vectors live in [`fixtures/torii/list_query`](../../fixtures/torii/list_query).

Design rules:

- **One grammar.** Filters, sort keys, projections, page size and cursors are
  spelled the same way on `GET` and `POST`, in every SDK and in the CLI.
- **Nothing is silently ignored.** Unknown parameters, unknown JSON members,
  fields a collection does not expose, malformed values and duplicate controls
  are rejected with `400` and an error naming the offending control.
- **Cheap by default.** Pages carry an opaque `next_cursor`; there is no offset.
  The exact match count is computed only when asked for.
- **Stable paging.** Cursors are keyset positions (or, for transaction
  history, block coordinates): rows inserted or removed between pages never
  cause a later page to repeat or skip unrelated rows.

## Endpoints

| Collection | List | Query |
| --- | --- | --- |
| domains | `GET /v1/domains` | `POST /v1/domains/query` |
| accounts | `GET /v1/accounts` | `POST /v1/accounts/query` |
| asset definitions | `GET /v1/assets/definitions` | `POST /v1/assets/definitions/query` |
| NFTs | `GET /v1/nfts` | `POST /v1/nfts/query` |
| RWA lots | `GET /v1/rwas` | `POST /v1/rwas/query` |
| account assets | `GET /v1/accounts/{account_id}/assets` | `POST /v1/accounts/{account_id}/assets/query` |
| asset holders | `GET /v1/assets/{definition_id}/holders` | `POST /v1/assets/{definition_id}/holders/query` |
| transactions | — | `POST /v1/transactions/query` |
| account transactions | `GET /v1/accounts/{account_id}/transactions` | `POST /v1/accounts/{account_id}/transactions/query` |
| repo agreements | `GET /v1/repo/agreements` | `POST /v1/repo/agreements/query` |
| account permissions | `GET /v1/accounts/{account_id}/permissions` | `POST /v1/accounts/{account_id}/permissions/query` |
| subscription plans | `GET /v1/subscriptions/plans` | `POST /v1/subscriptions/plans/query` |
| subscriptions | `GET /v1/subscriptions` | `POST /v1/subscriptions/query` |
| UAID manifests | `GET /v1/space-directory/uaids/{uaid}/manifests` | `POST /v1/space-directory/uaids/{uaid}/manifests/query` |
| account movements | `GET /v1/accounts/{account_id}/history` | `POST /v1/accounts/{account_id}/history/query` |
| contract activity | `GET /v1/contracts/activity` | `POST /v1/contracts/activity/query` |
| contract events | `GET /v1/contracts/events` | `POST /v1/contracts/events/query` |

`GET` and `POST …/query` are equivalent; `POST` additionally supports
`aggregate` and avoids URL length limits. Responses are JSON. Transactions, account movements, contract activity and events
are [history collections](#history-collections) with a few
restrictions.

## Request controls

| Control | `GET` parameter | `POST` member | Notes |
| --- | --- | --- | --- |
| filter | `filter=<text>` | `"filter": "<text>"` or the JSON form | see [Filters](#filters) |
| sort | `sort=-quantity,id` | `"sort": ["-quantity", "id"]` | `-` = descending; at most 8 keys |
| projection | `select=id,quantity` | `"select": ["id", "quantity"]` | at most 64 fields |
| aggregation | — | `"aggregate": {...}` | see [Aggregates](#aggregates) |
| page size | `limit=50` | `"limit": 50` | 1..`torii.app_api_max_list_limit` (default 500); default `torii.app_api_default_list_limit` (100) |
| continuation | `cursor=<token>` | `"cursor": "<token>"` | the previous page's `next_cursor` |
| total | `include_total=true` | `"include_total": true` | adds `total`; costs a full scan |

Each control appears at most once. A `GET` with any other parameter, or a
body with any other member, is rejected with `invalid_query`, listing the
accepted names. `select` and `aggregate` are mutually exclusive.

**Order and scan cost.** Domains, accounts, asset definitions, NFTs, RWA lots
repo agreements, subscription plans and subscriptions are stored by `id`. Their default order, and `sort=id` or
`sort=-id`, is canonical identifier order: the order Torii stores the
identifiers in, which is not always the alphabetical order of their text.
These reads seek to the cursor instead of sorting, and an exact `id = …` or
`id in […]` filter reads only those identifiers, so a page costs the rows it
examines, not the collection size. Each such page examines at most 65,536
storage entries, including entries excluded by visibility checks. A selective
filter can return a short (even empty) page with a `next_cursor`; keep following
it until it is `null`. A cursor contains only a visible identifier. If a scan
budget is exhausted without a visible continuation, the request fails with
`query_scan_limit_exceeded`. Every other order sorts the whole match set.
Aggregates and `include_total` scan the complete candidate set, including
entries before the cursor, with a limit of 1,048,576 storage entries per request
(`query_scan_limit_exceeded` beyond that).
Rows with equal sort values are ordered by their identity.

**Memory admission.** `torii.query_fanout_max_retained_bytes` bounds aggregate
query memory (default 512,000,000 bytes), while
`torii.query_fanout_max_working_set_bytes` bounds one complete query working set
(default 48,000,000 bytes). One quarter of the aggregate belongs to independent
signed-query ingress. With the default content limit, the remaining
384,000,000 bytes admit eight complete query owners. Increasing aggregate
capacity raises concurrency without increasing one query's decode, source or
response ceilings. Smaller aggregate pools reduce the admitted owner and all
its phase limits together.

The same owner follows collection request decoding, local execution and the
returned HTTP body. Compiled plans, decoded cursors and the next cursor share
the scratch phase with runtime ordering and projection; cursor JSON, its frame
and base64 output are charged for their actual overlap. Bodyless reads wait
within the finite query admission queue before query decoding. Reads with a
body fail admission before body polling when every complete owner is occupied.
These memory-capacity failures are independent of request-rate limits.

Query strings use ordinary RFC 3986 percent-encoding: any valid escape
(upper- or lower-case hexadecimal) and literal sub-delimiters such as `:` `,`
`!` `(` `)` are accepted, and `+` and `%20` both decode to a space. Decoded
values may contain tabs and line breaks, so multi-line filters work; other
control characters are rejected with `invalid_query`.

## Filters

The text form reads like a SQL `WHERE` clause:

```text
owned_by = "sorau…" and quantity >= 10.5
status in ["active", "paused"] or not exists(metadata.archived)
metadata.`display-name` is not null
```

| Construct | Meaning |
| --- | --- |
| `a = v`, `a != v`, `a < v`, `a <= v`, `a > v`, `a >= v` | comparisons (`==` and `<>` are accepted spellings) |
| `a in [v, …]`, `a not in [v, …]` | membership (`(…)` lists are also accepted) |
| `exists(a)` | the field is present |
| `a is null`, `a is not null` | absent-or-null / present-and-not-null |
| `x and y`, `x or y`, `not x`, `( … )` | boolean logic; `not` > `and` > `or` |

- Keywords are case-insensitive.
- Field paths are dot-separated identifiers. Quote a segment that is not an
  identifier, or that is a keyword, with backticks: ``metadata.`ui-order` ``.
  Paths cannot contain backticks themselves.
- Literals are JSON-style double-quoted strings, single-quoted strings,
  numbers, `true`, `false` and `null`; as in JSON, U+0000–U+001F must be
  escaped inside strings. Object and array literals (allowed only against
  `metadata.<key>` values) exist only in the JSON form.
- A scalar literal matches a list value (a list field such as `asset_ids`,
  or a metadata array) when any element matches; object and array literals
  compare whole values. Lists cannot be range-compared. Fractional JSON
  numbers stored in metadata compare by their decimal value.
- Account fields accept account literals (canonicalised before matching) or
  `null`.
- Integers that fit `u64`/`i64` are numbers. Decimals and wider integers are
  exact decimal strings (`10.5` and `"10.5"` are the same literal).
- `a != v` and `a not in […]` also match rows where `a` is absent.
- Limits: 32 KiB of text, depth 10, 1,024 nodes, 1,024 values per list,
  4,096 list values in total. List values must be unique and of one type.

The JSON form is the canonical machine spelling, convenient for builders:

```json
{"op": "and", "args": [
  {"op": "eq",  "args": ["owned_by", "sorau…"]},
  {"op": "gte", "args": ["quantity", "10.5"]},
  {"op": "not", "args": [{"op": "is_null", "args": ["metadata.tier"]}]}
]}
```

Operators: `and`, `or`, `not`, `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`,
`nin`, `exists`, `is_null`. A node has exactly the members `op` and `args`.
A one-operand `and` or `or` is its operand.
As everywhere in Torii JSON, member order is not significant. JSON-form
literals follow the text rules: integers are JSON numbers, and decimals are
exact strings such as `"10.5"`; fractional JSON numbers are rejected because
they are not exact.

**Canonical text rendering** (what SDK builders emit, and what Torii's
`Display` produces): operators `=`, `!=`, `<`, `<=`, `>`, `>=`, `in [..]`,
`not in [..]`, `exists(..)`, `is null`, `is not null`; keywords in lower case;
strings always double-quoted with JSON escapes; lists as `[a, b]`; every
nested `or` (inside `and`, `not` or another `or`) and an `and` inside `and` or
`not` are parenthesized; `not` of `is null` renders as `is not null`. Parsing
the rendering yields the same tree for every filter without object or array
literals; filters with them are sent in the JSON form.

Field paths are spelled the same way wherever text is parsed: in filter text
and in sort keys, both in the `GET` parameter and in the JSON `sort` array
(``"-metadata.`ui-order`"``), so a non-identifier segment is backtick-quoted.
Where a path is a JSON value of its own — filter JSON arguments, `select`
entries, `group_by` and metric fields — it is the raw dotted path
(`"metadata.ui-order"`).

## Response

```json
{"items": [ {...}, ... ], "next_cursor": "q1…", "total": 1234}
```

- `items` are in the requested order. Without `select`, items are the
  collection's full rows; with `select`, each item has exactly the selected
  fields at the same JSON paths as in a full row (`select=id,alias_binding.status`
  yields `{"id": …, "alias_binding": {"status": …}}`), with `null` for fields
  a row lacks. With `aggregate`, items are aggregate rows.
- `next_cursor` is `null` on the last page. Pass it unchanged as `cursor`
  to continue; it is bound to the collection, its path (the account or asset
  definition), the filter, sort and aggregate, and reusing it with different
  ones returns `invalid_cursor`. `limit`, `select` and `include_total` may
  change between pages. A cursor holds the last row's sort values (at most
  4,096 bytes); a page whose last row has longer sort values fails with
  `invalid_sort` instead of returning a cursor the next request would refuse.
- `total` is present only when `include_total` is true; it is the exact count
  for the complete query, including matches before the cursor.

A read executes once, on one dataspace route: every route of the global root
reads the same world state under the caller's visibility (dataspaces are
routing labels over one global block), so one execution answers the whole
read and totals and aggregates are exact.

To read everything, repeat the request with `cursor = next_cursor` until it is
`null`. Every SDK exposes this as an iterator.

## Errors

Request problems return `400` with the standard error envelope:

```json
{"code": "invalid_filter",
 "message": "invalid `filter`: use the keyword `and` instead of `&` or `&&` (column 17)",
 "details": {"field": "filter", "hint": "…"}}
```

| Code | Raised for |
| --- | --- |
| `invalid_query` | unknown parameters or members, non-object bodies |
| `invalid_filter` | syntax errors (with column), unknown fields, type mismatches, limits |
| `invalid_sort` | malformed, duplicate or unsortable keys |
| `invalid_select` | empty, duplicate or unknown fields |
| `invalid_aggregate` | malformed specs, non-numeric metrics, invalid `having` |
| `invalid_limit` | `limit` outside the accepted range |
| `invalid_cursor` | malformed cursors or cursors from a different query |
| `invalid_include_total` | non-boolean values |
| `query_scan_limit_exceeded` | reads that exceed the row, group, distinct-value or byte budget, and history pages that exhaust their budget without a caller-visible continuation |

`details.field` names the control; when a data field is at fault,
`details.actual` names it and `details.expected` lists the accepted fields as a
comma-separated string; `details.hint` suggests a fix (for example the closest
field name). Text syntax errors carry their position in the message
(`(column 17)`, or `(line 2, column 7)` for multi-line filters).

## Collection rows

Items are JSON objects. Every field below can be filtered on; fields marked
*sort* can be sorted on; `metadata.<key>` addresses one metadata entry (any
JSON value). Account ids are canonical I105 literals, asset definition ids are
Base58 literals, and quantities are exact decimal strings. Rows may gain
fields; clients must ignore fields they do not know. The fields that identify
a row (`id`; `account_id`, `asset`, `scope` and `quantity` for balances;
`entrypoint_hash`, `block_height` and `block_index` for transactions) are
always present; clients should treat every other field as possibly `null` or
absent.

| Collection | Fields (type) | Default order |
| --- | --- | --- |
| domains | `id` (string, *sort*), `owned_by` (string, *sort*), `logo` (string or null), `metadata.*` | `id` |
| accounts | `id` (string, *sort*), `label` (string or null, *sort*), `uaid` (string or null, *sort*), `metadata.*` | `id` |
| asset definitions | `id`, `name`, `alias`, `owned_by`, `owning_domain` (strings, *sort*), `mintable` (string), `alias_binding.alias`, `alias_binding.status` (strings), `alias_binding.lease_expiry_ms`, `alias_binding.grace_until_ms`, `alias_binding.bound_at_ms` (numbers, *sort*), `metadata.*` | `id` |
| NFTs | `id`, `owned_by` (strings, *sort*), `metadata.*` (the NFT content) | `id` |
| RWA lots | `id`, `owned_by`, `primary_reference`, `status` (strings, *sort*), `quantity` (decimal, *sort*), `is_frozen` (bool), `metadata.*` | `id` |
| account assets | `asset`, `asset_name`, `asset_alias`, `scope`, `account_id` (strings, *sort*), `quantity` (decimal, *sort*) | `asset`, `scope` |
| asset holders | `account_id`, `asset`, `asset_alias`, `scope` (strings, *sort*), `quantity` (decimal, *sort*) | `account_id`, `scope` |
| transactions, account transactions | `entrypoint_hash`, `block_hash`, `authority` (string or null), `entrypoint_kind` (strings), `block_height`, `block_index`, `timestamp_ms` (number or null) (numbers), `result_ok` (bool), `asset_ids`, `asset_definition_ids` (lists of strings), `metadata.*` | newest first |
| repo agreements | `id`, `initiator`, `counterparty`, `custodian`, `status`, `cash_source`, `cash_leg.asset_definition_id`, `collateral_leg.asset_definition_id`, `collateral_custody_asset` (strings, *sort*), `cash_leg.quantity`, `collateral_leg.quantity` (decimals, *sort*), `rate_bps`, `maturity_timestamp_ms`, `initiated_timestamp_ms`, `last_margin_check_timestamp_ms`, `settlement_timestamp_ms`, `governance.haircut_bps`, `governance.margin_frequency_secs` (numbers, *sort*) | `id` |
| account permissions | `name` (string, *sort*), `payload` (JSON); effective grants include direct and role permissions, deduplicated by name and payload | `name`, `payload` |
| subscription plans | `id`, `provider` (strings, *sort*), `billing`, `pricing` (JSON) | `id` |
| subscriptions | `id`, `owned_by`, `plan_id`, `provider`, `subscriber`, `status`, `billing_trigger_id` (strings, *sort*), `current_period_start_ms`, `current_period_end_ms`, `next_charge_ms`, `cancel_at_ms`, `failure_count` (numbers, *sort*), `cancel_at_period_end` (bool), `usage_accumulated`, `invoice`, `plan` (JSON) | `id` |
| UAID manifests | `dataspace_id` (number, *sort*), `dataspace_alias`, `manifest_hash`, `status` (strings, *sort*), `manifest`, `lifecycle` (JSON), `accounts` (list of strings) | `dataspace_id` |
| account movements | `id`, `source`, `type`, `status`, `direction`, `account_id`, `counterparty_account_id`, `asset_id`, `asset_definition_id`, `tx_hash` (strings), `timestamp_ms`, `block_height`, `block_index`, `movement_index`, `expires_at_ms`, `finalized_at_ms` (numbers), `operation_id`, `requesting_fi_id` (strings), `amount` (decimal), `result_ok` (bool) | newest chain position first, then descending movement index |
| contract activity | `authority`, `entrypoint_hash`, `contract_address`, `contract_alias`, `contract_entrypoint` (strings), `timestamp_ms`, `block_height`, `block_index` (numbers), `result_ok` (bool), `contract_payload`, `fee_payment` (JSON) | newest first |
| contract events | `event_id`, `provenance` (always `emitted`), `authority`, `execution_hash_hex`, `block_hash_hex`, `contract_address`, `event_kind` (strings), `schema_version`, `timestamp_ms`, `block_height`, `output_index`, `emission_index` (numbers), `result_ok` (always true), `participants`, `asset_ids` (lists of strings), `numeric_fields`, `payload`, `emission`, `fee_payment` (JSON) | descending `block_height`, `output_index`, `emission_index` |

Subscription status is a lower-case string (`active`, `paused`, `past_due`,
`canceled`, `suspended`). Manifest status is `Pending`, `Active`, `Expired` or
`Revoked`; use an ordinary filter such as `status != "Active"` for inactive
manifests. The UAID scopes the path and cursor; manifest rows are in `items`.

Asset definition items carry the complete definition record (including
`description`, `spec`, `logo` and `balance_scope_policy`) and an
`alias_binding` object when an alias is bound.

List-valued fields match element-wise: `asset_definition_ids = "…"` and
`asset_ids in […]` select rows where any element matches, and `!=`/`not in`
select rows where none does. Lists cannot be sorted or range-compared.

## History collections

Transactions are read in history order, newest first: by `block_height`
descending, then `block_index` (the transaction's position in its block)
descending. Account transactions are the committed transactions the account
signed or that reference it. Contract activity projects committed top-level
contract calls. Native event pages walk committed execution outputs and their
emissions in descending `(block_height, output_index, emission_index)` order.
Account movement pages add a descending
`movement_index` within each transaction, so page boundaries never skip other
movements from that transaction. History cursors contain only caller-visible
candidates; exhausting a page budget before finding one returns an explicit
`query_scan_limit_exceeded` error. Account movement expansion also consumes the
raw-row budget. These pages do not build a full-history process cache.

- The cursor holds the block coordinates of the last row and the next page
  starts strictly before them, so transactions committed while paging never
  shift later pages.
- `sort`, `include_total` and `aggregate` are rejected: each would need a
  scan of the whole history.
- Each page has a bounded history-scan budget of
  `torii.app_api_max_fetch_size` work units (about one per block read or
  transaction examined) and a matching byte allowance. A selective filter can therefore return a page with
  fewer than `limit` items, even none, together with a `next_cursor`; keep
  following `next_cursor` until it is `null`.
- Every block a page reads is authenticated by walking parent links down
  from a verified identity. Nodes keep such identities as checkpoints (every
  64 blocks, recorded at startup and as blocks commit, plus the blocks recent
  pages verified), so a page starts at most 64 blocks above its position and
  all of history is reachable. A page whose blocks alone exceed the budget
  is rejected with `query_scan_limit_exceeded`.
- Bounds on `block_height` in the filter's top-level `and` bound the rows a
  page examines: `block_height >= 1200` ends the walk below height 1200, and
  `block_height <= 1500` starts the walk just above height 1500. `filter=block_height >= 1200 and result_ok = true`
  examines only that range.

### Contract activity and native events

Contract activity projects committed top-level `ContractCall` inputs. The signed
`ContractInvocation` supplies `contract_address` and `contract_entrypoint`.
`contract_alias` and `contract_payload` appear only for a successful call whose
consensus-bound metadata matches its address, code hash and entrypoint. Admission
binds the payload to canonical arguments and the alias to the invoked address.
Rejected calls expose neither optional field.

Contract event rows instead project native `ContractEmissionV1` records retained
in successful committed Network, Pipeline or Time execution outputs. A call or
transaction metadata alone creates no event. Rolled-back emissions are absent;
a rejected output retaining emissions is invalid.

- `provenance` is `emitted`, `schema_version` is `1`, and `result_ok` is true.
  `event_id` is `<block_hash_hex>:<output_index>:<emission_index>`;
  `execution_hash_hex` identifies the output's root execution call.
- `emission` contains the authenticated contract address, code hash, entrypoint
  and event ordinals, caller, complete source event definition and canonical
  payload record. Historical decoding needs no current artifact or alias lookup.
- `event_kind` is the declared event name. `payload` renders the canonical record
  with its retained schema; participant, asset and numeric convenience fields
  come from that payload and the caller. Fee payment is projected for Network
  outputs when present. There is no inferred module or contract alias.
- Visibility requires access to the emitting contract's dataspace. Network
  outputs and Pipeline callbacks sourced from a Network input also require
  visibility of that committed input's route legs. Block-approved and Time
  callbacks use their public source event and the emitting contract's scope.

## Aggregates

`POST` only. Grouping happens after filtering; `having` filters grouped rows
and may reference group fields and metric aliases; `sort` may reference the
same names.

```json
{"filter": "quantity > 0",
 "aggregate": {"group_by": ["asset"],
               "metrics": [{"alias": "holders", "fn": "count"},
                           {"alias": "supply", "fn": "sum", "field": "quantity"}],
               "having": "holders >= 10"},
 "sort": ["-supply"], "limit": 20}
```

Functions: `count` (no field), `sum`, `min`, `max`, `avg` (numeric fields),
`distinct_count` (scalar fields). An aggregate has at most 8 `group_by`
fields and 16 metrics, and unknown members are rejected. A metric alias
must not name the first segment of a group field (such as `metadata` beside
`metadata.tier`). Values that compare equal group together, so `5` and `"5"`
in a metadata field are one group.

## Event streams

`GET /v1/events/sse?filter=<text>` takes a filter in the same text grammar,
restricted to what event subscriptions can match:

- fields `tx_status`, `tx_hash`, `tx_block_height`, `tx_lane_id`,
  `tx_dataspace_id`, `block_status`, `block_height`, `proof_backend`,
  `proof_call_hash` and `proof_envelope_hash`;
- `=` and `in [...]`, combined with `and` and `or`; `not` only over
  `tx_status = …` or `block_status = …`; and `tx_block_height is null`;
- transaction statuses `Queued`, `Expired`, `Approved`, `Rejected`; block
  statuses `Created`, `Approved`, `Rejected`, `Committed`, `Applied`.

For example `filter=tx_hash = "…" and tx_status in ["Approved", "Rejected"]`.
Anything else is rejected with `invalid_filter`.

Each SSE `data` line is one JSON object with `category` (`Pipeline`, `Data`
or `Other`) and `event` (for example `Transaction`, `Block`, `ProofVerified`,
or the data-event kind such as `Asset`). Statuses are variant names:
transactions report `Queued`, `Expired`, `Approved` or `Rejected`; blocks
carry `height` and `hash` and report `Created`, `Approved`, `Rejected`,
`Committed` or `Applied`. A rejected
transaction adds `rejection_code` (`account_does_not_exist`, `limit_check`,
`validation`, `instruction_execution`, `ivm_execution`,
`trigger_execution`) and the fixed public `rejection_reason`; a rejected
block adds `rejection_code` with the block rejection variant. A `summary`
member, where present, is diagnostic text without a stable format.

## Explorer feeds

`GET /v1/explorer/{collection}` and `POST /v1/explorer/{collection}/query`
accept shared `filter`, `select`, `limit` and `cursor`. Collections are
`accounts`, `domains`, `asset-definitions`, `assets`, `nfts`, `rwas`, `blocks`,
`transactions`, `transactions/latest`, `instructions` and `instructions/latest`.
All return `Page` with `items` and `next_cursor`; there is no nested pagination
object or sampling timestamp. The default limit is 25 and maximum 100.
`sort`, `aggregate` and `include_total` are rejected because these feeds retain
bounded scans in their existing canonical index or newest-history order.

Existing DTO row fields and visibility-aware counters are retained. A filter
runs over each bounded candidate page before projection; a page may be empty
with a continuation. Follow every continuation until `next_cursor` is null.
Cursors bind the collection, complete filter and current visibility scope.
History continuations also retain the committed snapshot hash and height.
Changing `select` or `limit` between pages is allowed.

| Feed | Filterable/projectable DTO fields |
| --- | --- |
| accounts | `id`, `network_prefix`, `owned_domains`, `owned_assets`, `owned_nfts`, `metadata.*` |
| domains | `id`, `logo`, `owned_by`, `accounts`, `assets`, `nfts`, `metadata.*` |
| asset-definitions | `id`, `owning_domain`, `mintable`, `logo`, `owned_by`, `assets`, `total_quantity`, `locked_quantity`, `circulating_quantity`, `metadata.*` |
| assets | `id`, `definition_id`, `account_id`, `value` |
| nfts | `id`, `owned_by`, `metadata.*` |
| rwas | `id`, `owned_by`, `quantity`, `held_quantity`, `primary_reference`, `status`, `is_frozen`, `parents`, `metadata.*` |
| blocks | `hash`, `height`, `created_at`, `prev_block_hash`, `transactions_hash`, `transactions_rejected`, `transactions_total` |
| transactions and latest | `authority`, `hash`, `block`, `created_at`, `executable`, `status` |
| instructions and latest | `authority`, `created_at`, `kind`, `box`, `box.wire_id`, `box.framed_sha256`, `box.instruction`, `transaction_hash`, `transaction_status`, `block`, `index` |

Instruction boxes contain only `wire_id`, `framed_sha256` (lowercase SHA-256 without a prefix), and `instruction` (canonical padded base64 of the native Norito `InstructionBox` frame). Decode the frame with the SDK native decoder to inspect its complete instruction payload. Transaction detail rejections contain `reason` (the canonical native `TransactionRejectionReason` frame in base64) and its public `message`.

DTO fields accept the complete shared filter AST. The following synthetic
membership selectors are filter-only and accept one string equality in the
outer conjunction: accounts `domain` and `with_asset`; NFTs/RWAs `domain`;
transactions `asset_id`; instructions `account` and `asset_id`. For example,
`domain = "wonderland.universal" and owned_assets > 0` queries accounts.
Negation, disjunction, range tests and duplicate conjuncts on a synthetic
selector are rejected explicitly. Resource selectors are never accepted as
top-level request parameters or JSON members.

The CLI exposes these feeds as `iroha explorer accounts`, `iroha explorer
asset-definitions`, `iroha explorer transactions-latest`, etc., using the same
list flags and `--all` traversal as other collections.
