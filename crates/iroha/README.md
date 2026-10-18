# Iroha Client

This is the reusable client library for the first Hyperledger Iroha 3 release.
Use it to build applications that communicate with Iroha peers over HTTP and
WebSocket.

This crate is the reusable Rust SDK surface. The `iroha` command-line binary is
built from the separate [`iroha_cli`](../iroha_cli) crate.

Follow the [Iroha 3 Rust tutorial](https://docs.iroha.tech/guide/tutorials/rust.html)
for setup, configuration, and client examples.

## Features

* Submit one or several Iroha Special Instructions (ISI) as a Transaction to Iroha Peer
* Read Torii collections with one filter, sort and cursor language
* Request data based on Iroha Queries from a Peer

Transaction finality waits require state-resolved `Applied` status. Temporary
HTTP 429 responses repeat only the status read, respecting Torii's delta-seconds
`Retry-After` and the original wait deadline. They never resubmit the transaction;
an exhausted deadline retains the last backpressure diagnostic.

`VerifiedPaymentReceipt::verify` independently joins one direct `SettleAtomic`
payment to a successful certified Network output. Supply the network, signed
transaction hash and complete intent retained from the authorized request, plus
a `VerifiedSumeragiBlock` from the existing verifier rooted in independently
authenticated signed genesis. The receipt binds exact payer buckets, asset
scopes, recipients, quantities, reference metadata and the authenticated Nexus
fee record or its explicit absence. It needs no later block and accepts no
status-only or deserialized verification claim. PipelineGas carriers are explicitly
unsupported until their fee outcome has an authenticated receipt. Customer credit
still requires the application's durable `(NetworkId, SettlementId)` uniqueness
transaction. `SettlementId` contains the participating debit owner and a stable
business reference. When another carrier committed that same independently
retained intent, `verify_recovered` authenticates the original successful carrier
and returns its hash through the same verifier. A replay outcome's block locator
only selects evidence; it never grants receipt authority.

`AccountClient::native_payment` composes that verification with submission and
durable recovery. Supply a `NativePaymentRequest` with the complete intent and
fee authorization, durable `WorkflowStorage`, and an independently rooted
`SumeragiFinalityVerifier`. Recreate the operation with the same inputs after
restart: `resume` uses only the original retained signed carrier, while `recover`
only reads and verifies evidence. Explicit `submit` authorizes a new paid attempt
with the reviewed fee intent. A second gateway can `resume` the original successful
payment by its payer-owned identity without signing. If no success or original
carrier is found, `resume` returns `NewAttemptAuthorizationRequired`. A timeout
or unavailable proof leaves the outcome unresolved; it does not authorize a
replacement payment.

`NativePaymentFullReturnRequest` derives one receiver-owned reverse payment
from a verified original. It preserves the original receipt and requires
separate authorization, fees and successful execution evidence for the return.
Partial returns are unsupported until consensus enforces a cumulative return
allowance. An ISO return report alone does not authorize a reverse movement.

`PaymentInbox` demonstrates the durable bank boundary over the existing
`WorkflowStorage` compare-and-store contract. Use a dedicated
`FileWorkflowStorage` directory or the same atomic unique-key transaction in the
bank's database. `credit` accepts only a `VerifiedPaymentReceipt` and an
independently selected customer/destination mapping. It publishes one immutable
customer-credit ledger entry and its pending notification together, keyed by
network and settlement ID. Retry the same receipt after an uncertain write;
reverify its original evidence after restart. The journal entry itself is the
credit, so do not follow it with a separate balance increment. Notification
delivery uses the same key and may repeat until acknowledged. A decoded bank
entry cannot construct a verified payment receipt.

`AccountClient::private_settlement` opens a durable operation over a
`PrivateSettlementRequest` containing independently prepared proof and encrypted
capsule artifacts. It checkpoints exact availability certificates before
promotion, resumes Prepare/Register/Commit/Finalize, and returns a
`VerifiedPrivateSettlementReceipt` only after successful execution is verified
against independently pinned genesis. `recover` reads and verifies without
uploading, signing or submitting. Reopening requires the original external
artifacts; the journal stores public certificates and carriers, never plaintext
witnesses or restricted proof/capsule blobs. This operation does not generate
proofs. If promotion lacks sufficient bound acknowledgements, `run` may restore
original provisional artifacts once per failed endpoint and verify that endpoint's
signed availability share before retrying promotion; the original certificate stays
unchanged. Upload acknowledgements are transport preflight, and the verified Prepare
certificate remains phase authority. Its transport/restart tests use synthetic execution with genuine
certificates; genuine prover and validator-network qualification remains open.

## Setup

**Requirements:** install
[Rust 1.93.1](https://www.rust-lang.org/learn/get-started), the toolchain pinned
for this workspace in the repository-root `rust-toolchain.toml`.

Add the following to the manifest file of your Rust project:

```toml
iroha = { git = "https://github.com/hyperledger-iroha/iroha.git", rev = "<IROHA_COMMIT>", package = "iroha" }
```

Pin `<IROHA_COMMIT>` to the revision deployed by your network. For a local
checkout, use `iroha = { path = "/path/to/iroha/crates/iroha" }`.

### Diagnostics

The client emits its diagnostics as [`tracing`](https://docs.rs/tracing) events;
install a `tracing` subscriber to see them. The SDK does not enable tracing's
`log` forwarding, so applications that only install a `log` logger receive no
client events by default. To forward them to `log`, enable the feature in your
own manifest:

```toml
tracing = { version = "0.1", features = ["log"] }
```

## Client construction

Construct an asynchronous client with `Client::builder(config).build()?`.
The builder immediately validates the endpoint, signing authority, address discriminant and
HTTP headers. Configure headers with `headers(...)`, HTTP transport with
`http_transport(Arc<dyn iroha::http::HttpTransport>)`, and WebSocket transport with
`stream_transport(Arc<dyn iroha::stream::StreamTransport>)` on the builder.
Configuration is fixed after construction. Native HTTP pools initialize on their
first corresponding HTTP use; asynchronous pool construction failures are returned
there through `iroha::Error`. The explicit blocking HTTP constructor is
`iroha::blocking::Client::with_http_transport(config, transport)?`.

Clones share their HTTP and stream transports and compatibility decision. To
change configuration, copy it with `client.to_builder()`, edit the builder, and
call `build()` to obtain a new context with a fresh compatibility cache and probe
coordinator. The copied builder retains both selected transports. When selecting
a different origin, choose its HTTP and operator credentials explicitly. Use
`builder.api_token(None)` to clear the typed listener credential, or
`builder.api_token(Some(secret))` to replace it for the new listener. Both calls
remove every `X-API-Token` spelling from generic header defaults; clearing
`builder.headers` alone does not clear the typed credential. The listener token
and the fresh operator signature authorize separate gates. Transport replacement
preserves an existing absolute request deadline.

`Config::http_transport_policy` defaults to `HttpTransportPolicy::Ordinary`.
Generated owned localnets select `DirectLoopback` explicitly. It requires cleartext
HTTP to exact `localhost`, an IPv4 loopback address, or `::1`, with no URL
credentials or fragments. The built-in local pools disable proxies, redirects and
native certificate-store loading; `localhost` resolves to loopback addresses. The
policy remains fixed through cloning, authority views and `to_builder()`, and
validates every HTTP request before dispatch, including injected transports. Remote
clients retain ordinary HTTP/HTTPS handling. This policy has no environment override.

Bind account operations with `client.account_client()?` and privileged operations
with `client.operator_client(operator_key_pair)?`. Synchronous applications use
`iroha::blocking`, which owns a reusable runtime and rejects calls from an async
runtime. `blocking::Client::with_request_deadline` retains that runtime and its HTTP
pools while binding the account context to the shorter deadline. Either view may
outlive the other; an expired deadline refuses HTTP dispatch. Remaining synchronous
capability methods and authority-owned operations are tracked in the repository's
first-release architecture redesign record.

Alias setup planning uses `client.plan_alias_setup(&request).await?`. It signs
the complete request, awaits asynchronous HTTP transport, and verifies the returned
plan against that request, the account, the network, and its expiry. Synchronous
callers use `iroha::blocking::Client::plan_alias_setup(&request)?`, which runs the
same transport and verification through the facade's owned runtime.

`account.kagemusha().load_issuance(...)`, `load_finality(...)` and `load_epoch(...)`
read bounded canonical Load receipts, receipt certificates with event paths, and
individual epoch-boundary certificates with the account's exact network
signature. The blocking account facade exposes the same methods. These reads
return data, not balance authority: the native wallet must verify BLS finality
against signed genesis and authenticated epoch changes, then bind the counted
event commitment to the exact retained receipt before signing its Advance.

Signed Iroha queries use `account.query_single(query).await?` for singular
lookups such as `FindAccountById`. Iterable signed queries
(`account.query(query)` with `iroha::query::AsyncQueryBuilderExt` imported)
stream typed rows through `execute().await?` and `next().await`. Each
continuation consumes its cursor before dispatch; a failed or cancelled
continuation ends that stream and cannot replay the signed request. When the
node reports more rows but returns no continuation cursor, the stream ends with
`QueryError::Truncated` instead of stopping silently. List collections with the
collection queries below.

## Collection queries

Domains, accounts, asset definitions, NFTs, RWA lots, account assets, asset
holders, transactions, account transactions and repo agreements share one query
language and one page envelope; the wire contract is
`specs/torii/collection_queries.md`.
Build a `ListQuery` with `iroha::collections` and read a `Collection`:

```rust
use iroha::{
    Error,
    client::Client,
    collections::{Collection, FilterExpr, ListQuery, SortKey, TryStreamExt as _, field},
    config::Config,
};

async fn list_definitions() -> eyre::Result<()> {
    let client = Client::builder(Config::load_file("client.toml")?).build()?;

    // Filter, sort and page size. `field(..)` builders and text filters
    // produce the same tree; `&`, `|` and `!` combine conditions.
    let query = ListQuery::new()
        .filter(field("owned_by").eq("sorau…") & field("metadata.tier").is_not_null())
        .sort_by(SortKey::desc("id"))
        .limit(50);
    let same: FilterExpr = r#"owned_by = "sorau…" and metadata.tier is not null"#.parse()?;
    assert_eq!(query.filter.as_ref(), Some(&same));

    // One page and its continuation.
    let page = client.list_page(&Collection::AssetDefinitions, &query).await?;
    if let Some(next) = query.next_page(&page) {
        let _second = client.list_page(&Collection::AssetDefinitions, &next).await?;
    }

    // Every row: `next_cursor` is followed lazily until the last page.
    let mut rows = client.list(Collection::AssetDefinitions, query);
    while let Some(row) = rows.try_next().await? {
        println!("{:?}", row.get("id"));
    }

    // Torii rejections carry the `{code, message, details}` envelope.
    let bad = ListQuery::new().filter(field("colour").eq("red"));
    match client.list_page(&Collection::AssetDefinitions, &bad).await {
        Err(Error::Api { error, .. }) if error.code() == "invalid_filter" => {
            let details = error.details();
            eprintln!(
                "{}; accepted fields: {:?}",
                error.message(),
                details.and_then(|details| details.expected())
            );
        }
        other => {
            other?;
        }
    }
    Ok(())
}
```

`Client` reads are public and unsigned. `client.account_client()?.list_page(..)`
and `.list(..)` add the account's canonical request signature, which only widens
visibility into restricted dataspaces; multisignature member contexts read
publicly. Parameterised collections carry their subject:
`Collection::AccountAssets(account_id)`, `Collection::AccountPermissions(account_id)`,
`Collection::AssetHolders(definition_id)`, `Collection::AccountTransactions(account_id)`
and `Collection::UaidManifests(uaid)`. Subscription plans and states use
`Collection::SubscriptionPlans` and `Collection::Subscriptions` with the same query
and page types. Pages require an explicit `next_cursor`; retired offset/count-mode
envelopes are rejected.

An authenticated collection read can return a capacity refusal while its State
view is busy. This remains a capacity error, with no anonymous fallback; it is
distinct from invalid credentials or a replayed request. A refused read is not
an empty collection and does not establish a payment outcome.

`Collection::Transactions`, `Collection::AccountTransactions`,
`Collection::ContractActivity`, and `Collection::ContractEvents` are history
collections (`Collection::is_history`): rows arrive newest first by
`block_height`, then `block_index`, and `sort`, `include_total` and `aggregate`
are rejected. A page may hold fewer rows than `limit`, or none, and still carry
a `next_cursor`; `list` keeps following it until it is absent. Bounds on
`block_height` in the filter's top-level `and` also bound Torii's scan, as in
`field("block_height").gte(1_200) & field("result_ok").eq(true)`.

Torii executes each collection query once over the caller-visible global state.
For collections that support totals and `POST` aggregates, visible rows contribute
exactly once even when they span several dataspace routes. Object and array literals
(only valid against `metadata.<key>`) exist only in the JSON form that the SDK
sends.

Queries are validated before dispatch: a query Torii would reject returns
`Error::InvalidListQuery` with the same code. `Error::code()` returns the code of
either error; `ApiError` also exposes the HTTP status, `details.field` (the
offending control), `expected`, `actual`, `hint`, the `x-iroha-reject-code`
header and `Retry-After`. Responses without an envelope remain `Error::Http`.

The blocking facade signs with its bound account and returns a lazy iterator:

```rust
use iroha::collections::{Collection, ListQuery};

fn print_domains(client: &iroha::blocking::Client) -> iroha::Result<()> {
    for domain in client.list(Collection::Domains, ListQuery::new().limit(200)) {
        println!("{:?}", domain?.get("id"));
    }
    Ok(())
}
```

## Node diagnostics

Use `client.status().get().await?` for the typed status document and
`client.status().version().await?` for the API version. Synchronous applications
use the same capability through `iroha::blocking::Client`, without `.await`.
The operation selects one response representation, enforces the context deadline
and rejects oversized or ambiguously labelled responses. Transport errors retain
their I/O category in `TransportErrorKind`; HTTP errors retain their bounded body.
Canonical committee responses retain `DecodeAttemptError` and native finality
errors as owned sources, distinguishing malformed bytes from an enclosing resource
refusal. Inspect error variants and fields; the top-level error is move-only.

Bind an operator with `client.operator_client(operator_key_pair)?`, then use
`operator.consensus().diagnostics().await?` for queue pressure, NPoS election state
and lane governance readiness. Synchronous callers use the same capability on
`iroha::blocking::OperatorClient`. These observations do not authenticate finality.

Public Nexus reads use `client.nexus().validator_committee(target_epoch).await?`
and `client.nexus().prepare_public_lane_plan(&request).await?`. The corresponding
capability on `iroha::blocking::Client` drives the same implementation. Committee
attachments still require independent native chain and genesis authentication.

Submission discovers the node's data-model version and signed-transaction schema
through public `/v1/node/capabilities` metadata before dispatching transaction
bytes. This probe omits canonical account authentication so a fresh account can
submit its registration. Configured transport headers, deadlines, response bounds
and exact version/schema checks still apply.

## Operator configuration

Bind the operator with `client.operator_client(operator_key_pair)?`, then read
`operator.configuration().get().await?`. The returned shared DTO includes the
confidential gas schedule. Configuration uses one operator-signed JSON request,
the context deadline and an 8-MiB response ceiling.

For synchronous operator-only work, construct
`iroha::blocking::OperatorClient::from_client(operator)?` and call
`operator.configuration().get()?`. This facade owns a reusable runtime without
requiring an account context. Public and account contexts have no configuration
capability.

## Event and block streams

Bind `let account = client.account_client()?`, then use
`account.events().subscribe(filters).await?` or
`account.blocks().subscribe(height).await?`. Filters must be nonempty; block
height is `NonZeroU64`, and the account must hold `CanReadAllLedgerData` to read
full signed blocks. These capabilities belong only to the account context.
Both sign the exact upgrade and use the `iroha-norito-v1` WebSocket subprotocol.

The owned streams implement `Stream<Item = iroha::Result<EventBox>>` or
`Stream<Item = iroha::Result<SignedBlock>>`. Initial subscription messages are
limited to 256 KiB and received messages to 64 MiB, including fragmentation.
Upgrade response bodies are limited to 64 KiB. Connection establishment and the
initial send share `torii_request_timeout`; zero disables that deadline.
Receiving has no implicit lifetime deadline. Use an async timeout when a read
needs one.

Call `stream.close().await?` to flush a close frame and release the connection.
Close uses the context request timeout, or five seconds when that timeout is
zero. A normal peer close (1000) ends the stream; abnormal close codes and reasons
remain in `Error::StreamClosed`. Decode, transport and protocol failures terminate
the stream. Dropping it releases I/O; it does not spawn cleanup or reconnect work.
Subscriptions never redirect, retry, resume or replay automatically.

`last_message_bytes()` reports the complete binary message size for the last
item delivered, including malformed binary messages. It is `None` before the
first item or after a transport failure without a delivered binary message.
Pending reads, local receive timeouts and normal completion preserve the last
observation. This metadata also exists on blocking streams. HTTP errors retain
an unambiguous `Retry-After` delta as `retry_after`; it is a hint for caller-owned
policy and never causes the SDK to retry.

For synchronous code, use
`iroha::blocking::AccountClient::from_client(account)?`, then the same capability
without `.await`. Its stream uses the reusable owned runtime:
`recv(Some(duration))` bounds one wait, `recv(None)` waits without an idle timeout,
and `close()` returns a typed result. `Ok(None)` means normal completion; a wait
expiry returns `Error::Timeout { operation: "stream.receive" }` and permits another
receive on the same subscription. Blocking calls reject execution inside an async
runtime. Custom stream connectors implement `StreamTransport` and `StreamSocket`;
the SDK retains request signing, protocol checks, deadlines and typed decoding.

## Subscription drafts

Subscription preparation returns a typed `SubscriptionDraft`; its payload variant
owns `Box<TransactionPayload>`, and its instruction variant owns the instruction
list. Its JSON representation retains the `kind` and `value` fields. Preparation
futures are `Send`, and signing remains an explicit account operation.

The gateway-compliance control methods on `Client` share the canonical HTTP projections and
request-idempotency binding in `iroha_torii_shared::sorafs_gateway_compliance_api`. Status, stage,
acknowledge and promote each use one bounded account-signed request under the existing deadline,
without retries. Signed catalogs and acknowledgements use the sole `sorafs_manifest` protocol
owner. Caller-selected trust is not network authentication, and returned status/action fields are
runtime observations, not current native eligibility or package-read authority. Original signing,
genuine reload observation and crash recovery belong to the managed publisher.

## Durable workflows

`AccountClient::bootstrap_workflow`, `dkg_workflow` and `threshold_opening_workflow` return a
durable handle for a sequence of transactions and off-chain rounds. A workflow is not atomic across
its steps: each transaction is atomic by itself, a finalized step is never rolled back, and every
result carries a progress report that lists confirmed, unresolved and not-started steps.

The handle offers `run`, `recover` (ledger reads only), `cancel` and `progress`. The journal is kept
in caller-supplied storage: `FileWorkflowStorage` is durable and owner-private,
`MemoryWorkflowStorage` is for tests. After an interruption, `run` first reads the committed outcome
of the persisted transaction identity and only then continues. A submission timeout is reported as
`SubmissionOutcomeUnknown` until that read resolves it, and the transaction is not rebuilt or
resubmitted while it may still commit. Capability logic (payloads, rounds, custody) comes from a
`WorkflowDriver`; the module contains no key-generation or threshold cryptography.

The contract is `specs/zk_durable_workflow.md`; its fixtures are in `fixtures/zk/workflow_v1/`.

## Examples

We highly recommend looking at the sample [`iroha_cli`](../iroha_cli) binary
crate, which builds the `iroha` executable, as well as our
[tutorial](https://docs.iroha.tech/guide/tutorials/rust.html) for more examples
and explanations.

### Address formatting

`account_address::encode_account_id_to_i105(&account, network_prefix)` requires
an explicit address prefix. Obtain it from an immutable client with
`client.account_chain_discriminant()` when rendering an address for that
context. Concurrent clients can render different networks without changing
process-global settings. The SDK helper module exposes no global prefix setter
or getter; the data model's remaining default-formatting API is separate work.

Explorer feeds use `Collection::ExplorerAccounts`, `ExplorerDomains`,
`ExplorerAssetDefinitions`, `ExplorerAssets`, `ExplorerNfts`, `ExplorerRwas`,
`ExplorerBlocks`, `ExplorerTransactions`, `ExplorerTransactionsLatest`,
`ExplorerInstructions` and `ExplorerInstructionsLatest`. They retain bounded
fixed-order reads with shared filter/select/limit/cursor controls. Iterate
until the cursor ends, including after empty pages. Account movements use
`Collection::AccountHistory(account_id)` with the same history controls.

`AccountClient::native_payment` binds a `NativePaymentRequest`, durable
`WorkflowStorage` and independently selected `SumeragiFinalityVerifier` into a
resumable direct Global payment. `submit` explicitly authorizes a paid attempt;
`resume` cannot build or sign another carrier, even when rejected-retry options
are set. Both return only an opaque verified original receipt. A fresh gateway
without verified success or a retained carrier receives
`NewAttemptAuthorizationRequired` from `resume`; `recover` performs no signing or
dispatch. The existing workflow journal
retains exact carrier identities and a bounded completion locator, which is
re-fetched and reverified after restart. A rejected duplicate carrier remains
rejected even when original business success is recovered. Status-only expiry,
local read limits and failed reads never authorize a new payment identity.
Before signing or dispatching restored bytes, the operation checks their exact
payment and fee authorization against the retained request; journal digests alone
grant no monetary authority. See
[`specs/zk_durable_workflow.md`](../../specs/zk_durable_workflow.md) for the exact
first-release layout, scope and online recovery contract.

`NativePaymentFullReturnRequest` derives one receiver-owned ID from an opaque
verified original and prepares its exact full reverse payment.
`AccountClient::native_payment_return` reuses the same durable operation and
exposes the same `submit`, `resume` and read-only `recover` boundary. It returns
`VerifiedPaymentReturn`, retaining both successful receipts. Partial
returns require a future consensus-owned cumulative allowance.

The confidential `AccountClient::private_settlement_one_call` operation acquires
one authenticated context batch, checks caller-held restricted openings, invokes
the existing native wallet/prover/sealer and uses the prepared settlement
workflow. Callers retain genesis/schema pins, exact private business terms,
original wallet reservations and the encrypted artifact key. All selected context
is durable before wallet work; `recover` reopens and independently re-verifies the
original context/proofs without invoking the wallet or sending transactions.
`run` explicitly continues the original preparation. Whole-network one-call
qualification remains open; the advanced `private_settlement` operation accepts
already prepared materials.
The current context transport requires `CanReadAllLedgerData` because its complete
World hashes disclose unrelated row identities and low-entropy values. A bank's
selected-dataspace grants do not authorize that response; scoped authenticated
context proofs remain unfinished.
