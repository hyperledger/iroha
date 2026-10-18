# Mochi development

<img src="assets/mochi-logo.svg" alt="Mochi" width="320">

Mochi is a desktop client of the same managed workspace used by Kagami. The
native bundle contains matching `mochi`, `kagami` and `iroha3d` executables.
`mochi --workspace <directory>` selects the workspace; no user-supplied TOML,
source build, PATH discovery or project-local secret export is involved.

## Desktop tour

- **Home** offers Quickstart: one click creates and starts a four-validator
  localnet under the first unused `local`, `local-2`, … name. With an environment
  selected it shows each validator's Torii URL, the developer account's balances,
  the latest blocks and quick actions.
- The header switches, creates and attaches environments and holds Start, Stop,
  Refresh and Reset. The status strip shows phase, running validators, block
  height, chain, network, dataspace and the observed Torii URL; click a value to copy.
- **Accounts** lists registered accounts with their holdings. Quick actions mint,
  send, burn or create a funded account. A new account's key pair is generated in
  memory, revealed only on request and dropped with the environment. Every quick
  action becomes the same signed preview as the composer and is submitted only by
  an explicit click.
- **Blocks** and **Activity** follow the observed validator's canonical streams.
  Idle chains create no blocks, so balances refresh only after committed blocks
  or submissions.
- **Endpoints** lists Torii, health, status, metrics, OpenAPI and MCP URLs for each
  validator, the network identity and copyable `kagami` and `curl` commands. It
  never shows generated keys, API tokens or private configuration paths.
- **Contracts** accepts a `.ko`, `.to`, `Musubi.toml` or package directory dropped
  anywhere on the window. **Transactions**, **State**, **Packages** and **Logs**
  cover the remaining workflows.
- The theme follows the operating system and can be toggled in the header. The
  mascot's face follows the selected network's phase; poke it for a squish.
  Brand assets and their provenance live in [assets](assets/README.md).

## Ownership

- `iroha_deploy::managed` owns generated configuration, four-validator lifecycle,
  retained identities, context selection, native worker authentication and logs.
- `mochi-core::developer` binds desktop observations and transaction previews to
  an immutable managed context. Closing Mochi does not stop the managed network.
- Musubi and `iroha_contract_deploy` own compilation, quoted-fee review, original
  transaction recovery and authenticated contract readback. Desktop recovery
  reviews the exact retained plan again before any new dispatch.
- `iroha_fs` owns private filesystem custody on native Unix and Windows.

The UI provides aggregate Start, Stop and explicit stopped-network Reset actions.
New localnet creates another named environment without resetting the current one;
the new environment is selected when ready. Both startup actions require a fresh
Ready observation before changing selection. Failed startup retains the previous
selection and exposes the prepared name for recovery from the environment menu.
Its Private dataspace action selects a network from the installed profile artifact
and delegates the operation, with a sixty-second foreground deadline, to the same
managed worker as Kagami. The desktop performs no parent HTTP requests or
wallet/journal writes.
Failed parent attempts retain their funding, namespace, registration or anchoring stage and
a fixed public failure code. Foreground deadline errors include that last stage
and cause; preparation failures remain distinct from finality catch-up, without
exposing server response bodies or private custody paths. Retries reconcile the
same retained operations.
After initial registration, `anchoring` means the worker is observing the parent
or relaying later child certificates; a retained receipt alone does not complete
that current work.
Local validator readiness and parent attachment progress are displayed separately;
only an independently verified parent receipt is shown as confirmed, including
its original parent and child heights. Retained confirmations remain historical
when the parent is unavailable. A bundle without installed profiles supports
localnets without inventing a public network authority.
Individual validator selection changes the observer endpoint only. It provides
no per-peer lifecycle or alternate generation path. The desktop preserves state
pagination, canonical block/event streams, bounded logs, balance/block summaries,
structured and JSON transaction drafts, signed previews and deployment receipts.
Exact deployment and fee review appears over every desktop view. Switching views
during preparation cannot hide the review, and only its explicit confirmation
approves dispatch; cancellation or closing Mochi leaves approval withheld.
Deployment results identify the original localnet or private dataspace on which
the contract applied. Parent receipts appear separately as historical evidence;
an unavailable parent observation does not undo a verified local deployment. A failed automatic
workspace refresh keeps the completed deployment receipt visible, clears live context, streams,
logs and activity, and reports the observation error. Explicit selection and Stop
retain their existing clearing behavior.

Deployment results also show artifact-derived initialization guidance when the
contract declares `hajimari`/`始まり`. It stays separate from the Applied receipt:
the hook requires an explicit call, and recovered guidance does not assert its
current state.

The Packages view exposes explicit Publish, Resume publication and Recover package files
actions through `DeveloperWorkspace::publish_package` and the shared Musubi engine.
Publish can start the default environment; recovery requires its existing selected context
and original operation ID. Original namespace custody and generation-bound operation/cache
paths are shared with Kagami. The view retains canonical exit status, output and diagnostics
even when the subsequent workspace observation fails. These source paths still require
combined native three-provider publication and cold-package qualification.

The generated client signer is also the ledger-stream authority. Node HTTP
operator signing uses a distinct generated key validated against all four node
configs. Neither account defaults to a bundled sample key. Observations and
previews reject a removed/replaced generation and never adopt a new network
implicitly. Canonical stream transport checks endpoint and network identity.

## Focused checks

```sh
scripts/cargo_fast.sh --stable-local-metadata --incremental -- check -p mochi-ui --features gui --bin mochi
cargo test -p mochi-core
cargo test -p mochi-integration
cargo test -p mochi-ui --features gui --bin mochi
ci/check_mochi.sh
```

Shared generator/worker tests live in `iroha_deploy`; custody tests live in
`iroha_fs`. Mochi tests cover context binding, query authority, canonical stream
transport and desktop review cancellation. Mock services do not qualify native
four-validator operation or Windows filesystem/process semantics. Release bundle
qualification must exercise the packaged binaries on each native platform.

See [the bundle contract](../specs/mochi_bundle.md) and
[developer-experience implementation goals](../specs/kagami_mochi_devex_goals.md).
Public guides are maintained in [Iroha documentation](https://docs.iroha.tech/).

Packaged macOS builds contain a native `Mochi.app`: the desktop, Kagami and
`iroha3d` live together in `Contents/MacOS`, and installed network profiles live
only in `Contents/Resources`. Linux/Windows packages use `bin`. See
[BUNDLE_README.md](BUNDLE_README.md) for installed commands. Loose Cargo-built
programs remain a development mode; they are not the macOS distribution layout.
App assembly does not claim signing or notarization.
