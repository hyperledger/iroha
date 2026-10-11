# Command-Line Help for `kagami`

This document contains the help content for the `kagami` command-line program.

**Command Overview:**

* [`kagami`↴](#kagami)
* [`kagami wizard`↴](#kagami-wizard)
* [`kagami localnet`↴](#kagami-localnet)
* [`kagami localnet up`↴](#kagami-localnet-up)
* [`kagami localnet status`↴](#kagami-localnet-status)
* [`kagami localnet logs`↴](#kagami-localnet-logs)
* [`kagami localnet down`↴](#kagami-localnet-down)
* [`kagami localnet reset`↴](#kagami-localnet-reset)
* [`kagami localnet generate`↴](#kagami-localnet-generate)
* [`kagami localnet validate-beacon-launch`↴](#kagami-localnet-validate-beacon-launch)
* [`kagami dataspace`↴](#kagami-dataspace)
* [`kagami dataspace up`↴](#kagami-dataspace-up)
* [`kagami dataspace status`↴](#kagami-dataspace-status)
* [`kagami dataspace networks`↴](#kagami-dataspace-networks)
* [`kagami context`↴](#kagami-context)
* [`kagami context list`↴](#kagami-context-list)
* [`kagami context show`↴](#kagami-context-show)
* [`kagami context use`↴](#kagami-context-use)
* [`kagami contract`↴](#kagami-contract)
* [`kagami contract deploy`↴](#kagami-contract-deploy)
* [`kagami contract view`↴](#kagami-contract-view)
* [`kagami contract call`↴](#kagami-contract-call)
* [`kagami package`↴](#kagami-package)
* [`kagami package publish`↴](#kagami-package-publish)
* [`kagami docker`↴](#kagami-docker)
* [`kagami keys`↴](#kagami-keys)
* [`kagami genesis`↴](#kagami-genesis)
* [`kagami genesis sign`↴](#kagami-genesis-sign)
* [`kagami genesis generate`↴](#kagami-genesis-generate)
* [`kagami genesis generate default`↴](#kagami-genesis-generate-default)
* [`kagami genesis generate synthetic`↴](#kagami-genesis-generate-synthetic)
* [`kagami genesis materialize`↴](#kagami-genesis-materialize)
* [`kagami genesis validate`↴](#kagami-genesis-validate)
* [`kagami genesis validate-prepared`↴](#kagami-genesis-validate-prepared)
* [`kagami genesis embed-pop`↴](#kagami-genesis-embed-pop)
* [`kagami genesis normalize`↴](#kagami-genesis-normalize)
* [`kagami privacy-bootstrap`↴](#kagami-privacy-bootstrap)
* [`kagami privacy-bootstrap emit-taira-v1`↴](#kagami-privacy-bootstrap-emit-taira-v1)
* [`kagami privacy-bootstrap validate-taira-v1`↴](#kagami-privacy-bootstrap-validate-taira-v1)
* [`kagami privacy-bootstrap validate-taira-nevo-review-v1`↴](#kagami-privacy-bootstrap-validate-taira-nevo-review-v1)
* [`kagami privacy-bootstrap render-taira-release-v1`↴](#kagami-privacy-bootstrap-render-taira-release-v1)
* [`kagami verify`↴](#kagami-verify)
* [`kagami advanced`↴](#kagami-advanced)
* [`kagami advanced network-bootstrap`↴](#kagami-advanced-network-bootstrap)
* [`kagami advanced network-bootstrap prepare`↴](#kagami-advanced-network-bootstrap-prepare)
* [`kagami advanced client-configs`↴](#kagami-advanced-client-configs)
* [`kagami advanced codec`↴](#kagami-advanced-codec)
* [`kagami advanced codec list-types`↴](#kagami-advanced-codec-list-types)
* [`kagami advanced codec norito-to-rust`↴](#kagami-advanced-codec-norito-to-rust)
* [`kagami advanced codec norito-to-json`↴](#kagami-advanced-codec-norito-to-json)
* [`kagami advanced codec json-to-norito`↴](#kagami-advanced-codec-json-to-norito)
* [`kagami advanced kura`↴](#kagami-advanced-kura)
* [`kagami advanced kura beacon-history`↴](#kagami-advanced-kura-beacon-history)
* [`kagami advanced kura print`↴](#kagami-advanced-kura-print)
* [`kagami advanced kura finality`↴](#kagami-advanced-kura-finality)
* [`kagami advanced kura sidecar`↴](#kagami-advanced-kura-sidecar)
* [`kagami advanced markdown-help`↴](#kagami-advanced-markdown-help)
* [`kagami advanced schema`↴](#kagami-advanced-schema)

## `kagami`

Start local networks, attach private dataspaces, and deploy Iroha contracts.

**Usage:** `kagami [OPTIONS] <COMMAND>`

Common tasks:
  kagami localnet up
  kagami dataspace up acme --network taira
  kagami contract deploy hello.ko
  kagami package publish .
  kagami context list
  kagami wizard
  kagami localnet generate --out-dir ./localnet
  kagami docker --peers 4 --config-dir ./localnet --image hyperledger/iroha:dev --out-file docker-compose.yml
  kagami keys --out-dir ./key-custody
  kagami keys --algorithm bls_normal --pop --out-dir ./validator-custody
  kagami advanced markdown-help


###### **Subcommands:**

* `wizard` — Guided onboarding flow for staging a Sora Nexus observer configuration
* `localnet` — Start and manage a persistent localnet without supplying configuration
* `dataspace` — Run an owner-private local dataspace attached to an installed remote network
* `context` — Select and inspect managed developer environments
* `contract` — Build and deploy native IVM contracts in one invocation
* `package` — Publish native Musubi packages through an exact generated local environment
* `docker` — Generate validator-only Docker Compose from a prepared bundle or explicit dev seed
* `keys` — Generate cryptographic key pairs and optional validator Proofs-of-Possession
* `genesis` — Commands related to genesis
* `privacy-bootstrap` — Emit and validate fail-closed Taira exact-12 privacy bootstrap artifacts
* `verify` — Verify a genesis manifest against a preset profile
* `advanced` — Advanced low-level helpers for codec conversion, schema generation, block inspection, and docs

###### **Options:**

* `--ui-mode <MODE>` — Control how Kagami formats status messages (auto detects TTY by default)

  Default value: `auto`

  Possible values: `auto`, `plain`, `rich`




## `kagami wizard`

Guided onboarding flow for staging a Sora Nexus observer configuration

**Usage:** `kagami wizard [OPTIONS]`

###### **Options:**

* `--output-dir <PATH>` — Directory where generated config/genesis files will be written

  Default value: `wizard-output`
* `--non-interactive` — Run non-interactively, accepting defaults for prompts that are not supplied via flags
* `--p2p-host <HOST>` — Override the public P2P host/IP advertised for this generated observer
* `--p2p-port <PORT>` — Override the public P2P port for this peer
* `--torii-port <PORT>` — Override the local Torii listener port for this peer
* `--relay-mode <RELAY_MODE>` — Override the relay mode instead of prompting interactively

  Possible values: `disabled`, `hub`, `spoke`, `assist`

* `--relay-hub-address <HOST:PORT>` — Relay hub addresses (`host:port`), repeat once per hub when relay mode uses them
* `--trusted-peers <PEERS>` — Trusted roster (`pubkey` or `pubkey@host:port`); include a reachable address without a relay
* `--trusted-peers-pop <POPS>` — Comma-separated PoP entries for trusted peers (`pubkey=pop_hex`)



## `kagami localnet`

Start and manage a persistent localnet without supplying configuration

**Usage:** `kagami localnet <COMMAND>`

###### **Subcommands:**

* `up` — Generate, start, verify, and select a localnet without supplying configuration
* `status` — Observe the live supervisor and its retained environment
* `logs` — Read a bounded retained supervisor or validator log tail
* `down` — Stop the owned validators, preserving their identities and ledger
* `reset` — Explicitly retire one stopped generation so the next up creates a fresh ledger
* `generate` — Generate an operator-owned network bundle without starting validators
* `validate-beacon-launch` — Validate an isolated native beacon configuration and opaque descriptor handoff



## `kagami localnet up`

Generate, start, verify, and select a localnet without supplying configuration

**Usage:** `kagami localnet up [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>` — Managed environment name

  Default value: `local`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--timeout <TIMEOUT>` — Complete generation and readiness budget in seconds

  Default value: `30`



## `kagami localnet status`

Observe the live supervisor and its retained environment

**Usage:** `kagami localnet status [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>` — Managed environment name

  Default value: `local`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami localnet logs`

Read a bounded retained supervisor or validator log tail

**Usage:** `kagami localnet logs [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>` — Managed environment name

  Default value: `local`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--peer <PEER>` — Validator index (0..3). Omit to read the supervisor log
* `--bytes <BYTES>` — Maximum bytes returned from the end of the log

  Default value: `16384`



## `kagami localnet down`

Stop the owned validators, preserving their identities and ledger

**Usage:** `kagami localnet down [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>` — Managed environment name

  Default value: `local`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami localnet reset`

Explicitly retire one stopped generation so the next up creates a fresh ledger

**Usage:** `kagami localnet reset [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>` — Exact environment to retire; required to make reset deliberate

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami localnet generate`

Generate an operator-owned network bundle without starting validators

**Usage:** `kagami localnet generate [OPTIONS] --out-dir <DIR>`

###### **Options:**

* `-p`, `--peers <COUNT>` — Number of peers to generate (minimum four)

  Default value: `4`
* `-s`, `--seed <SEED>` — Optional UTF-8 seed for deterministic development keys.

   Omit this option to generate independent keys from operating-system entropy.
* `--chain-id <CHAIN_ID>` — Canonical chain identifier written into genesis, peer configs, and the client config

  Default value: `00000000-0000-0000-0000-000000000000`
* `--chain-discriminant <PREFIX>` — Account-address chain prefix written into genesis and client/peer configs. Public chain identities retain their fixed prefix
* `--sora-profile <PROFILE>` — Enable Sora profile defaults; `nexus` enforces public dataspace rules (NPoS). Requires at least 4 peers

  Possible values: `dataspace`, `nexus`

* `--private-dataspace <DATASPACE>` — Select an exact restricted dataspace preset for the `dataspace` Sora profile

  Possible values:
  - `sbp`:
    State Bank of Pakistan dataspace (id 10, lane 3)
  - `cbuae`:
    Central Bank of the UAE dataspace (id 12, lane 4)
  - `bpng`:
    Bank of Papua New Guinea local dataspace (id 8648377547929788715, lane 5)

* `--perf-profile <PROFILE>` — Apply a localnet performance profile (10k TPS / 1s finality presets)

  Possible values: `10k-permissioned`, `10k-npos`

* `--bind-host <HOST>` — Host to bind P2P and Torii listeners to (host/IP only, no port)

  Default value: `0.0.0.0`
* `--public-host <HOST>` — Host to advertise to peers and use for client Torii URL (host/IP only, no port)

  Default value: `127.0.0.1`
* `--base-api-port <BASE_API_PORT>` — Base Torii API port (per-peer increments by 1)

  Default value: `8080`
* `--base-p2p-port <BASE_P2P_PORT>` — Base P2P port (per-peer increments by 1)

  Default value: `1337`
* `-o`, `--out-dir <DIR>` — Output directory for configs/genesis/scripts
* `--extra-accounts <EXTRA_ACCOUNTS>` — Extra accounts to pre-register (in wonderland)

  Default value: `0`
* `--sample-asset` — Register the optional sample asset and mint to the default account. The built-in KAGEMUSHA V1 asset is always emitted

  Default value: `false`
* `--asset-definition-id <ASSET_DEFINITION_ID>` — Register additional asset definition IDs owned by the generated client signer. Repeat the flag to register more than one asset definition. A localnet reserve is minted to the generated client signer for each requested asset definition
* `--block-cadence-ms <MILLISECONDS>` — Override the immutable signed block cadence in milliseconds. Leave unset to use the one-second localnet cadence
* `--consensus-mode <MODE>` — Consensus mode to emit in genesis/configs. Defaults to `permissioned`. Sora profile localnets and perf profiles require `npos`

  Possible values: `permissioned`, `npos`




## `kagami localnet validate-beacon-launch`

Validate an isolated native beacon configuration and opaque descriptor handoff

**Usage:** `kagami localnet validate-beacon-launch --network-dir <NETWORK_DIR> --peer-index <PEER_INDEX> --beacon-config <BEACON_CONFIG> --beacon-credential <BEACON_CREDENTIAL>`

###### **Options:**

* `--network-dir <NETWORK_DIR>` — Absolute directory containing the unchanged generated peer0..3 configurations
* `--peer-index <PEER_INDEX>` — Zero-based generated peer index
* `--beacon-config <BEACON_CONFIG>` — Separate native configuration in the private run's beacon/seat-N directory
* `--beacon-credential <BEACON_CREDENTIAL>` — Owner-only native beacon credential beside the separate configuration



## `kagami dataspace`

Run an owner-private local dataspace attached to an installed remote network

**Usage:** `kagami dataspace <COMMAND>`

###### **Subcommands:**

* `up` — Create, fund, register, and select four private validators without supplying configuration
* `status` — Observe local validators and independently verified parent attachment separately
* `networks` — List the independently pinned network profiles supplied by this installation



## `kagami dataspace up`

Create, fund, register, and select four private validators without supplying configuration

**Usage:** `kagami dataspace up [OPTIONS] --network <NETWORK> <ALIAS>`

###### **Arguments:**

* `<ALIAS>` — Canonical private dataspace alias to lease on the parent

###### **Options:**

* `--network <NETWORK>` — Exact independently installed parent profile, such as taira
* `--account-alias <ACCOUNT_ALIAS>` — Canonical owner label leased on the parent as LABEL@ALIAS; retained across retries

  Default value: `admin`
* `--name <NAME>` — Store-local context name (defaults to the dataspace alias)
* `--timeout <TIMEOUT>` — Complete parent authentication, local startup, and attachment budget in seconds

  Default value: `60`
* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami dataspace status`

Observe local validators and independently verified parent attachment separately

**Usage:** `kagami dataspace status [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami dataspace networks`

List the independently pinned network profiles supplied by this installation

**Usage:** `kagami dataspace networks [OPTIONS]`

###### **Options:**

* `--json` — Emit the installed profile names as one JSON array



## `kagami context`

Select and inspect managed developer environments

**Usage:** `kagami context <COMMAND>`

###### **Subcommands:**

* `list` — List retained contexts in this workspace
* `show` — Show the selected context, or one exact named context
* `use` — Select an existing context for subsequent developer commands



## `kagami context list`

List retained contexts in this workspace

**Usage:** `kagami context list [OPTIONS]`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami context show`

Show the selected context, or one exact named context

**Usage:** `kagami context show [OPTIONS] [NAME]`

###### **Arguments:**

* `<NAME>`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami context use`

Select an existing context for subsequent developer commands

**Usage:** `kagami context use [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>`

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr



## `kagami contract`

Build and deploy native IVM contracts in one invocation

**Usage:** `kagami contract <COMMAND>`

###### **Subcommands:**

* `deploy` — Deploy source, bytecode, or a Musubi package; automatically start a default localnet if needed
* `view` — Read a verified deployed view in the selected managed environment
* `call` — Prepare, execute or resume a finite durable mutable call



## `kagami contract deploy`

Deploy source, bytecode, or a Musubi package; automatically start a default localnet if needed

**Usage:** `kagami contract deploy [OPTIONS] [INPUT]`

###### **Arguments:**

* `<INPUT>` — .ko source, .to artifact, Musubi.toml, or package directory (defaults to the current directory)

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--context <CONTEXT>` — Use an existing managed context without changing the workspace selection
* `--alias <ALIAS>` — Exact authorized contract alias; otherwise derive the name in the context's dataspace
* `--package <PACKAGE>` — Exact Musubi package when the input selects a workspace
* `--contract <CONTRACT>` — Exact target when a package has more than one contract
* `--locked` — Require an unchanged Musubi dependency lock
* `--resume <RESUME>` — Recover this exact retained deployment without rebuilding or signing another plan
* `--max-fee <MAX_FEE>` — Bound the aggregate quoted fees in their single fee asset before dispatch



## `kagami contract view`

Read a verified deployed view in the selected managed environment

**Usage:** `kagami contract view [OPTIONS] --entrypoint <ENTRYPOINT> <ALIAS>`

###### **Arguments:**

* `<ALIAS>` — Exact deployed contract alias

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--context <CONTEXT>` — Existing managed environment; otherwise use the workspace selection
* `--entrypoint <ENTRYPOINT>` — Read-only public entrypoint
* `--args <ARGS>` — Named arguments validated against the retained deployed interface

  Default value: `{}`
* `--gas-limit <GAS_LIMIT>` — Positive view execution budget

  Default value: `1500000`



## `kagami contract call`

Prepare, execute or resume a finite durable mutable call

**Usage:** `kagami contract call [OPTIONS] [ALIAS]`

###### **Arguments:**

* `<ALIAS>` — Exact deployed alias for a fresh operation

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--context <CONTEXT>` — Existing managed environment; otherwise use the workspace selection
* `--entrypoint <ENTRYPOINT>` — Mutable public selector, including an explicitly requested lifecycle hook
* `--args <ARGS>` — Named arguments validated and encoded natively from the retained deployed interface

  Default value: `{}`
* `--max-fee <MAX_FEE>` — Positive aggregate cap across any exact self-grant and the call in the generated fee asset
* `--gas-limit <GAS_LIMIT>` — Signature-bound mutable execution budget

  Default value: `1500000`
* `--timeout <TIMEOUT>` — Original signing interval, retained unchanged when the operation is resumed

  Default value: `60`
* `--prepare` — Persist the exact original authorization without submitting either stage
* `--resume <RESUME>` — Recover this exact managed call without a new authorization or replacement transaction
* `--readback <READBACK>` — Explicit view to read after Applied; its availability is reported separately
* `--readback-args <READBACK_ARGS>` — Named arguments for the explicitly selected readback view

  Default value: `{}`
* `--readback-gas-limit <READBACK_GAS_LIMIT>` — Independent positive gas budget for the readback view

  Default value: `1500000`



## `kagami package`

Publish native Musubi packages through an exact generated local environment

**Usage:** `kagami package <COMMAND>`

###### **Subcommands:**

* `publish` — Publish with original generated client/namespace intent and the canonical durable engine



## `kagami package publish`

Publish with original generated client/namespace intent and the canonical durable engine

**Usage:** `kagami package publish [OPTIONS] [MANIFEST]`

###### **Arguments:**

* `<MANIFEST>` — Package/workspace manifest or directory (defaults to the selected workspace)

###### **Options:**

* `--state <STATE>` — Private runtime store. By default each workspace has its own OS application-state directory
* `--workspace <WORKSPACE>` — Workspace whose managed context is selected (defaults to the current directory)
* `--json` — Emit one public JSON result; progress remains on stderr
* `--context <CONTEXT>` — Use this exact retained environment without changing workspace selection
* `--package <PACKAGE>` — Exact package when the workspace contains more than one selected member
* `--detach` — Return at the canonical durable seed-ingress boundary
* `--resume <RESUME>` — Continue one original publication operation; requires an existing selected context
* `--recover <RECOVER>` — Recover pristine package sidecars for one original operation; never creates a new context



## `kagami docker`

Generate validator-only Docker Compose from a prepared bundle or explicit dev seed

**Usage:** `kagami docker [OPTIONS] --peers <COUNT> --config-dir <DIR> --image <NAME> --out-file <FILE>`

###### **Options:**

* `-p`, `--peers <COUNT>` — Number of peer services in the configuration.

   Must be an exact Sumeragi `3f + 1` committee in the range 4..=31.
* `-s`, `--seed <SEED>` — Enable deterministic development mode with this UTF-8 validator seed.

   When omitted, `--config-dir` must be an authoritative prepared bundle containing `peerN.toml`, signed genesis, verifier-key, and exact-hash files. Production workflows should omit this option so Compose cannot generate identities that diverge from genesis.
* `-H`, `--healthcheck` — Includes a healthcheck for every service in the configuration.

   Healthchecks use predefined settings.

   For more details on healthcheck configuration in Docker Compose files, see: <https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck>
* `-c`, `--config-dir <DIR>` — Authoritative prepared validator/genesis bundle, or development manifest directory.

   Normal mode requires `genesis.json`, `peer0.toml` through `peerN.toml`, `genesis.signed.nrt`, `genesis.public_key`, and `genesis.expected_hash`. Kagami validates their canonical wire, signer, semantic manifest binding, exact hash, validator roster, and PoPs together. With `--seed`, only `genesis.json` is read and runtime artifact paths are supplied explicitly through the generated manifest's `IROHA_GENESIS_*_FILE` variables.
* `--peer-config <FILE>` — Optional TOML file describing peer names and port mappings. Only available with deterministic development `--seed` mode.

   The file must contain an array named `peers`, for example:

   ```toml [[peers]] name = "alpha" p2p_port = 2000 api_port = 9000 [[peers]] name = "beta" p2p_port = 2001 api_port = 9001 ```
* `-i`, `--image <NAME>` — Docker image used by the peer services.

   By default, the image is pulled from Docker Hub if not cached. Pass the `--build` option to build the image from a Dockerfile instead.

   The image must be built from the same Git revision as Kagami.
* `-b`, `--build <DIR>` — Build the image from the Dockerfile in the specified directory. Do not rebuild if the image has been cached.

   The provided path is resolved relative to the current working directory.
* `--no-cache` — Always pull or rebuild the image even if it is cached locally
* `-o`, `--out-file <FILE>` — Path to the target Compose configuration file.

   The file must be outside `--config-dir` and is published atomically.

   If the file exists, the app will prompt its overwriting. If the TTY is not interactive, the app will stop execution with a non-zero exit code. To overwrite the file anyway, pass the `--force` flag.
* `-P`, `--print` — Print the generated configuration to stdout instead of writing it to the target file.

   Note that the target path still needs to be provided, as it is used to resolve paths.
* `-F`, `--force` — Overwrite the target file if it already exists
* `--no-banner` — Do not include the banner with the generation notice in the file



## `kagami keys`

Generate cryptographic key pairs and optional validator Proofs-of-Possession

**Usage:** `kagami keys [OPTIONS] --out-dir <DIR>`

###### **Options:**

* `-a`, `--algorithm <ALGORITHM>` — An algorithm to use for the key-pair generation

  Default value: `ed25519`

  Possible values: `ed25519`, `secp256k1`, `ml-dsa`, `gost3410-2012-256-paramset-a`, `gost3410-2012-256-paramset-b`, `gost3410-2012-256-paramset-c`, `gost3410-2012-512-paramset-a`, `gost3410-2012-512-paramset-b`, `bls_normal`, `bls_small`

* `--seed-hex <HEX>` — A 32-byte secret key-generation seed encoded as 64 hexadecimal characters.

   This is for reproducible fixtures. Omit it for OS-random production keys.
* `--out-dir <DIR>` — Write the key pair into a new owner-only custody directory.

   The directory must be fresh. The complete key pair publishes atomically. Files are written as `public.key` and `private.key`; `--pop` also writes `pop.hex`. The private key never passes through standard output.
* `--pop` — Also output a BLS Proof-of-Possession (PoP) for this key (BLS-normal only). Written as `pop.hex` in the custody directory



## `kagami genesis`

Commands related to genesis

**Usage:** `kagami genesis <COMMAND>`

###### **Subcommands:**

* `sign` — Sign the genesis block
* `generate` — Generate a genesis configuration and standard-output in JSON format
* `materialize` — Materialize an incomplete source template with operator-provisioned public authority
* `validate` — Validate a genesis JSON file and report invalid identifiers
* `validate-prepared` — Verify one exact bound-manifest/signed-genesis/signer/hash bundle
* `embed-pop` — Embed one or more PoPs into a genesis JSON manifest (inline `topology` entries carrying `pop_hex`)
* `normalize` — Expand a genesis manifest and show the final ordered transactions



## `kagami genesis sign`

Sign the genesis block

**Usage:** `kagami genesis sign [OPTIONS] --private-key-file <PATH> <GENESIS_FILE>`

###### **Arguments:**

* `<GENESIS_FILE>` — Path to genesis json file

###### **Options:**

* `-o`, `--out-file <PATH>` — Path to signed genesis output file in canonical Norito wire format (stdout by default)
* `--bound-manifest-out <PATH>` — Persist the exact config-bound genesis manifest used to build the signed block. May point to `GENESIS_FILE` to replace the input only after binding succeeds
* `--expected-hash-out <PATH>` — Write the canonical checked NetworkId derived from the exact signed consensus-header hash as one line.

   Validators and clients must select this same file through `genesis.expected_hash_file` and `network_id_file`, respectively.
* `--replace-expected-hash <NETWORK_ID>` — Replace the expected-hash file only if it still contains this exact prior NetworkId. Requires all three output paths. The identity is published last as the bundle's commit marker; interrupted publication must be retried with the same prior identity
* `-t`, `--topology <TOPOLOGY>` — Use this topology instead of specified in genesis.json. JSON-serialized vector of `PeerId`. For use in `iroha_swarm`.

   The final unique topology must be an exact Sumeragi `3f + 1` committee in the range 4..=31.
* `--peer-pop <PEER_POPS>` — Embed one or more PoPs into the same transaction as `--topology`. Repeatable flag: `--peer-pop <public_key=pop_hex>`
* `--private-key-file <PATH>` — Owner-held mode-0600 file containing one canonical private-key multihash
* `--expected-public-key <PUBLIC_KEY>` — Public key that the selected private key must derive.

   Use this when the verifier key is distributed separately from the owner-held signing key, such as through container secrets.
* `--creation-time-ms <MILLISECONDS>` — Deterministic genesis transaction creation-time base in Unix milliseconds.

   Omit this for a fresh wall-clock timestamp. Fixture generators should set it so repeated signing produces identical canonical wire bytes.
* `--config <PATH>` — Optional peer config TOML used to derive the DA proof-policy bundle embedded into genesis



## `kagami genesis generate`

Generate a genesis configuration and standard-output in JSON format

**Usage:** `kagami genesis generate [OPTIONS] --ivm-dir <PATH> --genesis-public-key <MULTI_HASH> --kagemusha-mint-finality-parameters <PATH> [COMMAND]`

###### **Subcommands:**

* `default` — Generate default genesis
* `synthetic` — Generate synthetic genesis with the specified number of domains, accounts and assets

###### **Options:**

* `--profile <PROFILE>` — Optional profile: picks Iroha3 chain, cadence, consensus, and VRF defaults for dev/taira/nexus
* `--chain-id <CHAIN_ID>` — Optional explicit chain id. With a profile, it must equal that profile's pinned chain id
* `--vrf-seed-hex <HEX>` — Optional VRF seed (hex, 32 bytes). Required for the public `iroha3-taira`/`iroha3-nexus` profiles
* `--xor-asset-definition-id <BASE58>` — Canonical public XOR asset definition id (Base58). Required for `iroha3-nexus` NPoS manifests; `iroha3-taira` defaults to its live XOR id
* `--executor <PATH>` — Optional path (relative to output) to the executor bytecode file (.to). If omitted, no executor upgrade is included in genesis
* `--ivm-dir <PATH>` — Relative path from the directory of output file to the directory that contains IVM bytecode libraries
* `--genesis-public-key <MULTI_HASH>`
* `--kagemusha-mint-finality-parameters <PATH>` — Path to the explicitly provisioned public KAGEMUSHA mint-finality genesis parameters
* `--ivm-gas-limit-per-block <U64>` — Optional: set the custom parameter `ivm_gas_limit_per_block` (u64) in genesis so all peers agree on the block gas budget. If omitted, a sensible default (1,680,000) is applied
* `--consensus-mode <MODE>` — Select the consensus mode snapshot to seed in the genesis parameters (default: permissioned; profiles that require NPoS select it themselves)

  Possible values: `permissioned`, `npos`

* `--lane-policy <PATH>` — Optional path to a JSON Sumeragi lane policy (fixed lanes, routes, autoscale) to set in genesis. If omitted, the chain has lane 0 only until governance sets a policy
* `--sm-openssl-preview <BOOL>` — Toggle the OpenSSL-backed SM preview helpers in the generated manifest

  Possible values: `true`, `false`

* `--default-hash <HASH>` — Override the default hash advertised in the manifest
* `--allowed-signing <ALGO>` — Replace the allowed signing algorithms (repeat flag to supply multiple values)

  Possible values: `ed25519`, `secp256k1`, `sm2`

* `--sm2-distid-default <DISTID>` — Override the fallback SM2 distinguishing identifier
* `--allowed-curve-id <CURVE_ID>` — Override the allowed curve identifiers (repeat flag to supply multiple values)



## `kagami genesis generate default`

Generate default genesis

**Usage:** `kagami genesis generate default`



## `kagami genesis generate synthetic`

Generate synthetic genesis with the specified number of domains, accounts and assets.

Synthetic mode is useful when we need a semi-realistic genesis for stress-testing Iroha's startup times as well as being able to just start an Iroha network and have instructions that represent a typical blockchain after migration.

**Usage:** `kagami genesis generate synthetic [OPTIONS]`

###### **Options:**

* `--domains <DOMAINS>` — Number of domains in synthetic genesis

  Default value: `0`
* `--accounts-per-domain <ACCOUNTS_PER_DOMAIN>` — Number of accounts per domains in synthetic genesis. The total number of accounts would be `domains * accounts_per_domain`

  Default value: `0`
* `--asset-definitions-per-domain <ASSET_DEFINITIONS_PER_DOMAIN>` — Number of asset definitions per domain in synthetic genesis. The total number of asset definitions would be `domains * asset_definitions_per_domain`

  Default value: `0`



## `kagami genesis materialize`

Materialize an incomplete source template with operator-provisioned public authority

**Usage:** `kagami genesis materialize [OPTIONS] --kagemusha-mint-finality-parameters <PATH> <TEMPLATE_FILE>`

###### **Arguments:**

* `<TEMPLATE_FILE>` — Incomplete genesis source file; the name must end in `.template.json`

###### **Options:**

* `--kagemusha-mint-finality-parameters <PATH>` — Explicitly provisioned public KAGEMUSHA mint-finality genesis parameters
* `--xor-asset-definition-id <ASSET_DEFINITION_ID>` — Explicit canonical XOR definition committed by an NPoS source template



## `kagami genesis validate`

Validate a genesis JSON file and report invalid identifiers

**Usage:** `kagami genesis validate <GENESIS_FILE>`

###### **Arguments:**

* `<GENESIS_FILE>` — Path to genesis json file



## `kagami genesis validate-prepared`

Verify one exact bound-manifest/signed-genesis/signer/hash bundle

**Usage:** `kagami genesis validate-prepared [OPTIONS] --reviewed-manifest <PATH> --validator-roster <PATH> --bound-manifest <PATH> --pre-sign-manifest <PATH> --signed-genesis <PATH> --genesis-public-key <PUBLIC_KEY> --expected-hash <HASH>`

###### **Options:**

* `--reviewed-manifest <PATH>` — Exact reviewed NEVO genesis before validator rendering
* `--validator-roster <PATH>` — Exact public validator roster used by the renderer
* `--bound-manifest <PATH>` — Exact config-bound genesis manifest used by the external signer
* `--pre-sign-manifest <PATH>` — Exact renderer output accepted by the external signer before config binding
* `--signed-genesis <PATH>` — Exact signed genesis in canonical framed Norito form
* `--peer-config <PATH>` — Effective validator configs whose complete roster and policy must reproduce the signed context. Repeat exactly four times in `taira-validator-1` through `-4` order
* `--genesis-public-key <PUBLIC_KEY>` — Public key of the independently provisioned genesis signer
* `--expected-hash <HASH>` — Exact signed genesis block-header hash



## `kagami genesis embed-pop`

Embed one or more PoPs into a genesis JSON manifest (inline `topology` entries carrying `pop_hex`)

**Usage:** `kagami genesis embed-pop [OPTIONS] --manifest <MANIFEST> --out <OUT>`

###### **Options:**

* `--manifest <MANIFEST>` — Input genesis JSON file (RawGenesisTransaction)
* `--out <OUT>` — Output file path
* `--peer-pop <PEER_POPS>` — Peer PoP entries in the form `public_key=hex`



## `kagami genesis normalize`

Expand a genesis manifest and show the final ordered transactions

**Usage:** `kagami genesis normalize [OPTIONS] <GENESIS_FILE>`

###### **Arguments:**

* `<GENESIS_FILE>` — Path to genesis json file

###### **Options:**

* `--format <FORMAT>` — Output format (`json` for structured output, `text` for a compact summary)

  Default value: `json`

  Possible values: `json`, `text`




## `kagami privacy-bootstrap`

Emit and validate fail-closed Taira exact-12 privacy bootstrap artifacts

**Usage:** `kagami privacy-bootstrap <COMMAND>`

###### **Subcommands:**

* `emit-taira-v1` — Emit one height-1 template of twelve ordered registration/activation pairs
* `validate-taira-v1` — Validate an emitted exact-12 instruction set and its digest inventory
* `validate-taira-nevo-review-v1` — Validate a reviewed Taira NEVO genesis source template without creating release artifacts
* `render-taira-release-v1` — Compose a secret-free Taira release plan, config, and non-signable genesis source template



## `kagami privacy-bootstrap emit-taira-v1`

Emit one height-1 template of twelve ordered registration/activation pairs

**Usage:** `kagami privacy-bootstrap emit-taira-v1 --instructions-output <INSTRUCTIONS_OUTPUT> --report-output <REPORT_OUTPUT>`

###### **Options:**

* `--instructions-output <INSTRUCTIONS_OUTPUT>` — New file receiving the canonical governance-template instruction array
* `--report-output <REPORT_OUTPUT>` — New file receiving base64 Norito instructions and deterministic digests



## `kagami privacy-bootstrap validate-taira-v1`

Validate an emitted exact-12 instruction set and its digest inventory

**Usage:** `kagami privacy-bootstrap validate-taira-v1 --instructions <INSTRUCTIONS> --report <REPORT>`

###### **Options:**

* `--instructions <INSTRUCTIONS>` — Canonical genesis instruction JSON array emitted by this command group
* `--report <REPORT>` — Canonical digest inventory emitted alongside the instruction array



## `kagami privacy-bootstrap validate-taira-nevo-review-v1`

Validate a reviewed Taira NEVO genesis source template without creating release artifacts

**Usage:** `kagami privacy-bootstrap validate-taira-nevo-review-v1 --unsigned-genesis <UNSIGNED_GENESIS> --review <REVIEW>`

###### **Options:**

* `--unsigned-genesis <UNSIGNED_GENESIS>` — Exact non-signable NEVO genesis source template bound by the review manifest
* `--review <REVIEW>` — Deterministic public NEVO review manifest binding the genesis source template



## `kagami privacy-bootstrap render-taira-release-v1`

Compose a secret-free Taira release plan, config, and non-signable genesis source template

**Usage:** `kagami privacy-bootstrap render-taira-release-v1 --activation-instructions <ACTIVATION_INSTRUCTIONS> --activation-report <ACTIVATION_REPORT> --broker-public-export <BROKER_PUBLIC_EXPORT> --plan-template <PLAN_TEMPLATE> --config-template <CONFIG_TEMPLATE> --genesis-template <GENESIS_TEMPLATE> --nevo-review <NEVO_REVIEW> --plan-output <PLAN_OUTPUT> --config-output <CONFIG_OUTPUT> --genesis-output <GENESIS_OUTPUT> --broker-public-output <BROKER_PUBLIC_OUTPUT>`

###### **Options:**

* `--activation-instructions <ACTIVATION_INSTRUCTIONS>` — Exact-12 instruction JSON emitted by `emit-taira-v1`
* `--activation-report <ACTIVATION_REPORT>` — Digest report emitted together with the exact-12 instructions
* `--broker-public-export <BROKER_PUBLIC_EXPORT>` — Canonical public JSON emitted by the qualified peer-1 broker
* `--plan-template <PLAN_TEMPLATE>` — Canonical disabled Taira privacy plan template
* `--config-template <CONFIG_TEMPLATE>` — Canonical disabled peer-1 Taira config template
* `--genesis-template <GENESIS_TEMPLATE>` — Canonical non-signable Taira genesis source template without privacy bootstrap instructions
* `--nevo-review <NEVO_REVIEW>` — Deterministic public NEVO review manifest binding the genesis template
* `--plan-output <PLAN_OUTPUT>` — Fresh output path for the complete public release plan
* `--config-output <CONFIG_OUTPUT>` — Fresh output path for the complete peer-1 release config
* `--genesis-output <GENESIS_OUTPUT>` — Fresh `.template.json` output path for the overlaid release genesis source template
* `--broker-public-output <BROKER_PUBLIC_OUTPUT>` — Fresh output path for the verified canonical public broker export



## `kagami verify`

Verify a genesis manifest against a preset profile

**Usage:** `kagami verify [OPTIONS] --profile <PROFILE> --genesis <PATH>`

###### **Options:**

* `--profile <PROFILE>` — Profile to verify against (`iroha3-dev`, `iroha3-taira`, `iroha3-nexus`)
* `--genesis <PATH>` — Path to the genesis manifest (JSON)
* `--vrf-seed-hex <HEX>` — Optional VRF seed (hex, 32 bytes). Required for NPoS taira/nexus manifests



## `kagami advanced`

Advanced low-level helpers for codec conversion, schema generation, block inspection, and docs

**Usage:** `kagami advanced <COMMAND>`

###### **Subcommands:**

* `network-bootstrap` — Prepare signed remote-network bootstrap and native installation authorities offline
* `client-configs` — Generate per-client CLI configs from a base client.toml
* `codec` — Commands related to Norito codec conversions
* `kura` — Commands related to block inspection
* `markdown-help` — Output CLI documentation in Markdown format
* `schema` — Generate the schema used for code generation in Iroha SDKs



## `kagami advanced network-bootstrap`

Prepare signed remote-network bootstrap and native installation authorities offline

**Usage:** `kagami advanced network-bootstrap <COMMAND>`

###### **Subcommands:**

* `prepare` — Verify pinned genesis/proofs and atomically prepare canonical public release artifacts



## `kagami advanced network-bootstrap prepare`

Verify pinned genesis/proofs and atomically prepare canonical public release artifacts

**Usage:** `kagami advanced network-bootstrap prepare [OPTIONS] --genesis-manifest <GENESIS_MANIFEST> --expected-genesis-manifest-sha256 <EXPECTED_GENESIS_MANIFEST_SHA256> --signed-genesis <SIGNED_GENESIS> --genesis-public-key <GENESIS_PUBLIC_KEY> --expected-network-id <EXPECTED_NETWORK_ID> --proof-json <PROOF_JSON> --network-name <NETWORK_NAME> --serial <SERIAL> --generation <GENERATION> --issued-at-ms <ISSUED_AT_MS> --expires-at-ms <EXPIRES_AT_MS> --torii-root <TORII_ROOT> --peer <PEER> --checkpoint-url <CHECKPOINT_URL> --release-public-key <RELEASE_PUBLIC_KEY> --release-key-file <RELEASE_KEY_FILE> --output-dir <OUTPUT_DIR>`

###### **Options:**

* `--genesis-manifest <GENESIS_MANIFEST>` — Exact manifest semantically bound to the independently authenticated signed genesis
* `--expected-genesis-manifest-sha256 <EXPECTED_GENESIS_MANIFEST_SHA256>` — Manifest SHA256 authenticated independently, for example by native public-inputs metadata
* `--signed-genesis <SIGNED_GENESIS>` — Original canonical signed genesis, selected independently of peer responses
* `--genesis-public-key <GENESIS_PUBLIC_KEY>` — Independently selected public key that must authenticate the complete genesis
* `--expected-network-id <EXPECTED_NETWORK_ID>` — Independently selected exact genesis-derived network identity
* `--proof-json <PROOF_JSON>` — Existing typed finality-proof JSON, repeated in contiguous height order from 1 through N
* `--network-name <NETWORK_NAME>` — Exact installed network selection; no official label is inferred
* `--serial <SERIAL>` — Official monotonic publication serial and resulting installation rollback floor
* `--generation <GENERATION>` — Explicit monotonic reset generation for this signed genesis
* `--issued-at-ms <ISSUED_AT_MS>` — Inclusive release validity start in Unix milliseconds
* `--expires-at-ms <EXPIRES_AT_MS>` — Exclusive expiry; native policy caps validity at one day
* `--torii-root <TORII_ROOT>` — Approved canonical HTTPS parent root; repeat for each selected root
* `--peer <PEER>` — Exact BLS public key and approved root as PUBLIC_KEY=HTTPS_ROOT; repeat for every member
* `--checkpoint-url <CHECKPOINT_URL>` — Independently selected canonical HTTPS location where checkpoint.nrt will be published
* `--release-public-key <RELEASE_PUBLIC_KEY>` — Independently selected release public key; must match the native signing file
* `--release-key-file <RELEASE_KEY_FILE>` — Absolute native owner-only canonical release signing-key file (mode 0400 or 0600)
* `--faucet-root <FAUCET_ROOT>` — Optional approved testnet faucet root; all allowance fields must be supplied together
* `--faucet-issuer <FAUCET_ISSUER>` — Independently authenticated single-key faucet issuer
* `--faucet-asset <FAUCET_ASSET>` — Exact sole currency available for automatic fees and namespace rent
* `--faucet-amount <FAUCET_AMOUNT>` — Positive allowance supplied by one testnet faucet claim
* `--max-operation-fee <MAX_OPERATION_FEE>` — Finite maximum aggregate fees for one managed parent operation
* `--max-namespace-rent <MAX_NAMESPACE_RENT>` — Finite maximum combined dataspace and owner-alias one-year namespace rent
* `--build-registry-root <BUILD_REGISTRY_ROOT>` — Optional approved parent build-registry root; repeat for selected roots
* `--output-dir <OUTPUT_DIR>` — Fresh directory beneath an existing safe owner-held parent; outputs publish together



## `kagami advanced client-configs`

Generate per-client CLI configs from a base client.toml

**Usage:** `kagami advanced client-configs [OPTIONS] --base-config <PATH> --names <NAME>`

###### **Options:**

* `--base-config <PATH>` — Base client config to copy the chain, exact network identity, account network context, Torii URL, and credentials from
* `--out-dir <DIR>` — Output directory for generated client configs (default: <base-config-dir>/clients)
* `--seed-hex <HEX>` — A 32-byte secret master seed encoded as 64 hexadecimal characters.

   Per-client keys are derived with an explicit domain and client name. Omit this option for independent operating-system-random keys.
* `--names <NAME>` — Comma-separated list of client names



## `kagami advanced codec`

Commands related to Norito codec conversions

**Usage:** `kagami advanced codec <COMMAND>`

###### **Subcommands:**

* `list-types` — Show all available types
* `norito-to-rust` — Decode Norito to Rust debug format from binary file
* `norito-to-json` — Decode Norito to JSON. By default uses stdin and stdout
* `json-to-norito` — Encode JSON as Norito. By default uses stdin and stdout



## `kagami advanced codec list-types`

Show all available types

**Usage:** `kagami advanced codec list-types`



## `kagami advanced codec norito-to-rust`

Decode Norito to Rust debug format from binary file

**Usage:** `kagami advanced codec norito-to-rust [OPTIONS] <BINARY>`

###### **Arguments:**

* `<BINARY>` — Path to the binary with encoded Iroha structure

###### **Options:**

* `-t`, `--type <TYPE_NAME>` — Type that is expected to be encoded in binary. If not specified then a guess will be attempted



## `kagami advanced codec norito-to-json`

Decode Norito to JSON. By default uses stdin and stdout

**Usage:** `kagami advanced codec norito-to-json [OPTIONS] --type <TYPE_NAME>`

###### **Options:**

* `-i`, `--input <INPUT>` — Path to the input file
* `-o`, `--output <OUTPUT>` — Path to the output file
* `-t`, `--type <TYPE_NAME>` — Type that is expected to be encoded in input



## `kagami advanced codec json-to-norito`

Encode JSON as Norito. By default uses stdin and stdout

**Usage:** `kagami advanced codec json-to-norito [OPTIONS] --type <TYPE_NAME>`

###### **Options:**

* `-i`, `--input <INPUT>` — Path to the input file
* `-o`, `--output <OUTPUT>` — Path to the output file
* `-t`, `--type <TYPE_NAME>` — Type that is expected to be encoded in input



## `kagami advanced kura`

Commands related to block inspection

**Usage:** `kagami advanced kura <COMMAND>`

###### **Subcommands:**

* `beacon-history` — Project bounded typed public beacon candidates, with explicit coverage limits
* `print` — Print contents of a certain length of the blocks
* `finality` — Verify a locally anchored retained prefix and export its exact finality proof
* `sidecar` — Print the pipeline recovery sidecar JSON for a given height



## `kagami advanced kura beacon-history`

Project bounded typed public beacon candidates, with explicit coverage limits

**Usage:** `kagami advanced kura beacon-history [OPTIONS] --from <BLOCK_HEIGHT> --length <LENGTH> <PATH_TO_BLOCK_STORE>`

###### **Arguments:**

* `<PATH_TO_BLOCK_STORE>` — Exact lane directory containing the canonical block journals

###### **Options:**

* `-f`, `--from <BLOCK_HEIGHT>` — First block height in the exact inspection interval
* `--length <LENGTH>` — Exact number of blocks, from the --from height (1..=4096)
* `-o`, `--output <OUTPUT>` — Write bounded JSON outside the inspected store; defaults to stdout



## `kagami advanced kura print`

Print contents of a certain length of the blocks

**Usage:** `kagami advanced kura print [OPTIONS] <PATH_TO_BLOCK_STORE>`

###### **Arguments:**

* `<PATH_TO_BLOCK_STORE>` — Exact lane directory containing the canonical block journals

###### **Options:**

* `-f`, `--from <BLOCK_HEIGHT>` — Height of the block from which start the inspection. Defaults to the latest block height
* `-n`, `--length <LENGTH>` — Number of the blocks to print. The excess will be truncated

  Default value: `1`
* `-o`, `--output <OUTPUT>` — Where to write the results of the inspection If omitted, writes to stdout



## `kagami advanced kura finality`

Verify a locally anchored retained prefix and export its exact finality proof

**Usage:** `kagami advanced kura finality [OPTIONS] --chain-id <CHAIN_ID> --height <HEIGHT> <PATH_TO_BLOCK_STORE>`

###### **Arguments:**

* `<PATH_TO_BLOCK_STORE>` — Exact lane directory containing the canonical block journals

###### **Options:**

* `--chain-id <CHAIN_ID>` — Exact chain label used to derive the native consensus instance
* `-H`, `--height <HEIGHT>` — Verify all heights from genesis through this height (1..=4096)
* `-o`, `--output <OUTPUT>` — Write the public JSON outside the inspected store (default: stdout)



## `kagami advanced kura sidecar`

Print the pipeline recovery sidecar JSON for a given height

**Usage:** `kagami advanced kura sidecar [OPTIONS] --height <HEIGHT> <PATH_TO_BLOCK_STORE>`

###### **Arguments:**

* `<PATH_TO_BLOCK_STORE>` — Exact lane directory containing the canonical block journals

###### **Options:**

* `-H`, `--height <HEIGHT>` — The block height whose sidecar to print
* `-o`, `--output <OUTPUT>` — Where to write the sidecar JSON (default: stdout)



## `kagami advanced markdown-help`

Output CLI documentation in Markdown format

**Usage:** `kagami advanced markdown-help`



## `kagami advanced schema`

Generate the schema used for code generation in Iroha SDKs

**Usage:** `kagami advanced schema [OPTIONS]`

###### **Options:**

* `--genesis-out <GENESIS_OUT>` — Optional path to output genesis schema



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
