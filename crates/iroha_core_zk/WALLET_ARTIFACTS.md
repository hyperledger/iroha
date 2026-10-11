# Wallet Artifact Producer

`kagemusha_wallet_artifacts` packages the current wallet circuit catalog through
`OfflineCompilerV1::wallet_pack` and the existing root-certificate and
artifact-manifest signing methods. Ordinary Load finality is verified directly
from native BLS commit certificates; wallet compilation needs no finality
circuits, proving keys, verifier catalog or server proof service.

Build the packaging binary without `test-utils`:

```sh
scripts/cargo_fast.sh --stable-local-metadata -- build --locked -p iroha_core_zk --features dev-tools --bin kagemusha_wallet_artifacts
kagemusha_wallet_artifacts --request /absolute/private/inputs/request.json
```

The closed JSON request contains these fields:

| Field | Selected Original |
| --- | --- |
| `schema` | `iroha.kagemusha.wallet-artifact-production.v1` |
| `chain_id`, `network_id_hex`, `genesis_public_key` | Actual signed genesis and its Ed25519 authority; the network derives from its header. |
| `signed_genesis` | `{ "path": "/absolute/original", "sha256": "64 lowercase hex digits" }` |
| `custody_directory` | Existing private recovery directory with `scheme-root.pkcs8.der` and `artifact.pkcs8.der`. |
| `scheme_root_public_key_hex`, `enrollment_public_key_hex`, `artifact_public_key_hex` | Independently selected, distinct uncompressed P-256 public points. |
| `output_parent`, `output_name` | Existing private parent and a fresh child name. |
| `maximum_total_bytes` | Positive wallet-original storage ceiling, at most 128 GiB. |

Input paths are absolute and canonical, without symlinks. The request and genesis
are immutable `0400` single-link files in private directories. Private-key reads
use `iroha_fs` custody and zeroized buffers; keys are never generated or replaced.
Public originals are rechecked before and after signing. Partial output survives
failure.

The wallet compiler uses the maintained 65,536-row source geometry, on-demand
coset tables and the default 64 MiB MSM scratch budget. These wallet-circuit
limits do not measure process RSS or establish device performance.

After compilation returns its completed draft, the command issues Enrollment and
Artifact certificates with serial 1. It authenticates the manifest signatures,
reloads the verifier pack, qualifies every wallet source, and binds its native
receipt verifier to the independently selected signed global genesis. Packaging
does not install a wallet, register a scheme, submit a transaction or admit a release.

The output retains Scheme, certificate and manifest originals, the exact public
request and signed genesis, and `compiler-cache`. The deployment `carrier/`
contains the verifier pack, producer inventory, transport and financial-original
metadata, and the closed `wallet-originals` directory. Provisional compiler
originals are excluded from the carrier.

## Native Load Finality

`GET /v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/finality` requires
canonical payer authentication, an empty body and
`Accept: application/x-norito`. It reads the payer's committed receipt and native
event, then returns `KagemushaWalletLoadFinalityV1`: the receipt block's original
BLS commit certificate and counted receipt-event Merkle proof. No historical
prefix is included. The server reads exactly the selected durable frame and
borrows the canonical header and certificate fields without decoding transaction
or execution-output graphs. The original wire, fixed certificate-sized selector
allowance, bounded certificate decoding and response remain charged to the request pool. It returns DATA, not a finality
capability or a validation of the skipped body fields.

The phone verifies the exact receipt digest and event inclusion against the BLS
quorum and authenticated epoch authority before signing Load Advance. Epoch
successors are synchronized through
`GET /v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/epochs/{boundary}`.
Each response is one raw canonical `SumeragiCommitCertificateV1`, selected by the
next boundary height from the phone's authenticated epoch owner. The server
checks that this is a boundary before the receipt height, but does not follow
unverified successors or accept a caller-provided roster. The phone authenticates
the incumbent quorum before retaining its successor, then requests the next
boundary until the receipt height is covered. No publisher,
Torii server or artifact signer substitutes for the native validator quorum.

Responses are private/no-store and use existing query admission, memory and
`torii.proof_api.request_timeout` bounds. Missing, refused or unavailable evidence
returns HTTP 503 `kagemusha_load_finality_unavailable`. There is no asynchronous
proving queue, finality storage initialization command or finality-specific server
configuration. The retired `finality-proof` endpoint and prover configuration
are rejected rather than supported through aliases.

The native evidence frame and each epoch page are bounded to 256 KiB; a longer
epoch history is synchronized through separate pages and cannot enlarge the
terminal receipt frame. This does not alter the peer Payment size bound.
Native verification and wallet source tests are
component evidence. Complete installation, financial workflow and physical-device
qualification remain separate checks.
