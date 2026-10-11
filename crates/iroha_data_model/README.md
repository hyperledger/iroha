# Iroha Data Model

Core data structures for the Hyperledger Iroha blockchain.

Chain labels, domain, topology and peer identities, names, state paths, metadata and parsing errors are owned by
`iroha_model_base`. Import `iroha_model_base::chain::ChainId`,
`iroha_model_base::domain::DomainId`,
`iroha_model_base::name::Name`, `iroha_model_base::state_path::StatePath`,
`iroha_model_base::metadata::Metadata`, `iroha_model_base::error::ParseError` and
`iroha_model_base::topology::{DataSpaceId, LaneId, ShardId, LaneIdError}` and
`iroha_model_base::peer::PeerId` directly. The `peer::Peer` ledger entity remains here. Ledger composition and the
complete built-in registry remain here. `NetworkId` retains the exact
genesis-block-header hash and remains part of ledger composition. The mixed `base_wire_fixtures` tests
preserve their declared frame identities across this compilation boundary.

## Dependency boundary

The model and its tests must remain independent of node execution, node
configuration, telemetry implementations and storage runtimes. ABI hash, pointer
validation and AXT interoperability tests belong in the owning
`ivm_abi` crate, which depends on Model. Model codec tests use the shared test-only
ABI-v1 golden authenticated there; Model has no reverse development dependency.
Engine execution tests belong in IVM or Core.

Run `python3 scripts/check_dependency_budget.py --check-boundaries --offline`
from the repository root to validate the feature-resolved normal/build graph
and the default/HTTP model graph including its root development dependencies.

Protocol JSON is always available, including with `default-features = false`.
Custom parameters, admission and consensus policies, and retained service metadata
use canonical Norito JSON. Optional governance, HTTP and cryptographic capability
features remain independent of this protocol requirement.

## Native bindings

The crate exports no C ABI of its own. Swift, Kotlin/Java, JavaScript and
Python consumers use the hand-written native bridges (`connect_norito_bridge`,
`iroha_js_host`, `iroha_python_rs`) with Norito as the wire contract.

## Trait Objects

Many parts of the data model operate on trait objects to allow mixing different
instruction and query types. The [`InstructionBox`] type wraps a
`Box<dyn Instruction>` and the [`QueryBox`] alias wraps a `Box<dyn Query + Send + Sync>`.

```rust
use iroha_data_model::prelude::*;

let instruction: InstructionBox = InstructionBox::from(
    Log::new(Level::INFO, "trait objects".into())
);
let query: QueryBox<Account> = Box::new(FindAccounts);
```

## Formal Verification

The [`verification`](src/verification.rs) module provides deterministic checks for
structural invariants across domains, accounts, asset definitions, and live asset
holdings. Construct a [`WorldSnapshot`] from your in-memory state and call
[`WorldSnapshot::verify`] to obtain a [`VerificationReport`] summarizing the
results, including detailed violation messages when invariants are broken.
