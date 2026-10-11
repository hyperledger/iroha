//! Deployment engine for Iroha networks and dataspaces.
//!
//! [`managed`] provides configuration-free persistent developer environments to Kagami
//! and Mochi. Advanced operator definitions remain available through [`definition`],
//! whose typed parsers use `iroha_config_base` to identify invalid files/keys and reject
//! unknown settings. The deployment contracts are in `specs/network_deployment.md`
//! and `specs/kagami_mochi_devex_goals.md`.
//!
//! [`verify::finality`] is the light finality verifier behind gate G5. It is anchored in an
//! authenticated signed genesis or a stored `SumeragiFinalityCheckpoint`,
//! verifies every contiguous certified successor with the data model's native
//! verifier, including each epoch handoff, and requires fresh challenge-bound
//! attestations from `2f + 1` members of the authenticated committee. [`verify::http`]
//! supplies bounded concurrent native SDK reads. [`bootstrap`] authenticates release-signed
//! checkpoint material against independently installed authority and retains rollback protection.
//! [`attachment`] retains compact parent inclusion receipts for the exact private child and SNS
//! owner. Its confirmed cursor advances only after independent native parent verification and
//! durable publication; a locally finalized child block remains a separate fact.
//!
//! [`managed`] owns persistent developer contexts and the native localnet process lifecycle.
//! Canonical node/genesis generation is owned by [`localnet`]; subsequent
//! starts retain the same network identity, signers and ledger. Kagami and Mochi use the same
//! bounded owner-authenticated local control protocol and signed readiness checks.
//!
//! Later phases add planning and the decision hash, the converge executor and
//! its journal, the local, container and SSH drivers, and the remaining
//! verification gates.
// TODO: Complete remote private-root provisioning/relaying and release qualification.
// Operator P2 adds `plan`, `converge` and gates G0-G8/G11; P3 adds SSH and edge renderers
// (specs/network_deployment.md §13).

mod deploy_mutation_guard;

pub mod attachment;
pub mod bootstrap;
pub mod definition;
pub mod genesis;
pub mod localnet;
pub mod managed;
pub mod provisioning;
pub mod secret_toml;
pub mod shell;
pub mod verify;

#[cfg(test)]
mod service_checked_writer_test_support;
