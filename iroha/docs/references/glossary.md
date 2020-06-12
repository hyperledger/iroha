# Glossary

//TODO: add links to docs.rs

Definitions of all Iroha related entities names can be found here.

## Iroha Query

Iroha read-only requests to the [World State View](#world-state-view).

## Iroha Special Instruction

Iroha provides a library of smart contracts called Iroha Special Instructions (ISI).
To execute logic on the ledger, these smart contracts can be invoked via either transactions or 
registered event listeners.

### Out of the Box Iroha Special Instruction

Out of the Box Iroha provides several basic Instructions for utility purposes or domains
related functionality.

#### Utilitary Iroha Special Instruction

This set contains logical instructions like `If`, I/O related like `Notify` and compositions
like `Sequence`. They are mostly used by [custom Instructions](#custom-iroha-special-instruction).

#### Domains related Iroha Special Instruction

This set contains domains related instructions (asset/account/domain/peer) and provides
an ability to make changes to the [World State View](#world-state-view) in a safe way.

### Custom Iroha Special Instruction

These Instructions are provided by [Iroha Modules](#todo), clients or 3rd parties. They can be only
build on top of (Out of the Box Instructions)[#out-of-the-box-iroha-special-instruction].

## World State View

In-memory representation of the current blockchain state.
