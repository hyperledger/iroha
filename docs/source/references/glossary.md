# Glossary

//TODO: add links to docs.rs

Definitions of all Iroha-related entities can be found here.

## Iroha Query

Iroha read-only request to the [World State View](#world-state-view).

## Iroha Special Instruction

Iroha provides a library of smart contracts called Iroha Special Instructions (ISI).
To execute some logic on the ledger, these smart contracts can be invoked via either transactions or registered event listeners.

### Out of the Box Iroha Special Instruction

Iroha provides several basic Instructions for utility purposes or domain-related functionality out-of-the-box:

#### Utility Iroha Special Instruction

This set contains logical instructions like `If`, I/O related like `Notify` and compositions like `Sequence`.
They are mostly used by [custom Instructions](#custom-iroha-special-instruction).

#### Domain-related Iroha Special Instruction

This set contains domain-related instructions (asset/account/domain/peer) and provides the opportunity to make changes to the [World State View](#world-state-view) safely.

### Custom Iroha Special Instruction

These Instructions provided by [Iroha Modules](#todo), clients or 3rd parties.
They can  only be build on top of [the Out of the Box Instructions](#out-of-the-box-iroha-special-instruction).

## World State View

In-memory representation of the current blockchain state.
