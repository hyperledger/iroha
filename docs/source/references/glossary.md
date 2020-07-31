# Glossary

//TODO: add links to docs.rs

Definitions of all Iroha-related entities can be found here.

## DEX

A decentralized exchange (DEX) is a marketplace for cryptocurrencies or blockchain investments
that is totally open sourced. Nobody is in control at a DEX, instead buyers and sell deal with
each other on a one-on-one basis via peer-peer (P25) trading applications. [source](http://cryptoincome.io/dex-decentralized-exchange/)

In Iroha DEX represented as a [module](#iroha_module) with a set of Iroha Special Instructions and Queries.

### Order

Is a proposal to transfer (to or from) some [assets](#asset) inside Iroha implemented via [trigger](#trigger).

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

## Trigger

Triggers are Iroha Special Instructions registered on [peer](#peer). Their execution depends on some conditions,
for example on the blockchain height, time or [query](#iroha-query) result.
