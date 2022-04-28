# Table of contents

- [Glossary](#glossary)
  - [Asset](#asset)
  - [Byzantine fault-tolerance (BFT)](#byzantine-fault-tolerance-bft)
  - [Leader](#leader)
  - [World state view (WSV)](#world-state-view-wsv)
  - [View change](#view-change)
  - [Iroha Query](#iroha-query)
  - [Iroha Special Instruction (ISI)](#iroha-special-instruction-isi)
  - [Iroha Components](#iroha-components)
  - [Iroha modules](#iroha-modules)

# Glossary

Definitions of all Iroha-related entities can be found here.

## Asset

A representation of a valuable object on the blockchain.


## Byzantine fault-tolerance (BFT)
The property of being able to properly function with a network containing a certain percentage of malicious actors. Iroha is capable of functioning with up to 33% malicious actors in its peer-to-peer network.

## Leader
In an iroha network a peer is selected randomly and granted the special privilege of forming the next block. This privilege can be revoked in networks that achieve [Byzantine fault-torelance](#bft) via [view change](#view-change).

## World state view (WSV)
In-memory representation of the current blockchain state. This includes all currently loaded blocks, with all of their contents, as well as peers elected for the current epoch.

## View change
A process that takes place in case of a failed attempt at consensus. Usually this entails the election of a new [Leader](#leader).

## Iroha Query
A request to read the World State View without modifying said view.

## Iroha Special Instruction (ISI)
A library of smart contracts provided with Iroha.  These can be invoked via either transactions or registered event listeners.

#### Utility Iroha special instruction
This set of [isi](#isi) contains logical instructions like `If`, I/O related like `Notify` and compositions like `Sequence`.  They are mostly used by [custom Instructions](#custom-iroha-special-instruction).

### Core Iroha Special Instruction
[Special instructions](#isi) provided with every Iroha deployment.  These include some [domain-specific](#dsisi) as well as [utility instructions](#utility).

### Domain-specific Iroha Special Instruction
Instructions related to domain-specific activities: (asset/account/domain/peer management).  These provide the tools necessary to make changes to the [World State View](#wsv) in a secure and safe manner.

### Custom Iroha Special Instruction
Instructions provided in [Iroha Modules](#mod), by clients or 3rd parties.  These can only be built using [the Core Instructions](#core).  Forking and modifying the Iroha source code is not recommended, as special instructions not agreed-upon by peers in an Iroha deployment will be treated as faults, thus  peers running a modified instance will have their access revoked.

## Iroha Components
Rust modules containing Iroha's functionality.

### Sumeragi (Emperor)
The Iroha module responsible for consensus.

### Torii (Gate)
Module with the incoming request handling logic for the peer. It is used to receive, accept and route incoming instructions, and HTTP queries, as well as run-time configuration updates.

### Kura (Warehouse)
Persistence-related logic. It handles storing the blocks, log rotation, block storage folder rotation etc.

### Kagami(Teacher and Exemplar and/or looking glass)
Generator for commonly used data. Can generate cryptographic key pairs, genesis blocks, documentation etc.

### Merkle tree (hash tree)
A data structure used to validate and verify the state at each block height. Iroha's current implementation is a binary tree. See [Wikipedia](https://en.wikipedia.org/wiki/Merkle_tree) for more details.

### Smart contracts
Smart contracts are blockchain-based programs that run when a specific set of conditions is met. In Iroha smart contracts are implemented using core Iroha special instructions.

### Triggers
An event type that allows invoking an Iroha special instruction at specific block commit, time (with some caveats) etc. More details can be found on our dedicated [wiki page](https://wiki.hyperledger.org/display/iroha/Triggers).

### Versioning
Each request is labelled with the API version to which it belongs. It allows a combination of different binary versions of Iroha client/peer software to interoperate, which in turn allows software upgrades in the Iroha network.

### Hijiri (peer reputation system)
Iroha's reputation system. It allows prioritising communication with peers that have a good track-record, and reducing the harm that can be caused by malicious peers.

## Iroha modules
Third party extensions to Iroha that provide custom functionality.
