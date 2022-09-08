# Iroha v2.0

The following is a specification for Hyperledger Iroha 2.0

---

## 1. Overview

Hyperledger Iroha 2 aims to be an even more simple, highly performant distributed ledger platform than Iroha 1.
Iroha 2 carries on the tradition of putting on emphasis on having a library of pre-defined smart contracts in the core,
so that developers do not have to write their own code to perform many tasks related to digital identity and asset management.

### 1.1. Relationship to Hyperledger Fabric, Hyperledger Sawtooth, Hyperledger Besu, and Others

It is our vision that in the future Hyperledger will consist less of disjointed projects
and more of coherent libraries of components that can be selected and installed in order to run a Hyperledger network.
Towards this end, it is the goal of Iroha to eventually provide encapsulated components that other projects (particularly in Hyperledger) can use.

### 1.2. Mobile and Web libraries

Having a solid distributed ledger system is not useful if there are no applications that can easily utilize it.
To ease use, we created and opened sourced software development kits for iOS, Android, and JavaScript.
Using these libraries, cryptographic public/private key pairs that are compatible with iroha can be created
and common API functions can be conveniently called.

## 2. System architecture

### 2.1. P2P Network

Generally, 3*f*+1 peers are needed to tolerate *f* Byzantine peers in the network (albeit some consensus algorithms may have higher peers requirements).
The number of *f* that a system should be made to tolerate should be determined by the system maintainer,
based on the requirements for expected use cases.

The following peer types are considered:

* Voting peers (participate in consensus)
* Normal peer (receives and relays blocks, but does not participate in consensus)
however, normal peers do validate all received data, with the mantra of *don't trust, verify*)

#### 2.1.2. Peers discovery and membership

Membership is provided in a decentralized way, on ledger.
By default 2*f*+1 signatures are needed to confirm adding or removing peers to or from the network.
If peers drop out and are unresponsive for "too long,"
then other peers will automatically execute a remove peer smart contract to remove the peer from the consensus process.

### 2.2. Cryptography

We use [Hyperledger Ursa](https://github.com/hyperledger/ursa).

### 2.3. Data Model

Iroha uses a simple data model made up of world with domains, accounts, assets and signatories,
as shown in the figure below:

```

   +-----------------------------------------------+
   |                                               |
   |     +-----------------+                       |
   |     |Domain           |                       |
   |     +--------------+  |                       |
   |     ||Asset        |  |                       |
+--+--+  ||Definition(s)|  |                       |
|World|  +--------------+  |                       |
+--+--+  |                 |                       |
   |     +------------+    |                       |
   |     ||Account(s)||    | has   +-----------+   |
   |     |------------------------->Signatories|   |
   |     +-----------------+       +-----------+   |
   |                       |                       |
   |                       |  has  +--------+      |
   |                       +------->Asset(s)|      |
   |                               +--------+      |
   +-----------------------------------------------+
```

### 2.4. Smart Contracts

Iroha provides a library of smart contracts called **I**roha **S**pecial **I**nstructions (ISI).
To execute logic on the ledger, these instructions can be invoked via either transactions
or registered [Iroha Trigger](#iroha-triggers).

More information about Iroha Special Instructions can be found in an
[Architecture Decision Record](https://wiki.hyperledger.org/display/iroha/Iroha+Special+Instructions+DSL).

### 2.5. Iroha Triggers

Triggers are [Iroha Special Instructions](#smart-contracts) that may be invoked based on condition.
This is very powerful feature and enables Turing complete computation for Iroha's Special Instructions.

* Trigger at timestamp
* Trigger at blockchain
* Trigger at *condition*

### 2.6. Transactions

Transactions are used to invoke an [Iroha Special Instruction](#smart-contracts) or a set of instructions.

#### 2.6.1 Multisignature Transactions

Using [Iroha Special Instructions](#smart-contracts) we can conditionally check transactions signatures.

```
[condition,
   [signatory_set, ...],
    ...
]
```

where ```signatory_set``` is an m-of-n signatory set.
If multiple ```signatory_set```s exist for a given condition, they can be either ```OR``` or ```AND``` unioned.

As an example illustrating why conditional multisig is useful,
consider a situation where a bank wants to allow either 2 tellers or 1 manager to sign off on any transfer transaction over $500 and under $1000.
In this case, the condition will be: ```Condition.asset("usd@nbc").qty(500).comparison(">").qty(1000).comparison("<")```
and the ```signatory_set```s for the tellers and manager will be ```OR``` unioned,
so that either the m-of-n signatues from the tellers
or the single signature from the manager will be acceptable for transaction signing.

### 2.7. Data storage

Data in Hyperledger Iroha v2 are stored in two places: a block store (disk) and a world-state-view (in memory).

To reach the performance targets, Iroha 2 does not use a database to store data,
but instead implements a custom storage solution, called **Kura**,
that is specially designed for storing and validating blockchain data.
One of the goals of Kura is that even without multiple-peer consensus
(e.g., when running a blockchain as a single node), transactional data can still be processed
using tamper-evident cryptographic proofs.

When Kura is initialized, data are read from the on-disk block store using either of two methods
(depending on the config settings): `fastInit` or `strictInit`.
`fastInit` reads all transactions in all blocks in order and recreates all the in-memory data structures,
but without doing any validation.
`strictInit` validates that all transactions and blocks have correct signatures
and that all transactions follow the business rules (e.g., no accounts should have a negative balance).

Additionally, an auditor job can be spawned that will go through the block store strictly
and compare the result with the world-state-view,
in case the server suspects that something has been compromised and wants to check.

Kura takes as input blocks, which comprise multiple transactions.
Kura is meant to take only blocks as input that have passed stateless and stateful validation,
and have been finalized by consensus. For finalized blocks,
Kura simply commits the block to the block storage on the disk
and updates atomically the in-memory data structures that make up the world-state-view.
To optimize networking syncing, which works on 100 block chunks,
chunks of 100 blocks each are stored in files in the block store.

Kura also helps out with stateful validation,
by providing functions that retrieve a copy of values affected in the world-state-view by the transactions in a block,
returning the values as a copy.
This then allows the stateful validation component to apply the transactions to update the world-state-view
and confirm that no transactions in the block violate business rule invariants
(e.g., no account shall have a negative balance of an asset after a transaction).

Iroha uses the in-memory World State View to also store information,
such as the latest input/output transactions for an account and for an asset,
in order to simplify the query API and allow real-time querying of Iroha 2 directly,
without requiring end-user applications to rely on middleware.
To confirm that transactions are indeed correct, Merkle proofs are also stored with and readily available from Kura.

### 2.8. Consensus

Byzantine fault tolerant systems are engineered to tolerate *f* numbers of Byzantine faulty peers in a network.
Iroha introduces a Byzantine Fault Tolerant consensus algorithm called Sumeragi.
Sumeragi is a Byzantine fault tolerant consensus algorithm for permissioned,
peer-to-peer networks that try to reach consensus about some set of data.
It is heavily inspired by the B-Chain algorithm:

Duan, S., Meling, H., Peisert, S., & Zhang, H. (2014).
*Bchain: Byzantine replication with high throughput and embedded reconfiguration*.
In International Conference on Principles of Distributed Systems (pp. 91-106). Springer.

As in B-Chain, we consider the concept of a global order over validating peers and sets **A** and **B** of peers,
where **A** consists of the first 2*f*+1 peers and **B** consists of the remainder.
As 2*f*+1 signatures are needed to confirm a transaction,
under the normal case only 2*f*+1 peers are involved in transaction validation;
the remaining peers only join the validation when faults are exhibited in peers in set **A**.
The 2*f*+1th peer is called the *proxy tail*.

#### 2.8.1. The Basics

- no ordering service; instead, the leader of each round just uses the transactions they have at hand
to create a block and the leader changes each round to prevent long-term censorship

- 3*f*+1 validators that are split into two groups, *a* and *b*, of 2*f*+1 and *f* validators each

- 2*f*+1 validators must sign off on a block in order for it to be committed

- the first node in set *a* is called the *leader* (sumeragi) and the 2*f*+1th node in set *a* is called the *proxy tail*

- the basic idea is that up to *f* validators can fail and the system should run,
so if there are *f* Byzantine faulty nodes, you want them to be in the *b* set as much as possible

- empty blocks are not produced, so to prevent an evil leader from censoring transactions
and claiming there are no transactions to create blocks with, everytime a node sends a transaction to the leader,
the leader has to submit a signed receipt of receiving it;
then, if the leader does not create a block in an orderly amount of time (the *block time*),
the submitting peer can use this as proof to convince non-faulty nodes to do a view change and elect a new leader

- after a node signs off on a block and forwards it to the *proxy tail*,
they expect a commit message within a reasonable amount of time (the *commit time*);
if there is no commit message in time, the node starts suspecting the *a* set.

- once a commit message is received from the proxy tail, all nodes commit the block locally;
if a node complains that they never received the commit message,
then a peer that has the block will provide that peer with the committed block
(note: there is no danger of a leader creating a new block while the network is waiting
for a commit message because the next round cannot continue nor can a new leader be elected
until after the current round is committed or leader election takes place)

- every time there is a problem, such as a block not being committed in time, a new *a* set is selected;
this is because we want to just move on and not worry about assigning blame, which would come with considerable overhead

- 2*f*+1 signatures are needed to commit, *f*+1 are needed to change the leader and proxy tail

##### 2.8.2. The Details

###### Network Topology

A network of nodes is assumed, where each node knows the identity of all other nodes on the network.
These nodes are called *validators*. We also assume that there are 3*f*+1 validators on the network,
where *f* is the number of simultaneous Byzantine faulty nodes that the network can contain
and still properly function (albeit, performance will degrade in the presence of a Byzantine faulty node,
but this is okay because Hyperledger Iroha is designed to operate in a permissioned environment).

Because the identities of the nodes are known by all and can be proven through digital signatures,
it makes sense to overlay a topology on top of the network of nodes in order to provide guarantees
that can enable consensus to be reached faster.

For each round (e.g., block), the previous round's (block's) hash is used to determine an ordering over the set of nodes,
such that there is a deterministic and canonical order for each block.
In this ordering, the first 2*f+1* nodes are grouped into a set called set *a*.
Under normal (non-faulty) conditions, consensus for a block is performed by set *a*.
The remaining *f* nodes are grouped into a set called set *b*. Under normal conditions,
set *b* acts as a passive set of validators to view and receive committed blocks,
but otherwise they do not participate in consensus.

###### Data Flow: Normal Case

Assume the leader has at least one transaction.
The leader creates a block either when the *block timer* goes off or its transaction cache is full.
The leader then sends the block to each node in set *a*. Each peer in set *a* then validates and signs the block,
and sends it to the proxy tail.
When each node in set *a* sends the block to the proxy tail, they set a timer, the *commit timer*,
within which time the node expects to get a commit message (or else it will suspect the *a* set).

The proxy tail should at this point have received the block from at least one of the peers.
From the time the first peer contacts the proxy tail with a block proposal, a timer is set, the *commit timer*.
Before the *commit timer* is over, the proxy tail expects to get 2*f* votes from the other nodes in set *a*,
to which it then will add its vote in order to get 2*f*+1 votes to commit the block.

###### Handling Faulty Cases

**Possible faulty cases related to the leader are:**

- leader ignores all transactions and never creates a block

  - the solution to this is to have other nodes broadcast a transaction across the network
  and if someone sends a transaction to the leader and it gets ignored, then the leader can be suspected;
  the suspected message is sent around the network and a new leader is elected if *f*+1 nodes are submitting transactions to
  the leader but no blocks are produced.

- leader creates a block, but only sends it to a minority of peers, so that 2*f*+1 votes cannot be obtained for consensus

  - the solution is to have a *commit timer* on each node where a new leader will be elected.

- leader creates multiple blocks and sends them to different peers, causing the network to not reach consensus about a block

  - the solution is to have a *commit timer* on each node where a new leader will be elected
  if a block is not agreed upon.

**Possible faulty cases related to the proxy tail are:**

- proxy tail received some votes, but does not receive enough votes for a block to commit

  - the *commit timer* on regular nodes or the *commit timer* on the proxy tail will go off and a new leader and proxy tail will be elected
  when *f*+1 nodes are suspecting.

- proxy tail receives enough votes for a block, but lies and says that they didn't

  - the *commit timer* on nodes will go off and a new leader and proxy tail are elected.

- proxy tail does not inform any other node about a block commit (block withholding attack)

  - the *commit timer* on nodes will go off and a new leader and proxy tail will be elected. Once 2 blocks have passed,
  arbitrary rewriting of history in the future is not possible. Once a subsequent block is produced, it is not possible
  to replace the block.

- proxy tail does not inform set *b* about a block commit

  - through normal data synchronization (P2P gossip), set *b* will get up to date

- proxy tail selectively sends a committed block to some, but not other nodes

  - Either the *commit timer* on nodes will go off and a new leader and proxy tail are elected, or the other nodes
  will recieve the block through P2P sync. If a new round is performed, the leader will add information to the new block
  containing the block hashes it invalidates. If the block passes, then the peers are to replace partially shared block with the
  new block but not the other way around due to the signatures invalidating the hash.

**Possible faulty cases related to any node in set *a* are:**

- a peer could delay signing on purpose so they slow down consensus, without witholding their signature

  - this is not very nice, but it is also hard to prove;
  the Hijiri reputation system can be used to lower the reputation of slow nodes anyway

- a peer may not sign off on a block

  - if the lack of a signature causes a block to not commit, a new node will be brought in from set *b*

- a peer may make falsely suspect the *a* set

  - *f*+1 suspicion claims are required to make a block invalid and change the leader and the proxy tail

### 2.9. Blocks synchronization

When nodes gossip to each other, they include the latest known block hash.
If a receiving node does not know about this block, they will then request data.


### 2.10. Data permissions

Data permissioning is crucial to many real use cases.
For example, companies will not likely accept distributed ledger technology
if it means that competing institutions will know the intricate details of transactions.


### 2.12. Hijiri: Peer reputation system

The hijiri reputation system is based on rounds.
At each round, validating peers that are registered with the membership service perform the following tasks
to establish trust (reliability) ratings for the peers:

* data throughput test
* version test
* computational test
* data consistency test

Which peers validate each other are based on the pairwise distance between hashes
(e.g., ```sort(abs(hash && 0x0000ffff - publicKey && 0x0000ffff))```).
The hashes are computed based on the public keys of the peers that are concatenated with the round number
and then SHA-3 hashed. Rounds occur whenever the Merkle root is less than TODO:XXX.
Results are shared in a separate Merkle tree, maintained independently of the transactions (so the systems can run in parallel).

### 2.13 Iroha Queries

To retrieve information about World State View of the Peer clients will use Iroha Queries API.

### 2.14 Client API

Client libraries interact with Iroha over the HTTP and WebSocket. Check the up to date API reference [here](./references/api_spec.md).

### 2.15 Versioning

As the system develops and new Iroha 2.x versions are released some of the formats and structures might change.
It is practical to track these changes in the following serialized objects:

1. Client API data formats
2. Internal P2P message formats
3. Transactions
4. Blocks

For this purpose these structures will be serialized together with their version information. The detailed description of the versioning support in relation to the serialization formats used in Iroha can be found in this [RFC](https://wiki.hyperledger.org/display/iroha/Message+Versioning).

Versioning support will have the following benefits:
1. Client libraries will be able to clearly indicate if they recieve an unsupported versioned response.
2. Iroha peers will be able to clearly indicate if they recieve an unsupported versioned request.
3. The network upgrade will not require for all peers to be upgraded simultaneously.
4. Transactions and Blocks older versions can be handled conditionally after the network upgrade.

## 3.0 Performance Goals

- 20,000 tps
- 2-3 s block time


# Glossary

The glossary of commonly used terms can be found [here](./references/glossary.md)
