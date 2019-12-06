=================
Overview of Iroha
=================

What are the key features of Iroha?
-----------------------------------

- Simple deployment and maintenance
- Variety of libraries for developers
- Role-based access control
- Modular design, driven by command–query separation principle
- Assets and identity management

In our quality model, we focus on and continuously improve:

- Reliability (fault tolerance, recoverability)
- Performance Efficiency (in particular time-behavior and resource utilization)
- Usability (learnability, user error protection, appropriateness recognisability)

Where can Iroha be used?
------------------------

Hyperledger Iroha is a general purpose permissioned blockchain system that can be used to manage digital assets, identity, and serialized data.
This can be useful for applications such as interbank settlement, central bank digital currencies, payment systems, national IDs, and logistics, among others.

For a detailed description please check our `Use Case Scenarios section <develop/cases.html>`_.

How is it different from Bitcoin or Ethereum?
---------------------------------------------

Bitcoin and Ethereum are designed to be permissionless ledgers where anyone can join and access all the data.
They also have native cryptocurrencies that are required to interact with the systems.

In Iroha, there is no native cryptocurrency. Instead, to meet the needs of enterprises, system interaction is permissioned, meaning that only people with requisite access can interact with the system. Additionally, queries are also permissioned, such that access to all the data can be controlled.


One major difference from Ethereum, in particular, is that Hyperledger Iroha allows users to perform common functions, such as creating and transferring digital assets, by using prebuilt commands that are in the system.
This negates the need to write cumbersome and hard to test smart contracts, enabling developers to complete simple tasks faster and with less risk.

How is it different from the rest of Hyperledger frameworks or other permissioned blockchains?
----------------------------------------------------------------------------------------------

Iroha has a novel, Crash fault tolerant consensus algorithm (called YAC [#f1]_) that is high-performance and allows for finality of transactions with low latency.

Also, Iroha's built-in commands are a major benefit compared to other platforms, since it is very simple to do common tasks such as create digital assets, register accounts, and transfer assets between accounts.
Moreover, it narrows the attack vector, improving overall security of the system, as there are less things to fail.

Finally, Iroha is the only ledger that has a robust permission system, allowing permissions to be set for all commands, queries, and joining of the network.

.. [#f1] Yet Another Consensus

How to create applications around Iroha?
----------------------------------------

In order to bring the power of blockchain into your application, you should think first of how it is going to interface with Iroha peers.
A good start is to check `Concepts and Architecture section <concepts_architecture/index.html>`_, explaining what exactly is a transaction and query, and how users of your application are supposed to interact with it.

We also have several client libraries which provide tools for developers to form building blocks, such as signatures, commands,
send messages to Iroha peers and check the status.