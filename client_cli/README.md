# Iroha CLI Client

With the Iroha CLI Client, you can interact with Iroha Peers Web API.
It is a "thin" wrapper around functionality exposed in the `iroha_client` crate. Specifically, it should be used as a reference for using `iroha_client`'s features, and not as a production-ready client. As such, the CLI client is not guaranteed to support all features supported by the client library.

## Features

* Submit Transactions with your Iroha Special Instructions to Iroha Peers
* Send Requests with your Queries to Iroha Peers

## Installation

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.62.1), installed and configured.

Build Iroha and its binaries:

```bash
cargo build
```

The above command will produce the `iroha_client_cli` ELF executable file for Linux/BSD, the `iroha_client_cli` executable for MacOS, and the `iroha_client_cli.exe` executable for Windows, depending on your platform and configuration.

## Usage Examples

:grey_exclamation: All examples below are Unix-oriented. If you're working on Windows, we would highly encourage you to consider using WSL, as most documentation assumes a POSIX-like shell running on your system. Please be advised that the differences in the syntax may go beyond executing `iroha_client_cli.exe` instead of `iroha_client_cli`.

In this section we will show you how to use Iroha CLI Client to do the following:

- [Create a new domain](#create-new-domain)
- [Create a new account](#create-new-account)
- [Mint an asset to an account's wallet](#mint-asset-to-account)
- [Query an account's assets](#query-account-assets-quantity)

To get the full list of commands and their descriptions, run:

```
./iroha_client_cli --help
```

### TL;DR

```bash
./iroha_client_cli domain register --id="Soramitsu"
./iroha_client_cli account register --id="White Rabbit@Soramitsu" --key=""
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
./iroha_client_cli asset mint --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010 
./iroha_client_cli asset get --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" 
```

### Create new Domain

Let's start with domain creation. To create a domain, you need to specify the entity type first (`domain` in our case) and then the command (`register`) with a list of required parameters.
For the `domain` entity, you only need to provide the `id` argument as a string that doesn't contain the `@` and `#` symbols.

```bash
./iroha_client_cli domain register --id="Soramitsu"
```

Now you have a domain without any accounts.

### Create new Account

Let's create a new account. Like in the previous example, specify the entity type (`account`) and the command (`register`). Then define the account name as the value of the `id` argument.
Additionally, you need to provide the `key` argument with the account's public key as a double-quoted multihash representation of the key. Providing an empty string also works (but is highly discouraged), while omitting the argument altogether will produce an error.

```bash
./iroha_client_cli account register --id="White Rabbit@Soramitsu" --key=""
```

### Mint Asset to Account

It's time to give something to the Account you created. Let's add some Assets of the type `Quantity` to the account.

To do so, you must first register an Asset Definition and only then add some Assets to the account. Specify the `asset` entity and then use the `register` and `mint` commands respectively. 
	
Every asset has its own value type. In this example, it is defined as `Quantity`, a 32-bit unsigned integer. We also support `BigQuantity` and `Fixed`, which are a 128-bit unsigned integer and a 64-bit fixed-precision binary fraction, as well as `Store` for key-value structured data.

```bash
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
./iroha_client_cli asset mint --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010 
```

You created `XOR#Soramitsu`, an asset of type `Quantity`, and then gave `1010` units of this asset to the account `White Rabbit@Soramitsu`.

### Query Account Assets Quantity

Because distributed systems heavily rely on the concept of _eventual_ consistency and Iroha works by awaiting consensus between peers, your request is not guaranteed to be processed (or be accepted) even if it is correctly formed. 
While the Iroha Client will successfully send your transactions and the Iroha Peer will confirm receiving them, it is possible that your request will not appear in the next block.

Different causes such as a transaction timeout, a faulty peer in the network, catastrophic failure of the peer that you've sent your data towards, and many other conditions naturally occurring inside of any blockchain may lead to a rejection of your transaction at many different stages of processing.

It should be noted that Iroha is designed to reduce the incidence of such rejections, and only rejects properly formed transactions in situations when not rejecting it would lead to data corruption and a hard-fork of the network.

As such it's important to check that your instructions were applied and the _world_ is now in the desired state.
For this you need to use Query API.

Let's use Get Account Assets Query as an example.
To know how many units of a particular asset an account has, use `asset get` with the specified account and asset:

```bash
./iroha_client_cli asset get --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" 
```

This query returns the quantity of `XOR#Soramitsu` asset for the `White Rabbit@Soramitsu` account.
