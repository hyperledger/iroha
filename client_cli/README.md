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

Check [build and installation instructions](https://hyperledger.github.io/iroha-2-docs/guide/build-and-install.html) for more details.

## Usage

Run Iroha Client CLI:

```
iroha_client_cli [OPTIONS] <SUBCOMMAND>
```

### Options

|        Option         |                    Description                     |
| --------------------- | -------------------------------------------------- |
| -c, --config <config> | Set a config file path (`config.json` by default). |

### Subcommands

|  Command  |                                                                 Description                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `account` | Execute commands related to accounts: register a new one, list all accounts, grant a permission to an account, list all account permissions |
| `asset`   | Execute commands related to assets: register a new one, mint or transfer assets, get info about an asset, list all assets                   |
| `blocks`  | Get block stream from Iroha peer                                                                                                            |
| `domain`  | Execute commands related to domains: register a new one, list all domains                                                                   |
| `events`  | Get event stream from Iroha peer                                                                                                            |
| `json`    | Submit multi-instructions as JSON                                                                                                           |
| `peer`    | Execute commands related to peer administration and networking                                                                              |
| `wasm`    | Execute commands related to WASM                                                                                                            |
| `help`    | Print the help message for `iroha_client_cli` and/or the current subcommand other than `help` subcommand                                    |

Refer to [Iroha Special Instructions](https://hyperledger.github.io/iroha-2-docs/guide/blockchain/instructions.html) for more information about Iroha instructions such as register, mint, grant, and so on.

Check the [Bash guide in Iroha Tutorial](https://hyperledger.github.io/iroha-2-docs/guide/bash.html) for detailed instructions on working with Iroha Client CLI.

## Examples

:grey_exclamation: All examples below are Unix-oriented. If you're working on Windows, we would highly encourage you to consider using WSL, as most documentation assumes a POSIX-like shell running on your system. Please be advised that the differences in the syntax may go beyond executing `iroha_client_cli.exe` instead of `iroha_client_cli`.

```bash
./iroha_client_cli domain register --id="Soramitsu"
./iroha_client_cli account register --id="White Rabbit@Soramitsu" --key=""
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
./iroha_client_cli asset mint --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010
./iroha_client_cli asset get --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu"
```

In this section we will show you how to use Iroha CLI Client to do the following:

- [Create new Domain](#create-new-domain)
- [Create new Account](#create-new-account)
- [Mint Asset to Account](#mint-asset-to-account)
- [Query Account Assets Quantity](#query-account-assets-quantity)
- [Execute WASM transaction](#execute-wasm-transaction)
- [Execute Multi-instruction Transactions](#execute-multi-instruction-instructions)

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

It's possible to filter based on either account, asset or domain id by using the filtering API provided by the Iroha client CLI.

Generally it looks like this:

```bash
./iroha_client_cli ENTITY list filter PREDICATE
```

Where ENTITY is asset, account or domain and PREDICATE is condition used for filtering serialized using JSON5 (check `iroha_client::data_model::predicate::value::ValuePredicate` type).

Examples:

```bash
# Filter domains by id
./iroha_client_cli domain list filter '{"Identifiable": {"Is": "wonderland"}}'
# Filter accounts by domain
./iroha_client_cli account list filter '{"Identifiable": {"EndsWith": "@wonderland"}}'
# It is possible to combine filters using "Or" or "And"
# Filter asset by domain
./iroha_client_cli asset list filter '{"Or": [{"Identifiable": {"Contains": "#wonderland#"}}, {"And": [{"Identifiable": {"Contains": "##"}}, {"Identifiable": {"EndsWith": "@wonderland"}}]}]}'
```

### Execute WASM transaction

Use `--file` to specify a path to the WASM file:

```bash
./iroha_client_cli wasm --file=/path/to/file.wasm
```

Or skip `--file` to read WASM from standard input:

```bash
cat /path/to/file.wasm | ./iroha_client_cli wasm
```

These subcommands submit the provided wasm binary as an `Executable` to be executed outside a trigger context.

### Execute Multi-instruction Transactions

The reference implementation of the Rust client, `iroha_client_cli`, is often used for diagnosing problems in other implementations.

To test transactions in the JSON format (used in the genesis block and by other SDKs), pipe the transaction into the client and add the `json` subcommand to the arguments:

```bash
cat /path/to/file.json | ./iroha_client_cli json
```
