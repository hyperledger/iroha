# Iroha CLI Client

Iroha Client CLI is a "thin" wrapper around functionality exposed in the `iroha` crate. Specifically, it should be used as a reference for using `iroha`'s features, and not as a production-ready client. As such, the CLI client is not guaranteed to support all features supported by the client library. Check [Iroha 2 documentation](https://docs.iroha.tech/get-started/operate-iroha-2-via-cli.html) for a detailed tutorial on working with Iroha Client CLI.

## Installation

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.62.1), installed and configured.

Build Iroha and its binaries:

```bash
cargo build
```

The above command will produce the `iroha` ELF executable file for Linux/BSD, the `iroha` executable for MacOS, and the `iroha.exe` executable for Windows, depending on your platform and configuration.

Alternatively, check out the [documentation](https://docs.iroha.tech/get-started/install-iroha-2.html) for system-wide installation instructions.

## Usage

Run Iroha Client CLI:

```
iroha [OPTIONS] <SUBCOMMAND>
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
| `json`    | Submit multi-instructions or request query as JSON                                                                                                           |
| `peer`    | Execute commands related to peer administration and networking                                                                              |
| `wasm`    | Execute commands related to WASM                                                                                                            |
| `help`    | Print the help message for `iroha` and/or the current subcommand other than `help` subcommand                                    |

Refer to [Iroha Special Instructions](https://docs.iroha.tech/blockchain/instructions.html) for more information about Iroha instructions such as register, mint, grant, and so on.

## Examples

:grey_exclamation: All examples below are Unix-oriented. If you're working on Windows, we would highly encourage you to consider using WSL, as most documentation assumes a POSIX-like shell running on your system. Please be advised that the differences in the syntax may go beyond executing `iroha.exe` instead of `iroha`.

```bash
./iroha domain register --id="Soramitsu"
./iroha account register --id="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu"
./iroha asset register --id="XOR#Soramitsu" --type=Numeric
./iroha asset mint --account="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010
./iroha asset get --account="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu" --asset="XOR#Soramitsu"
```

In this section we will show you how to use Iroha CLI Client to do the following:

  - [Create new Domain](#create-new-domain)
  - [Create new Account](#create-new-account)
  - [Mint Asset to Account](#mint-asset-to-account)
  - [Query Account Assets Quantity](#query-account-assets-quantity)
  - [Execute WASM transaction](#execute-wasm-transaction)
  - [Execute Multi-instruction Transactions](#execute-multi-instruction-transactions)

### Create new Domain

To create a domain, you need to specify the entity type first (`domain` in our case) and then the command (`register`) with a list of required parameters. For the `domain` entity, you only need to provide the `id` argument as a string that doesn't contain the `@` and `#` symbols.

```bash
./iroha domain register --id="Soramitsu"
```

### Create new Account

To create an account, specify the entity type (`account`) and the command (`register`). Then define the value of the `id` argument in "signatory@domain" format, where signatory is the account's public key in multihash representation:

```bash
./iroha account register --id="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu"
```

### Mint Asset to Account

To add assets to the account, you must first register an Asset Definition. Specify the `asset` entity and then use the `register` and `mint` commands respectively. Here is an example of adding Assets of the type `Quantity` to the account:

```bash
./iroha asset register --id="XOR#Soramitsu" --type=Numeric
./iroha asset mint --account="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010
```

With this, you created `XOR#Soramitsu`, an asset of type `Numeric`, and then gave `1010` units of this asset to the account `ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu`.

### Query Account Assets Quantity

You can use Query API to check that your instructions were applied and the _world_ is in the desired state. For example, to know how many units of a particular asset an account has, use `asset get` with the specified account and asset:

```bash
./iroha asset get --account="ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu" --asset="XOR#Soramitsu"
```

This query returns the quantity of `XOR#Soramitsu` asset for the `ed01204A3C5A6B77BBE439969F95F0AA4E01AE31EC45A0D68C131B2C622751FCC5E3B6@Soramitsu` account.

You can also filter based on either account, asset or domain id by using the filtering API provided by the Iroha client CLI. Generally, filtering follows the `./iroha ENTITY list filter PREDICATE` pattern, where ENTITY is asset, account or domain and PREDICATE is condition used for filtering serialized using JSON5 (check `iroha::data_model::predicate::value::ValuePredicate` type).

Here are some examples of filtering:

```bash
# Filter domains by id
./iroha domain list filter '{"Identifiable": {"Is": "wonderland"}}'
# Filter accounts by domain
./iroha account list filter '{"Identifiable": {"EndsWith": "@wonderland"}}'
# Filter asset by domain
./iroha asset list filter '{"Or": [{"Identifiable": {"Contains": "#wonderland#"}}, {"And": [{"Identifiable": {"Contains": "##"}}, {"Identifiable": {"EndsWith": "@wonderland"}}]}]}'
```

### Execute WASM transaction

Use `--file` to specify a path to the WASM file:

```bash
./iroha wasm --file=/path/to/file.wasm
```

Or skip `--file` to read WASM from standard input:

```bash
cat /path/to/file.wasm | ./iroha wasm
```

These subcommands submit the provided wasm binary as an `Executable` to be executed outside a trigger context.

### Execute Multi-instruction Transactions

The reference implementation of the Rust client, `iroha`, is often used for diagnosing problems in other implementations.

To test transactions in the JSON format (used in the genesis block and by other SDKs), pipe the transaction into the client and add the `json` subcommand to the arguments:

```bash
cat /path/to/file.json | ./iroha json transaction
```

### Request arbitrary query

```bash
echo '{ "FindAllParameters": null }' | ./iroha --config client.toml json query
```
