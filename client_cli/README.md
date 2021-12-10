# Iroha CLI Client

## Description

Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.
It's a "light" client which only converts Command Line Interface commands into Iroha Web API Network Requests.

### Features

* Iroha CLI Client can submit Transactions with your Iroha Special Instructions to Iroha Peers
* Iroha CLI Client can send Requests with your Queries to Iroha Peers

## Installation

### Requirements

* [Rust](https://www.rust-lang.org/learn/get-started)

### Build

```bash
cargo build
```

### Artifact

`iroha_client_cli` executable file for Unix and `iroha_client_cli.exe` executable file for Windows will appear.
All examples below are Unix oriented, to run them on Windows replace `./iroha_client_cli` with `iroha_client_cli.exe`.

## Examples

Full description and list of commands detailed in `./iroha_client_cli --help`.

### TL;DR

```bash
./iroha_client_cli domain register --id="Soramitsu"
./iroha_client_cli account register --id="White Rabbit@Soramitsu" --key=""
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
./iroha_client_cli asset mint --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010 
./iroha_client_cli asset get --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" 
```

### Create new Domain

Let's start with domain creation. We need to provide `register` command first, 
following by entity type (domain in our case) and list of required parameters.
For domain entity we only need `id` parameter as a string.

```bash
./iroha_client_cli domain register --id="Soramitsu"
```

### Create new Account

Right now we have the only domain without any accounts, let's fix it.
Like in the previous example, we need to define account name, it is done using `id` flag.
We also give a `key` argument with account's public key as a double-quoted
string value.

```bash
./iroha_client_cli account register --id="White Rabbit@Soramitsu" --key=""
```

### Mint Asset to Account

Okay, it's time to give something to our Account. We will add some Assets quantity to it.
This time we need to register an Asset Definition first and then add some Assets to the account.
As you can see, we use new command `asset` and it's subcommands `register` and `mint`. 
Every asset has its own value type, here we define domain as quantity (integer/number).

```bash
./iroha_client_cli asset register --id="XOR#Soramitsu" --value-type=Quantity
./iroha_client_cli asset mint --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" --quantity=1010 
```

### Query Account Assets Quantity

Because distributed systems heavily relay on the concept of eventual consistency and Iroha works in Consensus between peers, your requests may or may not be processed
while Iroha Client will successfully send them and Iroha Peer will accept them. Different stages of transactions processing and different cases may lead to
rejection of transaction after your receive response from Command Line Interface. To check that your instruction were applied and system now in the desired state
you need to become familiar and use Query API.

Let's use Get Account Assets Query as an example. Command will look familiar because it almost the same as the update command.
We need to know quantity so we skip this argument and replace `update asset add` part with `get asset`.

```bash
./iroha_client_cli asset get --account="White Rabbit@Soramitsu" --asset="XOR#Soramitsu" 
```

### Want to help us develop Iroha?

That's great! 
Check out [this document](https://github.com/hyperledger/iroha/blob/iroha2-dev/CONTRIBUTING.md)

## [Need help?](https://github.com/hyperledger/iroha/blob/iroha2-dev/CONTRIBUTING.md#contact)

## License

Iroha codebase is licensed under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Iroha documentation files are made available under the Creative Commons
Attribution 4.0 International License (CC-BY-4.0), available at
http://creativecommons.org/licenses/by/4.0/
