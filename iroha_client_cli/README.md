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

Full description and list of commands detailed in `iroha_cli --help`.

```
$: ./iroha_client_cli --help
Iroha CLI Client 0.1.0
Iroha CLI Client provides an ability to interact with Iroha Peers Web API without direct network usage.

USAGE:
    iroha_client_cli [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config <FILE>    Sets a config file path. [default: config.json]

SUBCOMMANDS:
    account    Use this command to work with Account Entities in Iroha Peer.
    asset      Use this command to work with Asset and Asset Definition Entities in Iroha Peer.
    domain     Use this command to work with Domain Entities in Iroha Peer.
    help       Prints this message or the help of the given subcommand(s)
```

### TL;DR

```bash
./iroha_client_cli domain add --name="Soramitsu"
./iroha_client_cli account register --domain="Soramitsu" --name="White Rabbit" --key=""
./iroha_client_cli asset register --domain="Soramitsu" --name="XOR" 
./iroha_client_cli asset mint --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" --quantity=1010 
./iroha_client_cli asset get --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" 
```

### Create new Domain

Let's start with domain creation. We need to provide `create` command first, 
following by entity type (`domain` in our case) and list of required parameters.
For domain entity we only need `name` parameter which is stringly typed.

```bash
./iroha_client_cli domain add --name="Soramitsu"
```

### Create new Account

Right now we have the only domain without any accounts, let's fix it.
Like in the previous example, we need to define domain name, this time as 
`domain` argument, because `name` argument should be filled with account's name.
We also give a `key` argument with account's public key as a double-quoted
string value.

```bash
./iroha_client_cli account register --domain="Soramitsu" --name="White Rabbit" --key=""
```

### Mint Asset to Account

Okay, it's time to give something to our Account. We will add some Assets quantity to it.
This time we need to register an Asset Definition first and then add some Assets to the account.
As you can see, we use new command `asset` and it's subcommands `register` and `mint`. 

```bash
./iroha_client_cli asset register --domain="Soramitsu" --name="XOR" 
./iroha_client_cli asset mint --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" --quantity=1010 
```

### Query Account Assets Quantity

Because distributed systems heavily relay on the concept of eventual consistency and Iroha works in Consensus between peers, your requests may or may not be processed
while Iroha Client will successufully send them and Iroha Peer will accept them. Different stages of transactions processing and different cases may lead to
rejection of transaction after your receive response from Command Line Interface. To check that your instruction were applied and system now in the desired state
you need to become familar and use Query API.

Let's use Get Account Assets Query as an example. Command will look familar because it almost the same as the update command.
We need to know quantity so we skipp this argument and replace `update asset add` part with `get asset`.

```bash
./iroha_client_cli asset get --account_id="White Rabbit@Soramitsu" --id="XOR#Soramitsu" 
```

### Want to help us develop Iroha?

That's great! 
Check out [this document](https://github.com/hyperledger/iroha/blob/iroha2-dev/CONTRIBUTING.md)

## Need help?

* Join [Telegram chat](https://t.me/hyperledgeriroha) or [Hyperledger RocketChat](https://chat.hyperledger.org/channel/iroha) where the maintainers, contributors and fellow users are ready to help you. 
You can also discuss your concerns and proposals and simply chat about Iroha there or in Gitter [![Join the chat at https://gitter.im/hyperledger-iroha/Lobby](https://badges.gitter.im/hyperledger-iroha/Lobby.svg)](https://gitter.im/hyperledger-iroha/Lobby)
* Submit issues and improvement suggestions via [Hyperledger Jira](https://jira.hyperledger.org/secure/CreateIssue!default.jspa) 
* Subscribe to our [mailing list](https://lists.hyperledger.org/g/iroha) to receive the latest and most important news and spread your word within Iroha community

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
