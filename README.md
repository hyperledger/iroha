# Iroha 2

A very simple and performant blockchain.

## Description

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Rust](https://github.com/hyperledger/iroha/workflows/Rust/badge.svg?branch=iroha2-dev)
[![codecov](https://codecov.io/gh/hyperledger/iroha/branch/iroha2-dev/graph/badge.svg)](https://codecov.io/gh/hyperledger/iroha)


Iroha is a straightforward distributed ledger technology (DLT), inspired by Japanese Kaizen principle — eliminate excessiveness (muri). Iroha has essential functionality for your asset, information and identity management needs, at the same time being an efficient and trustworthy crash fault-tolerant tool for your enterprise needs.

### Features

Iroha has the following features:

* Creation and management of custom fungible assets, such as currencies, kilos of gold, etc.
* Management of user accounts
* Taxonomy of accounts based on domains in the system
* The system of rights and verification of user permissions for the execution of transactions and queries in the system

## Usage

### Requirements

* [Rust](https://www.rust-lang.org/learn/get-started)
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Start Peers

```bash
cargo build
docker-compose up
```

More details about different ways to use Iroha application can be found [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/iroha/README.md#usage).

### Use Client CLI
With the `docker-compose` instance running,

```bash
<<<<<<< HEAD
cp client/config.json target/debug/
=======
cp core/config.json target/debug/
>>>>>>> 1d532220 (Fix paths in files outside cargo)
cd target/debug
./iroha_client_cli --help
```

More details about Iroha Client CLI can be found [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/client_cli/README.md).

## Project Structure

Iroha project mainly consists of the following crates:

* [`iroha`](cli) is CLI binary for peer deployment
* [`iroha_actor`](actor) provide message passing model among Iroha components
* [`iroha_client`](client) provide library for building peer operating clients
* [`iroha_client_cli`](client_cli) is a client implementation: CLI binary for peer operation
* [`iroha_config`](config) support configurations
* [`iroha_core`](core) is the primary library
* [`iroha_crypto`](crypto) support cryptographic aspects of Iroha
* [`iroha_crypto_cli`](crypto_cli) generate cryptographic keys
* [`iroha_data_model`](data_model) define common data models in Iroha
* [`iroha_dsl`](dsl) provide declarative API for various requests
* [`iroha_futures`](futures) support asynchronous aspects of Iroha
* [`iroha_logger`](logger) serve logging with various layers and levels
* [`iroha_macro`](macro) provide macros for code writing
* [`iroha_p2p`](p2p) define network interface between peers
* [`iroha_permissions_validators`](permissions_validators) check permissions on various requests
* [`iroha_substrate`](substrate) bridge substrate `XClaim` external module
* [`iroha_telemetry`](telemetry) provide telemetry monitoring and analysis
* [`iroha_version`](version) provide versioning of a message between peers for non-simultaneous system updates

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
