# Overview

A very simple and performant blockchain.

## About

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Rust](https://github.com/hyperledger/iroha/workflows/Rust/badge.svg?branch=iroha2-dev)
[![codecov](https://codecov.io/gh/hyperledger/iroha/branch/iroha2-dev/graph/badge.svg)](https://codecov.io/gh/hyperledger/iroha)


Iroha is a straightforward distributed ledger technology (DLT), inspired by the Japanese Kaizen principle — eliminate excesses (muri). Iroha has essential functionality for your asset, information and identity management needs, while also being an efficient and trustworthy crash and fault-tolerant tool for your enterprise needs.

## Features

Iroha has the following features:

* Creation and management of custom fungible assets, such as currencies, gold, etc.
* User account management including domain-based taxonomy
* The system of rights and verification of user permissions for the execution of transactions and queries in the system
* Byzantine fault-tolerance with up to 34% fault rate

# System Requirements

## Building
### Minimum

A modern multi-core CPU with at least 2GB of RAM per core as well as approximately 20 GB of free storage space.

### Recommended

Ryzen 5 1600 or above, 16GB of RAM or more. 40GB of SSD storage.

## Running

The actual minimum requirements depend on the load that your deployment will experience. As Iroha performs most of the operations in-memory, it is recommended to revise and increase the amount of available RAM or consider Optane-based solutions.

### Minimum (small-scale deployment)

Network connection, a 1 core CPU with 1GB of RAM. 1GB of persistent storage.

### Recommended (enterprise-grade single server)

High-bandwidth network connection, a 64 core single-socket or dual-socket CPU(s) with 512GB of ECC-capable RAM and 2TB of persistent storage

# Building, testing and running

## Pre-requisites

* [Rust](https://www.rust-lang.org/learn/get-started)
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

## Test Iroha

### Unit tests

```bash
cargo test
```

### Integration tests

```bash
bash ./scripts/setup_docker_test_env.sh
bash ./scripts/test_docker_compose.sh
bash ./scripts/cleanup_docker_test_env.sh
```


## Build Iroha and its CLI client.

```bash
cargo build
```

## (Optional) build the latest Iroha image

Skipping this step will pull the docker container the Hyperledger DockerHub.

```bash
docker build . -t hyperledger/iroha2:dev
```

## Instantiate the minimum viable network

```
docker compose up
```

More details about the usage of Iroha can be found [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/tutorials/mint-your-first-asset.md).

## Use Client CLI
With the `docker-compose` instance running,

```bash
cp client/config.json target/debug/
cd target/debug
./iroha_client_cli --help
```

More details about Iroha Client CLI can be found [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/client_cli/README.md).

# Integration
## Overall structure

Iroha project mainly consists of the following crates:

* [`iroha`](cli) — the command-line application for deploying an Iroha peer
* [`iroha_actor`](actor), which  provides a message passing model for Iroha components
* [`iroha_client`](client), which provides a library for building clients which communicate with peers
* [`iroha_client_cli`](client_cli) — reference implementation of a client.
* [`iroha_config`](config), which handles configuration, generating documentation for options and run-time changes
* [`iroha_core`](core) — the primary library used by all other crates which includes the peer's endpoint management
* [`iroha_crypto`](crypto) — cryptographic aspects of Iroha
* [`iroha_crypto_cli`](crypto_cli), which is used to generate cryptographic keys
* [`iroha_data_model`](data_model), which  defines common data models in Iroha
* [`iroha_futures`](futures) — technical crate used for `async` programming
* [`iroha_logger`](logger), which uses `tracing` to provide logging facilities
* [`iroha_macro`](macro) — convenience macros
* [`iroha_p2p`](p2p) — peer creation and handshake logic
* [`iroha_permissions_validators`](permissions_validators) — permission validation logic
* [`iroha_substrate`](substrate) — bridge substrate `XClaim` external module
* [`iroha_telemetry`](telemetry) provides telemetry monitoring and analysis
* [`iroha_version`](version) — message versioning for non-simultaneous system updates

# Maintenance 
## Configuration

A detailed breakdown of all available configuration parameters is available [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md). All configuration parameters can be either provided as a `config.json` or using environment variables. 

## Endpoints

A detailed list of all available endpoints is available [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/api_spec.md#endpoints). 

## Logging

By default Iroha logs in a human readable format to `stdout`. The logging level is set as described [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md#loggermax_log_level), and it can be changed at run-time using the `configuration` endpoint. 

For example if your iroha instance is running at `127.0.0.1:8080` to change the log level to `DEBUG` using `curl` one can 
```bash
curl -X POST -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"ChangeLogLevel": "DEBUG"}' -i
```

Optional JSON formatted logging can be saved to the [logging file](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md#loggerlog_file_path). [Log rotation](https://www.commandlinux.com/man-page/man5/logrotate.conf.5.html) is the peer administrator's responsibility. 

## Monitoring

The details of the `Health` endpoint can be found [here](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/api_spec.md#health). 

## Storage

The blocks are written to the `blocks` sub-folder (created automatically by Iroha) in the working directory of the peer. Additionally, if specified, the logging file must also be stored in a user-specified directory. 

No additional storage is necessary. 

## Scaling 

Multiple instances of Iroha peer and client can be run on the same physical machine and in the same working directory (although it is recommended to give each a clean new working directory). 

The provided `docker-compose` file showcases a minimum viable network and the general methods of using the `hyperledger/iroha2:dev` docker image for deploying a network of peers. 

# Further reading

  * [Iroha 2 Whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md)
  * [Minting your first asset (tutorial)](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/tutorials/mint-your-first-asset.md)
  * [Gloassary of terms](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/glossary.md)
  * [Configuration](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md)
  * [Iroha Special Instructions](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/isi.md)
  * [API specification](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/api_spec.md)
  * [Iroha Python](https://github.com/hyperledger/iroha-python)

# Contributing

That's great!
Check out [`Contributing guide`](https://github.com/hyperledger/iroha/blob/iroha2-dev/CONTRIBUTING.md)

# Help

* Join [Telegram chat](https://t.me/hyperledgeriroha) or [Hyperledger RocketChat](https://chat.hyperledger.org/channel/iroha) where the maintainers, contributors and fellow users are ready to help you.
You can also discuss your concerns and proposals and simply chat about Iroha there or in Gitter [![Join the chat at https://gitter.im/hyperledger-iroha/Lobby](https://badges.gitter.im/hyperledger-iroha/Lobby.svg)](https://gitter.im/hyperledger-iroha/Lobby)
* Submit issues and improvement suggestions via [Hyperledger Jira](https://jira.hyperledger.org/secure/CreateIssue!default.jspa)
* Subscribe to our [mailing list](https://lists.hyperledger.org/g/iroha) to receive the latest and most important news and spread your word within Iroha community

# License

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
