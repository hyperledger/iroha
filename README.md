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

| Use-case          | CPU               | RAM   | Storage |
|-------------------|-------------------|-------|---------|
| Build (minimum)   | Dual-core CPU     | 4GB   | 20GB    |
| Build (recommend) | AMD Ryzen™ 5 1600 | 16GB  | 40GB    |
| Deploy (small)    | Dual-core CPU     | 8GB+  | 20GB+   |
| Deploy (large)    | AMD Epyc™ 64-core | 128GB | 128GB+  |

## Notes
* Rust compilation highly favours multi-core CPUs such as Apple M1™, AMD Ryzen™/Threadripper™/Epyc™, Intel Alder Lake
* On systems with restricted memory but many CPU cores, compilation of Iroha may sometimes fail with (`SIGKILL`). If this happens to you, restrict the number of CPU cores using `cargo build -j <number>`, where `<number>` (without the angle brackets) is half your RAM capacity rounded down. 
* Blockchain operations are done in-memory, so RAM requirements may increase over time, depending on the size and number of blocks in your blockchain. 
* Iroha itself does not require any persistent storage, as all of its configuration options can be specified via environment variables. 


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
cp configs/client_config.json target/debug/config.json
cd target/debug
./iroha_client_cli --help
```
More details about Iroha Client CLI can be found [here](./client_cli/README.md).

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
* [`iroha_telemetry`](telemetry) — monitoring and analysis of telemetry data
* [`iroha_version`](version) — message versioning for non-simultaneous system updates

# Maintenance 
## Configuration

A detailed breakdown of all available configuration parameters is available [here](./docs/source/references/config.md). All configuration parameters can be either provided as a `config.json` or using environment variables. 

The tests in the repository verify that the `trusted_peers.json` is compatible with the provided `config.json`, and that the `client/config.json` can be used to operate on the provided `genesis.json` block. It may be useful to generate the configurations by looking at [`core/src/samples.rs`](./core/src/samples.rs) and [`client/src/samples.rs`](./core/src/samples.rs) to see examples that can be serialised into `json` and used for your needs. 

## Endpoints

A detailed list of all available endpoints is available [here](./docs/source/references/api_spec.md#endpoints). 

## Logging

By default Iroha logs in a human readable format to `stdout`. The logging level is set as described [here](./docs/source/references/config.md#loggermax_log_level), and it can be changed at run-time using the `configuration` endpoint. 

For example if your iroha instance is running at `127.0.0.1:8080` to change the log level to `DEBUG` using `curl` one can 
```bash
curl -X POST -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"LogLevel": "DEBUG"}' -i
```

Optional JSON formatted logging can be saved to the [logging file](./docs/source/references/config.md#loggerlog_file_path). [Log rotation](https://www.commandlinux.com/man-page/man5/logrotate.conf.5.html) is the peer administrator's responsibility. 

## Monitoring

The details of the `Health` endpoint can be found [here](./docs/source/references/api_spec.md#health). 

Iroha is instrumented to produce both JSON-formatted as well as `prometheus`-readable metrics at the `status` and `metrics` endpoints respectively. More information is found in the [API specifications](./docs/source/references/api_spec.md).

The [`prometheus`](https://prometheus.io/docs/introduction/overview/) monitoring system is the de-factor standard for monitoring long-running services such as an Iroha peer. In order to get started, please [install `prometheus`](https://prometheus.io/docs/introduction/first_steps/), and execute the following in the project root. 

```
prometheus --config.file=configs/prometheus.yml
```

## Storage

The blocks are written to the `blocks` sub-folder (created automatically by Iroha) in the working directory of the peer. Additionally, if specified, the logging file must also be stored in a user-specified directory. 

No additional storage is necessary. 

## Scaling 

Multiple instances of Iroha peer and client can be run on the same physical machine and in the same working directory (although it is recommended to give each a clean new working directory). 

The provided `docker-compose` file showcases a minimum viable network and the general methods of using the `hyperledger/iroha2:dev` docker image for deploying a network of peers. 

# Further reading

  * [Iroha 2 Whitepaper](./docs/source/iroha_2_whitepaper.md)
  * [Minting your first asset (tutorial)](./docs/source/tutorials/mint-your-first-asset.md)
  * [Glossary](./docs/source/references/glossary.md)
  * [Configuration](./docs/source/references/config.md)
  * [Iroha Special Instructions](./docs/source/references/isi.md)
  * [API specification](./docs/source/references/api_spec.md)
  * [Iroha Python](https://github.com/hyperledger/iroha-python)

# Contributing

That's great!
Check out our [contributing guide](./CONTRIBUTING.md)

# [Help](./CONTRIBUTING.md#contact)

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
