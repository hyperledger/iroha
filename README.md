# Overview

A simple and efficient blockchain ledger.

## About

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Rust](https://github.com/hyperledger/iroha/workflows/Rust/badge.svg?branch=iroha2-dev)
[![codecov](https://codecov.io/gh/hyperledger/iroha/branch/iroha2-dev/graph/badge.svg)](https://codecov.io/gh/hyperledger/iroha)


Iroha is a distributed ledger technology (DLT). Its design principles are inspired by the Japanese Kaizen principle — eliminate excesses (muri). Iroha can help you manage your accounts, assets, on-chain data storage with efficient smartcontracts, while being Byzantine- and crash-fault tolerant, being able to withstand a fault rate of 33%.

## Features

Iroha is a fully-featured blockchain ledger

* Creation and management of custom fungible assets, such as currencies, gold, etc.
* Non-fungible asset support.
* User account management, with a domain hierarchy, and multi-signature transactions.
* Efficient portable smartcontracts implemented either via WebAssembly, or Iroha Special Instructions.
* Support for both permissioned, and permission-less blockchain deployments.
* Byzantine fault-tolerance with up to 34% fault rate.
* Efficient in-memory operation.
* Extensive telemetry support out of the box.
* Modular structure. Don't need it? Compile with `--no-default-features` and add the features you need.
* Event-driven architecture with strongly-typed events.

# System Requirements

| Use-case          | CPU               | RAM   | Storage[^1] |
|-------------------|-------------------|-------|-------------|
| Build (minimum)   | Dual-core CPU     | 4GB   | 20GB        |
| Build (recommend) | AMD Ryzen™ 5 1600 | 16GB  | 40GB        |
| Deploy (small)    | Dual-core CPU     | 8GB+  | 20GB+       |
| Deploy (large)    | AMD Epyc™ 64-core | 128GB | 128GB+      |

[^1]: Note, all operations are done in RAM, so it can theoretically work without persistent storage. However, since synchronising blocks can take a long time, we recommend adding a hard drive.

### Notes on system requirements

* Rust compilation highly favours multi-core CPUs such as Apple M1™, AMD Ryzen™/Threadripper™/Epyc™, Intel Alder Lake™ etc.
* On systems with restricted memory but many CPU cores, compilation of Iroha may sometimes fail with (`SIGKILL`). If this happens to you, restrict the number of CPU cores using `cargo build -j <number>`, where `<number>` (without the angle brackets) is half your RAM capacity rounded down.
* Be advised that RAM usage will grow linearly, as all transactions are stored in in-memory. You should expect to consume more RAM with a higher TPS and uptime.
* You need on average 5KiB of RAM per-account. So a 1 000 000 account network uses 5GiB of memory. Each transfer or Mint instruction occupies slightly less memory at 1KiB per instruction.


# Building, testing and running

## Pre-requisites

* [Rust](https://www.rust-lang.org/learn/get-started)
* (Optional) [Docker](https://docs.docker.com/get-docker/)
* (Optional) [Docker Compose](https://docs.docker.com/compose/install/)

## (Optional) Test

### Cargo

```bash
cargo test
```

### API functional tests

```bash
cargo build
chmod +x target/debug/iroha
chmod +x target/debug/iroha_client_cli

bash ./scripts/test_env.sh setup
bash ./scripts/tests/register_mint_quantity.sh
bash ./scripts/test_env.sh cleanup
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
cp configs/client_cli/config.json target/debug/config.json
cd target/debug
./iroha_client_cli --help
```
More details about Iroha Client CLI can be found [here](./client_cli/README.md).

# Integration
## Overall structure

Iroha project mainly consists of the following crates:

* [`iroha`](cli) — the command-line application for deploying an Iroha peer. Contains the routing table and definitions of API endpoints.
* [`iroha_actor`](actor), which  provides a message passing model for Iroha components
* [`iroha_client`](client), which provides a library for building clients which communicate with peers
* [`iroha_client_cli`](client_cli) — reference implementation of a client.
* [`iroha_config`](config), which handles configuration, generating documentation for options and run-time changes
* [`iroha_core`](core) — the primary library used by all other crates which includes the peer's endpoint management
* [`iroha_crypto`](crypto) — cryptographic aspects of Iroha
* [`kagami`](tools/kagami), which is used to generate cryptographic keys, default genesis, configuration reference, and schema
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

It may be useful to generate the configurations by looking at [`core/src/samples.rs`](./core/src/samples.rs) and [`client/src/samples.rs`](./core/src/samples.rs) to see examples that can be serialised into `json` and used for your needs.

## Endpoints

A detailed list of all available endpoints is available [in the API specifications](./docs/source/references/api_spec.md#endpoints).

## Logging

By default, Iroha logs in both a human readable format to `stdout`. The logging level can be changed either via a [configuration option](./docs/source/references/config.md#loggermax_log_level), or at run-time using the `configuration` endpoint.

For example if your iroha instance is running at `127.0.0.1:8080` to change the log level to `DEBUG` using `curl`, you should send a `POST` request containing the new level in JSON. For example
```bash
curl -X POST \
    -H 'content-type: application/json' \
    http://127.0.0.1:8080/configuration \
    -d '{"LogLevel": "DEBUG"}' -i
```

Optionally, Iroha supports a JSON logging mode. To enable this please set the [logging file](./docs/source/references/config.md#loggerlog_file_path) (on UNIX, you can also specify `/dev/stdout` or `/dev/stderr` if you prefer to pipe the output to [`bunyan`](https://www.npmjs.com/package/bunyan)). [Log rotation](https://www.commandlinux.com/man-page/man5/logrotate.conf.5.html) is the peer administrator's responsibility.

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

## Scalability

Multiple instances of Iroha peer and client binaries  can be run on the same physical machine and in the same working directory (although it is recommended to give each a clean new working directory).

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

Check out our [contributing guide](./CONTRIBUTING.md) for more details.

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
