# Hyperledger Iroha

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Rust](https://github.com/hyperledger/iroha/workflows/Rust/badge.svg?branch=iroha2-dev)
[![codecov](https://codecov.io/gh/hyperledger/iroha/branch/iroha2-dev/graph/badge.svg)](https://codecov.io/gh/hyperledger/iroha)

Iroha is a simple and efficient blockchain ledger based on the **distributed ledger technology (DLT)**. Its design principles are inspired by the Japanese Kaizen principle of eliminating excesses (*muri*).

Iroha can help you manage your accounts, assets, on-chain data storage with efficient smart contracts, while being Byzantine- and crash-fault tolerant.

## Features

Iroha is a fully-featured blockchain ledger. With Iroha you can:

* Create and manage custom fungible assets, such as currencies, gold, and others
* Create and manage non-fungible assets
* Manage user accounts with a domain hierarchy and multi-signature transactions
* Use efficient portable smart contracts implemented either via WebAssembly or Iroha Special Instructions
* Use both permissioned and permission-less blockchain deployments

Iroha offers:

* Byzantine fault-tolerance with up to 33% fault rate  
* Efficient in-memory operations
* Extensive telemetry support out of the box
* Modular structure
* Event-driven architecture with strongly-typed events

## Overview

- Check [system requirements](#system-requirements) and instructions on how to [build and run Iroha](#build-test-and-run-iroha)
- Learn about the [crates](#integration) Iroha provides
- Learn how to [configure and use Iroha](#maintenance)
- [Read more about Iroha](#further-reading)

Engage with the community:
- [Contribute](./CONTRIBUTING.md) to the repository
- [Contact us](./CONTRIBUTING.md#contact) to get help

# System Requirements

RAM and storage requirements depend on your use case: whether you need to build or deploy a network, how big it is, and so on. This table summarises the requirements:

| Use case          | CPU               | RAM   | Storage[^1] |
|-------------------|-------------------|-------|-------------|
| Build (minimum)   | Dual-core CPU     | 4GB   | 20GB        |
| Build (recommend) | AMD Ryzen™ 5 1600 | 16GB  | 40GB        |
| Deploy (small)    | Dual-core CPU     | 8GB+  | 20GB+       |
| Deploy (large)    | AMD Epyc™ 64-core | 128GB | 128GB+      |

[^1]: Note that all operations are done in RAM, so in theory Iroha can work without persistent storage. However, since synchronising blocks over the network after a power failure may take a long time, we recommend adding a hard drive.

Regarding RAM requirements:

* On average, you need 5 KiB of RAM per account. A network with 1 000 000 accounts uses 5GiB of memory.
* Each transfer or Mint instruction requires 1 KiB per instruction.
* RAM usage grows linearly, as all transactions are stored in memory. You should expect to consume more RAM with a higher TPS and uptime.

CPU considerations:

* Rust compilation highly favours multi-core CPUs such as Apple M1™, AMD Ryzen™/Threadripper™/Epyc™, and Intel Alder Lake™.
* On systems with restricted memory and many CPU cores, Iroha compilation may sometimes fail with `SIGKILL`. To avoid it, restrict the number of CPU cores using `cargo build -j <number>`, where `<number>` (without the angle brackets) is half of your RAM capacity rounded down.

# Build, Test, and Run Iroha

Prerequisites:

* [Rust](https://www.rust-lang.org/learn/get-started)
* (Optional) [Docker](https://docs.docker.com/get-docker/)
* (Optional) [Docker Compose](https://docs.docker.com/compose/install/)

<details> <summary> (Optional) Run included tests</summary>

Run included code tests:

```bash
cargo test
```

Run API functional tests:

```bash
cargo build
chmod +x target/debug/iroha
chmod +x target/debug/iroha_client_cli

bash ./scripts/test_env.sh setup
bash ./scripts/tests/register_mint_quantity.sh
bash ./scripts/test_env.sh cleanup
```

</details>

## Build Iroha

- Build Iroha and accompanying binaries:

  ```bash
  cargo build
  ```

- (Optional) Build the latest Iroha image:

  ```bash
  docker build . -t hyperledger/iroha2:dev
  ```

  If you skip this step, the Iroha container will be built using the latest available image.

## Run Iroha

Once you have built Iroha, you can instantiate the minimum viable network:

```
docker compose up
```

With the `docker-compose` instance running, use [Iroha Client CLI](./client_cli/README.md):

```bash
cp configs/client_cli/config.json target/debug/config.json
cd target/debug
./iroha_client_cli --help
```

Learn how to [mint your first asset with Iroha](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/tutorials/mint-your-first-asset.md).

# Integration

Iroha project mainly consists of the following crates:

* [`iroha`](cli) is the command-line application for deploying an Iroha peer. Contains the routing table and definitions of API endpoints.
* [`iroha_actor`](actor) provides a message passing model for Iroha components.
* [`iroha_client`](client) provides a library for building clients that communicate with peers.
* [`iroha_client_cli`](client_cli) is the reference implementation of a client.
* [`iroha_config`](config) handles configuration and documentation generation for options and run-time changes.
* [`iroha_core`](core) is the primary library used by all other crates, including the peer endpoint management.
* [`iroha_crypto`](crypto) defines cryptographic aspects of Iroha.
* [`kagami`](tools/kagami) is used to generate cryptographic keys, default genesis, configuration reference, and schema.
* [`iroha_data_model`](data_model) defines common data models in Iroha.
* [`iroha_futures`](futures) is used for `async` programming.
* [`iroha_logger`](logger) uses `tracing` to provide logging facilities.
* [`iroha_macro`](macro) provides the convenience macros.
* [`iroha_p2p`](p2p) defines peer creation and handshake logic.
* [`iroha_permissions_validators`](permissions_validators) defines permission validation logic.
* [`iroha_substrate`](substrate) is the bridge substrate `XClaim` external module.
* [`iroha_telemetry`](telemetry) is used for monitoring and analysis of telemetry data.
* [`iroha_version`](version) provides message versioning for non-simultaneous system updates.

# Maintenance

A brief overview on how to configure and maintain an Iroha instance:

- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Logging](#logging)
- [Monitoring](#monitoring)
- [Storage](#storage)
- [Scalability](#scalability)

## Configuration

You can provide configuration parameters either as a `config.json` or using environment variables. Refer to the [detailed list](./docs/source/references/config.md) of all available configuration parameters.

Configuration example you may use as a reference point: [cli/src/samples.rs](./cli/src/samples.rs)

## Endpoints

You can find the detailed list of all available endpoints in the [API specifications](./docs/source/references/api_spec.md#endpoints).

## Logging

By default, Iroha provides logs in a human-readable format and prints them out to `stdout`.

The logging level can be changed either via a [configuration option](./docs/source/references/config.md#loggermax_log_level) or at run-time using the `configuration` endpoint.

<details><summary>Example: changing log level</summary>

For example, if your Iroha instance is running at `127.0.0.1:8080` and you want to change the log level to `DEBUG` using `curl`, you should send a `POST` request with a JSON containing the new log level. Like this:
```bash
curl -X POST \
    -H 'content-type: application/json' \
    http://127.0.0.1:8080/configuration \
    -d '{"LogLevel": "DEBUG"}' -i
```
</details>

### JSON Logging Mode

Additionally, Iroha supports a JSON logging mode.

To enable it, provide the [logging file](./docs/source/references/config.md#loggerlog_file_path) to store the logs in. On UNIX, you can also specify `/dev/stdout` or `/dev/stderr` if you prefer to pipe the output to [`bunyan`](https://www.npmjs.com/package/bunyan).

[Log rotation](https://www.commandlinux.com/man-page/man5/logrotate.conf.5.html) is the responsibility of the peer administrator.

## Monitoring

The details of the `Health` endpoint can be found in the [API specifications](./docs/source/references/api_spec.md#health).

Iroha can produce both JSON-formatted as well as `prometheus`-readable metrics at the `status` and `metrics` endpoints respectively.

The [`prometheus`](https://prometheus.io/docs/introduction/overview/) monitoring system is the de-factor standard for monitoring long-running services such as an Iroha peer. In order to get started, [install `prometheus`](https://prometheus.io/docs/introduction/first_steps/) and execute the following in the project root:

```
prometheus --config.file=configs/prometheus.yml
```

## Storage

The blocks are written to the `blocks` sub-folder, which is created automatically by Iroha in the working directory of the peer. Additionally, if specified, the logging file must also be stored in a user-specified directory.

No additional storage is necessary.

## Scalability

Multiple instances of Iroha peer and client binaries can be run on the same physical machine and in the same working directory. However, we recommend to give each instance a clean new working directory.

The provided `docker-compose` file showcases a minimum viable network and the general methods of using the `hyperledger/iroha2:dev` docker image for deploying a network of peers.

# Further Reading

* [Iroha 2 Whitepaper](./docs/source/iroha_2_whitepaper.md)
* [Minting your first asset (tutorial)](./docs/source/tutorials/mint-your-first-asset.md)
* [Glossary](./docs/source/references/glossary.md)
* [Configuration](./docs/source/references/config.md)
* [Iroha Special Instructions](./docs/source/references/isi.md)
* [API specification](./docs/source/references/api_spec.md)

Iroha SDKs:

* [Iroha Python](https://github.com/hyperledger/iroha-python)
* [Iroha Java](https://github.com/hyperledger/iroha-java)
* [Iroha Javascript](https://github.com/hyperledger/iroha-javascript)
* [Iroha iOS Swift](https://github.com/hyperledger/iroha-ios)

# How to Contribute

We welcome community contributions! Report bugs and suggest improvements via GitHub issues and pull requests. 

Check out our [contributing guide](./CONTRIBUTING.md) to learn more.

# Get Help

Check out the channels you could use to [get help or engage with the community](./CONTRIBUTING.md#contact).

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
