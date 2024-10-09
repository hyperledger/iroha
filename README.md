# Hyperledger Iroha

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Rust](https://github.com/hyperledger/iroha/workflows/Rust/badge.svg?branch=main)

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

## System Requirements

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

## Build, Test, and Run Iroha

Prerequisites:

* [Rust](https://www.rust-lang.org/learn/get-started)
* (Optional) [Docker](https://docs.docker.com/get-docker/)
* (Optional) [Docker Compose](https://docs.docker.com/compose/install/)

### Build Iroha

- Build Iroha and accompanying binaries:

  ```bash
  cargo build
  ```

- (Optional) Build the latest Iroha image:

  ```bash
  docker build . -t hyperledger/iroha2:dev
  ```

  If you skip this step, the Iroha container will be built using the latest available image.

### Run Iroha

Once you have built Iroha, you can instantiate the minimum viable network:

```
docker compose up
```

With the `docker-compose` instance running, use [Iroha Client CLI](crates/iroha_cli/README.md):

```bash
cargo run --bin iroha -- --config ./defaults/client.toml
```

## Integration

Iroha project mainly consists of the following crates:

* [`iroha`](crates/iroha) provides a library for building clients that communicate with peers.
* [`irohad`](crates/irohad) is the command-line application for deploying an Iroha peer. Contains the routing table and definitions of API endpoints.
* [`iroha_cli`](crates/iroha_cli) is the command-line client, a reference application using the client SDK.
* [`iroha_core`](crates/iroha_core) is the primary library used by all other crates, including the peer endpoint management.
* [`iroha_config`](crates/iroha_config) handles configuration and documentation generation for options and run-time changes.
* [`iroha_crypto`](crates/iroha_crypto) defines cryptographic aspects of Iroha.
* [`kagami`](crates/iroha_kagami) is used to generate cryptographic keys, default genesis, configuration reference, and schema.
* [`iroha_data_model`](crates/iroha_data_model) defines common data models in Iroha.
* [`iroha_futures`](crates/iroha_futures) is used for `async` programming.
* [`iroha_logger`](crates/iroha_logger) uses `tracing` to provide logging facilities.
* [`iroha_macro`](crates/iroha_macro) provides the convenience macros.
* [`iroha_p2p`](crates/iroha_p2p) defines peer creation and handshake logic.
* [`iroha_default_executor`](wasm_samples/default_executor) defines runtime validation logic.
* [`iroha_telemetry`](crates/iroha_telemetry) is used for monitoring and analysis of telemetry data.
* [`iroha_version`](crates/iroha_version) provides message versioning for non-simultaneous system updates.

## Maintenance

A brief overview on how to configure and maintain an Iroha instance:

- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Logging](#logging)
- [Monitoring](#monitoring)
- [Storage](#storage)
- [Scalability](#scalability)

### Configuration

There is a set of configuration parameters that could be passed either through a configuration file or environment variables.

```shell
irohad --config /path/to/config.toml
```

**Note:** detailed configuration reference is [work in progress](https://github.com/hyperledger/iroha-2-docs/issues/392).

### Endpoints

For a list of all endpoints, available operations, and ways to customize them with parameters, see [API Reference > Torii Endpoints](https://hyperledger.github.io/iroha-2-docs/api/torii-endpoints)

### Logging

By default, Iroha provides logs in a human-readable format and prints them out to `stdout`.

The logging level can be changed either via the `logger.level` configuration parameter or at run-time using the `configuration` endpoint.

<details><summary>Example: changing log level</summary>

For example, if your Iroha instance is running at `127.0.0.1:8080` and you want to change the log level to `DEBUG` using `curl`, you should send a `POST` request with a JSON containing the new log level. Like this:
```bash
curl -X POST \
    -H 'content-type: application/json' \
    http://127.0.0.1:8080/configuration \
    -d '{"logger": {"level": "DEBUG"}}' -i
```
</details>

The log format might be configured via the `logger.format` configuration parameter. Possible values are: `full` (default), `compact`, `pretty`, and `json`.

Output goes to `/dev/stdout`. Piping to files or [log rotation](https://www.commandlinux.com/man-page/man5/logrotate.conf.5.html) is the responsibility of the peer administrator.

### Monitoring

The details of the `Health` endpoint can be found in the [API Reference > Torii Endpoints](https://hyperledger.github.io/iroha-2-docs/api/torii-endpoints#health).

Iroha can produce both JSON-formatted as well as `prometheus`-readable metrics at the `status` and `metrics` endpoints respectively.

The [`prometheus`](https://prometheus.io/docs/introduction/overview/) monitoring system is the de-factor standard for monitoring long-running services such as an Iroha peer. In order to get started, [install `prometheus`](https://prometheus.io/docs/introduction/first_steps/) and use [the configuration template](docs/source/references/prometheus.template.yml).

### Storage

Iroha stores blocks and snapshots in the `storage` directory, which is created automatically by Iroha in the working directory of the peer. If `kura.block_store_path` is specified in the config file, it overrides the default one and is resolved relative to the config file location.

**Note:** detailed configuration reference is [work in progress](https://github.com/hyperledger/iroha-2-docs/issues/392).

### Scalability

Multiple instances of Iroha peer and client binaries can be run on the same physical machine and in the same working directory. However, we recommend to give each instance a clean new working directory.

The provided `docker-compose` file showcases a minimum viable network and the general methods of using the `hyperledger/iroha2:dev` docker image for deploying a network of peers.

## Further Reading

We encourage you to check out our [Iroha 2 Tutorial](https://hyperledger.github.io/iroha-2-docs/) first. It is suitable for both experienced developers and prospective users of Iroha 2, and it provides language-specific guides for Bash, Python, Rust, Kotlin/Java, and Javascript/TypeScript.

* [Iroha 2 Documentation](https://hyperledger.github.io/iroha-2-docs/)
  * [Glossary](https://hyperledger.github.io/iroha-2-docs/guide/glossary)
  * [Iroha Special Instructions](https://hyperledger.github.io/iroha-2-docs/guide/blockchain/instructions)
  * [API Reference](https://hyperledger.github.io/iroha-2-docs/api/torii-endpoints)
<!-- * [Configuration Reference](./docs/source/references/config.md) -->
* [Iroha 2 Whitepaper](./docs/source/iroha_2_whitepaper.md)

Iroha SDKs:

* [Iroha Python](https://github.com/hyperledger/iroha-python)
* [Iroha Java](https://github.com/hyperledger/iroha-java)
* [Iroha Javascript](https://github.com/hyperledger/iroha-javascript)
* [Iroha iOS Swift](https://github.com/hyperledger/iroha-ios)

## How to Contribute

We welcome community contributions! Report bugs and suggest improvements via GitHub issues and pull requests.

Check out our [contributing guide](./CONTRIBUTING.md) to learn more.

## Get Help

Check out the channels you could use to [get help or engage with the community](./CONTRIBUTING.md#contact).

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
