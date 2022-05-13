# Iroha CLI

## Description


Binary crate containing the Iroha peer binary. The binary is used to instantiate a peer and bootstrap an Iroha-based network. The feature flags used to compile the binary determine the network's capabilities.

The library portions of this crate are related to CLI-argument processing, configuration loading and Endpoint routing. Everything related to the interfaces or API specifications is handled in this crate.

## Build

### Prerequisites

A working [Rust toolchain](https://www.rust-lang.org/learn/get-started) is required to build the peer binary.

Optionally, [Docker](https://www.docker.com/) can be used to build images containing any of the provided binaries. Using [Docker buildx](https://docs.docker.com/buildx/working-with-buildx/) is recommended, but not required.

### Default

The following command will build the Iroha peer binary, as well as every other supporting binary.

```bash
cargo build --release
```

the results of the compilation can be found in `<IROHA REPO ROOT>/target/release/`, where `<IROHA REPO ROOT>` is the path to where you cloned this repository (without the angle brackets).

### Adding features

To add optional features, e.g. support for _bridge_, compile with

```bash
cargo build --release --features bridge
```

A full list of features can be found in the [cargo manifest file](Cargo.toml) of this repository.

### Disabling default features

By default the Iroha binary is compiled with the `bridge` and `telemetry` features. If you with to remove those features, add `--no-default-features` to the command.

```bash
cargo build --release --no-default-features
```

This flag can be combined with the `--features` flag in order to precisely specify the feature set that you wish.

## Configuration

### Generating Keys

We highly recommend that any non-testing deployment generate a new key pair, with the recommended algorithm `Ed25519`. For convenience, you can use the provided [`kagami`](../tools/kagami/README.md). For example,

<!-- TODO, update the links for the release version.  -->

```bash
cargo run --bin kagami -- crypto
```

should produce

```bash
Public key (multihash): ed0120bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Private key: 0311152fad9308482f51ca2832fdfab18e1c74f36c6adb198e3ef0213fe42fd8bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Digest function: ed25519
```

**NOTE**: to see the command-line options for `kagami` you must first terminate the arguments passed to `cargo`, so the command for running the `kagami` binary with JSON formatting is

```bash
cargo run --bin kagami -- crypto --json
```

**NOTE**: The `kagami` binary can be run without `cargo` using the `<IROHA REPO ROOT>/target/release/kagami` binary.

### Configuration file

For the Iroha peer binary to run, a configuration file must be provided. Iroha will not run with defaults if the configuration file is not available.

The Iroha binary looks for either a `config.json` file in the current directory, or for a JSON file `IROHA2_CONFIG_PATH`. If the configuration file is not valid, the Iroha peer binary exits and does nothing. If neither of these files is provided, all the fields from the default `config.json` should be specified as environment variables. Note that environment variables override the variables in their respective fields provided via `config.json`.

The environment variables replacing `config.json` should be passed as JSON strings, meaning that any inner quotes should be properly escaped in the command line as shown in the rather unwieldy example below.

<details>

``` bash
IROHA_TORII="{\"P2P_ADDR\": \"127.0.0.1:1339\", \"API_URL\": \"127.0.0.1:8080\"}" IROHA_SUMERAGI="{\"TRUSTED_PEERS\": [{\"address\": \"127.0.0.1:1337\",\"public_key\": \"ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"},{\"address\": \"127.0.0.1:1338\",\"public_key\": \"ed0120cc25624d62896d3a0bfd8940f928dc2abf27cc57cefeb442aa96d9081aae58a1\"},{\"address\": \"127.0.0.1:1339\",\"public_key\": \"ed0120faca9e8aa83225cb4d16d67f27dd4f93fc30ffa11adc1f5c88fd5495ecc91020\"},{\"address\": \"127.0.0.1:1340\",\"public_key\": \"ed01208e351a70b6a603ed285d666b8d689b680865913ba03ce29fb7d13a166c4e7f1f\"}]}" IROHA_KURA="{\"INIT_MODE\": \"strict\",\"BLOCK_STORE_PATH\": \"./blocks\"}" IROHA_BLOCK_SYNC="{\"GOSSIP_PERIOD_MS\": 10000,\"BATCH_SIZE\": 2}" IROHA_PUBLIC_KEY="ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b" IROHA_PRIVATE_KEY="{\"digest_function\": \"ed25519\",\"payload\": \"282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"}" IROHA_GENESIS="{\"ACCOUNT_PUBLIC_KEY\": \"ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\",\"ACCOUNT_PRIVATE_KEY\": {\"digest_function\": \"ed25519\",\"payload\": \"d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\"}}" ./iroha 
```

</details>

The  [configuration options reference](../docs/source/references/config.md) provides detailed explanations of each configuration variable. All variables defined in `config.json` can be overridden with environment variables. **We don't recommend using environment variables for configuration outside docker-compose and Kubernetes deployments**. Please change the values in the configuration file instead, so that we can better debug the problems that you might be having.

A [sample configuration file](../configs/peer/config.json) is provided for quick testing.

One of the peers on your network must be provided with the genesis block, which is either `IROHA2_GENESIS_PATH` or `genesis.json` in the working directory.

## Deployment
### Native binary

#### Prepare a deployment environment

If you plan on running the `iroha` peer binary from the directory `deploy`, copy and if necessary edit `config.json` and `genesis.json`.
```bash
cp ./target/release/iroha
cp ./configs/peer/config.json deploy
cp ./configs/peer/genesis.json deploy
```

Briefly, you should change all key pairs (don't forget to add these changes to `genesis.json`), adjust the port values for your initial set of trusted peers, and change the number of trusted peers to fit your initial network topology.

**NOTE**: the number of peers needed for tolerating _f_ byzantine faults is _3f+1_.


#### Start Iroha

Start Iroha peer. It can be done either with `--genesis` param to specify `genesis.json` location or without. Pay attention that for multi-peer setup only one peer should be started with `--genesis` param.

```bash
cd deploy
./iroha --submit-genesis
```

### Docker

We provide a sample configuration in [`docker-compose.yml`](../docker-compose.yml). We highly recommend that you adjust the `config.json` to include a set of new key pairs.

[Generate keys](#generating-keys) and put them into `services.*.environment` in `docker-compose.yml`. Don't forget that the public keys of `TRUSTED_PEERS` must also be updated.

#### Build Images

```bash
docker-compose build
```

#### Run Containers

```bash
docker-compose up
```

If you want to keep containers up and running after closing the terminal, use *detached* flag:

```bash
docker-compose up -d
```

#### Stop Containers

```bash
docker-compose stop
```

#### Remove Containers

```bash
docker-compose down
```

### Contributing

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
