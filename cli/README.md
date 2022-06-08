# Iroha CLI

The binary `iroha` crate contains the Iroha peer binary. The binary is used to instantiate a peer and bootstrap an Iroha-based network. The capabilities of the network are determined by the feature flags used to compile the binary.

The `iroha` crate contains the Iroha peer binary, which is used to instantiate a peer and bootstrap an Iroha-based network. The capabilities of the network are determined by the feature flags used to compile said binary.

## Build

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.60), installed and configured.

Optionally, [Docker](https://www.docker.com/) can be used to build images containing any of the provided binaries. Using [Docker buildx](https://docs.docker.com/buildx/working-with-buildx/) is recommended, but not required.

### Build the default Iroha binary

Build the Iroha peer binary as well as every other supporting binary:

```bash
cargo build --release
```

The results of the compilation can be found in `<IROHA REPO ROOT>/target/release/`, where `<IROHA REPO ROOT>` is the path to where you cloned this repository (without the angle brackets).

### Add features

To add optional features, use ``--features``. For example, to add the support for _dex_, run:

```bash
cargo build --release --features dex
```

A full list of features can be found in the [cargo manifest file](Cargo.toml) for this crate.

### Disable default features

By default, the Iroha binary is compiled with the `bridge`, `telemetry`, and `schema-endpoint` features. If you wish to remove those features, add `--no-default-features` to the command.

```bash
cargo build --release --no-default-features
```

This flag can be combined with the `--features` flag in order to precisely specify the feature set that you wish.

## Configuration

To run the Iroha peer binary, you must [generate the keys](#generating-keys) and provide a [configuration file](#configuration-file).

### Generating Keys

We highly recommend you to generate a new key pair for any non-testing deployment. We also recommend using the `Ed25519` algorithm. For convenience, you can use the provided [`kagami`](../tools/kagami/README.md) tool to generate key pairs. For example,

<!-- TODO, update the links for the release version.  -->

```bash
cargo run --bin kagami -- crypto
```

<details> <summary>Expand to see the output</summary>

```bash
Public key (multihash): ed0120bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Private key: 0311152fad9308482f51ca2832fdfab18e1c74f36c6adb198e3ef0213fe42fd8bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Digest function: ed25519
```

</details>

To see the command-line options for `kagami`, you must first terminate the arguments passed to `cargo`. For example, run the `kagami` binary with JSON formatting:

```bash
cargo run --bin kagami -- crypto --json
```

**NOTE**: The `kagami` binary can be run without `cargo` using the `<IROHA REPO ROOT>/target/release/kagami` binary.
Refer to [generating key pairs with `kagami`](../tools/kagami#crypto) for more details.

### Configuration file

You must provide a configuration file to run the Iroha peer binary. Iroha will not run with defaults if the configuration file is not available.

The Iroha binary looks for either a `config.json` file in the current directory or a JSON file in `IROHA2_CONFIG_PATH`. If the configuration file is not valid, the Iroha peer binary exits and does nothing. If neither of these files is provided, all the fields from the default `config.json` should be specified as environment variables. Note that environment variables override the variables in their respective fields provided via `config.json`.

The environment variables replacing `config.json` should be passed as JSON strings, meaning that any inner quotes should be properly escaped in the command line as shown in the example below.

<details> <summary>Expand to see the example</summary>

``` bash
IROHA_TORII="{\"P2P_ADDR\": \"127.0.0.1:1339\", \"API_URL\": \"127.0.0.1:8080\"}" IROHA_SUMERAGI="{\"TRUSTED_PEERS\": [{\"address\": \"127.0.0.1:1337\",\"public_key\": \"ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"},{\"address\": \"127.0.0.1:1338\",\"public_key\": \"ed0120cc25624d62896d3a0bfd8940f928dc2abf27cc57cefeb442aa96d9081aae58a1\"},{\"address\": \"127.0.0.1:1339\",\"public_key\": \"ed0120faca9e8aa83225cb4d16d67f27dd4f93fc30ffa11adc1f5c88fd5495ecc91020\"},{\"address\": \"127.0.0.1:1340\",\"public_key\": \"ed01208e351a70b6a603ed285d666b8d689b680865913ba03ce29fb7d13a166c4e7f1f\"}]}" IROHA_KURA="{\"INIT_MODE\": \"strict\",\"BLOCK_STORE_PATH\": \"./blocks\"}" IROHA_BLOCK_SYNC="{\"GOSSIP_PERIOD_MS\": 10000,\"BATCH_SIZE\": 2}" IROHA_PUBLIC_KEY="ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b" IROHA_PRIVATE_KEY="{\"digest_function\": \"ed25519\",\"payload\": \"282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b\"}" IROHA_GENESIS="{\"ACCOUNT_PUBLIC_KEY\": \"ed01204cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\",\"ACCOUNT_PRIVATE_KEY\": {\"digest_function\": \"ed25519\",\"payload\": \"d748e18ce60cb30dea3e73c9019b7af45a8d465e3d71bcc9a5ef99a008205e534cffd0ee429b1bdd36b3910ec570852b8bb63f18750341772fb46bc856c5caaf\"}}" ./iroha 
```

</details>

:grey_exclamation: We do not recommend using environment variables for configuration outside docker-compose and Kubernetes deployments. Please change the values in the configuration file instead. That would also help us debug the problems that you might be having.

The [configuration options reference](../docs/source/references/config.md) provides detailed explanations of each configuration variable. You may use the [sample configuration file](../configs/peer/config.json) for quick testing.

One of the peers on your network must be provided with the genesis block, which is either `IROHA2_GENESIS_PATH` or `genesis.json` in the working directory.
Check [configuration options](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md#genesis) for details.
Learn more about the genesis block in [our tutorial](https://hyperledger.github.io/iroha-2-docs/guide/configure/genesis.html).

## Deployment

You may deploy Iroha as a [native binary](#native-binary) or by using [Docker](#docker).

### Native binary

1. Prepare a deployment environment.

    If you plan on running the `iroha` peer binary from the directory `deploy`, copy `config.json` and `genesis.json`:

    ```bash
    cp ./target/release/iroha
    cp ./configs/peer/config.json deploy
    cp ./configs/peer/genesis.json deploy
    ```

2. Make necessary edits to `config.json` and `genesis.json`, such as:

    - Generate new key pairs and add their values to `genesis.json`)
    - Adjust the port values for your initial set of trusted peers
    - Change the number of trusted peers to fit your initial network topology

    **NOTE**: the number of peers needed for tolerating _f_ byzantine faults is _3f+1_.

3. Start an Iroha peer.

    You can do this either with `--genesis` parameter to specify `genesis.json` location or without. Pay attention that for multi-peer setup only one peer should be started with `--genesis` parameter.

    ```bash
    cd deploy
    ./iroha --submit-genesis
    ```

### Docker

We provide a sample configuration for Docker in [`docker-compose.yml`](../docker-compose.yml). We highly recommend that you adjust the `config.json` to include a set of new key pairs.

[Generate the keys](#generating-keys) and put them into `services.*.environment` in `docker-compose.yml`. Don't forget to update the public keys of `TRUSTED_PEERS`.

- Build images:

    ```bash
    docker-compose build
    ```

- Run containers:

    ```bash
    docker-compose up
    ```

  To keep containers up and running after closing the terminal, use the `-d` (*detached*) flag:

    ```bash
    docker-compose up -d
    ```

- Stop containers:

    ```bash
    docker-compose stop
    ```

- Remove containers:

    ```bash
    docker-compose down
    ```

