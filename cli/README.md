# Iroha CLI

The binary `iroha` crate contains the Iroha peer binary. The binary is used to instantiate a peer and bootstrap an Iroha-based network. The capabilities of the network are determined by the feature flags used to compile the binary.

The `iroha` crate contains the Iroha peer binary, which is used to instantiate a peer and bootstrap an Iroha-based network. The capabilities of the network are determined by the feature flags used to compile said binary.

## Build

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.62.1), installed and configured.

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
Public key (multihash): "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
Private key (ed25519): "0311152FAD9308482F51CA2832FDFAB18E1C74F36C6ADB198E3EF0213FE42FD8BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
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
IROHA_TORII="{\"P2P_ADDR\": \"127.0.0.1:1339\", \"API_URL\": \"127.0.0.1:8080\"}" IROHA_SUMERAGI="{\"TRUSTED_PEERS\": [{\"address\": \"127.0.0.1:1337\",\"public_key\": \"ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B\"},{\"address\": \"127.0.0.1:1338\",\"public_key\": \"ed0120CC25624D62896D3A0BFD8940F928DC2ABF27CC57CEFEB442AA96D9081AAE58A1\"},{\"address\": \"127.0.0.1:1339\",\"public_key\": \"ed0120FACA9E8AA83225CB4D16D67F27DD4F93FC30FFA11ADC1F5C88FD5495ECC91020\"},{\"address\": \"127.0.0.1:1340\",\"public_key\": \"ed01208E351A70B6A603ED285D666B8D689B680865913BA03CE29FB7D13A166C4E7F1F\"}]}" IROHA_KURA="{\"INIT_MODE\": \"strict\",\"BLOCK_STORE_PATH\": \"./storage\"}" IROHA_BLOCK_SYNC="{\"GOSSIP_PERIOD_MS\": 1000,\"BATCH_SIZE\": 2}" IROHA_PUBLIC_KEY="ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B" IROHA_PRIVATE_KEY="{\"digest_function\": \"ed25519\",\"payload\": \"282ED9F3CF92811C3818DBC4AE594ED59DC1A2F78E4241E31924E101D6B1FB831C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B\"}" IROHA_GENESIS="{\"ACCOUNT_PUBLIC_KEY\": \"ed01204CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF\",\"ACCOUNT_PRIVATE_KEY\": {\"digest_function\": \"ed25519\",\"payload\": \"D748E18CE60CB30DEA3E73C9019B7AF45A8D465E3D71BCC9A5EF99A008205E534CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF\"}}" ./iroha
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

