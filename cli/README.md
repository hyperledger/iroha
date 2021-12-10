# Iroha Application

## Description

When you start your own ledger, Iroha Application will make peers in it up and running
based on predefined configuration.

## Usage

### CLI Help
```
./iroha --help
```

### Generating Keys

Before deployment each Peer should generate own pair of cryptographic keys. In our example we will use `Ed25519` and 
[iroha_crypto_cli](https://github.com/hyperledger/iroha/blob/iroha2-dev/crypto_cli/README.md) tool. This tool is a recommended way to generate iroha keys.

```bash
./iroha_crypto_cli
```

As a result you will see something like that:

```bash
Public key (multihash): ed0120bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Private key: 0311152fad9308482f51ca2832fdfab18e1c74f36c6adb198e3ef0213fe42fd8bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c
Digest function: ed25519
```

### Configuration

All the parameters are configured in `config.json` file. The full documentation of each parameters is available [here](../docs/source/references/config.md). The values specified in the config can be overwritten by environment variables.

### Manual Deployment

All the commands are assumed to be executed in the root directory of the clone of this repository in Unix bash compatible shell.

#### Make a Directory for Deployment

```bash
mkdir deploy
```

#### Build Iroha Binary

Build and copy Iroha binary into the directory. 

```bash
cargo build --release
cp ./target/release/iroha deploy
```

#### Copy configs

Copy and if necessary edit config, genesis and trusted peers.
```bash
cp ./configs/peer/config.json deploy
cp ./configs/peer/genesis.json deploy
cp ./configs/peer/trusted_peers.json deploy
```

Set `trusted_peers.json` to contain ids of the peers you are planning to start.

Also update the `PUBLIC_KEY`, `PRIVATE_KEY`, `TORII.P2P_ADDR` and `TORII.API_URL` correspondingly, they should be unique for each of the peers. `trusted_peers.json` address fields should correspond to `TORII.P2P_URL`s of peers.

#### Start Iroha

Start Iroha peer. It can be done either with `--genesis` param to specify `genesis.json` location or without. Pay attention that for multi-peer setup only one peer should be started with `--genesis` param.  

```bash
cd deploy
./iroha --submit-genesis
```

### Docker Compose Deployment

To change configuration for this type of deployment use either environment variables in `docker-compose.yml` or change `config.json` that the `Dockerfile` references.

#### Updating Keys

[Generate keys](#generating-keys) and put them into `services.*.environment` in `docker-compose.yml`,
or the keys default to those of `config.json`.

Take a look at the reference configurations for a [single peer](https://github.com/hyperledger/iroha/blob/iroha2-dev/docker-compose-single.yml)
and for [multiple peers](https://github.com/hyperledger/iroha/blob/iroha2-dev/docker-compose.yml).

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

### Want to help us develop Iroha?

That's great! 
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
