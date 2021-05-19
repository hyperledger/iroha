# Iroha Application

## Description

When you start your own ledger, Iroha Application will make peers in it up and running
based on predefined configuration.

## Usage

### Generating Keys

Before deployment each Peer should generate own pair of crypthographic keys. In our example we will use `Ed25519` and 
[iroha_crypto_cli](https://github.com/hyperledger/iroha/blob/iroha2-dev/iroha_crypto_cli/README.md) tool. This tool is a recommended way to generate iroha keys.

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
mkdir iroha_deploy
```

#### Build Iroha Binary

Build and copy Iroha binary into the directory. 

```bash
cargo build
cp ./target/debug/iroha iroha_deploy
```

#### Copy configs

Copy and if necessary edit config, genesis and trusted peers.
```bash
cp ./iroha/config.json iroha_deploy
cp ./iroha/genesis.json iroha_deploy
cp ./iroha/trusted_peers.json iroha_deploy
```

Depending on how many peers you plan to run, update the config:
- 1 Peer - set `"MAX_FAULTY_PEERS": 0`, and set `trusted_peers.json` to only contain this peer id.
- N Peer - set `"MAX_FAULTY_PEERS": F`, where 0 < F <= (N - 1)/3, and set `trusted_peers.json` to contain ids of the peers you are planning to start.

Also update the `PUBLIC_KEY`, `PRIVATE_KEY`, `TORII_P2P_URL` and `TORII_API_URL` correspondingly, they should be unique for each of the peers. `trusted_peers.json` address fields should correspond to `TORII_P2P_URL`s of peers.

#### Start Iroha

Start Iroha peer. It can be done either with `--genesis` param to specify `genesis.json` location or without. Pay attention that for multipeer setup only one peer should be started with `--genesis` param.  

```bash
cd iroha_deploy
./iroha --genesis="genesis.json"
```

### Docker Compose Deployment

To change configuration for this type of deployment use either environment variables in `docker-compose.yml` or change `config.json` that the `Dockerfile` references.

#### Updating Keys

See [generating keys](#generating-keys) for information on how to generate keys for your peers. You can skip this step for a test setup, then Iroha peers will use already generated testing keys from this repository.

Paste these values into `docker-compose.yml` environment variables for the first Iroha Peer:

```yaml
version: "3.3"
services:
  iroha:
    build: .
    image: iroha:debug
    environment:
      TORII_URL: iroha:1337
      IROHA_PUBLIC_KEY: 'ed0120bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c'
      IROHA_PRIVATE_KEY: '{"digest_function": "ed25519", "payload": "0311152fad9308482f51ca2832fdfab18e1c74f36c6adb198e3ef0213fe42fd8bdf918243253b1e731fa096194c8928da37c4d3226f97eebd18cf5523d758d6c"}'
...
```

Repeat this for each Peer, and do not forget to update `IROHA_TRUSTED_PEERS` correspondingly. 

Also take a look at the reference configurations for a [single peer](https://github.com/hyperledger/iroha/blob/iroha2-dev/docker-compose-single.yml)
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
