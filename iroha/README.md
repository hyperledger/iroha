# Iroha Application

## Description

When you start your own ledger, Iroha Application will make peers in it up and running
based on predefined configuration.

## Usage

### Docker Compose Deployment

#### Prepare Key Pairs

Before deployment each Peer should generate own pair of crypthographic keys. In our example we will use `Ed25519` and 
[ursa_key_utils](https://github.com/soramitsu/ursa_key_utils) tool.

```bash
./ursa_key_utils
```

As a result you will see something like that:

```bash
Public key: [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]
Private key: [113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]
```

Paste these values into `docker-compose.yml` environment variables for the first Iroha Peer:

```yaml
version: "3.3"
services:
  iroha:
    build:
      context: ./
      dockerfile: Dockerfile.debug
    image: iroha:debug
    environment:
      TORII_URL: iroha:1337
      IROHA_PUBLIC_KEY: '[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]'
      IROHA_PRIVATE_KEY: '[113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]'
 
...
```

Repeat this for each Peer.

#### Build Binaries

```bash
cargo build
```

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
