# Iroha Client

## Description

Iroha Client is a Rust Library wich encapsulates network related logic and gives users
an ability to interact with Iroha Peers like they are non-distributed application.

### Features

* Submit one or several Iroha Special Instructions as a Transaction to Iroha Peer
* Request data based on Iroha Queries from Peer

## Usage

### Requirements

* [Rust](https://www.rust-lang.org/learn/get-started)

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Add to your project

```toml
iroha_client = { git = "https://github.com/hyperledger/iroha/", branch="iroha2-dev" }
```

### Code example

```rust
let configuration =
    &Configuration::from_path("config.json").expect("Failed to load configuration.");
let mut iroha_client = Client::new(configuration);
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
