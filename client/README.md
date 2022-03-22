# Iroha Client

## Description

The library crate containing the basic building blocks of an Iroha client. If you want to build your own client application, this library is what you should link against. More details can be found in our [tutorial](https://hyperledger.github.io/iroha-2-docs/guide/rust.html) .

### Features

* Submit one or several Iroha Special Instructions as a Transaction to Iroha Peer
* Request data based on Iroha Queries from Peer

## Setup

A working [Rust toolchain](https://www.rust-lang.org/learn/get-started) is required. We highly recommend looking at our [contributing guide](./CONTRIBUTING.md) for more tools that would be useful in development.

Add the following to the manifest file of your Rust project.

```toml
iroha_client = { git = "https://github.com/hyperledger/iroha/", branch="iroha2-dev" }
```

## Example

```rust
let configuration =
    &Configuration::from_path("config.json").expect("Failed to load configuration.");
let mut iroha_client = Client::new(configuration);
```

We highly recommend looking at the sample [`iroha_client_cli`](../client_cli) crate as well as our tutorial for more examples. 

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
