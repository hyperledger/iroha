# Iroha Client

This is the Iroha 2 client library crate. With it you can build your own client applications to communicate with peers in an Iroha 2 network via HTTP/WebSocket.

Follow the [Iroha 2 tutorial](https://hyperledger.github.io/iroha-2-docs/guide/rust.html) for instructions on how to set up, configure, and use the Iroha 2 client and client library.

## Features

* Submit one or several Iroha Special Instructions (ISI) as a Transaction to Iroha Peer
* Request data based on Iroha Queries from a Peer

## Setup

**Requirements:** a working [Rust toolchain](https://www.rust-lang.org/learn/get-started) (version 1.60), installed and configured.

Add the following to the manifest file of your Rust project:

```toml
iroha_client = { git = "https://github.com/hyperledger/iroha/", branch="iroha2-dev" }
```

## Examples

```rust
let configuration =
    &Configuration::from_path("config.json").expect("Failed to load configuration.");
let mut iroha_client = Client::new(configuration);
```

We highly recommend looking at the sample [`iroha_client_cli`](../client_cli) implementation binary as well as our [tutorial](https://hyperledger.github.io/iroha-2-docs/guide/rust.html) for more examples and explanations.
