# Iroha Crypto CLI

## Description

Tool for generating public/private key pairs for use in Iroha networks.

All keys are represented in the [multihash format](https://github.com/multiformats/multihash).

## Usage

Assuming that the command is run either from the root of the cloned repository or the directory containing this document, use


```bash
cargo run --bin iroha_crypto_cli
```

**NOTE:** arguments before the `--` terminator are interpreted as arguments given to `cargo run`, rather than `iroha_crypto_cli` to pass the argument `--help` use the following syntax. 

```bash
cargo run --bin iroha_crypto_cli -- --help
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
