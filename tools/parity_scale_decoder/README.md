# Parity Scale Decoder Tool

## Description

This tool will help you to decode **Iroha 2** types from binaries using [Parity Scale Codec](https://github.com/paritytech/parity-scale-codec)

## Usage

Building:

```bash
cargo build --bin parity_scale_decoder
```

If your terminal does not support colors:

```bash
cargo build --features no-color --bin parity_scale_decoder
```

From the main project directory:

* List all supported types:

  ```bash
  ./target/debug/parity_scale_decoder list-type
  ```

* Decode type from binary:

  ```bash
  ./target/debug/parity_scale_decoder decode <path_to_binary> --type <type>
  ```

  As an example you can use provided samples:

  ```bash
  ./target/debug/parity_scale_decoder decode tools/parity_scale_decoder/samples/account.bin --type Account
  ```

* Decode any type from binary:

  If you are not sure about type you can simply omit `--type` option:
  
  ```bash
  ./target/debug/parity_scale_decoder decode <path_to_binary> 
  ```

* To see all available options run:

  ```bash
  ./target/debug/parity_scale_decoder --help
  ```

## Contributing

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
