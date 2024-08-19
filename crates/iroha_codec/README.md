# Parity Scale Decoder Tool

This tool helps you decode **Iroha 2** data types from binaries using [Parity Scale Codec](https://github.com/paritytech/parity-scale-codec).

## Build

To build the tool, run:

```bash
cargo build --bin iroha_codec
```

## Usage

Run Parity Scale Decoder Tool:

```bash
iroha_codec <SUBCOMMAND>
```

### Subcommands

| Command                                             | Description                                                                                                                        |
|-----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| [`list-types`](#list-types)                         | List all available data types                                                                                                      |
| [`scale-to-json`](#scale-to-json-and-json-to-scale) | Decode the data type from SCALE to JSON                                                                                            |
| [`json-to-scale`](#scale-to-json-and-json-to-scale) | Encode the data type from JSON to SCALE                                                                                            |
| [`scale-to-rust`](#scale-to-rust)                   | Decode the data type from SCALE binary file to Rust debug format.<br>Can be used to analyze binary input if data type is not known |
| `help`                                              | Print the help message for the tool or a subcommand                                                                                |

## `list-types`

To list all supported data types, run from the project main directory:

```bash
./target/debug/iroha_codec list-types
```

<details> <summary> Expand to see expected output</summary>

```
Account
AccountEvent
AccountEventFilter
AccountEventSet
AccountId
AccountMintBox
AccountPermissionChanged
AccountRoleChanged
Action
Algorithm
...

344 types are supported
```

</details>

## `scale-to-json` and `json-to-scale`

Both commands by default read data from `stdin` and print result to `stdout`.
There are flags `--input` and `--output` which can be used to read/write from files instead.

These commands require `--type` argument. If data type is not known, [`scale-to-rust`](#scale-to-rust) can be used to detect it.

* Decode the specified data type from a binary:

  ```bash
  ./target/debug/iroha_codec scale-to-json --input <path_to_binary> --type <type>
  ```

### `scale-to-json` and `json-to-scale` usage examples

* Decode the `NewAccount` data type from the `samples/account.bin` binary:

  ```bash
  ./target/debug/iroha_codec scale-to-json --input iroha_codec/samples/account.bin --type NewAccount
  ```

* Encode the `NewAccount` data type from the `samples/account.json`:

  ```bash
  ./target/debug/iroha_codec json-to-scale --input iroha_codec/samples/account.json --output result.bin --type NewAccount
  ```

## `scale-to-rust`

Decode the data type from a given binary.

|   Option   |                                                          Description                                                          |          Type          |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `--binary` | The path to the binary file with an encoded Iroha structure for the tool to decode.                                           | An owned, mutable path |
| `--type`   | The data type that is expected to be encoded in the provided binary.<br />If not specified, the tool tries to guess the type. | String                 |

* Decode the specified data type from a binary:

  ```bash
  ./target/debug/iroha_codec scale-to-rust <path_to_binary> --type <type>
  ```

* If you are not sure which data type is encoded in the binary, run the tool without the `--type` option:

  ```bash
    ./target/debug/iroha_codec scale-to-rust <path_to_binary>
  ```

### `scale-to-rust` usage examples

* Decode the `NewAccount` data type from the `samples/account.bin` binary:

  ```bash
  ./target/debug/iroha_codec scale-to-rust iroha_codec/samples/account.bin --type NewAccount
  ```

* Decode the `NewDomain` data type from the `samples/domain.bin` binary:

  ```bash
  ./target/debug/iroha_codec scale-to-rust iroha_codec/samples/domain.bin --type NewDomain
  ```
