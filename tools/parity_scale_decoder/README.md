# Parity Scale Decoder Tool

This tool helps you decode **Iroha 2** data types from binaries using [Parity Scale Codec](https://github.com/paritytech/parity-scale-codec).

## Build

To build the tool, run:

```bash
cargo build --bin parity_scale_decoder
```

If your terminal does not support colours, run:

```bash
cargo build --features no_color --bin parity_scale_decoder
```

## Usage

Run Parity Scale Decoder Tool:

```bash
parity_scale_decoder <SUBCOMMAND>
```

### Subcommands

|          Command          |                     Description                     |
| ------------------------- | --------------------------------------------------- |
| [`list-type`](#list-type) | List all available data types                       |
| [`decode`](#decode)       | Decode the data type from binary                    |
| `help`                    | Print the help message for the tool or a subcommand |

## `list-type`

To list all supported data types, run from the project main directory:

```bash
./target/debug/parity_scale_decoder list-type
```

<details> <summary> Expand to see possible outputs</summary>

```
No type is supported
1 type is supported
3 types are supported
```

</details>

## `decode`

Decode the data type from a given binary.

|   Option   |                                                          Description                                                          |          Type          |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `--binary` | The path to the binary file with an encoded Iroha structure for the tool to decode.                                           | An owned, mutable path |
| `--type`   | The data type that is expected to be encoded in the provided binary.<br />If not specified, the tool tries to guess the type. | String                 |

* Decode the specified data type from a binary:

  ```bash
  ./target/debug/parity_scale_decoder decode <path_to_binary> --type <type>
  ```

* If you are not sure which data type is encoded in the binary, run the tool without the `--type` option:

  ```bash
    ./target/debug/parity_scale_decoder decode <path_to_binary>
  ```

### `decode` usage examples

* Decode the `Account` data type from the `samples/account.bin` binary:

  ```bash
  ./target/debug/parity_scale_decoder decode tools/parity_scale_decoder/samples/account.bin --type Account
  ```

* Decode the `Domain` data type from the `samples/domain.bin` binary:

  ```bash
  ./target/debug/parity_scale_decoder decode tools/parity_scale_decoder/samples/domain.bin --type Domain
  ```
