# Kura Inspector

Kura Inspector is a CLI tool to inspect blocks in disk storage ([Kura](../iroha_2_whitepaper.html#data-storage)).

With Kura Inspector you can inspect the disk storage regardless of the operating status of Iroha and print out block contents in a human-readabe format.

## Examples

- Print the contents of the latest block:

      kura_inspector print

- Print all blocks with a height between 100 and 104:

      kura_inspector -f 100 print -n 5

- Print errors for all blocks with a height between 100 and 104:

      kura_inspector -f 100 print -n 5 >/dev/null

## Usage

Run Kura Inspector:

    kura_inspector [OPTIONS] <SUBCOMMAND>

### Options

|     Option     |                     Description                     |  Default value   |  Type   |
| -------------- | --------------------------------------------------- | ---------------- | ------- |
| `-f`, `--from` | The block height from which to start the inspection | The latest block | `usize` |

### Subcommands

|      Command      |                     Description                     |
| ----------------- | --------------------------------------------------- |
| [`print`](#print) | Print the contents of a specified number of blocks  |
| `help`            | Print the help message for the tool or a subcommand |

### Errors

An error in Kura Inspector occurs if one the following happens:

- `kura_inspector` fails to configure `kura::BlockStore` ([Kura Configurations](../references/config.html#kura))
- `kura_inspector` [fails](#print-errors) to run the `print` subcommand

## `print`

The `print` command reads data from the `block_store` and prints the results to `output`.

|      Option      |                                      Description                                      |  Default value  |  Type   |
| ---------------- | ------------------------------------------------------------------------------------- | --------------- | ------- |
| `-n`, `--length` | The number of blocks to print. The excess is truncated.                               | 1               | `usize` |
| `-o`, `--output` | Where to write the results of the inspection: valid data and [errors](#print-errors). | Standard Output |         |

### `print` errors

An error in `print` occurs if one the following happens:
- `kura_inspector` fails to read `block_store`
- `kura_inspector` fails to print the `output`
- `kura_inspector` tries to print the latest block and there is none
