# Kagami

This tool is used to generate and validate the automatically generated data files shipped with Iroha.

### Building

Use

```bash
cargo build --bin kagami
```

anywhere in this repository. This will place `kagami` inside the `target/debug/` directory (from the root of the repository).

### Usage

```bash
Kagami 0.1
Iroha development team.
Generator for data used in Iroha.

USAGE:
kagami [FLAGS] [OPTIONS]

FLAGS:
-d, --docs       If specified, print configuration docs
-g, --genesis    If specified, print the Genesis
-h, --help       Prints help information
--json       If specified the output will be formatted as json.
-s, --schema     If specified, print Schema
-V, --version    Prints version information

OPTIONS:
--algorithm <algorithm>        Function used to generate the key pair. [default: ed25519]  [possible values:
ed25519, secp256k1, bls_normal, bls_small]
--private_key <private_key>    Sets a private key. Should be used separately from `seed`.
--seed <seed>                  Sets a seed for random number generator. Should be used separately from
`private_key`.
```

#### Key generation

With a few examples.

By default, will generate a key pair.

```bash
$ ./kagami
```

```bash
Kagami. To see help run with `--help`.
No flags specified, generating key-pair.
Public key (multihash): ed0120232adec551bfa1856279ebccc3c3a09783c516478f4cbb2f42f342614bec7601
Private key: a1e2c094496dd53ea103f1423b90ccb7d65ff25ab46f5fa1643c14e6010f7f75232adec551bfa1856279ebccc3c3a09783c516478f4cbb2f42f342614bec7601
Digest function: ed25519
```

To generate a key pair from a given seed, run

```bash
$ ./kagami --seed
```

To generate a key with the `secp256k1` algorithm, which corresponds to the private key `8e170e7abe3cc71afeb2459b2d055641159dca4825e0536234e120ced756fabda2bfcb42761216a95a5bf2574219c602a9e7d410420af8b020c9e9e40ffb3690`, run

```bash
$ ./kagami --algorithm --private-key 8e170e7abe3cc71afeb2459b2d055641159dca4825e0536234e120ced756fabda2bfcb42761216a95a5bf2574219c602a9e7d410420af8b020c9e9e40ffb3690
```

```bash
Kagami. To see help run with `--help`.
No flags specified, generating key-pair.
Public key (multihash): ed0120a2bfcb42761216a95a5bf2574219c602a9e7d410420af8b020c9e9e40ffb3690
Private key: 8e170e7abe3cc71afeb2459b2d055641159dca4825e0536234e120ced756fabda2bfcb42761216a95a5bf2574219c602a9e7d410420af8b020c9e9e40ffb3690
Digest function: ed25519
```


#### Genesis

```bash
kagami -g
```

Should produce a genesis block in JSON format. You might want to use shell redirections e.g. `kagami -g >genesis.json`.

#### Schema

```bash
kagami -s
```

Should generate the schema in JSON format.  You might want to use shell redirections e.g. `kagami -g >genesis.json`.

#### Peer configuration reference

```bash 
kagami --docs
```

Should generate the documentation in Markdown format. Should be identical to the [reference configuration](../../docs/source/references/config.md).
