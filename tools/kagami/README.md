# Kagami (Teacher and Exemplar and/or Looking glass)

Generate and validate the automatically generated data files shipped with Iroha.

### Building

Use

```bash
cargo build --bin kagami
```

anywhere in this repository. This will place `kagami` inside the `target/debug/` directory (from the root of the repository).

### Usage

```bash
kagami 2.0.0-pre-rc.3
Soramitsu Iroha2 team (https://github.com/orgs/soramitsu/teams/iroha2)
Tool generating the cryptorgraphic key pairs,

USAGE:
kagami <SUBCOMMAND>

OPTIONS:
-h, --help       Print help information
-V, --version    Print version information

SUBCOMMANDS:
crypto     Generate cryptorgraphic key pairs
docs       Generate a Markdown reference of configuration parameters
genesis    Generate a default genesis block that is used in tests
help       Print this message or the help of the given subcommand(s)
schema     Generate schema used for code generation in Iroha SDKs
```

#### Key generation

With a few examples.

```bash
$ ./kagami crypto
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
$ ./kagami crypto --seed <seed>
```

To generate a key with the `secp256k1` algorithm, which corresponds to the private key `8e170e7abe3cc71afeb2459b2d055641159dca4825e0536234e120ced756fabda2bfcb42761216a95a5bf2574219c602a9e7d410420af8b020c9e9e40ffb3690`, run

```bash
$ ./kagami crypto --algorithm secp256k1 --private-key "b32129af69b829a88ab9bac60b2a33cc57f8843e93aae0478e93f2285059c236"
```

```bash
Public key (multihash): e70121031c59a9cabaf58f3b8a6157362b9f6feac3dd47ee947fbf2f335805e1a7f96bde
Private key: b32129af69b829a88ab9bac60b2a33cc57f8843e93aae0478e93f2285059c236
Digest function: secp256k1
```


#### Genesis

```bash
kagami genesis
```

Should produce a genesis block in JSON format. You might want to use shell redirections e.g. `kagami -g >genesis.json`.

#### Schema

```bash
kagami schema
```

Should generate the schema in JSON format.  You might want to use shell redirections e.g. `kagami -g >genesis.json`.

#### Peer configuration reference

```bash
kagami docs
```

Should generate the documentation in Markdown format. Should be identical to the [reference configuration](../../docs/source/references/config.md).
