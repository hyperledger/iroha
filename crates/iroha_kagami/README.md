# Kagami (Teacher and Exemplar and/or Looking glass)

Kagami is a tool used to generate and validate automatically generated data files that are shipped with Iroha.

## Build

From anywhere in the repository, run:

```bash
cargo build --bin kagami
```

This will place `kagami` inside the `target/debug/` directory (from the root of the repository).

## Usage

As it is an internal tool with no stable API, we decided to move all the documentation into the CLI help messages and keep it up to date in a single place.

Run:

```bash
kagami --help
```
