# How to build

To get a help message, run from the project root:
`bash scripts/build_wasm.sh --help`

# Examples

## All WASM crates

```bash
bash scripts/build_wasm.sh
```

## WASM libraries only

```bash
bash scripts/build_wasm.sh libs
```

## WASM samples only

```bash
bash scripts/build_wasm.sh samples
```

## WASM in specific profile
1. Deploy
```bash
bash scripts/build_wasm.sh --profile=deploy
```
2. Release (with debug information) **(default)**
```bash
bash scripts/build_wasm.sh --profile=release
```