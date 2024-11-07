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
bash scripts/build_wasm.sh --target=libs
```

## WASM samples only

```bash
bash scripts/build_wasm.sh --target=samples
```

## WASM in specific profile
1. Release **(default)**
```bash
bash scripts/build_wasm.sh --profile=deploy
```
2. Debug
```bash
bash scripts/build_wasm.sh --profile=profiling
```