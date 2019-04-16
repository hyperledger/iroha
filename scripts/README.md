# Set up `iroha` development environment

## Git repository

Clone `iroha` repository on your directory.

```bash
git clone -b develop --depth=1 https://github.com/hyperledger/iroha /path/to/iroha
```

## How to run development environment

```bash
/path/to/iroha/scripts/run-iroha-dev.sh
```

You will be attached to interactive environment for development and testing with `iroha` folder mounted from host machine.

Docker environment will be removed when you logout from the container.

## Build `iroha` and run tests

Build:
```bash
cmake -H. -Bbuild; cmake --build build -- -j$(nproc)
```

`irohad` and `iroha-cli` binaries will be in `./build/bin` directory.

Test:
```bash
cmake --build build --target test
```

## Execute `iroha-cli` with `irohad` running

Execute `run-iroha-dev.sh` again to attach to existing container.
