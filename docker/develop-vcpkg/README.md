# How to build:

Navigate to root repository folder and run:
```
docker build -t hyperledger/iroha-docker-develop:v1 -f docker/develop-vcpkg/Dockerfile .
```

# Why

This container provides environment to build Iroha.

# Note

Iroha has to be build with `-DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE`
