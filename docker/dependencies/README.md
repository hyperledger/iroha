# Overview

Purpose of docker container, which is to be generated from this folder, is to test, if Iroha system can build, when all dependencies are installed into custom, separated directories.

# How to build:
1. Build docker image:
    - ```cd $IROHA_ROOT/docker/dependencies```
    - ```docker build --build-arg PARALLELISM=$DESIRED_THREADS_AMOUNT -t iroha-dpnd .```
    - Now, you have image named "iroha-dpnd", containing all necessary dependencies in /opt/dependencies folder
2. Create a container and get into it:\
    ```docker run --rm -it iroha-dpnd```
3. Now, you are inside and ready to pull and build Iroha:
    - run: 
        - ```git clone https://github.com/hyperledger/iroha.git```
        - ```cd iroha && mkdir build && cd build```
        - ```cmake -DCMAKE_PREFIX_PATH="$(ls /opt/dependencies/* -d1 | paste -s -d\; -)" ..```
        - ```make -j 'DESIRED_THREADS_AMOUNT'```
4. After performing those steps you will have a working develop build inside container
5. Exit container by ctrl+D