FROM ubuntu:20.04

# number of concurrent threads during build
# usage: docker build --build-arg PARALLELISM=8 -t name/name .
ARG PARALLELISM=1

ENV IROHA_HOME /opt/iroha
ENV IROHA_BUILD /opt/iroha/build

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y --no-install-recommends install \
            apt-utils software-properties-common wget gpg-agent \
            libtool \
            # compilers (gcc-9, gcc-10)
            build-essential g++-9 g++-10 cmake ninja-build \
            gdb gdbserver \
            # CI dependencies
            git ssh tar gzip ca-certificates gnupg \
            # code coverage
            lcov \
            # Python3
            python3-dev python3-pip python-is-python3 \
            # other
            curl file ccache libssl-dev \
            gcovr cppcheck doxygen rsync graphviz graphviz-dev vim zip unzip pkg-config \
            jq autoconf \
            postgresql postgresql-contrib; \
    if [ $(uname -m) = "x86_64" ] ;then \
        apt-get -y --no-install-recommends install \
            clang-10 lldb-10 lld-10 libc++-10-dev libc++abi-10-dev clang-format clang-format-7 clang-format-12; \
    fi; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

RUN cd /opt/ && \
    git clone https://github.com/sobolevn/git-secret.git git-secret && \
    cd git-secret && make build && \
    PREFIX="/usr/local" make install

## golang stuff for iroha+burrow
RUN curl -fL https://golang.org/dl/go1.17.2.linux-$(dpkg --print-architecture).tar.gz | tar -C /opt -xz
ENV GOPATH=/opt/gopath
RUN mkdir ${GOPATH}
ENV PATH=${PATH}:/opt/go/bin:${GOPATH}/bin
RUN go get github.com/golang/protobuf/protoc-gen-go
RUN export PATH="$PATH:$(go env GOPATH)/bin" # according to: https://grpc.io/docs/languages/go/quickstart/

## Rust-lang stuff for iroha+ursa
ENV RUSTUP_HOME=/opt/rust
ENV CARGO_HOME=/opt/rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --no-modify-path --profile minimal ; \
    echo 'source /opt/rust/env' >>/etc/profile ; \
    echo 'source /opt/rust/env' >>/etc/bash.bashrc

## Allow access to database, trust local connections
# RUN sed -i /etc/postgresql/12/main/pg_hba.conf -Ee's,(^local\s+all\s+postgres\s+)\w+,\1trust,'
RUN echo " \n\
# TYPE  DATABASE        USER            ADDRESS                 METHOD \n\
local   all             all                                     trust \n\
host    all             all             127.0.0.1/32            trust \n\
host    all             all             ::1/128                 trust \n\
local   replication     all                                     trust \n\
host    replication     all             127.0.0.1/32            trust \n\
host    replication     all             ::1/128                 trust \n\
" > /etc/postgresql/12/main/pg_hba.conf

ENV PATH=${PATH}:/usr/lib/postgresql/12/bin/

## non-interactive adduser
##   -m = create home dir
##   -s = set default shell
##   iroha-ci = username
##   -u = userid, default for Ubuntu is 1000
##   -U = create a group same as username
##   no password
RUN useradd -ms /bin/bash iroha-ci -u 1000 -U && \
    usermod -aG postgres iroha-ci

WORKDIR /opt/iroha
RUN set -e; \
    chown -R iroha-ci:iroha-ci /opt/iroha; \
    chmod -R 777 /opt/iroha; \
    mkdir -p /tmp/ccache -m 777; \
    ccache --clear

USER iroha-ci
# CMD /bin/bash
