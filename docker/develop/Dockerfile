FROM ubuntu:20.04

# number of concurrent threads during build
# usage: docker build --build-arg PARALLELISM=8 -t name/name .
ARG PARALLELISM=1

ENV IROHA_HOME /opt/iroha
ENV IROHA_BUILD /opt/iroha/build

RUN apt-get update && \
    apt-get -y --no-install-recommends install apt-utils software-properties-common wget gpg-agent; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

RUN set -e; \
    apt-get update && \
    apt-get -y --no-install-recommends install libtool \
        # compilers (gcc-7, gcc-9)
        build-essential g++-7 g++-9 ninja-build \
        # CI dependencies
        git ssh tar gzip ca-certificates gnupg \
        # code coverage
        lcov \
        # Python3
        python3-pip python-is-python3 \
        # other
        curl file gdb gdbserver ccache python3-dev \
        gcovr cppcheck doxygen rsync graphviz graphviz-dev unzip vim zip pkg-config; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

# compiler clang-7, clang-9 and libc++ only on x86_64, for debug purpose
RUN set -e; \
    if [ `uname -m` = "x86_64" ]; then \
      apt-get update && \
      apt-get -y --no-install-recommends install \
        clang-7 lldb-7 lld-7 libc++-7-dev libc++abi-7-dev clang-format-7 \
        clang-9; \
      apt-get -y clean && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# golang stuff
RUN curl https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz | tar -C /opt -xz
ENV GOPATH=/opt/gopath
RUN mkdir ${GOPATH}
ENV PATH=${PATH}:/opt/go/bin:${GOPATH}/bin
RUN go get github.com/golang/protobuf/protoc-gen-go

# install cmake 3.14.0
RUN set -e; \
    curl -L -o /tmp/cmake.sh https://github.com/Kitware/CMake/releases/download/v3.14.0/cmake-3.14.0-Linux-x86_64.sh; \
    sh /tmp/cmake.sh --prefix=/usr/local --skip-license; \
    rm /tmp/cmake.sh

# install dependencies
COPY vcpkg /tmp/vcpkg-vars
RUN set -e; \
    sh /tmp/vcpkg-vars/build_iroha_deps.sh /tmp/vcpkg /tmp/vcpkg-vars; \
    /tmp/vcpkg/vcpkg export $(/tmp/vcpkg/vcpkg list | cut -d':' -f1 | tr '\n' ' ') --raw --output=dependencies; \
    mv /tmp/vcpkg/dependencies /opt/dependencies; \
    chmod +x /opt/dependencies/installed/x64-linux/tools/protobuf/protoc*; \
    rm -rf /tmp/vcpkg*

# install sonar cli
ENV SONAR_CLI_VERSION=3.3.0.1492
RUN set -e; \
    mkdir -p /opt/sonar; \
    curl -L -o /tmp/sonar.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_CLI_VERSION}-linux.zip; \
    unzip -o -d /tmp/sonar-scanner /tmp/sonar.zip; \
    mv /tmp/sonar-scanner/sonar-scanner-${SONAR_CLI_VERSION}-linux /opt/sonar/scanner; \
    ln -s -f /opt/sonar/scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner; \
    rm -rf /tmp/sonar*

# fetch lcov reports converter
RUN set -e; \
    curl -L -o /tmp/lcov_cobertura.py https://raw.githubusercontent.com/eriwen/lcov-to-cobertura-xml/8c55cd11f80a21e7e46f20f8c81fcde0bf11f5e5/lcov_cobertura/lcov_cobertura.py

# OpenJRE 8
RUN set -e; \
    apt-get update; \
    apt-get -y install openjdk-8-jre; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*; \
    java -version

# python bindings dependencies
RUN set -e; \
    pip3 install setuptools wheel; \
    pip3 install grpcio_tools pysha3 iroha==0.0.5.4

# install rust
RUN set -e; \
    curl -L -o /tmp/rust-1.37.0-x86_64-unknown-linux-gnu.tar.gz https://static.rust-lang.org/dist/rust-1.37.0-x86_64-unknown-linux-gnu.tar.gz; \
    tar xf /tmp/rust-1.37.0-x86_64-unknown-linux-gnu.tar.gz -C /tmp; \
    /tmp/rust-1.37.0-x86_64-unknown-linux-gnu/install.sh; \
    rm -rf /tmp/rust-1.37.0-x86_64-unknown-linux-gnu*

# non-interactive adduser
#   -m = create home dir
#   -s = set default shell
#   iroha-ci = username
#   -u = userid, default for Ubuntu is 1000
#   -U = create a group same as username
#   no password
RUN useradd -ms /bin/bash iroha-ci -u 1000 -U

WORKDIR /opt/iroha
RUN set -e; \
    chmod -R 777 /opt/iroha; \
    mkdir -p /tmp/ccache -m 777; \
    ccache --clear


USER iroha-ci
ENV CMAKE_TOOLCHAIN_FILE /opt/dependencies/scripts/buildsystems/vcpkg.cmake
CMD ["/bin/bash"]
