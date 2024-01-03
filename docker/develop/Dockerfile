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
        # compilers (gcc-9, gcc-10)
        build-essential g++-9 g++-10 cmake ninja-build \
        # CI dependencies
        git ssh tar gzip ca-certificates gnupg \
        # code coverage
        lcov \
        # Python3
        python3-pip python-is-python3 \
        # other
        curl file gdb gdbserver ccache python3-dev libssl-dev \
        gcovr cppcheck doxygen rsync graphviz graphviz-dev unzip vim zip pkg-config; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

# compiler clang-10 and libc++ only on x86_64, for debug purpose
RUN set -e; \
    if [ `uname -m` = "x86_64" ]; then \
      apt-get update && \
      apt-get -y --no-install-recommends install \
        clang-10 lldb-10 lld-10 libc++-10-dev libc++abi-10-dev clang-format-7; \
      apt-get -y clean && \
      rm -rf /var/lib/apt/lists/*; \
    fi

# golang stuff
RUN curl https://dl.google.com/go/go1.17.2.linux-$(dpkg --print-architecture).tar.gz | tar -C /opt -xz
ENV GOPATH=/opt/gopath
RUN mkdir ${GOPATH}
ENV PATH=${PATH}:/opt/go/bin:${GOPATH}/bin
RUN go get github.com/golang/protobuf/protoc-gen-go
RUN export PATH="$PATH:$(go env GOPATH)/bin" # according to: https://grpc.io/docs/languages/go/quickstart/

## pip3 contains fresher versions of packages than apt
RUN pip3 install --no-cache-dir cmake ninja

# install dependencies
COPY vcpkg /tmp/vcpkg-vars
RUN set -xe; \
    case "$(uname -m)" in  arm*|s390*|ppc64*)  export VCPKG_FORCE_SYSTEM_BINARIES=1 ;; esac; \
    /tmp/vcpkg-vars/build_iroha_deps.sh /tmp/vcpkg /tmp/vcpkg-vars; \
    /tmp/vcpkg/vcpkg export $(/tmp/vcpkg/vcpkg list | cut -d':' -f1 | tr '\n' ' ') --raw --output=dependencies; \
    mv /tmp/vcpkg/dependencies /opt/dependencies; \
    chmod +x /opt/dependencies/installed/*/tools/protobuf/protoc*; \
    unset VCPKG_FORCE_SYSTEM_BINARIES; \
    rm -rf /tmp/vcpkg*
    ##NOTE Newer packages like libpq may require newer cmake version, and will fail with no sanity error message when VCPKG_FORCE_SYSTEM_BINARIES=1;
    ##NOTE But vcpkg on platforms arm,s390,ppc64 require VCPKG_FORCE_SYSTEM_BINARIES=1

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
    export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1; \
    pip3 install setuptools wheel; \
    pip3 install grpcio_tools pysha3 iroha==0.0.5.4; \
    unset GRPC_PYTHON_BUILD_SYSTEM_OPENSSL

# install rust
RUN set -e; \
    curl -L -o /tmp/rust-1.37.0-$(uname -m)-unknown-linux-gnu.tar.gz https://static.rust-lang.org/dist/rust-1.37.0-$(uname -m)-unknown-linux-gnu.tar.gz; \
    tar xf /tmp/rust-1.37.0-$(uname -m)-unknown-linux-gnu.tar.gz -C /tmp; \
    /tmp/rust-1.37.0-$(uname -m)-unknown-linux-gnu/install.sh; \
    rm -rf /tmp/rust-1.37.0-$(uname -m)-unknown-linux-gnu*

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
