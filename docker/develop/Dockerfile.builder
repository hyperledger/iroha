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
        # CI dependencies
        git ssh tar gzip ca-certificates gnupg \
        # code coverage
        lcov \
        # Python3
        python3-dev python3-pip python-is-python3 \
        # other
        curl file gdb gdbserver ccache libssl-dev \
        gcovr cppcheck doxygen rsync graphviz graphviz-dev vim zip unzip pkg-config \
        postgresql postgresql-contrib

# compiler clang-10 and libc++ only on x86_64, for debug purpose
RUN if [ `uname -m` = "x86_64" ]; then \
      apt-get update && \
      apt-get -y --no-install-recommends install \
        clang-10 lldb-10 lld-10 libc++-10-dev libc++abi-10-dev clang-format-7; \
    fi

## Finish APT installation, clean up
RUN apt-get -y clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

# # install dependencies
# COPY vcpkg /tmp/vcpkg-vars
# RUN set -e; \
#     export VCPKG_FORCE_SYSTEM_BINARIES=1; \
#     sh /tmp/vcpkg-vars/build_iroha_deps.sh /tmp/vcpkg /tmp/vcpkg-vars; \
#     /tmp/vcpkg/vcpkg export $(/tmp/vcpkg/vcpkg list | cut -d':' -f1 | tr '\n' ' ') --raw --output=dependencies; \
#     mv /tmp/vcpkg/dependencies /opt/dependencies; \
#     chmod +x /opt/dependencies/installed/*/tools/protobuf/protoc*; \
#     unset VCPKG_FORCE_SYSTEM_BINARIES; \
#     rm -rf /tmp/vcpkg*

# # install sonar cli
# ENV SONAR_CLI_VERSION=3.3.0.1492
# RUN set -e; \
#     mkdir -p /opt/sonar; \
#     curl -L -o /tmp/sonar.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_CLI_VERSION}-linux.zip; \
#     unzip -o -d /tmp/sonar-scanner /tmp/sonar.zip; \
#     mv /tmp/sonar-scanner/sonar-scanner-${SONAR_CLI_VERSION}-linux /opt/sonar/scanner; \
#     ln -s -f /opt/sonar/scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner; \
#     rm -rf /tmp/sonar*

# # fetch lcov reports converter
# RUN set -e; \
#     curl -L -o /tmp/lcov_cobertura.py https://raw.githubusercontent.com/eriwen/lcov-to-cobertura-xml/8c55cd11f80a21e7e46f20f8c81fcde0bf11f5e5/lcov_cobertura/lcov_cobertura.py

# # OpenJRE 8
# RUN set -e; \
#     apt-get update; \
#     apt-get -y install openjdk-8-jre; \
#     apt-get -y clean && \
#     rm -rf /var/lib/apt/lists/*; \
#     java -version

# # python bindings dependencies
# RUN set -e; \
#     export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1; \
#     pip3 install setuptools wheel; \
#     pip3 install grpcio_tools pysha3 iroha==0.0.5.4; \
#     unset GRPC_PYTHON_BUILD_SYSTEM_OPENSSL

## Allow access to database, trust local connections
# RUN sed -i /etc/postgresql/12/main/pg_hba.conf -Ee's,(^local\s+all\s+postgres\s+)\w+,\1trust,'
# COPY pg_hba.conf /etc/postgresql/12/main/pg_hba.conf
RUN echo " \n\
# TYPE  DATABASE        USER            ADDRESS                 METHOD \n\
local   all             all                                     trust \n\
host    all             all             127.0.0.1/32            trust \n\
host    all             all             ::1/128                 trust \n\
local   replication     all                                     trust \n\
host    replication     all             127.0.0.1/32            trust \n\
host    replication     all             ::1/128                 trust \n\
" > /etc/postgresql/12/main/pg_hba.conf

# non-interactive adduser
#   -m = create home dir
#   -s = set default shell
#   iroha-ci = username
#   -u = userid, default for Ubuntu is 1000
#   -U = create a group same as username
#   no password
# RUN useradd -ms /bin/bash iroha -u 1000 -U

# WORKDIR /opt/iroha
# RUN set -e; \
#     chmod -R 777 /opt/iroha; \
#     mkdir -p /tmp/ccache -m 777; \
#     ccache --clear

# USER iroha
# CMD /bin/bash
