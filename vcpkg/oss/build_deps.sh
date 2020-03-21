#/bin/bash

set -ex

IROHA_REPO=${SRC}/iroha

git clone https://github.com/microsoft/vcpkg /tmp/vcpkg
git -C /tmp/vcpkg checkout $(cat ${IROHA_REPO}/vcpkg/VCPKG_COMMIT_SHA)

git -C /tmp/vcpkg apply --ignore-whitespace ${IROHA_REPO}/vcpkg/patches/*.patch ${IROHA_REPO}/vcpkg/oss/patches/*.patch

sh /tmp/vcpkg/bootstrap-vcpkg.sh

export ASAN_OPTIONS=detect_leaks=0
SANITIZER_FLAGS_VAR=SANITIZER_FLAGS_${SANITIZER}
export VCPKG_C_FLAGS="$CFLAGS ${!SANITIZER_FLAGS_VAR}"
export VCPKG_CXX_FLAGS="$CXXFLAGS ${!SANITIZER_FLAGS_VAR}"
export VCPKG_LINKER_FLAGS="${!SANITIZER_FLAGS_VAR}"

cat ${IROHA_REPO}/vcpkg/oss/VCPKG_DEPS | xargs /tmp/vcpkg/vcpkg install

function bumper { while sleep 1; do echo bump; done; }
function run_with_bumper { bumper & p=$!; $@; kill $p; }

cat ${IROHA_REPO}/vcpkg/VCPKG_HEAD_DEPS_LIST | xargs /tmp/vcpkg/vcpkg install --head
