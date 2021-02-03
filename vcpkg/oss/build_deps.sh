#/bin/bash

set -e;

git clone https://github.com/microsoft/vcpkg /tmp/vcpkg;
git -C /tmp/vcpkg checkout $(cat /tmp/vcpkg-vars/VCPKG_COMMIT_SHA);

for i in /tmp/vcpkg-vars/patches/*.patch; do git -C /tmp/vcpkg apply --ignore-whitespace $i; done;
for i in /tmp/vcpkg-vars/oss/patches/*.patch; do git -C /tmp/vcpkg apply --ignore-whitespace $i; done;

sh /tmp/vcpkg/bootstrap-vcpkg.sh;

cat /tmp/vcpkg-vars/VCPKG_NO_SANITIZERS_DEPS_LIST | xargs /tmp/vcpkg/vcpkg install;

git -C /tmp/vcpkg checkout -- scripts/toolchains/linux.cmake;
git -C /tmp/vcpkg apply --ignore-whitespace /tmp/vcpkg-vars/oss/patches/0002-vcpkg-dependencies-flags.patch;

/tmp/vcpkg/vcpkg install boost-locale;

git -C /tmp/vcpkg apply --ignore-whitespace /tmp/vcpkg-vars/oss/patches/0003-vcpkg-dependencies-sanitizer.patch;

comm -23 <(sort /tmp/vcpkg-vars/VCPKG_DEPS_LIST) <(sort /tmp/vcpkg-vars/oss/VCPKG_SKIP_DEPS) | xargs /tmp/vcpkg/vcpkg install;

function bumper { while sleep 1; do echo bump; done; };
function run_with_bumper { bumper & p=$!; $@; kill $p; };

ASAN_OPTIONS=detect_leaks=0 run_with_bumper /tmp/vcpkg/vcpkg install grpc;

cat /tmp/vcpkg-vars/VCPKG_HEAD_DEPS_LIST | xargs /tmp/vcpkg/vcpkg install --head;

/tmp/vcpkg/vcpkg list | cut -d':' -f1 | xargs /tmp/vcpkg/vcpkg export --raw --output=dependencies;

mv /tmp/vcpkg/dependencies /opt/dependencies;
chmod +x /opt/dependencies/installed/x64-linux/tools/protobuf/protoc*;

rm -rf /tmp/vcpkg /tmp/vcpkg-vars
