#!/bin/bash

set -ex
# brew dependencies
brew install llvm@7 gcc6 git postgres@9.6

# CMake 3.11.4
curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.11.4/cmake-3.11.4-Darwin-x86_64.tar.gz
tar zxf /tmp/cmake.tar.gz
mv cmake-3.11.4-Darwin-x86_64/CMake.app ~/
rm -rf /tmp/cmake.tar.gz /tmp/cmake-3.11.4-Darwin-x86_64

# VCPKG
## SHARE FIRST!!
## config.vm.synced_folder "vcpkg", "/tmp/vcpkg-vars", type: "rsync"

git clone https://github.com/microsoft/vcpkg /tmp/vcpkg
(cd /tmp/vcpkg ; git checkout $(cat /tmp/vcpkg-vars/VCPKG_COMMIT_SHA))
for i in /tmp/vcpkg-vars/patches/*.patch; do git -C /tmp/vcpkg apply $i; done
sh /tmp/vcpkg/bootstrap-vcpkg.sh
/tmp/vcpkg/vcpkg install $(cat /tmp/vcpkg-vars/VCPKG_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
/tmp/vcpkg/vcpkg install --head $(cat /tmp/vcpkg-vars/VCPKG_HEAD_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
/tmp/vcpkg/vcpkg export $(/tmp/vcpkg/vcpkg list | cut -d':' -f1 | tr '\n' ' ') --raw --output=dependencies
mv /tmp/vcpkg/dependencies /opt/dependencies
chmod +x /opt/dependencies/installed/x64-linux/tools/protobuf/protoc*
rm -rf /tmp/vcpkg*

echo 'export PATH="$HOME/CMake.app/Contents/bin:/usr/local/opt/postgresql@9.6/bin:$PATH"' >> ~/.bash_profile