#!/usr/bin/env bash
set -e

if [ -z "$1" ]
  then
    vcpkg_path="$(pwd)/vcpkg"
  else
    vcpkg_path="$1"
fi
if [ -z "$2" ]
  then
    iroha_vcpkg_path="$(pwd)/iroha/vcpkg"
  else
    iroha_vcpkg_path="$2"
fi

git clone https://github.com/microsoft/vcpkg $vcpkg_path
git -C $vcpkg_path checkout $(cat "$iroha_vcpkg_path"/VCPKG_COMMIT_SHA)
for i in "$iroha_vcpkg_path"/patches/*.patch; do git -C $vcpkg_path apply $i; done;
$vcpkg_path/bootstrap-vcpkg.sh
$vcpkg_path/vcpkg install $(cat "$iroha_vcpkg_path"/VCPKG_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
$vcpkg_path/vcpkg install --head $(cat "$iroha_vcpkg_path"/VCPKG_HEAD_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
