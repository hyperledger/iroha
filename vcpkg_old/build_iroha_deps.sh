#!/usr/bin/env bash
set -e

vcpkg_path="${1:-$(pwd)/vcpkg}"
iroha_vcpkg_path="${2:-$(pwd)/iroha/vcpkg_old}"

git clone https://github.com/microsoft/vcpkg $vcpkg_path
git -C $vcpkg_path checkout $(cat "$iroha_vcpkg_path"/VCPKG_COMMIT_SHA)
for i in "$iroha_vcpkg_path"/patches/*.patch; do git -C $vcpkg_path apply $i; done;
$vcpkg_path/bootstrap-vcpkg.sh
$vcpkg_path/vcpkg install $(cat "$iroha_vcpkg_path"/VCPKG_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
$vcpkg_path/vcpkg install --head $(cat "$iroha_vcpkg_path"/VCPKG_HEAD_DEPS_LIST | cut -d':' -f1 | tr '\n' ' ')
