#!/usr/bin/env bash
set -e

# TODO: remove after full support of Apple Silicone from VCPKG and all deps
trap 'cleanup $? $LINENO' EXIT

cleanup () {
    if [ "$1" != "0" ]; then
        echo "Error $1 occurred on line $2"
    fi

    if [ "$arm64_set" = true ] ; then
        echo "Restoring back environment variables."
        export VCPKG_DEFAULT_TRIPLET=$prev_triplet_value
        export VCPKG_FORCE_SYSTEM_BINARIES=$prev_force_binaries_value
    fi
}

# Taken from https://cutecoder.org/software/detecting-apple-silicon-shell-script/
arch_name="$(uname -m)"
arm64_set=false

if [ "${arch_name}" = "x86_64" ]; then
    if [ "$(sysctl -in sysctl.proc_translated)" = "1" ]; then
        echo "Running on Rosetta 2"
    else
        echo "Running on native Intel"
    fi 
elif [ "${arch_name}" = "arm64" ]; then
    echo "Running on ARM; setting up required variables for VCPKG"

    prev_triplet_value=$VCPKG_DEFAULT_TRIPLET
    prev_force_binaries_value=$VCPKG_FORCE_SYSTEM_BINARIES

    export VCPKG_DEFAULT_TRIPLET=arm64-osx
    export VCPKG_FORCE_SYSTEM_BINARIES=1
    arm64_set=true
else
    echo "Unknown architecture: ${arch_name}"
fi
# end TODO

vcpkg_path="${1:-$(pwd)/vcpkg}"
iroha_vcpkg_path="${2:-$(pwd)/iroha/vcpkg}"

git clone https://github.com/microsoft/vcpkg $vcpkg_path
git -C $vcpkg_path checkout $(cat "$iroha_vcpkg_path"/VCPKG_COMMIT_SHA)
for i in "$iroha_vcpkg_path"/patches/*.patch; do git -C $vcpkg_path apply --ignore-whitespace $i; done;
$vcpkg_path/bootstrap-vcpkg.sh
cat "$iroha_vcpkg_path"/VCPKG_DEPS_LIST | xargs $vcpkg_path/vcpkg install
cat "$iroha_vcpkg_path"/VCPKG_HEAD_DEPS_LIST | xargs $vcpkg_path/vcpkg install --head
