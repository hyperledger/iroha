#!/usr/bin/env bash
set -xeuo pipefail

vcpkg_path="${1:-$(pwd)/vcpkg}"
script_dir=$(dirname $(realpath ${BASH_SOURCE[0]}))
VCPKG_COMMIT_SHA=${VCPKG_COMMIT_SHA:-$(cat "$script_dir/VCPKG_COMMIT_SHA")}
VCPKG_COMMIT_SHA=${VCPKG_COMMIT_SHA:-da9defc3bddbba39edd9c7e04d4f2bc4bca3f6d4}
build_dir=${2:-${build_dir:-$(dirname $script_dir)/build}}

git -C $vcpkg_path fetch origin || 
    git clone https://github.com/microsoft/vcpkg $vcpkg_path

git -C $vcpkg_path checkout -f $VCPKG_COMMIT_SHA
git -C $vcpkg_path/ports clean -fdx

## Apply patches, bypass if already applied, stop on fail
for i in "$script_dir"/patches/*.patch; do 
    if git -C $vcpkg_path apply --reverse --check --ignore-whitespace $i &>/dev/null
        then continue ;fi
    git -C $vcpkg_path apply --ignore-whitespace $i
done

# cp -r "$script_dir"/ports $vcpkg_path/

## Every time clean build of vcpkgtool takes 43 seconds on MacBook 2016 i7 2.8GHz
## ToDo try reuse existing vcpkg_tool
$vcpkg_path/bootstrap-vcpkg.sh -useSystemBinaries

vcpkg --x-manifest-root=$(realpath $script_directory/..) \
    --binarysource=files,$vcpkg_path/binarycache,readwrite \
    --x-install-root=$build_dir/vcpkg_installed \
    install

#    --x-install-root=$vcpkg_path/installed \  #default for manifest mode is PWD/vcpkg_installed

## Profiling
## system macos big sur on macbook pro 2016 i7 2.8GHz
## Installation of already built packages takes about 43 sec
## 
## CMake configure
## time cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=/Users/tanya/devel/vcpkg2/scripts/buildsystems/vcpkg.cmake
## Executed in    7,56 secs
##
## CMake cl
