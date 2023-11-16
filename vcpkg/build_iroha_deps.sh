#!/usr/bin/env bash
set -xeuo pipefail

vcpkg_path="${1:-$(pwd)/vcpkg-build}"
script_dir=$(dirname $(realpath ${BASH_SOURCE[0]}))
VCPKG_REF=${VCPKG_REF:-$(head -1 "$script_dir/VCPKG_COMMIT_SHA")}
VCPKG_REF=${VCPKG_REF:-2021.05.12}

git -C $vcpkg_path fetch origin ||
   git clone https://github.com/microsoft/vcpkg $vcpkg_path

git -C $vcpkg_path -c advice.detachedHead=false checkout -f $VCPKG_REF
git -C $vcpkg_path/ports clean -fdx

## Apply patches, bypass if already applied, stop on fail
for i in "$script_dir"/patches/*.patch; do
   if git -C $vcpkg_path apply --reverse --check --ignore-whitespace $i &>/dev/null
      then continue ;fi
   git -C $vcpkg_path apply --ignore-whitespace $i
done

## maybe todo - simpler way to add and patch custom ports
# cp -r "$script_dir"/ports $vcpkg_path/

# MANIFEST_ROOT=$(realpath $script_dir/..)
# MANIFEST_ROOT=$(git -C $script_dir rev-parse --show-toplevel)
BINARYCACHE_PATH=$(realpath $vcpkg_path)/binarycache
INSTALL_ROOT=$vcpkg_path/installed

## Address error message "Environment variable VCPKG_FORCE_SYSTEM_BINARIES must be set on arm, s390x, and ppc64le platforms"
case "$(uname -m)" in
   arm*|s390*|ppc64*|aarch64)  export VCPKG_FORCE_SYSTEM_BINARIES=1 ;;
esac

## Every time clean build of vcpkgtool takes 43 seconds on MacBook 2016 i7 2.8GHz
##                                 and takes 3 minutes on default GitHub runner
## ToDo try reuse existing vcpkg_tool
case $(uname | tr '[:upper:]' '[:lower:]') in
   windows*|msys*|mingw*)
      bootstrap(){
         $vcpkg_path/bootstrap-vcpkg.bat -disableMetrics
      }
      # MANIFEST_ROOT=$(cygpath -wa $MANIFEST_ROOT)
      BINARYCACHE_PATH=$(cygpath -wa $BINARYCACHE_PATH)
      INSTALL_ROOT=$(cygpath -wa $INSTALL_ROOT)
      ;;
   *)
      bootstrap(){
         $vcpkg_path/bootstrap-vcpkg.sh -disableMetrics -useSystemBinaries
      }
      ;;
   quick-alternative)
      ## TODO: Do not use `bootstrap` because it is slow and old and has too much logic overhead
      bootstrap()(
         vcpkg_tool_path=$vcpkg_path/vcpkg-tool
         VCPKG_TOOL_REF=2021-05-05-9f849c4c43e50d1b16186ae76681c27b0c1be9d9  #2021-02-24-d67989bce1043b98092ac45996a8230a059a2d7e #
         git -C $vcpkg_tool_path fetch origin ||
            git clone https://github.com/microsoft/vcpkg-tool.git $vcpkg_tool_path
         cd $vcpkg_tool_path
         git -c advice.detachedHead=false checkout $VCPKG_TOOL_REF
         cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -GNinja -DBUILD_TESTING=OFF -DVCPKG_DEVELOPMENT_WARNINGS=OFF -DRULE_LAUNCH_COMPILE=ccache
         cmake --build build
         cp build/vcpkg $vcpkg_path/vcpkg
      )
      ;;
esac

bootstrap

case usual-mode in
   usual-mode)
      ## The old lamp way to install without manifests
      $vcpkg_path/vcpkg install \
         --feature-flags=-manifests \
         $(cat $script_dir/VCPKG_DEPS_LIST | tr -d '\r')
      # ( #cd /tmp
      # cat $script_dir/VCPKG_DEPS_LIST | while read pkgspec ;do
      #    $vcpkg_path/vcpkg install --feature-flags=-manifests $pkgspec
      # done
      # )
      ;;
   manifest-mode)
      $vcpkg_path/vcpkg install \
         --x-install-root=$INSTALL_ROOT \
         --feature-flags=manifests
      #   --x-manifest-root=. \
      #   --binarysource=files,$BINARYCACHE_PATH,readwrite \
      ;;
esac

#################### PROFILING ####################
## system macos big sur on macbook pro 2016 i7 2.8GHz
## Installation of already built packages takes about 43 sec
##
## CMake configure
## time cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=$HOME/devel/vcpkg2/scripts/buildsystems/vcpkg.cmake
## Executed in    7,56 secs
##
## CMake clean build using make
## time cmake --build build -- -j
## Executed in   18,35 mins
