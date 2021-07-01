#!/usr/bin/env bash
set -euo pipefail
shopt -s lastpipe

echowarn(){
   echo >&2 '::warning::'"$@"
}
echoerr(){
   echo >&2 '::error::'"$@"
}

readonly DEFAULT_oses="ubuntu macos windows" DEFAULT_build_types="Debug" DEFAULT_cmake_opts="default burrow ursa"
readonly DEFAULT_ubuntu_compilers="gcc-9" AVAILABLE_ubuntu_compilers="gcc-9 gcc-10 clang-10"
readonly DEFAULT_macos_compilers="clang"  AVAILABLE_macos_compilers="clang llvm gcc-10"
readonly DEFAULT_windows_compilers="msvc" AVAILABLE_windows_compilers="msvc mingw cygwin"
readonly ALL_oses="ubuntu macos windows" ALL_build_types="Debug Release" ALL_cmake_opts="default burrow ursa" ALL_compilers="gcc-9 gcc-10 clang-10 clang llvm msvc"

generate(){
   declare -rn DEFAULT_compilers=DEFAULT_${os}_compilers
   declare -rn AVAILABLE_compilers=AVAILABLE_${os}_compilers
   local compilers=${compilers:-$DEFAULT_compilers}
   local cc bt op used_compilers=
   for cc in $compilers ;do
      if ! [[ " $AVAILABLE_compilers " = *" $cc "* ]] ;then
         continue
      fi
      used_compilers+=$cc' '
      for bt in $build_types ;do
         for co in $cmake_opts ;do
            MATRIX+="$os $cc $bt $co"$'\n'
         done
      done
   done
   if test "$used_compilers" = ''; then
      echowarn "No available compilers for '$os' among '$compilers', available: '$AVAILABLE_compilers'"
   fi
}

handle_user_line(){
   # echo ----------- "$@"
   if [[ "${1:-}" != '/build' ]] ;then
      echowarn "Line skipped, should start with '/build'"
      return
   fi
   shift
   local oses compilers cmake_opts build_types
   dockerpush=yes

   while [[ $# > 0 ]] ;do
      case "$1" in
         macos)                     oses+=" $1 " ;;
         ubuntu|linux)              oses+=" ubuntu " ;;
         windows)                   oses+=" $1 " ;;
         default)                   cmake_opts+=" $1 "  ;;
         burrow)                    cmake_opts+=" $1 "  ;;
         ursa)                      cmake_opts+=" $1 "  ;;
         release|Release)           build_types+=" Release " ;;
         debug|Debug)               build_types+=" Debug"  ;;
         gcc-9|gcc9)                compilers+=" gcc-9 " ;;
         gcc-10|gcc10)              compilers+=" gcc-10 " ;;
         clang-10|clang10)          compilers+=" clang-10"  ;;
         llvm)                      compilers+=" $1 " ;;
         clang)                     compilers+=" $1 " ;;
         msvc)                      compilers+=" $1 " ;;
         mingw)                     compilers+=" $1 " ;;
         cygwin)                    compilers+=" $1 " ;;
         dockerpush)                dockerpush=yes ;;
         nodockerpush)              dockerpush=no ;;
         all|everything|before_merge|before-merge)
            oses="$ALL_oses" build_types="$ALL_build_types" cmake_opts="$ALL_cmake_opts" compilers="$ALL_compilers"
            ;;
         *)
            echoerr "Unknown /build argument '$1'"
            return 1
            ;;
      esac
      shift
   done

   oses=${oses:-$DEFAULT_oses}
   build_types=${build_types:-$DEFAULT_build_types}
   cmake_opts=${cmake_opts:-$DEFAULT_cmake_opts}

   for os in $oses ;do
      generate
   done
}

while read input_line ;do
   #  if [[ "$input_line" =~ ^/build\ .* ]] ;then
        handle_user_line $input_line || continue
   #  fi
done

to_json(){
   echo "{
         os:\"$1\",
         cc:\"$2\",
         BuildType:\"$3\",
         CMAKE_USE:\"$( [[ "$4" = default ]] || echo "-DUSE_${4^^}=ON" )\",
         dockerpush: \"$dockerpush\"
      }"
}
to_json_multiline(){
   echo [
   comma=''
   while read line ;do
      # if [[ "" = "$line" ]] ;then continue ;fi
      echo "$comma$(to_json $line)"
      comma=,
   done
   echo ]
}
json_include(){
   jq -cn ".include=$(to_json_multiline)"
}

MATRIX="$(echo "$MATRIX" | sed '/^$/d' | sort -uV)"
echo "$MATRIX"
echo "$MATRIX"                                               | json_include >matrix
echo "$MATRIX" | awk -v IGNORECASE=1 '/ubuntu/'              | json_include >matrix_ubuntu
echo "$MATRIX" | awk -v IGNORECASE=1 '/ubuntu/ && /release/' | json_include >matrix_ubuntu_release
echo "$MATRIX" | awk -v IGNORECASE=1 '/ubuntu/ && /debug/'   | json_include >matrix_ubuntu_debug
echo "$MATRIX" | awk -v IGNORECASE=1 '/macos/'               | json_include >matrix_macos
echo "$MATRIX" | awk -v IGNORECASE=1 '/windows/'             | json_include >matrix_windows
