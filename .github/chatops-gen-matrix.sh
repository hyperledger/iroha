#!/usr/bin/env bash
set -euo pipefail

JSON_ubuntu='{}'
JSON_macos='{}'
json_edit(){
    declare -n json=JSON_$1
    shift
    json="$(echo "$json" | jq "$@" || echo "$json")"
}
show_json(){
    declare -n json=JSON_$1
    echo "$json" | jq
}

handle_line(){
    local os compiler cmake_opts build_type dockerpush=yes
    local readonly DEFAULT_os="ubuntu macos" DEFAULT_build_type="Debug" DEFAULT_cmake_opts="default burrow ursa"
    local readonly DEFAULT_ubuntu_compiler="gcc-9" AVAILABLE_ubuntu_compiler="gcc-9 gcc-10 clang-10"
    local readonly DEFAULT_macos_compiler="clang"  AVAILABLE_macos_compiler="clang llvm gcc-10"
    for arg ;do
        # echo arg $arg
        case "$arg" in 
            macos)                     os+=" $arg " ;;
            ubuntu|linux)              os+=" ubuntu " ;;
            windows)                   os+=" $arg " ;;
            default)                   cmake_opts+=" $arg "  ;;
            burrow)                    cmake_opts+=" $arg "  ;;
            ursa)                      cmake_opts+=" $arg "  ;;
            release|Release)           build_type+=" Release " ;;
            debug|Debug)               build_type+=" Debug"  ;;
            gcc-9|gcc9)                compiler+=" gcc-9 " ;;
            gcc-10|gcc10)              compiler+=" gcc-10 " ;;
            clang-10|clang10)          compiler+=" clang-10"  ;;
            llvm)                      compiler+=" $arg " ;;
            clang)                     compiler+=" $arg " ;;
            # msvc)                      compiler+=" $arg " ;;
            # mingw)                     compiler+=" $arg " ;;
            # notest)  ;;
            # test)  ;;
            dockerpush)                dockerpush=yes ;;
            nodockerpush)              dockerpush=no ;;
            /build) ;;
            *)  echo ::warning::"Unknown /build argument '$arg'" ;;
        esac
    done

    ##UBUNTU_MATRIX
    os=${os:-$DEFAULT_os}
    build_type=${build_type:-$DEFAULT_build_type}
    cmake_opts=${cmake_opts:-$DEFAULT_cmake_opts}

    use_from_o(){
        if [[ $o = default ]] ;then
            use=''
        else
            use=-DUSE_${o^^}=ON
        fi
    }

    generate(){
        declare -n DEFAULT_compiler=DEFAULT_$1_compiler
        declare -n AVAILABLE_compiler=AVAILABLE_$1_compiler
        declare -n MATRIX=MATRIX_$1
        
        if [[ " $os " = *" $1 "* ]] ;then
            cc=${compiler:-$DEFAULT_compiler}
            local c b o
            for c in $cc ;do
                if ! [[ " $AVAILABLE_compiler " = *" $c "* ]] ;then 
                    c=
                    continue
                fi
                for b in $build_type ;do
                    for o in $cmake_opts ;do
                        MATRIX+="$1 $c $b $o"$'\n'
                        local use; use_from_o
                        json_edit $1 ".include+=[{ 
                            cc:\"$c\", 
                            build_type:\"$b\" 
                            ${use:+,CMAKE_USE:\"$use\"}
                            ,dockerpush: \"$dockerpush\"
                        }]"
            done;done;done
            if test "${c:-}" = "" ; then
                echo ::warning::"No available compiler for '$1' among '$cc', available: '$AVAILABLE_compiler'"
            fi
            echo "${MATRIX:-}"
        fi
    }
    generate ubuntu
    generate macos
}

while read comment_line;do
    if [[ "$comment_line" =~ ^/build\ .* ]] ;then
        # echo comment_line="$comment_line"
        handle_line $comment_line
    fi
done

show_json ubuntu
show_json macos

echo "$JSON_ubuntu" >matrix_ubuntu
echo "$JSON_macos"  >matrix_macos
