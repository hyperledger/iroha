#!/usr/bin/env bash
set -euo pipefail

## The script expands '*.src.yml' from $1(default: script's directory)
## to $2 (default:subdirectory 'workflows') with corresponding name '*.yml'
## Main goal is to dereference YAML anchors.
## Deals only with Git cached/indexed files
## Set -x to debug
## NOTE: spaces in filenames are not allowed for code simplicity

while [[ $# > 0 ]] ;do
    case $1 in 
        --no-git|--worktree) 
            files_list(){
                ls $@
            }
            file_contents(){
                cat $@
            }
            ;;
        -x|--trace)
            set -x
            ;;
        -*)
            echo >&2 "make-workflows: ERROR: unxpected parameter"
            exit 2
            ;;
        *)
            if [[ "$(echo ${dirs_from:-})" = '' ]] ;then
                dirs_from=$1
            else
                dirs_from+=" "${dir_to:-}
                dir_to=$1
            fi
            ;;
    esac
    shift
done
function_undefined(){
    [[ $(type -t $1) != 'function' ]]
}
if function_undefined files_list ;then
    files_list(){
        git diff --cached --name-only --relative -- "$@"
    }
    file_contents(){
        git show $(printf ":%s " $@)
    }
fi

script_dir=$(dirname $(realpath "$0"))
dirs_from=${dirs_from:-${script_dir}}
dir_to=${dir_to:-$(git rev-parse --show-toplevel)/.github/workflows}
dir_to=$(realpath $dir_to)
edited_files=

for dir_from in $dirs_from ;do
    pushd $dir_from >/dev/null
    for f in $(files_list '*.src.yml') ;do
        out=$(echo $f | sed s,.src.yml\$,.yml,)
        wout=$dir_to/$out
        tempout=$(mktemp)
        trap "rm -f $tempout" EXIT
        echo >>$tempout "## DO NOT EDIT"
        echo >>$tempout "## Generated from $f with $(basename $0)"
        echo >>$tempout ""
        ## Take cached content from index
        file_contents ./$f | yq eval 'explode(.)' - >>$tempout
        if ! diff -q $wout $tempout &>/dev/null ;then
            mv $tempout $wout
            edited_files+="'$(realpath --relative-to=$OLDPWD $wout)' "
        fi
    done
    popd >/dev/null
done

if [[ -n "$edited_files" ]]
then echo "make-workflows: these files were edited: $edited_files"
else echo "make-workflows: everything is up to date"
fi
