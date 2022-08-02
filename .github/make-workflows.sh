#!/usr/bin/env bash
set -euo pipefail


--help(){
    cat<<'END'
make-workflows:
    This script expands '*.src.yml' from $1 (default: script's directory)
    to $2 (default:REPO_ROOT/.github/workflows) with corresponding name '*.yml'
    Main goal is to dereference YAML anchors.
    Deals only with Git cached/indexed files until --no-git-index passed.
    DEBUG: use option -x
    NOTE: spaces in filenames are not allowed to keep code simplicity
END
    cat<<END
Usage:
    make-workflows.sh [--no-git-index] [dirs_from... [dir_to]]
    make-workflows.sh [--help]
Options:
    --no-git-index|--worktree   List files and get contents from working tree
                                instead of git index
    -h, --help       show this help
    -x, --trace
    +x, --no-trace   enable/disable bash trace
END
    exit
}

files_list(){
    git diff --cached --name-only --relative --diff-filter=d -- "$@"
    ## NOTE: --diff-filter=d  to exclude deleted files
}
file_contents(){
    git show $(printf ":%s " $@)
}

while [[ $# > 0 ]] ;do
    case "$1" in
        ## List files and get contents from working tree instead of git index
        --no-git-index|--worktree)
            files_list(){
                ls $@
            }
            file_contents(){
                cat $@
            }
            ;;
        -x|--trace)    set -x ;;
        +x|--no-trace) set +x ;;
        -h|--help|'-?') --help ;;
        -*)
            echo >&2 "make-workflows: ERROR: unxpected parameter"
            --help >&2
            exit 2
            ;;
        ## The last non-option argument is dir_to all previous are dirs_from
        *)
            if [[ "$1" = *' '* ]] ;then
                echo >&2 "make-workflows: ERROR: spaces in arguments are not allowed: '$1'"
                exit 1
            fi
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

readonly script_dir=$(dirname $(realpath "$0"))
readonly dirs_from=${dirs_from:-${script_dir}}
readonly repo_root=$(git rev-parse --show-toplevel)
         dir_to=${dir_to:-$repo_root/.github/workflows}
readonly dir_to=$(realpath $dir_to)
edited_files=

for dir_from in $dirs_from ;do
    pushd $dir_from >/dev/null
    for f in $(files_list '*.src.yml') ;do
        out=$(echo $f | sed 's|.src.yml$|.yml|')
        wout=$dir_to/$out
        tempout=$(mktemp)
        trap "rm -f $tempout" EXIT   ## in case of error file will be removed before exit
        echo >>$tempout "## DO NOT EDIT"
        echo >>$tempout "## Generated from $f with $(basename $0)"
        echo >>$tempout ""
        ## Take cached content from index
        file_contents ./$f | yq eval 'explode(.)' - >>$tempout
        if ! diff -q $wout $tempout &>/dev/null ;then
            mv $tempout $wout
            edited_files+="'$(realpath --relative-to=$OLDPWD $wout)' "
        else
            rm -f $tempout
        fi
    done
    popd >/dev/null
done

if [[ -n "$edited_files" ]]
then echo "make-workflows: these files were edited: $edited_files"
else echo "make-workflows: everything is up to date"
fi
