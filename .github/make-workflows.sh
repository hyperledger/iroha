#!/usr/bin/env bash
set -euo pipefail

## The script expands '*.src.yml' from $1(default: script's directory) 
## to $2 (default:subdirectory 'workflows') with corresponding name '*.yml'
## Main goal is to dereference YAML anchors.
## Deals only with Git cached/indexed files
## Set -x to debug

script_dir=$(dirname $(realpath "$0"))
dir_from=${1:-${script_dir}}
dir_to=${2:-workflows}
cd $dir_from

edited=
for f in $(git status -s -- \*.src.yml | sed 's,^.. ,,') ;do
    readonly out=$(echo $f | sed s,.src.yml\$,.yml,)
    readonly wout=$dir_to/$out
    readonly tempout=$(mktemp)
    trap "rm -f $tempout" EXIT
    echo >>$tempout "## DO NOT EDIT"
    echo >>$tempout "## Generated from $f with $(basename $0)"
    echo >>$tempout ""
    yq eval 'explode(.)' $f >>$tempout
    if ! diff -q $wout $tempout &>/dev/null ;then
        mv $tempout $wout
        edited+="'$out' "
    fi
done

if [[ -n "$edited" ]] 
then echo >&2 "make-workflows: these files were edited: $edited"
else echo >&2 "make-workflows: everything is up to date"
fi
