#!/usr/bin/env bash
set -euo pipefail

script_dir=$(dirname $(realpath "$0"))
cd $script_dir

edited=
for f in $(git status -s -- \*.src.yml | sed 's,^.. ,,') ;do
    readonly out=$(echo $f | sed s,.src.yml\$,.yml,)
    readonly wout=workflows/$out
    readonly tempout=$(mktemp)
    trap "rm -f $tempout" EXIT
    echo >>$tempout "## DO NOT EDIT"
    echo >>$tempout "## Generated from $f with $(basename $0)"
    echo >>$tempout ""
    yq eval 'explode(.)' $f >>$tempout
    if ! diff -q $wout $tempout ;then
        mv $tempout $wout
        edited+="'$out' "
    fi
done

if [[ -n "$edited" ]] 
then echo >&2 "make-workflows: these files were edited: $edited"
else echo >&2 "make-workflows: everything is up to date"
fi
