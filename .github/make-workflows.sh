#!/usr/bin/env bash
set -xeuo pipefail

script_dir=$(dirname $(realpath "$0"))
cd $script_dir

edited=
for f in $(git status -s -- \*.src.yml | sed 's,^.. ,,') ;do
    out=$(echo $f | sed s,.src.yml\$,.yml,)
    wout=workflows/$out
    tempout=$(mktemp)
    yq eval 'explode(.)' $f >$tempout
    if ! diff -q $wout $tempout ;then
        mv $tempout $wout
    else
        rm -f $tempout
    fi
    edited+="$out "
done

echo >&2 "make-workflows: created/edited $edited"
