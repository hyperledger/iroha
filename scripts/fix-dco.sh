#!/usr/bin/env bash

## Use it as parameter to git-filter-branch
## Read the docs git help filter-branch before using it.
## Example:
##   git filter-branch --msg-filter $PWD/scripts/fix-dco.sh -f -- HEAD~69..HEAD

cat >msg
cat msg
sigo="Signed-off-by: $GIT_AUTHOR_NAME <$GIT_AUTHOR_EMAIL>";
if grep -q "^$sigo" msg >&2 ;then
	echo >&2 "already signed";
else
	echo;
	echo "$sigo";
fi;
