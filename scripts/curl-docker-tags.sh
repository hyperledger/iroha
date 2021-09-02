#!/usr/bin/env bash
set -xeuo pipefail
shopt -s lastpipe

[[ $1 = */* ]]
org=${1%%/*}
repo=${1#*/}
org=${org:-hyperledger}
repo=${repo:-iroha}

cd $(mktemp -d)
trap "rm -rf $PWD" EXIT

declare -i page=1

while true ;do
    curl -fsSL "https://registry.hub.docker.com/v2/repositories/$org/$repo/tags/?page_size=9999&page=$page" >page$page.json
    if cat page$page.json | jq '.next==null' --exit-status >/dev/null
    then break
    fi
    ((page++))
done

jq -n '{ results: [ inputs.results ] | add }' page*.json >results.json

cat results.json |
    jq -r '.results |
        map(. | {name:.name, last_updated:.last_updated, digest0:.images[0].digest})
        | group_by(.digest0)
        | map(. | {digest:.[0].digest0, last_updated:.[0].last_updated, names:map(.|.name)} )[]
        | .last_updated +" -- "+ .digest +" <- "+ (.names|@csv)'
