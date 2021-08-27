#!/usr/bin/env bash
set -xeuo pipefail
shopt -s lastpipe

[[ $1 = */* ]]
org=${1%%/*}
repo=${1#*/}
org=${org:-hyperledger}
repo=${repo:-iroha}

curl -fsSL "https://registry.hub.docker.com/v2/repositories/$org/$repo/tags/?page_size=9999" |
    jq -r '.results |
        map(. | {name:.name, digest0:.images[0].digest})
        | group_by(.digest0)
        | map(. | {digest:.[0].digest0, names:map(.|.name)})[]
        | .digest + " <- " + (.names|@csv)  '
