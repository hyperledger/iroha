#!/bin/sh
set -ex

# This diagram describes the state when the root multisig account is successfully authenticated in this test:
# https://github.com/hyperledger-iroha/iroha/pull/5027#discussion_r1741722664

cargo build
scripts/test_env.py setup
cd test

gen_key_pair() {
    ./kagami crypto -cs $1
}

DOMAIN="wonderland"

gen_account_id() {
    public_key=$(gen_key_pair $1 | head -n 1)
    echo "$public_key@$DOMAIN"
}

gen_signatories() {
    for n in $(seq 1 $1); do
        i=$((n-1))
        key_pair=($(gen_key_pair $i))
        public_key=${key_pair[0]}
        private_key=${key_pair[1]}
        # yield an account ID
        echo "$public_key@$DOMAIN"
        # generate a config
        cat client.toml | sed '/domain/d' | sed '/public_key/d' | sed '/private_key/d' > client.$i.toml
        echo "domain = \"$DOMAIN\"" >> client.$i.toml
        echo "public_key = \"$public_key\"" >> client.$i.toml
        echo "private_key = \"$private_key\"" >> client.$i.toml
    done
}

# populate signatories
N_SIGNATORIES=6
SIGNATORIES=($(gen_signatories $N_SIGNATORIES))
for signatory in ${SIGNATORIES[@]}; do
    ./iroha account register --id $signatory
done
WEIGHTS=($(yes 1 | head -n $N_SIGNATORIES))

# register a multisig account, namely msa12
MSA_12=$(gen_account_id "msa12")
SIGS_12=(${SIGNATORIES[@]:1:2})
./iroha multisig register --account $MSA_12 --signatories ${SIGS_12[*]} --weights 1 1 --quorum 1

# register a multisig account, namely msa345
MSA_345=$(gen_account_id "msa345")
SIGS_345=(${SIGNATORIES[@]:3:3})
./iroha multisig register --account $MSA_345 --signatories ${SIGS_345[*]} --weights 1 1 1 --quorum 1

# register a multisig account, namely msa12345
MSA_12345=$(gen_account_id "msa12345")
SIGS_12345=($MSA_12 $MSA_345)
./iroha multisig register --account $MSA_12345 --signatories ${SIGS_12345[*]} --weights 1 1 --quorum 2

# register a multisig account, namely msa012345
MSA_012345=$(gen_account_id "msa")
SIGS_012345=(${SIGNATORIES[0]} $MSA_12345)
./iroha multisig register --account $MSA_012345 --signatories ${SIGS_012345[*]} --weights 1 1 --quorum 2

# propose a multisig transaction
INSTRUCTIONS="../scripts/tests/instructions.json"
cat $INSTRUCTIONS | ./iroha --config "client.0.toml" multisig propose --account $MSA_012345

get_list_as_signatory() {
    ./iroha --config "client.$1.toml" multisig list all
}

get_target_account() {
    ./iroha account list filter '{"Atom": {"Id": {"Atom": {"Equals": "'$MSA_012345'"}}}}'
}

# check that the root proposal is entered
LIST_0_INIT=$(get_list_as_signatory 0)
echo "$LIST_0_INIT" | jq '.[].instructions' | diff - <(cat $INSTRUCTIONS)

# check that one of the leaf signatories is involved
LIST_2_INIT=$(get_list_as_signatory 2)
echo "$LIST_2_INIT" | jq '.[].instructions' | diff - <(cat $INSTRUCTIONS)

LIST_5_INIT=$(get_list_as_signatory 5)
echo "$LIST_5_INIT" | jq '.[].instructions' | diff - <(cat $INSTRUCTIONS)

# check that the multisig transaction has not yet executed
TARGET_ACCOUNT_INIT=$(get_target_account)
# NOTE: without ` || false` this line passes even if `success_marker` exists
! echo "$TARGET_ACCOUNT_INIT" | jq -e '.[0].metadata.success_marker' || false

# approve a relaying approval
HASH_TO_12345=$(echo "$LIST_2_INIT" | jq -r 'keys[0]')
./iroha --config "client.2.toml" multisig approve --account $MSA_12 --instructions-hash $HASH_TO_12345

# check that the relaying approval has passed but the whole entry stays in the list
LIST_2_RELAYED=$(get_list_as_signatory 2)
echo "$LIST_2_RELAYED" | jq '.[].instructions' | diff - <(cat $INSTRUCTIONS)

# give the last approval to execute
./iroha --config "client.5.toml" multisig approve --account $MSA_345 --instructions-hash $HASH_TO_12345

# check that the transaction entry is deleted when seen from the last approver
LIST_5_EXECUTED=$(get_list_as_signatory 5)
! echo "$LIST_5_EXECUTED" | jq -e '.[].instructions' || false

# check that the transaction entry is deleted when seen from another signatory
LIST_2_EXECUTED=$(get_list_as_signatory 2)
! echo "$LIST_2_EXECUTED" | jq -e '.[].instructions' || false

# check that the multisig transaction has executed
TARGET_ACCOUNT_EXECUTED=$(get_target_account)
echo "$TARGET_ACCOUNT_EXECUTED" | jq -e '.[0].metadata.success_marker'

cd -
scripts/test_env.py cleanup
