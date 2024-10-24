#!/bin/sh
set -ex

# This diagram describes the state when the root multisig account is successfully authenticated in this test:
# https://github.com/hyperledger/iroha/pull/5027#discussion_r1741722664

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
./iroha multisig register --account $MSA_12 --signatories ${SIGS_12[*]} --weights 1 1 --quorum 2

# register a multisig account, namely msa345
MSA_345=$(gen_account_id "msa345")
SIGS_345=(${SIGNATORIES[@]:3:3})
./iroha multisig register --account $MSA_345 --signatories ${SIGS_345[*]} --weights 1 1 1 --quorum 1

# register a multisig account, namely msa12345
MSA_12345=$(gen_account_id "msa12345")
SIGS_12345=($MSA_12 $MSA_345)
./iroha multisig register --account $MSA_12345 --signatories ${SIGS_12345[*]} --weights 1 1 --quorum 1

# register a multisig account, namely msa012345
MSA_012345=$(gen_account_id "msa")
SIGS_012345=(${SIGNATORIES[0]} $MSA_12345)
./iroha multisig register --account $MSA_012345 --signatories ${SIGS_012345[*]} --weights 1 1 --quorum 2

# propose a multisig transaction
INSTRUCTIONS="../scripts/tests/instructions.json"
propose_stdout=($(cat $INSTRUCTIONS | ./iroha --config "client.0.toml" multisig propose --account $MSA_012345))
INSTRUCTIONS_HASH=${propose_stdout[0]}

# ticks as many times as the multisig recursion
TICK="../scripts/tests/tick.json"
for i in $(seq 0 1); do
    cat $TICK | ./iroha json transaction
done

# check that one of the leaf signatories is involved
LIST=$(./iroha --config "client.5.toml" multisig list all)
echo "$LIST" | grep $INSTRUCTIONS_HASH

# approve the multisig transaction
HASH_TO_12345=$(echo "$LIST" | grep -A1 "multisig_transactions" | sed 's/_/@/g' | grep -A1 $MSA_345 | tail -n 1 | tr -d '"')
./iroha --config "client.5.toml" multisig approve --account $MSA_345 --instructions-hash $HASH_TO_12345

# ticks as many times as the multisig recursion
for i in $(seq 0 1); do
    cat $TICK | ./iroha json transaction
done

# check that the multisig transaction is executed
./iroha account list all | grep "congratulations"
! ./iroha --config "client.5.toml" multisig list all | grep $INSTRUCTIONS_HASH

cd -
scripts/test_env.py cleanup
