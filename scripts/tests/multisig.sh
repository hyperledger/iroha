#!/bin/sh
set -ex

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
    for i in $(seq 1 $1); do
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
N_SIGNATORIES=3
SIGNATORIES=($(gen_signatories $N_SIGNATORIES))
for signatory in ${SIGNATORIES[@]}; do
    ./iroha account register --id $signatory
done

# register a multisig account
MULTISIG_ACCOUNT=$(gen_account_id "msa")
WEIGHTS=($(yes 1 | head -n $N_SIGNATORIES)) # equal votes
QUORUM=$N_SIGNATORIES # unanimous
TRANSACTION_TTL="1y 6M 2w 3d 12h 30m 30s 500ms"
./iroha --config "client.1.toml" multisig register --account $MULTISIG_ACCOUNT --signatories ${SIGNATORIES[*]} --weights ${WEIGHTS[*]} --quorum $QUORUM --transaction-ttl "$TRANSACTION_TTL"

# propose a multisig transaction
INSTRUCTIONS="../scripts/tests/instructions.json"
propose_stdout=($(cat $INSTRUCTIONS | ./iroha --config "client.1.toml" multisig propose --account $MULTISIG_ACCOUNT))
INSTRUCTIONS_HASH=${propose_stdout[0]}

# check that 2nd signatory is involved
./iroha --config "client.2.toml" multisig list all | grep $INSTRUCTIONS_HASH

# approve the multisig transaction
for i in $(seq 2 $N_SIGNATORIES); do
    ./iroha --config "client.$i.toml" multisig approve --account $MULTISIG_ACCOUNT --instructions-hash $INSTRUCTIONS_HASH
done

# check that the multisig transaction is executed
./iroha account list all | grep "congratulations"
! ./iroha --config "client.2.toml" multisig list all | grep $INSTRUCTIONS_HASH

cd -
scripts/test_env.py cleanup
