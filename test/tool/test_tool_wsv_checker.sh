#!/usr/bin/env bash
set -eEuo pipefail
shopt -s lastpipe inherit_errexit gnu_errfmt shift_verbose

## Expects CWD is iroha repo root
##

function OnErr { caller | { trap '' DEBUG; read lno file; echo ">ERROR in $file:$lno | $(sed -n ${lno}p $file)"; };  }
trap OnErr ERR

# show_eval(){
#     echo "--- $(printf '%q ' "$@")"
#     eval "$(printf '%q ' "$@")" #<stdin
# }

while test $# -gt 0 ;do
    case $1 in
        -block_store_path)
            BLOCK_STORE_PATH="$2"
            shift
        ;;
        -rocksdb_path)
            ROCKSDB_PATH="$2"
            shift
        ;;
        -pg_opt)
            PG_OPT=""$2""
            shift
        ;;
        -bin_dir)
            BIN_DIR="$2"
            shift
            ;;
        -wsv_checker)
            WSV_CHECKER="$2"
            shift
        ;;
        -irohad)
            IROHAD="$2"
            shift
        ;;
        -migration_tool)
            MIGRATION_TOOL="$2"
            shift
        ;;
    esac
    shift
done

SCRIPT_DIR=$(dirname $(realpath $0))
BIN_DIR=${BIN_DIR:=$PWD/bin}

#cd $(mktemp -d)
#trap "rm -r $PWD" EXIT

echo '----------------------------------------------------'
echo "---- RUNNING TESTS WITH PARAMETERS: ----"
echo ROCKSDB_PATH=${ROCKSDB_PATH:=$PWD/rocksdb}
echo PG_OPT=\'${PG_OPT:="dbname=iroha_data host=localhost port=5432 user=postgres password=postgres"}\'
echo WSV_CHECKER=${WSV_CHECKER:=$BIN_DIR/wsv_checker}
echo IROHAD=${IROHAD:=$BIN_DIR/irohad}
echo MIGRATION_TOOL=${MIGRATION_TOOL:=$BIN_DIR/migration-tool}
echo BLOCK_STORE_PATH=${BLOCK_STORE_PATH:=}
echo '----------------------------------------------------'

psql_with_params(){
    # set -x
    psql $(printf -- '--%s ' ${PG_OPT/password=*/})
}

trap_debug(){
    trap 'echo ":$LINENO | $(sed -n ${LINENO}p $0)"' DEBUG
}
untrap_debug(){
    trap '' DEBUG
}

######################################################
test0_DESCRIPTION="Successful test. Make 2 WSVs postgres and rocks, than assert with wsv_checker they are same."
test0()(
    set -euo pipefail

    jq <$SCRIPT_DIR/irohad.for.wsv_checker.config ".pg_opt=\"$PG_OPT\" | .block_store_path=\"$BLOCK_STORE_PATH\"" | tee config

    ## Make WSV in postgres database from block store
    $IROHAD --config config --drop_state --keypair_name $SCRIPT_DIR/../../example/node0 --exit_after_init

    ## Make WSV in rocks database from block store
    $MIGRATION_TOOL -block_store_path="$BLOCK_STORE_PATH" -rocksdb_path "$ROCKSDB_PATH"

    $WSV_CHECKER -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH"

    ## No difference in dumps expected
    diff <(tail -n+2 rockdb.wsv) <(tail -n+2 postgres.wsv)
)

######################################################
test1_DESCRIPTION="Change role permissions and account_has_asset amount, than assert wsv_checker detects changes."
test1()(
    set -euo pipefail

    psql_with_params >/dev/null <<END
--SAVEPOINT original;
update role_has_permissions set permission = '00000000000001110100100100000100100100011010111010011' where role_id = 'client';
update account_has_asset set amount = 1234567 where account_id = 'superuser@bootstrap';
END
    cat >revert1.sql <<END
update role_has_permissions set permission = '00000000000001110100100100000100100100011010111010000' where role_id = 'client';
update account_has_asset set amount = 0.0 where account_id = 'superuser@bootstrap';
END
    trap 'echo clean-up; psql_with_params <revert1.sql >/dev/null' EXIT

    if ! $WSV_CHECKER -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH" | tee log ;then
        grep -Fq <log '~~~ WSV-s DIFFER!!! ~~~'
        grep -Fq <log "Role-s 'client' have different permissions: '00000000000001110100100100000100100100011010111010000' and '00000000000001110100100100000100100100011010111010011'"
        grep -Fq <log 'Wsv-s have different roles.'
        grep -Fq <log "AssetQuantity-s 'xor#sora' have different quantity: '0.0' and '1234567.0'"
        grep -Fq <log 'Wsv-s have different domains.'
        echo "SUCCESS! wsv_checker test on wrong hacked database passed!"
    else
        echo "FAIL! wsv_checker test on wrong hacked database has NOT shown errors!"
        false
    fi
)

##################################################################
test2_DESCRIPTION="Add WRONG_ROLE,WRONG_ACCOUNT,WRONG_DOMAIN, than assert wsv_checker detects changes."
test2()(
    set -euo pipefail

    psql_with_params >/dev/null <<END
    --SAVEPOINT original;
    insert into role values ('WRONG_ROLE');
    insert into role_has_permissions values ('WRONG_ROLE','00000000001010111000000001001000001001011110101001000');
    insert into domain values ('WRONG_DOMAIN','WRONG_ROLE');
    insert into account values ('WRONG_ACCOUNT@WRONG_DOMAIN','WRONG_DOMAIN',33,'{}');
    insert into account_has_roles values ('WRONG_ACCOUNT@WRONG_DOMAIN','WRONG_ROLE');
    insert into account_has_asset values ('WRONG_ACCOUNT@WRONG_DOMAIN','xor#sora',999.);
    insert into signatory values ('1a7e5b005fb8dda7193e314045161b8fc1cf7091e170a3df920d5459db64c0f8');
    insert into account_has_signatory values ('WRONG_ACCOUNT@WRONG_DOMAIN','1a7e5b005fb8dda7193e314045161b8fc1cf7091e170a3df920d5459db64c0f8');
END

    cat >revert2.sql <<END
    delete from account_has_roles where account_id = 'WRONG_ACCOUNT@WRONG_DOMAIN';
    delete from account_has_asset where account_id = 'WRONG_ACCOUNT@WRONG_DOMAIN';
    delete from account_has_signatory where account_id = 'WRONG_ACCOUNT@WRONG_DOMAIN';
    delete from account where domain_id = 'WRONG_DOMAIN';
    delete from domain where default_role = 'WRONG_ROLE';
    delete from role_has_permissions where role_id = 'WRONG_ROLE';
    delete from role where role_id = 'WRONG_ROLE';
    delete from signatory where public_key = '1a7e5b005fb8dda7193e314045161b8fc1cf7091e170a3df920d5459db64c0f8';
END
    trap 'echo "clean-up."; psql_with_params <revert2.sql >/dev/null' EXIT

    if ! $WSV_CHECKER -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH" | tee log ;then
        grep -Fq <log '~~~ WSV-s DIFFER!!! ~~~' log
        grep -Fq <log "Role-s have different name: 'add_can_get_peers_perm_notary' and 'WRONG_ROLE'"
        grep -Fq <log 'Wsv-s have different roles.'
        grep -Fq <log "Domain names differ: 'bootstrap' vs 'WRONG_DOMAIN'"
        grep -Fq <log 'Wsv-s have different domains.'
        echo "SUCCESS! wsv_checker test on wrong hacked database passed!"
    else
        echo "FAIL! wsv_checker test on wrong hacked database has NOT shown errors!"
        false
    fi
)

######################################################
## ToDo edit someting in rocksdb than check and see error
######################################################

## Run all tests, i.e. functions whose name begins with 'test'
TESTS=($(declare -F | sed -nE 's,declare -f (test.*),\1,p'))
PASSED_TESTS=()
FAILED_TESTS=()
SKIPPED_TESTS=()  ##TODO
declare -i i=0

if test "${#TESTS[@]}" -gt 0 ;then
    for t in ${TESTS[@]} ;do
        declare -n description=${t}_DESCRIPTION
        echo "[   RUN    ] TEST.$i $t '$description'"
        set +e
        $t
        if test $? -eq 0 ;then
            echo "[  PASSED  ] TEST.$i $t"
            PASSED_TESTS+=($t)
        else
            echo "[  FAILED  ] TEST.$i $t"
            FAILED_TESTS+=($t)
        fi
        ((++i))
        set -e
    done
fi

echo "TOTAL $i tests were executed."

if test ${#PASSED_TESTS[@]} -gt 0 ;then
    printf "PASSED ${#PASSED_TESTS[@]} tests: \n"
    printf "   [  PASSED  ] %s\n" ${PASSED_TESTS[@]}
else
    echo "!! No tests PASSED!"
fi

if test ${#FAILED_TESTS[@]} -gt 0 ;then
    printf "FAILED ${#FAILED_TESTS[@]} tests: \n"
    printf "   [  FAILED  ] %s\n" ${FAILED_TESTS[@]}
else
    echo "HOORAY. all tests PASSED."
fi

if test ${#SKIPPED_TESTS[@]} -gt 0 ;then
    printf "SKIPPED ${#SKIPPED_TESTS[@]} tests: \n"
    printf "   [  SKIPPED ] %s\n" ${SKIPPED_TESTS[@]}
fi
