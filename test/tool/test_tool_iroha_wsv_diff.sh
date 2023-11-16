#!/usr/bin/env bash
set -eEuo pipefail
shopt -s lastpipe inherit_errexit gnu_errfmt shift_verbose expand_aliases

## Expects CWD is iroha repo root
##

function OnErr { set +x; caller | { trap '' DEBUG; read lno file; echo ">ERROR in $file:$lno | $(sed -n ${lno}p $file)"; };  }
trap OnErr ERR

while test $# -gt 0 ;do
    case $1 in
        -block_store_path) BLOCK_STORE_PATH="$2"; shift ;;
        -rocksdb_path)     ROCKSDB_PATH="$2";     shift ;;
        -pg_opt)           PG_OPT="$2";           shift ;;
        -bin_dir)          BIN_DIR="$2";          shift ;;
        -iroha_wsv_diff)      iroha_wsv_diff="$2";      shift ;;
        -irohad)           IROHAD="$2";           shift ;;
        -iroha_migrate)   iroha_migrate="$2";   shift ;;
        -filter)           FILTER="$2";           shift ;;
        -drop_state)       DROP_STATE="$1" ;;
        -dry_run|-list)    DRY_RUN=1 ;;
        *)                 echo >&2 "WRONG OPTION '$1'"; exit 1;;
    esac
    shift
done

SCRIPT_DIR=$(dirname $(realpath $0))
BIN_DIR=${BIN_DIR:=$PWD/bin}

#cd $(mktemp -d)
#trap "rm -r $PWD" EXIT

echo "---- RUNNING TESTS WITH PARAMETERS: ----"
echo ROCKSDB_PATH=${ROCKSDB_PATH:=$PWD/rocksdb}
echo PG_OPT=\'${PG_OPT:="dbname=iroha_data host=localhost port=5432 user=postgres password=postgres"}\'
echo iroha_wsv_diff=${iroha_wsv_diff:=$BIN_DIR/iroha_wsv_diff}
echo IROHAD=${IROHAD:=$BIN_DIR/irohad}
echo iroha_migrate=${iroha_migrate:=$BIN_DIR/iroha_migrate}
echo BLOCK_STORE_PATH=${BLOCK_STORE_PATH:=/tmp/block_store_test}
echo FILTER=\'${FILTER:='.*'}\'
echo DROP_STATE=${DROP_STATE:=}'  # Countinue reindexing blocks if wsv corresponds to blockstore or drop state to reindex from genesis block'
DRY_RUN=${DRY_RUN:=}
echo '----------------------------------------------------'

psql_with_params(){
    # set -x
    psql $(printf -- '--%s ' ${PG_OPT/password=*/})
}

######################################################
test_equal_wsv_DESCRIPTION="Successful test. Make 2 WSVs postgres and rocks, than assert with iroha_wsv_diff they are same."
test_equal_wsv()(
    set -euo pipefail

    jq <$SCRIPT_DIR/irohad.restore_wsv.config ".pg_opt=\"$PG_OPT\" | .block_store_path=\"$BLOCK_STORE_PATH\"" | tee config

    ## Make WSV in postgres database from block store
    time $IROHAD -config config -exit_after_init $DROP_STATE -keypair_name $SCRIPT_DIR/../../example/node0

    ## Make WSV in rocks database from block store
    time $iroha_migrate -block_store_path="$BLOCK_STORE_PATH" -rocksdb_path "$ROCKSDB_PATH" $DROP_STATE

    $iroha_wsv_diff -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH" -ignore_checking_with_schema_version

    # ## No difference in dumps expected
    diff <(tail -n+2 rockdb.wsv) <(tail -n+2 postgres.wsv)
)

######################################################
test_wrong_permissions_and_asset_amount_DESCRIPTION="Change role permissions and account_has_asset amount, than assert iroha_wsv_diff detects changes. Expects WSV of 7000 blocks from sxxanet."
test_wrong_permissions_and_asset_amount()(
    set -euo pipefail

    psql_with_params <<END
--SAVEPOINT original;
update role_has_permissions set permission = '00000000000001110100100100000100100100011010111010011' where role_id = 'client';
update account_has_asset set amount = 1234567 where account_id = 'superuser@bootstrap' and asset_id = 'xor#sora';
END
    cat >revert1.sql <<END
update role_has_permissions set permission = '00000000000001110100100100000100100100011010111010000' where role_id = 'client';
update account_has_asset set amount = 0.0 where account_id = 'superuser@bootstrap' and asset_id = 'xor#sora';
END
    trap 'echo clean-up; psql_with_params <revert1.sql >/dev/null' EXIT

    if ! $iroha_wsv_diff -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH" -ignore_checking_with_schema_version | tee log ;then
        grep -Fq <log '~~~ WSV-s DIFFER!!! ~~~'
        grep -Fq <log "Role-s 'client' have different permissions: '00000000000001110100100100000100100100011010111010000' and '00000000000001110100100100000100100100011010111010011'"
        grep -Fq <log 'Wsv-s have different roles.'
        grep -Eq <log "AssetQuantity-s 'xor#sora' have different quantity: '0(.0)?' and '1234567(.0)?'"
        grep -Fq <log 'Wsv-s have different domains.'
        echo "SUCCESS! iroha_wsv_diff test on wrong hacked database passed!"
    else
        echo "FAIL! iroha_wsv_diff test on wrong hacked database has NOT shown errors!"
        false
    fi
)

##################################################################
test_odd_domain_account_role_DESCRIPTION="Add WRONG_ROLE,WRONG_ACCOUNT,WRONG_DOMAIN, than assert iroha_wsv_diff detects changes. Expects WSV of 7000 blocks from sxxanet."
test_odd_domain_account_role()(
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

    if ! $iroha_wsv_diff -pg_opt "$PG_OPT" -rocksdb_path "$ROCKSDB_PATH" -ignore_checking_with_schema_version | tee log ;then
        grep -Fq <log '~~~ WSV-s DIFFER!!! ~~~' log
        grep -Fq <log "Role-s have different name: 'admin' and 'WRONG_ROLE'"
        grep -Fq <log 'Wsv-s have different roles.'
        grep -Fq <log "Domain names differ: 'bootstrap' vs 'WRONG_DOMAIN'"
        grep -Fq <log 'Wsv-s have different domains.'
        echo "SUCCESS! iroha_wsv_diff test on wrong hacked database passed!"
    else
        echo "FAIL! iroha_wsv_diff test on wrong hacked database has NOT shown errors!"
        false
    fi
)

######################################################
## ToDo edit someting in rocksdb than check and see error
######################################################

## Run all tests, i.e. functions whose name begins with 'test', order of declaration is important
## Take all functions whose names begin with 'test' in order of declaration
ALL_TESTS=($(sed -nE 's,^ *(test.*)\(\).*,\1,p' $0 | grep -Ff <(declare -F | sed -nE 's,^declare -f (test.*),\1,p')))  #($(declare -F | sed -nE 's,declare -f (test.*),\1,p'))
TESTS=()
SKIPPED_TESTS=()
declare -i i=0
for t in ${ALL_TESTS[@]} ;do
    ((++i))
    if echo $t | grep -q "$FILTER" ;then
        TESTS[$i]=$t
    else
        SKIPPED_TESTS[$i]=$t
    fi
done
PASSED_TESTS=()
FAILED_TESTS=()
declare -i i=0
declare -i total_executed=0

if test "$DRY_RUN" = 1 ;then
    WILL_RUN='[  DRY_RUN ]'
else
    WILL_RUN='[ WILL_RUN ]'
fi
echo "There are ${#ALL_TESTS[@]} tests:"
for i in ${!TESTS[@]} ;do
    t=${TESTS[$i]}
    declare -n description=${t}_DESCRIPTION
    echo "$WILL_RUN $i. $t '$description'"
done
for i in ${!SKIPPED_TESTS[@]} ;do
    t=${SKIPPED_TESTS[$i]}
    declare -n description=${t}_DESCRIPTION
    echo "[   SKIP   ] $i. $t '$description'"
done
if test "$DRY_RUN" = 1 ;then
    exit 0
fi

echo '----------------------------------------------------'
if test "${#TESTS[@]}" -gt 0 ;then
    for i in ${!TESTS[@]} ;do
        t=${TESTS[$i]}
        declare -n description=${t}_DESCRIPTION
        echo "[    RUN   ] $i. $t '$description'"
        set +e
        $t
        if test $? -eq 0 ;then
            echo "[  PASSED  ] $i. $t"
            PASSED_TESTS[$i]=$t
        else
            echo "[  FAILED  ] $i. $t"
            FAILED_TESTS[$i]=$t
        fi
        set -e
        ((++total_executed))
    done
fi
echo '----------------------------------------------------'

echo "TOTAL $total_executed tests were executed."

if test ${#PASSED_TESTS[@]} -gt 0 ;then
    all=$(test ${#ALL_TESTS[@]} -eq ${#PASSED_TESTS[@]} && echo ' ALL' || true)
    printf "PASSED$all ${#PASSED_TESTS[@]} of ${#ALL_TESTS[@]} tests: \n"
    for i in ${!PASSED_TESTS[@]} ;do
        echo "   [  PASSED  ] $i. ${PASSED_TESTS[$i]}"
    done
else
    echo "!! No tests PASSED!"
fi

if test ${#FAILED_TESTS[@]} -gt 0 ;then
    printf "FAILED ${#FAILED_TESTS[@]} tests: \n"
    for i in ${!FAILED_TESTS[@]} ;do
        echo "   [  FAILED  ] $i. ${FAILED_TESTS[$i]}"
    done
fi

if test ${#SKIPPED_TESTS[@]} -gt 0 ;then
    printf "SKIPPED ${#SKIPPED_TESTS[@]} tests: \n"
    for i in ${!SKIPPED_TESTS[@]} ;do
        echo "   [  SKIPPED ] $i. ${SKIPPED_TESTS[$i]}"
    done
fi

if test ${#ALL_TESTS[@]} -eq ${#PASSED_TESTS[@]} ;then
    echo "HOORAY. all tests PASSED."
else
    exit 1
fi
