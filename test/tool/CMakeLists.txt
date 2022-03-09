# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/test_data/)
execute_process(
  COMMAND rm -rf ${CMAKE_BINARY_DIR}/test_data/block_store
  COMMAND tar -xf ${CMAKE_CURRENT_LIST_DIR}/block_store_4999.tgz -C ${CMAKE_BINARY_DIR}/test_data/
)

add_test(NAME tool_iroha_migrate_and_export
        COMMAND
          ${CMAKE_CURRENT_LIST_DIR}/test_tool_migration.sh
          -iroha_migrate ${CMAKE_BINARY_DIR}/bin/iroha_migrate
          -block_store_path ${CMAKE_BINARY_DIR}/test_data/block_store
          -rocksdb_path ${CMAKE_BINARY_DIR}/test_data/test.rocksdb
        WORKING_DIRECTORY
          ${CMAKE_SOURCE_DIR}
        )

add_test(NAME tool_iroha_migrate_wrong_args
        COMMAND
          ${CMAKE_BINARY_DIR}/bin/iroha_migrate
        WORKING_DIRECTORY
          ${CMAKE_SOURCE_DIR}
        )
set_tests_properties(tool_iroha_migrate_wrong_args PROPERTIES
                      WILL_FAIL true
                      FAIL_REGULAR_EXPRESSION "ERROR in")

## Must be run after tool_iroha_migrate_and_export
## Should never run in parallel
add_test(NAME tool_iroha_wsv_diff_wrong_args
        COMMAND
          ${CMAKE_BINARY_DIR}/bin/iroha_wsv_diff
        )
set_tests_properties(tool_iroha_wsv_diff_wrong_args PROPERTIES
                      WILL_FAIL true
                      FAIL_REGULAR_EXPRESSION "ERROR:")

## Several test cases for iroha_wsv_diff
add_test(NAME tool_iroha_wsv_diff
        COMMAND
          ${CMAKE_CURRENT_LIST_DIR}/test_tool_iroha_wsv_diff.sh
          -block_store_path ${CMAKE_BINARY_DIR}/test_data/block_store
          -bin_dir ${CMAKE_BINARY_DIR}/bin
        WORKING_DIRECTORY
          ${CMAKE_BINARY_DIR}
        )
