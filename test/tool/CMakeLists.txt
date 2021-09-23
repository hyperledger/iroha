# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_test(NAME tool_iroha_migrate_and_export
        COMMAND
          ${CMAKE_CURRENT_LIST_DIR}/test_tool_migration.sh
          -migration_tool ${CMAKE_BINARY_DIR}/bin/migration-tool
          -block_store_path ${CMAKE_CURRENT_LIST_DIR}/block_store_7000
          -rocksdb_path /tmp/test.rocksdb
        WORKING_DIRECTORY
          ${CMAKE_SOURCE_DIR}
        )

add_test(NAME tool_iroha_migrate_wrong_args
        COMMAND
          ${CMAKE_BINARY_DIR}/bin/migration-tool
        WORKING_DIRECTORY
          ${CMAKE_SOURCE_DIR}
        )
set_tests_properties(tool_iroha_migrate_wrong_args PROPERTIES WILL_FAIL true)
set_tests_properties(tool_iroha_migrate_wrong_args PROPERTIES FAIL_REGULAR_EXPRESSION "ERROR in")

## Must be run after tool_iroha_migrate_and_export
## Should never run in parallel
add_test(NAME tool_wsv_checker_wrong_args
        COMMAND
          ${CMAKE_BINARY_DIR}/bin/wsv_checker
        )
set_tests_properties(tool_wsv_checker_wrong_args PROPERTIES WILL_FAIL true)
set_tests_properties(tool_wsv_checker_wrong_args PROPERTIES FAIL_REGULAR_EXPRESSION "ERROR:")

## Several test cases for wsv_checker
add_test(NAME tool_wsv_checker
        COMMAND
          ${CMAKE_CURRENT_LIST_DIR}/test_tool_wsv_checker.sh
          -block_store_path ${CMAKE_CURRENT_LIST_DIR}/block_store_7000
          -bin_dir ${CMAKE_BINARY_DIR}/bin
        WORKING_DIRECTORY
          ${CMAKE_BINARY_DIR}
        )
