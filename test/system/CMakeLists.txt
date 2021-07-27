#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(irohad_test irohad_test.cpp)
target_link_libraries(irohad_test
        ametsuchi
        Boost::boost
        Boost::filesystem
        SOCI::postgresql
        SOCI::core
        RapidJSON::rapidjson
        test_client_factory
        integration_framework_config_helper
        libs_files
        shared_model_proto_backend
        acceptance_fixture
        command_client
        query_client
        keys_manager
        iroha_conf_literals
        logger
        logger_manager
        pg_connection_init
        rdb_connection_init
        irohad_utility_client
        )
add_dependencies(irohad_test irohad)
add_definitions(-DPATHIROHAD="${PROJECT_BINARY_DIR}/bin")
add_definitions(-DPATHTESTDATA="${CMAKE_CURRENT_SOURCE_DIR}/irohad_test_data")

if (SANITIZE)
    target_link_libraries(irohad_test asan)
    foreach(el ${SANITIZE})
        target_compile_options(irohad_test PRIVATE  -fsanitize=${el})
    endforeach(el)
endif ()
