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
        test_client_factory
        RapidJSON::rapidjson
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
        )
add_dependencies(irohad_test irohad)
target_compile_definitions(irohad_test
    PRIVATE
      -DPATH_IROHAD="$<TARGET_FILE:irohad>"
      -DPATH_TEST_DATA="${STATIC_TEST_DATA_DIR}"
      -DPATH_TEMP_DIR="${GENERATED_TEST_DATA_DIR}/irohad_test_temp"
      -DPATH_TORII_TLS_CREDS="${TEST_TORII_TLS_DATA_DIR}"
    )

if (SANITIZE)
    target_link_libraries(irohad_test asan)
    foreach(el ${SANITIZE})
        target_compile_options(irohad_test PRIVATE  -fsanitize=${el})
    endforeach(el)
endif ()
