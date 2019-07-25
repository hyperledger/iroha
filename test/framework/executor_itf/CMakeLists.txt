#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(executor_itf executor_itf.cpp)
target_link_libraries(executor_itf
    ametsuchi # for executors only
    commands_mocks_factory
    common_test_constants
    integration_framework_config_helper
    pg_connection_init
    query_mocks_factory
    shared_model_interfaces
    shared_model_proto_backend
    test_logger
    SOCI::postgresql
    SOCI::core
    )

