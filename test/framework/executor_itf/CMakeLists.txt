#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(executor_itf executor_itf.cpp)
target_link_libraries(executor_itf
    commands_mocks_factory
    common_test_constants
    integration_framework_config_helper
    query_mocks_factory
    shared_model_interfaces
    test_logger
    tx_executor
    )
