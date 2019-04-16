#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(regression_test regression_test.cpp)

target_link_libraries(regression_test
    application
    integration_framework
    test_logger
    )

addtest(query_regression_test query_test.cpp)

target_link_libraries(query_regression_test
        application
        integration_framework
        )
