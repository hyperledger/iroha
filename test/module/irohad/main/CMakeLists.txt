#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(server_runner_test server_runner_test.cpp)
target_link_libraries(server_runner_test
    server_runner
    endpoint
    test_logger
    )
