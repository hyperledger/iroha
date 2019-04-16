#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Base64 Test

AddTest(logger_test logger_test.cpp)
target_link_libraries(logger_test
    logger
    logger_manager
    )

