# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(executor_fixture executor_fixture.cpp)
target_link_libraries(executor_fixture
    executor_itf
    )

add_library(executor_fixture_param executor_fixture_param.cpp)
target_link_libraries(executor_fixture_param
    gtest::main
    )
