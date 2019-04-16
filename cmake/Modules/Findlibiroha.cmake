# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

include(FetchContent)
FetchContent_Declare(
        libiroha
        GIT_REPOSITORY https://github.com/hyperledger/libiroha
        GIT_TAG        52405cb6145321be221aacd044da0e2c15c772ab
)

FetchContent_GetProperties(libiroha)
if(NOT libiroha_POPULATED)
    set(TESTING OFF)
    FetchContent_Populate(libiroha)
    add_subdirectory(${libiroha_SOURCE_DIR} ${libiroha_BINARY_DIR})
endif()


include_directories(${libiroha_SOURCE_DIR})
