#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(string_converter_test string_converter_test.cpp)

target_link_libraries(string_converter_test
    common
    )
