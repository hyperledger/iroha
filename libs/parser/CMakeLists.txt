#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(parser parser.cpp)

target_link_libraries(parser
    Boost::boost
    )
