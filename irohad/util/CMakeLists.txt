#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(irohad_utility utility.cpp)
target_link_libraries(irohad_utility
    utility_endpoint
    )
