#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(generator generator.cpp)
target_link_libraries(generator
    common
    )
