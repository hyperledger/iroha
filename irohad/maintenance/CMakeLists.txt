#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(maintenance metrics.cpp)
target_link_libraries(maintenance
    prometheus-cpp::core prometheus-cpp::pull
    async_subscription
)
