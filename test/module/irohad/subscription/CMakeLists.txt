#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(subscription_test subscription_test.cpp)
target_link_libraries(subscription_test
    async_subscription
    )
