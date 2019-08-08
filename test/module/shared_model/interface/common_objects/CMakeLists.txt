#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(amount_test amount_test.cpp)
target_link_libraries(amount_test
    shared_model_interfaces
    )
