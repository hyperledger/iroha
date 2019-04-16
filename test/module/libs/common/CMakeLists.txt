#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(result_test result_test.cpp)
target_link_libraries(result_test
        common
        )

addtest(combine_latest_until_first_completed_test
        combine_latest_until_first_completed_test.cpp
        )
target_link_libraries(combine_latest_until_first_completed_test
        rxcpp
        )
