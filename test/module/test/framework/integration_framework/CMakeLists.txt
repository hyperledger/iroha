#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(port_guard_test port_guard_test.cpp)
target_link_libraries(port_guard_test
   Boost::thread
   integration_framework
   )
