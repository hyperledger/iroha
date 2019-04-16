#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Reusable tests
add_subdirectory(irohad)
add_subdirectory(libs)
add_subdirectory(vendor)
add_subdirectory(test)
if (NOT USE_LIBIROHA)
    add_subdirectory(shared_model)
endif()
