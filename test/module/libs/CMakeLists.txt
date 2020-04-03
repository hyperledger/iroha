#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(CMAKE_BUILD_TYPE Debug)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

# Reusable tests
add_subdirectory(cache)
add_subdirectory(crypto)
add_subdirectory(datetime)
add_subdirectory(converter)
add_subdirectory(common)
add_subdirectory(multihash)
