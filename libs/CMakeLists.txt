#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(logger)
add_subdirectory(parser)

if (NOT USE_LIBIROHA)
    add_subdirectory(common)
    add_subdirectory(crypto)
    add_subdirectory(generator)
endif()
