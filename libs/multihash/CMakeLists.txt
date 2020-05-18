# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(multihash multihash.cpp)
target_link_libraries(multihash common)
