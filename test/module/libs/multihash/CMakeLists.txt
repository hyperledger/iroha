# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

addtest(multihash_test multihash_test.cpp)
target_link_libraries(multihash_test
    multihash
    )
