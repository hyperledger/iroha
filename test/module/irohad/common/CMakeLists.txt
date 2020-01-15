#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

AddTest(blob_converter_test blob_converter_test.cpp)
target_link_libraries(blob_converter_test
    common
    )

AddTest(raw_block_loader_test raw_block_loader_test.cpp)
target_link_libraries(raw_block_loader_test
    raw_block_loader
    )
