#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(keys_manager
    keys_manager_impl.cpp
    )

target_link_libraries(keys_manager
    Boost::boost
    Boost::filesystem
    libs_files
    logger
    shared_model_cryptography
    )
