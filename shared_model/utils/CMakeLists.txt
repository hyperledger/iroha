# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(shared_model_utils
    string_builder.cpp
    )
target_link_libraries(shared_model_utils
    libs_to_string
    )
