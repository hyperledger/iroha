#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_default_builders INTERFACE)

target_link_libraries(shared_model_default_builders INTERFACE
    shared_model_plain_backend
    shared_model_proto_backend
    shared_model_stateless_validation
    )
