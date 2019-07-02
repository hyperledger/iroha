#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(shared_model_proto_backend_plain
    impl/peer.cpp
    )

target_link_libraries(shared_model_proto_backend_plain
    shared_model_cryptography
    )
