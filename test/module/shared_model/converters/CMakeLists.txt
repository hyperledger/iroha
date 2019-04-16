#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

AddTest(json_proto_converter_test
    json_proto_converter_test.cpp
    )

target_link_libraries(json_proto_converter_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )
