#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(simulator_test simulator_test.cpp)
target_link_libraries(simulator_test
    simulator
    shared_model_stateless_validation
    shared_model_cryptography_model
    shared_model_proto_backend
    test_logger
    )
