#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

if (IROHA_ROOT_PROJECT)
  addtest(transport_builder_test
      transport_builder_test.cpp
      )
  target_link_libraries(transport_builder_test
      shared_model_default_builders
      shared_model_stateless_validation
      shared_model_interfaces_factories
      )
endif ()

addtest(proto_transaction_responses_factory_test
    transaction_responses/proto_transaction_response_factory_test.cpp
    )

target_link_libraries(proto_transaction_responses_factory_test
    shared_model_proto_backend
    )

addtest(block_builder_test
    block_builder_test.cpp
    )

target_link_libraries(block_builder_test
    shared_model_default_builders
    shared_model_stateless_validation
    )
