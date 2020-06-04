#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(shared_proto_tx_response_test
    shared_proto_tx_response_test.cpp
    )
target_link_libraries(shared_proto_tx_response_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

addtest(shared_proto_transaction_test
    shared_proto_transaction_test.cpp
    )
target_link_libraries(shared_proto_transaction_test
    shared_model_proto_backend
    shared_model_cryptography
    shared_model_stateless_validation
    )

addtest(ordering_test ordering_test.cpp)
target_link_libraries(ordering_test
    shared_model_proto_backend
    shared_model_interfaces
    )

addtest(shared_proto_queries_test
    shared_proto_queries_test.cpp
    )
target_link_libraries(shared_proto_queries_test
    shared_model_proto_backend
    shared_model_cryptography
    shared_model_stateless_validation
    )

if (IROHA_ROOT_PROJECT)
  addtest(shared_proto_query_responses_test
      shared_proto_query_responses_test.cpp
      )
  target_link_libraries(shared_proto_query_responses_test
      shared_model_proto_backend
      shared_model_stateless_validation
      shared_model_cryptography
      )
endif ()

addtest(shared_proto_util_test
    shared_proto_util_test.cpp
    )
target_link_libraries(shared_proto_util_test
    shared_model_proto_backend
    )

addtest(permissions_test
    permissions_test.cpp
    )
target_link_libraries(permissions_test
    shared_model_proto_backend
    )

addtest(proto_batch_test
    proto_batch_test.cpp
    )
target_link_libraries(proto_batch_test
    shared_model_proto_backend
    shared_model_stateless_validation
    shared_model_interfaces_factories
    )

addtest(proto_transaction_sequence_test
    proto_transaction_sequence_test.cpp
    )
target_link_libraries(proto_transaction_sequence_test
    shared_model_proto_backend
    shared_model_stateless_validation
    shared_model_interfaces_factories
    )

addtest(proto_common_objects_factory_test
    common_objects/proto_common_objects_factory_test.cpp
    )
target_link_libraries(proto_common_objects_factory_test
    shared_model_cryptography
    shared_model_stateless_validation
    )

addtest(proto_proposal_factory_test
    proto_proposal_factory_test.cpp
    )
target_link_libraries(proto_proposal_factory_test
    shared_model_stateless_validation
    shared_model_proto_backend
    )

addtest(proto_block_factory_test
    proto_block_factory_test.cpp
    )
target_link_libraries(proto_block_factory_test
    shared_model_proto_backend
    shared_model_stateless_validation
    )

if (IROHA_ROOT_PROJECT)
  addtest(proto_query_response_factory_test
      proto_query_response_factory_test.cpp
      )
  target_link_libraries(proto_query_response_factory_test
      shared_model_plain_backend
      shared_model_proto_backend
      shared_model_stateless_validation
      )
endif()

addtest(shared_proto_add_signature_test
    shared_proto_add_signature_test.cpp
    )
target_link_libraries(shared_proto_add_signature_test
    shared_model_proto_backend
    )
