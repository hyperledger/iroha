# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(processor)

add_library(query_client
    impl/query_client.cpp
    )
target_link_libraries(query_client
    torii_service
    endpoint
    )

add_library(command_client
    impl/command_client.cpp
    )
target_link_libraries(command_client
    torii_service
    endpoint
    common
    )

add_library(torii_service
    impl/query_service.cpp
    impl/command_service_impl.cpp
    impl/command_service_transport_grpc.cpp
    )
target_link_libraries(torii_service
    endpoint
    logger
    processors
    shared_model_interfaces_factories
    shared_model_stateless_validation
    shared_model_proto_backend
    common
    )
