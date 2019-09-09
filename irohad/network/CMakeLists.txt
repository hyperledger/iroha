# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(networking
    impl/peer_communication_service_impl.cpp
    )

target_link_libraries(networking
    rxcpp
    shared_model_interfaces
    synchronizer
    logger
    )

add_library(block_loader
    impl/block_loader_impl.cpp
    )
target_link_libraries(block_loader
    grpc_client_factory
    )

#add_library(grpc_client_factory impl/grpc_client_factory.cpp)
#target_link_libraries(grpc_client_factory
#    common
#    grpc++
#    )

target_link_libraries(block_loader
    loader_grpc
    rxcpp
    shared_model_interfaces
    shared_model_proto_backend
    schema
    logger
    common
    grpc_client_factory
    )

add_library(block_loader_service
    impl/block_loader_service.cpp
    )
target_link_libraries(block_loader_service
    loader_grpc
    ametsuchi
    )

add_library(ordering_gate_common
    ordering_gate_common.cpp
    )
target_link_libraries(ordering_gate_common
    boost
    )

add_library(grpc_client_factory
    #impl/client_factory.cpp
    impl/channel_pool.cpp
    )
target_link_libraries(grpc_client_factory
    common
    grpc++
    )

add_library(grpc_channel_factory
    impl/channel_factory.cpp
    )
target_link_libraries(grpc_channel_factory
    grpc++
    )

add_library(tls_credentials
    impl/tls_credentials.cpp
    )

add_library(grpc_channel_factory_tls
    impl/channel_factory_tls.cpp
    impl/peer_tls_certificates_provider_root.cpp
    impl/peer_tls_certificates_provider_wsv.cpp
    )
target_link_libraries(grpc_channel_factory_tls
    grpc_channel_factory
    grpc++
    )
