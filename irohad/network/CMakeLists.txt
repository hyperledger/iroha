# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(networking
    impl/peer_communication_service_impl.cpp
    )

target_link_libraries(networking
    shared_model_interfaces
    synchronizer
    logger
    )

add_library(block_loader
    impl/block_loader_impl.cpp
    )

target_link_libraries(block_loader
    grpc_generic_client_factory
    loader_grpc
    shared_model_interfaces
    shared_model_proto_backend
    schema
    logger
    common
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
    Boost::boost
    )

add_library(grpc_generic_client_factory
    impl/generic_client_factory.cpp
    )
target_link_libraries(grpc_generic_client_factory
    PRIVATE
    common
    PUBLIC
    gRPC::grpc++
    )

add_library(grpc_channel_pool
    impl/channel_pool.cpp
    )
target_link_libraries(grpc_channel_pool
    PRIVATE
    common
    crypto_blob_hasher
    grpc_channel_factory
    shared_model_interfaces
    PUBLIC
    gRPC::grpc++
    )

add_library(grpc_channel_factory
    impl/channel_factory.cpp
    )
target_link_libraries(grpc_channel_factory
    PUBLIC
    gRPC::grpc++
    )

add_library(tls_credentials
    impl/tls_credentials.cpp
    )
target_link_libraries(tls_credentials
    common
    libs_files
    )

add_library(peer_tls_certificates_providers
    impl/peer_tls_certificates_provider_root.cpp
    impl/peer_tls_certificates_provider_wsv.cpp
    )
target_link_libraries(peer_tls_certificates_providers
    logger
    shared_model_interfaces
    )

add_library(grpc_channel_factory_tls impl/channel_factory_tls.cpp)
target_link_libraries(grpc_channel_factory_tls
    grpc_channel_factory
    gRPC::grpc++
    logger
    peer_tls_certificates_providers
    shared_model_interfaces
    )
