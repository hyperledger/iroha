#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

add_library(server_runner
    server_runner.cpp
    )
target_link_libraries(server_runner
    logger
    gRPC::grpc++
    Boost::boost
    common
    )

add_library(raw_block_loader impl/raw_block_loader.cpp)
target_link_libraries(raw_block_loader
    shared_model_interfaces
    shared_model_proto_backend
    shared_model_stateless_validation
    logger
    )

add_library(pg_connection_init impl/pg_connection_init.cpp)
target_link_libraries(pg_connection_init
    SOCI::postgresql
    SOCI::core
    failover_callback
    pool_wrapper
    logger
    )

add_library(pending_txs_storage_init impl/pending_transaction_storage_init.cpp)
target_link_libraries(pending_txs_storage_init
    pending_txs_storage
    )

add_library(application
    application.cpp
    # TODO andrei 08.11.2018 IR-1851 Create separate targets for initialization
    # helpers in application
    impl/on_demand_ordering_init.cpp
    impl/consensus_init.cpp
    impl/block_loader_init.cpp
    )
target_link_libraries(application
    PRIVATE
    peer_tls_certificates_providers
    tls_credentials
    yac
    yac_transport
    PUBLIC
    logger
    logger_manager
    server_runner
    ametsuchi
    networking
    on_demand_ordering_service
    on_demand_ordering_service_transport_grpc
    on_demand_connection_manager
    on_demand_ordering_gate
    on_demand_common
    chain_validator
    stateful_validator
    processors
    simulator
    block_loader
    block_loader_service
    mst_processor
    torii_service
    pending_txs_storage_init
    common
    pg_connection_init
    generator
    )

add_executable(irohad irohad.cpp)
target_link_libraries(irohad
    application
    raw_block_loader
    gflags
    RapidJSON::rapidjson
    keys_manager
    common
    iroha_conf_loader
    logger
    logger_manager
    irohad_version
    pg_connection_init
    )

add_library(iroha_conf_loader iroha_conf_loader.cpp)
target_link_libraries(iroha_conf_loader
    iroha_conf_literals
    logger_manager
    libs_files
    RapidJSON::rapidjson
    )

add_library(iroha_conf_literals iroha_conf_literals.cpp)
target_link_libraries(iroha_conf_literals
    logger
    )

add_install_step_for_bin(irohad)
