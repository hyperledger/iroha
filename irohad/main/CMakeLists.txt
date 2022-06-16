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
    shared_model_cryptography_model
    )

add_library(raw_block_loader impl/raw_block_loader.cpp)
target_link_libraries(raw_block_loader
    shared_model_interfaces
    shared_model_proto_backend
    shared_model_stateless_validation
    logger
    )

add_library(rdb_connection_init impl/rocksdb_connection_init.cpp)
target_link_libraries(rdb_connection_init
    RocksDB::rocksdb
    failover_callback
    irohad_version
    logger
    )

add_library(pg_connection_init impl/pg_connection_init.cpp)
target_link_libraries(pg_connection_init
    SOCI::postgresql
    SOCI::core
    failover_callback
    irohad_version
    k_times_reconnection_strategy
    pool_wrapper
    logger
    )

add_library(async_subscription
    impl/subscription.cpp
    impl/async_dispatcher.cpp)

add_library(sync_subscription
    impl/subscription.cpp
    impl/sync_dispatcher.cpp)

add_library(application
    application.cpp
    # TODO andrei 08.11.2018 IR-1851 Create separate targets for initialization
    # helpers in application
    impl/on_demand_ordering_init.cpp
    impl/consensus_init.cpp
    impl/block_loader_init.cpp
    impl/storage_init.cpp
    )
target_link_libraries(application
    PRIVATE
    default_vm_call
    grpc_channel_factory
    grpc_channel_pool
    grpc_generic_client_factory
    peer_tls_certificates_providers
    permutation_generator
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
    torii_service
    pending_txs_storage
    common
    pg_connection_init
    rdb_connection_init
    generator
    async_subscription
    iroha_http_server
    iroha_conf_loader
    )

add_executable(irohad irohad.cpp)
target_link_libraries(irohad
    application
    raw_block_loader
    gflags
    RapidJSON::rapidjson
    grpc_channel_factory
    keys_manager
    common
    iroha_conf_loader
    irohad_utility_service
    irohad_utility_status_notifier
    logger
    logger_manager
    irohad_version
    pg_connection_init
    rdb_connection_init
    maintenance
    iroha_http_server
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
