#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(failover_callback
    impl/failover_callback.cpp
    impl/failover_callback_holder.cpp
    )

target_link_libraries(failover_callback
    logger
    SOCI::postgresql
    SOCI::core
    )

add_library(pool_wrapper
    impl/pool_wrapper.cpp
    )

target_link_libraries(pool_wrapper
    failover_callback
    SOCI::core
    )

add_library(flat_file_storage
    impl/flat_file/flat_file.cpp
    impl/flat_file_block_storage.cpp
    impl/flat_file_block_storage_factory.cpp
    )

target_link_libraries(flat_file_storage
    libs_files
    shared_model_proto_backend
    logger
    boost
    )

add_library(postgres_storage
    impl/postgres_block_storage.cpp
    impl/postgres_block_storage_factory.cpp
    )

target_link_libraries(postgres_storage
    shared_model_proto_backend
    logger
    SOCI::core
    SOCI::postgresql
    )

target_compile_definitions(postgres_storage
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )

add_library(postgres_options impl/postgres_options.cpp)
target_link_libraries(postgres_options
    logger
    )

add_library(ametsuchi
    impl/command_executor.cpp
    impl/tx_executor.cpp
    impl/storage_impl.cpp
    impl/temporary_wsv_impl.cpp
    impl/mutable_storage_impl.cpp
    impl/postgres_wsv_query.cpp
    impl/postgres_wsv_command.cpp
    impl/peer_query_wsv.cpp
    impl/postgres_block_query.cpp
    impl/postgres_command_executor.cpp
    impl/postgres_indexer.cpp
    impl/postgres_block_index.cpp
    impl/wsv_restorer_impl.cpp
    impl/postgres_query_executor.cpp
    impl/postgres_specific_query_executor.cpp
    impl/tx_presence_cache_impl.cpp
    impl/in_memory_block_storage.cpp
    impl/in_memory_block_storage_factory.cpp
    impl/k_times_reconnection_strategy.cpp
    )

target_link_libraries(ametsuchi
    pg_connection_init
    flat_file_storage
    postgres_storage
    logger
    logger_manager
    rxcpp
    libs_files
    common
    postgres_options
    shared_model_interfaces
    shared_model_proto_backend_plain
    shared_model_stateless_validation
    failover_callback
    SOCI::postgresql
    SOCI::core
    )

target_compile_definitions(ametsuchi
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )
