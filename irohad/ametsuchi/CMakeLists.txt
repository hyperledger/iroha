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

add_library(rocksdb_block_storage
    impl/rocksdb_block_storage.cpp
    impl/rocksdb_block_storage_factory.cpp
    )

target_link_libraries(rocksdb_block_storage
    libs_files
    shared_model_proto_backend
    logger
    Boost::boost
    RocksDB::rocksdb
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
    Boost::boost
    Boost::filesystem
    Boost::iostreams
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

add_library(k_times_reconnection_strategy
    impl/k_times_reconnection_strategy.cpp
    )

add_library(tx_executor impl/tx_executor.cpp)
target_link_libraries(tx_executor
    common
    )

add_library(proto_command_executor
    impl/proto_command_executor.cpp
    )
target_link_libraries(proto_command_executor
    shared_model_proto_backend
    shared_model_stateless_validation
    )

add_library(query_executor_base
    impl/query_executor_base.cpp
    )
target_link_libraries(query_executor_base
    logger
    )

add_library(rocksdb_query_executor
    impl/rocksdb_query_executor.cpp
    )
target_link_libraries(rocksdb_query_executor
    query_executor_base
    )

add_library(postgres_query_executor
    impl/postgres_query_executor.cpp
    )
target_link_libraries(postgres_query_executor
    SOCI::core
    query_executor_base
    )
target_compile_definitions(postgres_query_executor
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )

add_library(proto_specific_query_executor
    impl/proto_specific_query_executor.cpp
    )
target_link_libraries(proto_specific_query_executor
    postgres_query_executor
    rocksdb_query_executor
    shared_model_proto_backend
    shared_model_stateless_validation
    )

add_library(ametsuchi
    impl/storage_base.cpp
    impl/storage_impl.cpp
    impl/rocksdb_storage_impl.cpp
    impl/rocksdb_temporary_wsv_impl.cpp
    impl/block_query_base.cpp
    impl/temporary_wsv_impl.cpp
    impl/postgres_temporary_wsv_impl.cpp
    impl/mutable_storage_impl.cpp
    impl/postgres_wsv_query.cpp
    impl/postgres_wsv_command.cpp
    impl/peer_query_wsv.cpp
    impl/postgres_block_query.cpp
    impl/setting_query.cpp
    impl/postgres_setting_query.cpp
    impl/rocksdb_settings_query.cpp
    impl/rocksdb_block_query.cpp
    impl/executor_common.cpp
    impl/command_executor.cpp
    impl/postgres_command_executor.cpp
    impl/wsv_restorer_impl.cpp
    impl/postgres_specific_query_executor.cpp
    impl/tx_presence_cache_impl.cpp
    )

add_library(im_memory_block_storage
    impl/in_memory_block_storage.cpp
    impl/in_memory_block_storage_factory.cpp
    )
target_link_libraries(im_memory_block_storage
    common
    logger
    )

add_library(block_indexer
    impl/block_index_impl.cpp
    )
target_link_libraries(block_indexer
    common
    logger
    shared_model_interfaces
    shared_model_cryptography
    )

add_library(postgres_indexer
    impl/postgres_indexer.cpp
    )
target_link_libraries(postgres_indexer
    block_indexer
    SOCI::postgresql
    SOCI::core
    )

add_library(rocksdb_indexer
    impl/rocksdb_indexer.cpp
    )
target_link_libraries(rocksdb_indexer
    block_indexer
    RocksDB::rocksdb
    )

add_library(common_burrow_storage
    impl/burrow_storage.cpp
    )
target_link_libraries(common_burrow_storage 
    common
    )

add_library(rocksdb_burrow_storage
    impl/rocksdb_burrow_storage.cpp
    )
target_link_libraries(rocksdb_burrow_storage
    common_burrow_storage
    RocksDB::rocksdb
    )

target_compile_definitions(postgres_indexer
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )

add_library(postgres_burrow_storage
    impl/postgres_burrow_storage.cpp
    )
target_link_libraries(postgres_burrow_storage 
    common_burrow_storage
    )

add_library(default_vm_call INTERFACE)
if(USE_BURROW)
    add_library(burrow_vm_caller impl/burrow_vm_caller.cpp)
    target_link_libraries(burrow_vm_caller
        burrow_vm_caller_generated
        fmt::fmt
        proto_command_executor
        proto_specific_query_executor
        )

    target_link_libraries(default_vm_call INTERFACE burrow_vm_caller)
endif()

target_link_libraries(ametsuchi
    default_vm_call
    pg_connection_init
    rdb_connection_init
    ametsuchi_rocksdb
    flat_file_storage
    rocksdb_block_storage
    postgres_indexer
    postgres_storage
    logger
    logger_manager
    libs_files
    common
    postgres_burrow_storage
    rocksdb_burrow_storage
    postgres_options
    shared_model_interfaces
    shared_model_plain_backend
    shared_model_stateless_validation
    tx_executor
    failover_callback
    SOCI::postgresql
    SOCI::core
    postgres_query_executor
    rocksdb_query_executor
    im_memory_block_storage
    )

target_compile_definitions(ametsuchi
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )
add_library(ametsuchi_rocksdb
    impl/rocksdb_wsv_query.cpp
    impl/rocksdb_wsv_command.cpp
    impl/rocksdb_command_executor.cpp
    impl/rocksdb_specific_query_executor.cpp
    )
target_link_libraries(ametsuchi_rocksdb
    RocksDB::rocksdb
    logger
    logger_manager
    libs_files
    common
    Boost::boost
    Boost::filesystem
    im_memory_block_storage
    shared_model_proto_backend
    shared_model_plain_backend
    shared_model_interfaces_factories
    rocksdb_indexer
    shared_model_interfaces
    async_subscription
    )
