#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(ametsuchi
    impl/flat_file/flat_file.cpp
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
    impl/postgres_block_index.cpp
    impl/wsv_restorer_impl.cpp
    impl/postgres_options.cpp
    impl/postgres_query_executor.cpp
    impl/tx_presence_cache_impl.cpp
    impl/in_memory_block_storage.cpp
    impl/in_memory_block_storage_factory.cpp
    impl/flat_file_block_storage.cpp
    impl/flat_file_block_storage_factory.cpp
    impl/k_times_reconnection_strategy.cpp
    )

target_link_libraries(ametsuchi
    logger
    logger_manager
    rxcpp
    libs_files
    common
    shared_model_interfaces
    shared_model_stateless_validation
    SOCI::postgresql
    SOCI::core
    )

target_compile_definitions(ametsuchi
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )
