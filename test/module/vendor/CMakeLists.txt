#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(rxcpp_subject_usage rxcpp_subject_usage.cpp)
target_link_libraries(rxcpp_subject_usage
    rxcpp
    )

addtest(tbb_test tbb_test.cpp)
target_link_libraries(tbb_test
    TBB::tbb
    )

addtest(rocksdb_test rocksdb_test.cpp)
target_link_libraries(rocksdb_test
    Boost::filesystem
    RocksDB::rocksdb
    )

addtest(rocksdb_block_storage_test rocksdb_block_storage_test.cpp)
target_link_libraries(rocksdb_block_storage_test
    rocksdb_block_storage
    shared_model_proto_backend
    common
    logger
    Boost::filesystem
    RocksDB::rocksdb
    )
