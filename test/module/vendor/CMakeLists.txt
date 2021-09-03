#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(rxcpp_subject_usage rxcpp_subject_usage.cpp)
target_link_libraries(rxcpp_subject_usage
    rxcpp
    )

addtest(rocksdb_test rocksdb_test.cpp)
target_link_libraries(rocksdb_test
    Boost::filesystem
    common
    logger
    RocksDB::rocksdb
    )
