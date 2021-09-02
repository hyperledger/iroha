/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <rocksdb/db.h>

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>

TEST(RocksDBTestCommon, Usage) {
  std::string const name = (boost::filesystem::temp_directory_path()
                            / boost::filesystem::unique_path())
                               .string();

  rocksdb::DB *db;
  rocksdb::Options options;
  options.create_if_missing = true;
  options.error_if_exists = true;
  auto status = rocksdb::DB::Open(options, name, &db);
  ASSERT_TRUE(status.ok()) << status.ToString();

  std::string const key{"key"};
  std::string const value{"key"};
  status = db->Put(rocksdb::WriteOptions(), key, value);
  ASSERT_TRUE(status.ok()) << status.ToString();
  std::string read_value;
  status = db->Get(rocksdb::ReadOptions(), key, &read_value);
  ASSERT_TRUE(status.ok()) << status.ToString();
  ASSERT_EQ(read_value, value);

  delete db;

  rocksdb::DestroyDB(name, options);
}
