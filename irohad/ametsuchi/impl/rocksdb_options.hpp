/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_OPTIONS_HPP
#define IROHA_ROCKSDB_OPTIONS_HPP

namespace iroha::ametsuchi {

  /**
   * Type for convenient formatting of RocksDB.
   */
  class RocksDbOptions final {
    const std::string db_path_;

   public:
    explicit RocksDbOptions(std::string_view db_path) : db_path_(db_path) {}

   public:
    const std::string &dbPath() const {
      return db_path_;
    }
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_OPTIONS_HPP
