/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_BLOCK_QUERY_HPP
#define IROHA_ROCKSDB_BLOCK_QUERY_HPP

#include "ametsuchi/impl/block_query_base.hpp"

namespace iroha::ametsuchi {

  struct RocksDBContext;

  /**
   * Class which implements BlockQuery with a RocksDB backend.
   */
  class RocksDbBlockQuery : public BlockQueryBase {
   public:
    RocksDbBlockQuery(std::shared_ptr<RocksDBContext> db_context,
                      BlockStorage &block_storage,
                      logger::LoggerPtr log);

    std::optional<int32_t> getTxStatus(
        const shared_model::crypto::Hash &hash) override;

   private:
    std::shared_ptr<RocksDBContext> db_context_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_BLOCK_QUERY_HPP
