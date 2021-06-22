/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_BLOCK_QUERY_HPP
#define IROHA_POSTGRES_BLOCK_QUERY_HPP

#include <soci/soci.h>

#include "ametsuchi/impl/block_query_base.hpp"

namespace iroha::ametsuchi {

  /**
   * Class which implements BlockQuery with a Postgres backend.
   */
  class PostgresBlockQuery : public BlockQueryBase {
   public:
    PostgresBlockQuery(soci::session &sql,
                       BlockStorage &block_storage,
                       logger::LoggerPtr log);

    PostgresBlockQuery(std::unique_ptr<soci::session> sql,
                       BlockStorage &block_storage,
                       logger::LoggerPtr log);

    std::optional<int32_t> getTxStatus(
        const shared_model::crypto::Hash &hash) override;

   private:
    std::unique_ptr<soci::session> psql_;
    soci::session &sql_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_BLOCK_QUERY_HPP
