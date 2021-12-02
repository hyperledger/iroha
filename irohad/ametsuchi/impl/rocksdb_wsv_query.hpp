/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_WSV_QUERY_HPP
#define IROHA_ROCKSDB_WSV_QUERY_HPP

#include "ametsuchi/wsv_query.hpp"

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class RocksDBWsvQuery : public WsvQuery {
     public:
      RocksDBWsvQuery(std::shared_ptr<RocksDBContext> db_context,
                      logger::LoggerPtr log);

      boost::optional<std::vector<std::string>> getSignatories(
          const shared_model::interface::types::AccountIdType &account_id)
          override;

      boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers(bool syncing_peers) override;

      boost::optional<std::shared_ptr<shared_model::interface::Peer>>
      getPeerByPublicKey(shared_model::interface::types::PublicKeyHexStringView
                             public_key) override;

      iroha::expected::Result<iroha::TopBlockInfo, std::string>
      getTopBlockInfo() const override;

      iroha::expected::Result<size_t, std::string> countPeers(
          bool syncing_peers) override;
      iroha::expected::Result<size_t, std::string> countDomains() override;
      iroha::expected::Result<size_t, std::string> countTransactions() override;

     private:
      std::shared_ptr<RocksDBContext> db_context_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_ROCKSDB_WSV_QUERY_HPP
