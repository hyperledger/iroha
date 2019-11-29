/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP

#include "interfaces/queries/tx_pagination_meta.hpp"

#include "common/result_fwd.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace protocol {
    class TxPaginationMeta;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {

    /// Provides query metadata for any transaction list pagination.
    class TxPaginationMeta final : public interface::TxPaginationMeta {
     public:
      static iroha::expected::Result<std::unique_ptr<TxPaginationMeta>,
                                     std::string>
      create(const iroha::protocol::TxPaginationMeta &meta);

      TxPaginationMeta(const iroha::protocol::TxPaginationMeta &meta,
                       boost::optional<shared_model::interface::types::HashType>
                           first_tx_hash);

      interface::types::TransactionsNumberType pageSize() const override;

      const boost::optional<interface::types::HashType> &firstTxHash()
          const override;

     private:
      const iroha::protocol::TxPaginationMeta &meta_;
      boost::optional<interface::types::HashType> first_tx_hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
