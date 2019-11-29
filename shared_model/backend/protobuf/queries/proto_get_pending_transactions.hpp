/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
#define IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP

#include "interfaces/queries/get_pending_transactions.hpp"

#include <boost/optional.hpp>
#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class GetPendingTransactions;
    class Query;
  }  // namespace protocol
}  // namespace iroha

namespace shared_model {
  namespace interface {
    class TxPaginationMeta;
  }

  namespace proto {
    class GetPendingTransactions final
        : public interface::GetPendingTransactions {
     public:
      static iroha::expected::Result<std::unique_ptr<GetPendingTransactions>,
                                     std::string>
      create(const iroha::protocol::Query &query);

      GetPendingTransactions(
          const iroha::protocol::Query &query,
          boost::optional<
              std::unique_ptr<shared_model::interface::TxPaginationMeta>>
              pagination_meta);

      ~GetPendingTransactions() override;

      boost::optional<const interface::TxPaginationMeta &> paginationMeta()
          const override;

     private:
      const iroha::protocol::GetPendingTransactions &pending_transactions_;
      boost::optional<
          std::unique_ptr<shared_model::interface::TxPaginationMeta>>
          pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
