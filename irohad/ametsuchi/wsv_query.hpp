/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_WSV_QUERY_HPP
#define IROHA_WSV_QUERY_HPP

#include <vector>

#include <boost/optional.hpp>
#include "common/result.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace iroha {
  struct TopBlockInfo;

  namespace ametsuchi {
    /**
     *  Public interface for world state view queries
     */
    class WsvQuery {
     public:
      virtual ~WsvQuery() = default;

      /**
       * Get signatories of account by user account_id
       * @param account_id
       * @return
       */
      virtual boost::optional<
          std::vector<shared_model::interface::types::PubkeyType>>
      getSignatories(
          const shared_model::interface::types::AccountIdType &account_id) = 0;

      /**
       *
       * @return
       */
      virtual boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers() = 0;

      /// Get top block info from ledger state.
      virtual iroha::expected::Result<iroha::TopBlockInfo, std::string>
      getTopBlockInfo() const = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSV_QUERY_HPP
