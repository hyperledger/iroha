/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_WSV_QUERY_HPP
#define IROHA_WSV_QUERY_HPP

#include <boost/optional.hpp>
#include <vector>

#include "common/result.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

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
      virtual boost::optional<std::vector<std::string>> getSignatories(
          const shared_model::interface::types::AccountIdType &account_id) = 0;

      /**
       * Fetch peers stored in ledger
       * @return list of peers in insertion to ledger order
       */
      virtual boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers(bool syncing_peers) = 0;

      // ToDo?(iceseer) #997
      // /**
      //  * @brief Fetch domains stored in ledger
      //  * @return list of domains in insertion to ledger order
      //  */
      // virtual iroha::expected::Result<
      //   std::vector<std::shared_ptr<shared_model::interface::Domain>>,
      //   std::string>
      // getDomains() = 0;

      /**
       * @brief Fetch number of domains in ledger
       * @return number of domains in ledger
       */
      virtual iroha::expected::Result<size_t, std::string> countPeers(
          bool syncing_peers) = 0;

      /**
       * @brief Fetch number of domains in ledger
       * @return number of domains in ledger
       */
      virtual iroha::expected::Result<size_t, std::string> countDomains() = 0;

      /**
       * @brief Fetch number of valid transactions in ledger
       * @return number of transactions in ledger
       */
      virtual iroha::expected::Result<size_t, std::string>
      countTransactions() = 0;

      /**
       * Fetch peer with given public key from ledger
       * @return the peer if found, none otherwise
       */
      virtual boost::optional<std::shared_ptr<shared_model::interface::Peer>>
      getPeerByPublicKey(shared_model::interface::types::PublicKeyHexStringView
                             public_key) = 0;

      /// Get top block info from ledger state.
      virtual iroha::expected::Result<iroha::TopBlockInfo, std::string>
      getTopBlockInfo() const = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSV_QUERY_HPP
