/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_WSV_QUERY_HPP
#define IROHA_WSV_QUERY_HPP

#include <vector>

#include <boost/optional.hpp>
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace iroha {
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
       * Fetch peers stored in ledger
       * @return list of peers in insertion to ledger order
       */
      virtual boost::optional<
          std::vector<std::shared_ptr<shared_model::interface::Peer>>>
      getPeers() = 0;

      /**
       * Fetch peer with given public key from ledger
       * @return the peer if found, none otherwise
       */
      virtual boost::optional<std::shared_ptr<shared_model::interface::Peer>>
      getPeerByPublicKey(shared_model::interface::types::PublicKeyHexStringView
                             public_key) = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSV_QUERY_HPP
