/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include <boost/range/any_range.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    using PeersForwardCollectionType =
        boost::any_range<Peer, boost::forward_traversal_tag, const Peer &>;

    /**
     * Provide response with peers in the network
     */
    class PeersResponse : public ModelPrimitive<PeersResponse> {
     public:
      /**
       * @return a list of peers
       */
      virtual PeersForwardCollectionType peers() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_PEERS_RESPONSE_HPP
