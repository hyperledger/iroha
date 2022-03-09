/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PEER_HPP
#define IROHA_SHARED_MODEL_PEER_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

#include <optional>

namespace shared_model {
  namespace interface {

    /**
     * Representation of a network participant.
     */
    class Peer : public ModelPrimitive<Peer> {
     public:
      /**
       * @return Peer address, for fetching data
       */
      virtual const interface::types::AddressType &address() const = 0;

      /**
       * @return Peer TLS certficate
       */
      virtual const std::optional<interface::types::TLSCertificateType>
          &tlsCertificate() const = 0;

      /**
       * @return Public key, for fetching data
       */
      virtual const std::string &pubkey() const = 0;

      /**
       * @return flag determines if the peer is syncing or validating
       */
      virtual bool isSyncingPeer() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PEER_HPP
