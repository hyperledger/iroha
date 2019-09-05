/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PEER_HPP
#define IROHA_SHARED_MODEL_PEER_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

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
       * @return Peer TLS certificate
       */
      virtual const interface::types::TLSCertificateType &tlsCertificate()
          const = 0;

      /**
       * @return Public key, for fetching data
       */
      virtual const interface::types::PubkeyType &pubkey() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PEER_HPP
