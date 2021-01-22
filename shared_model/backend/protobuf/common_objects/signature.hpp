/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SIGNATURE_HPP
#define IROHA_PROTO_SIGNATURE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {
    class Signature final : public TrivialProto<interface::Signature,
                                                iroha::protocol::Signature> {
     public:
      template <typename SignatureType>
      explicit Signature(SignatureType &&signature)
          : TrivialProto(std::forward<SignatureType>(signature)) {}

      Signature(const Signature &o) : Signature(o.proto_) {}

      Signature(Signature &&o) noexcept : Signature(std::move(o.proto_)) {}

      const std::string &publicKey() const override {
        return proto_->public_key();
      }

      const std::string &signedData() const override {
        return proto_->signature();
      }

     private:
      interface::Signature *clone() const override {
        return new Signature(iroha::protocol::Signature(*proto_));
      }
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SIGNATURE_HPP
