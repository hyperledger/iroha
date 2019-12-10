/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SIGNATURE_HPP
#define IROHA_PROTO_SIGNATURE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"
#include "cryptography/signed.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {
    class Signature final : public TrivialProto<interface::Signature,
                                                iroha::protocol::Signature> {
     public:
      template <typename SignatureType>
      static iroha::expected::Result<std::unique_ptr<Signature>, std::string>
      create(SignatureType &&proto) {
        using shared_model::crypto::Blob;
        return Blob::fromHexString(proto.public_key()) |
            [&](auto &&public_key) {
              return Blob::fromHexString(proto.signature()) |
                  [&](auto &&signature) {
                    return std::make_unique<Signature>(
                        std::forward<SignatureType>(proto),
                        PublicKeyType{std::move(public_key)},
                        SignedType{std::move(signature)});
                  };
            };
      }

      template <typename SignatureType>
      explicit Signature(SignatureType &&signature,
                         PublicKeyType public_key,
                         SignedType signed_data)
          : TrivialProto(std::forward<SignatureType>(signature)),
            public_key_(std::move(public_key)),
            signed_(std::move(signed_data)) {}

      Signature(const Signature &o)
          : Signature(o.proto_, o.public_key_, o.signed_) {}

      Signature(Signature &&o) noexcept
          : Signature(std::move(o.proto_),
                      std::move(o.public_key_),
                      std::move(o.signed_)) {}

      const PublicKeyType &publicKey() const override {
        return public_key_;
      }

      const SignedType &signedData() const override {
        return signed_;
      }

     private:
      interface::Signature *clone() const override {
        return new Signature(*this);
      }

      const PublicKeyType public_key_;
      const SignedType signed_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SIGNATURE_HPP
