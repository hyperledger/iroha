/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BATCH_META_HPP
#define IROHA_PROTO_BATCH_META_HPP

#include <boost/range/numeric.hpp>
#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/batch_meta.hpp"
#include "transaction.pb.h"

namespace shared_model {
  namespace proto {
    class BatchMeta final
        : public TrivialProto<
              interface::BatchMeta,
              iroha::protocol::Transaction::Payload::BatchMeta> {
     public:
      template <typename BatchMetaType>
      explicit BatchMeta(BatchMetaType &&batch_meta)
          : TrivialProto(std::forward<BatchMetaType>(batch_meta)),
            type_{[this] {
              unsigned which = proto_->GetDescriptor()
                                   ->FindFieldByName("type")
                                   ->enum_type()
                                   ->FindValueByNumber(proto_->type())
                                   ->index();
              return static_cast<interface::types::BatchType>(which);
            }()},
            reduced_hashes_{boost::accumulate(
                proto_->reduced_hashes(),
                ReducedHashesType{},
                [](auto &&acc, const auto &hash) {
                  acc.emplace_back(crypto::Hash::fromHexString(hash));
                  return std::forward<decltype(acc)>(acc);
                })} {}

      BatchMeta(const BatchMeta &o) : BatchMeta(o.proto_) {}

      BatchMeta(BatchMeta &&o) noexcept : BatchMeta(std::move(o.proto_)) {}

      interface::types::BatchType type() const override {
        return type_;
      };
      const ReducedHashesType &reducedHashes() const override {
        return reduced_hashes_;
      };

     private:
      interface::types::BatchType type_;

      const ReducedHashesType reduced_hashes_;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_PROTO_AMOUNT_HPP
