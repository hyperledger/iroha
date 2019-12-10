/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BATCH_META_HPP
#define IROHA_PROTO_BATCH_META_HPP

#include "interfaces/iroha_internal/batch_meta.hpp"

#include "common/result_fwd.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"
#include "transaction.pb.h"

namespace shared_model {
  namespace proto {
    class BatchMeta final : public interface::BatchMeta {
     public:
      static iroha::expected::Result<std::unique_ptr<BatchMeta>, std::string>
      create(iroha::protocol::Transaction::Payload::BatchMeta &batch_meta);

      BatchMeta(interface::types::BatchType type,
                ReducedHashesType reduced_hashes);

      interface::types::BatchType type() const override;

      const ReducedHashesType &reducedHashes() const override;

     private:
      interface::types::BatchType type_;

      const ReducedHashesType reduced_hashes_;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_PROTO_BATCH_META_HPP
