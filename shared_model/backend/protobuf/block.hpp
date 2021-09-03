/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_HPP

#include "block.pb.h"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"

namespace shared_model {
  namespace proto {
    class Block final : public interface::Block {
     public:
      using TransportType = iroha::protocol::Block_v1;

      Block(Block &&o) noexcept;
      Block &operator=(Block &&o) noexcept = default;
      explicit Block(const TransportType &ref);
      explicit Block(TransportType &&ref);

      interface::types::TransactionsCollectionType transactions()
          const override;

      interface::types::HeightType height() const override;

      const interface::types::HashType &prevHash() const override;

      const interface::types::BlobType &blob() const override;

      interface::types::SignatureRangeType signatures() const override;

      bool addSignature(
          interface::types::SignedHexStringView signed_blob,
          interface::types::PublicKeyHexStringView public_key) override;

      const interface::types::HashType &hash() const override;

      interface::types::TimestampType createdTime() const override;

      interface::types::HashCollectionType rejected_transactions_hashes()
          const override;

      const interface::types::BlobType &payload() const override;

      typename interface::Block::ModelType *clone() const override;

      const iroha::protocol::Block_v1 &getTransport() const;

      ~Block() override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_HPP
