/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP

#include "interfaces/queries/blocks_query.hpp"

#include "backend/protobuf/common_objects/signature.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class BlocksQuery final : public interface::BlocksQuery {
     public:
      using TransportType = iroha::protocol::BlocksQuery;

      explicit BlocksQuery(const TransportType &query);
      explicit BlocksQuery(TransportType &&query);

      const interface::types::AccountIdType &creatorAccountId() const override;

      interface::types::CounterType queryCounter() const override;

      const interface::types::BlobType &blob() const override;

      const interface::types::BlobType &payload() const override;

      // ------------------------| Signable override  |-------------------------
      interface::types::SignatureRangeType signatures() const override;

      bool addSignature(
          interface::types::SignedHexStringView signed_blob,
          interface::types::PublicKeyHexStringView public_key) override;

      const interface::types::HashType &hash() const override;

      interface::types::TimestampType createdTime() const override;

      const TransportType &getTransport() const;

     private:
      // ------------------------------| fields |-------------------------------
      TransportType proto_;

      interface::types::BlobType blob_;

      const interface::types::BlobType payload_;

      SignatureSetType<proto::Signature> signatures_;

      interface::types::HashType hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP
