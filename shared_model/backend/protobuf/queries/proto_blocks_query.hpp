/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP

#include "interfaces/queries/blocks_query.hpp"

#include "backend/protobuf/common_objects/signature.hpp"
#include "common/result_fwd.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class BlocksQuery final : public interface::BlocksQuery {
     public:
      using TransportType = iroha::protocol::BlocksQuery;
      using SignatureSet = SignatureSetType<std::unique_ptr<Signature>>;

      static iroha::expected::Result<std::unique_ptr<BlocksQuery>, std::string>
      create(TransportType query);

      explicit BlocksQuery(TransportType &&query, SignatureSet signatures);

      const interface::types::AccountIdType &creatorAccountId() const override;

      interface::types::CounterType queryCounter() const override;

      const interface::types::BlobType &blob() const override;

      const interface::types::BlobType &payload() const override;

      // ------------------------| Signable override  |-------------------------
      interface::types::SignatureRangeType signatures() const override;

      bool addSignature(const crypto::Signed &signed_blob,
                        const crypto::PublicKey &public_key) override;

      const interface::types::HashType &hash() const override;

      interface::types::TimestampType createdTime() const override;

      const TransportType &getTransport() const;

     private:
      // ------------------------------| fields |-------------------------------
      TransportType proto_;

      interface::types::BlobType blob_;

      const interface::types::BlobType payload_;

      SignatureSet signatures_;

      interface::types::HashType hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCKS_QUERY_HPP
