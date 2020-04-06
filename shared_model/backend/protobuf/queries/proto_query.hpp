/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_QUERY_HPP
#define IROHA_SHARED_MODEL_PROTO_QUERY_HPP

#include "interfaces/queries/query.hpp"

#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    class Query final : public interface::Query {
     public:
      using TransportType = iroha::protocol::Query;

      Query(const Query &o);
      Query(Query &&o) noexcept;

      explicit Query(const TransportType &ref);
      explicit Query(TransportType &&ref);

      ~Query() override;

      const Query::QueryVariantType &get() const override;

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
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_QUERY_HPP
