/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_QUERY_HPP
#define IROHA_SHARED_MODEL_PROTO_QUERY_HPP

#include "interfaces/queries/query.hpp"

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class Query;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Signature;

    class Query final : public interface::Query {
     public:
      using TransportType = iroha::protocol::Query;
      using SignatureSet = SignatureSetType<std::unique_ptr<Signature>>;

      static iroha::expected::Result<std::unique_ptr<Query>, std::string>
      create(TransportType proto);

      Query(Query &&o) noexcept;

      ~Query() override;

      const Query::QueryVariantType &get() const override;

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
      template <typename T>
      iroha::expected::Result<Query, std::string> createImpl(T &&proto);

      struct Impl;
      Query(std::unique_ptr<Impl> impl);
      std::unique_ptr<Impl> impl_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_QUERY_HPP
