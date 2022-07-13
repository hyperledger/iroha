/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PROPOSAL_HPP
#define IROHA_SHARED_MODEL_PROTO_PROPOSAL_HPP

#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "proposal.pb.h"

namespace shared_model {
  namespace proto {
    class Proposal final : public interface::Proposal {
     public:
      using TransportType = iroha::protocol::Proposal;

      Proposal(Proposal &&o) noexcept;
      Proposal &operator=(Proposal &&o) noexcept = default;

      explicit Proposal(const TransportType &ref);
      explicit Proposal(TransportType &&ref);

      interface::types::TransactionsCollectionType transactions()
          const override;

      interface::types::TimestampType createdTime() const override;

      interface::types::HeightType height() const override;

      const interface::types::BlobType &blob() const override;

      const TransportType &getTransport() const;

      const interface::types::HashType &hash() const override;

      interface::types::TransactionsCollectionType mut_transactions() override;

      ~Proposal() override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROPOSAL_HPP
