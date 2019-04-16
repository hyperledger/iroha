/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UNSAFE_PROPOSAL_FACTORY_HPP
#define IROHA_UNSAFE_PROPOSAL_FACTORY_HPP

#include <memory>

#include <boost/range/any_range.hpp>
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;

    /**
     * UnsafeProposalFactory creates proposal without stateless validation
     */
    class UnsafeProposalFactory {
     public:
      using TransactionsCollectionType =
          boost::any_range<Transaction,
                           boost::forward_traversal_tag,
                           const Transaction &>;

      virtual std::unique_ptr<Proposal> unsafeCreateProposal(
          types::HeightType height,
          types::TimestampType created_time,
          TransactionsCollectionType transactions) = 0;

      virtual ~UnsafeProposalFactory() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_UNSAFE_PROPOSAL_FACTORY_HPP
