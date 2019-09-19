/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP
#define IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP

#include <memory>

#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template proposal builder for creating new types of proposal builders by
     * means of replacing template parameters
     */
    class [[deprecated]] TemplateProposalBuilder {
     private:
      std::unique_ptr<iroha::protocol::Proposal> proposal_;

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      auto transform(Transformation t) const;

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateProposalBuilder();

      TemplateProposalBuilder(const TemplateProposalBuilder &o);

      TemplateProposalBuilder height(const interface::types::HeightType height)
          const;

      TemplateProposalBuilder transactions(
          const std::vector<shared_model::proto::Transaction> &transactions)
          const;

      TemplateProposalBuilder createdTime(
          const interface::types::TimestampType created_time) const;

      Proposal build();

      ~TemplateProposalBuilder();
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP
