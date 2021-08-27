/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP
#define IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP

#include "backend/protobuf/proposal.hpp"
#include "interfaces/common_objects/types.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/default_validator.hpp"

#include "proposal.pb.h"

namespace shared_model {
  namespace proto {

    /**
     * Template proposal builder for creating new types of proposal builders by
     * means of replacing template parameters
     * @tparam S -- field counter for checking that all required fields are set
     * @tparam SV -- stateless validator called when build method is invoked
     */
    template <int S = 0, typename SV = validation::DefaultProposalValidator>
    class /*[[deprecated]]*/ TemplateProposalBuilder {
     private:
      template <int, typename>
      friend class TemplateProposalBuilder;

      enum RequiredFields { Transactions, Height, CreatedTime, TOTAL };

      template <int s>
      using NextBuilder = TemplateProposalBuilder<S | (1 << s), SV>;

      iroha::protocol::Proposal proposal_;
      SV stateless_validator_;

      template <int Sp>
      TemplateProposalBuilder(const TemplateProposalBuilder<Sp, SV> &o)
          : proposal_(o.proposal_),
            stateless_validator_(o.stateless_validator_) {}

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <int Fields, typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder<Fields> copy = *this;
        t(copy.proposal_);
        return copy;
      }

      TemplateProposalBuilder(const SV &validator)
          : stateless_validator_(validator){};

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateProposalBuilder(bool transport_proposal = false)
          : TemplateProposalBuilder(SV(
                transport_proposal ? iroha::test::kProposalTestsValidatorsConfig
                                   : iroha::test::kTestsValidatorsConfig)) {}

      auto height(const interface::types::HeightType height) const {
        return transform<Height>(
            [&](auto &proposal) { proposal.set_height(height); });
      }

      template <class T>
      auto transactions(const T &transactions) const {
        return transform<Transactions>([&](auto &proposal) {
          for (const auto &tx : transactions) {
            new (proposal.add_transactions())
                iroha::protocol::Transaction(tx.getTransport());
          }
        });
      }

      auto createdTime(const interface::types::TimestampType created_time)
          const {
        return transform<CreatedTime>(
            [&](auto &proposal) { proposal.set_created_time(created_time); });
      }

      Proposal build() {
        static_assert(S == (1 << TOTAL) - 1, "Required fields are not set");
        auto result = Proposal(iroha::protocol::Proposal(proposal_));
        if (auto error = stateless_validator_.validate(result)) {
          throw std::invalid_argument(error->toString());
        }
        return result;
      }

      static const int total = RequiredFields::TOTAL;
    };
  }  // namespace proto
}  // namespace shared_model
#endif  // IROHA_PROTO_TEMPLATE_PROPOSAL_BUILDER_HPP
