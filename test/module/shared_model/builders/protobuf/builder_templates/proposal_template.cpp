/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/builders/protobuf/builder_templates/proposal_template.hpp"

#include "proposal.pb.h"

using namespace shared_model;
using namespace shared_model::proto;

template <typename Transformation>
auto TemplateProposalBuilder::transform(Transformation t) const {
  TemplateProposalBuilder copy = *this;
  t(*copy.proposal_);
  return copy;
}

TemplateProposalBuilder::TemplateProposalBuilder()
    : proposal_{std::make_unique<iroha::protocol::Proposal>()} {}

TemplateProposalBuilder::TemplateProposalBuilder(
    const TemplateProposalBuilder &o)
    : proposal_{std::make_unique<iroha::protocol::Proposal>(*o.proposal_)} {}

TemplateProposalBuilder TemplateProposalBuilder::height(
    const interface::types::HeightType height) const {
  return transform([&](auto &proposal) { proposal.set_height(height); });
}

TemplateProposalBuilder TemplateProposalBuilder::transactions(
    const std::vector<shared_model::proto::Transaction> &transactions) const {
  return transform([&](auto &proposal) {
    for (const auto &tx : transactions) {
      new (proposal.add_transactions())
          iroha::protocol::Transaction(tx.getTransport());
    }
  });
}

TemplateProposalBuilder TemplateProposalBuilder::createdTime(
    const interface::types::TimestampType created_time) const {
  return transform(
      [&](auto &proposal) { proposal.set_created_time(created_time); });
}

Proposal TemplateProposalBuilder::build() {
  auto result = Proposal(iroha::protocol::Proposal(*proposal_));

  return result;
}

TemplateProposalBuilder::~TemplateProposalBuilder() = default;
