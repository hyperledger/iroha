/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_PROPOSAL_BUILDER_HPP
#define IROHA_PROTO_PROPOSAL_BUILDER_HPP

#include "module/shared_model/builders/protobuf/builder_templates/proposal_template.hpp"

namespace shared_model {
  namespace proto {

    using ProposalBuilder = TemplateProposalBuilder<>;
  }
}  // namespace shared_model

#endif  // IROHA_PROTO_PROPOSAL_BUILDER_HPP
