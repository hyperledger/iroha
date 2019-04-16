/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_PROPOSAL_BUILDER_HPP
#define IROHA_TEST_PROPOSAL_BUILDER_HPP

#include "module/shared_model/builders/protobuf/builder_templates/proposal_template.hpp"
#include "module/shared_model/validators/validators.hpp"

/**
 * Builder alias, to build shared model proto proposal object avoiding "required
 * fields" check
 */
using TestProposalBuilder = shared_model::proto::TemplateProposalBuilder<
    (1 << shared_model::proto::TemplateProposalBuilder<>::total) - 1,
    shared_model::validation::AlwaysValidValidator>;

#endif  // IROHA_TEST_PROPOSAL_BUILDER_HPP
