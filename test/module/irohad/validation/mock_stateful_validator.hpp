/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_STATEFUL_VALIDATOR_HPP
#define IROHA_MOCK_STATEFUL_VALIDATOR_HPP

#include "validation/stateful_validator.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace validation {

    class MockStatefulValidator : public StatefulValidator {
     public:
      MOCK_METHOD2(validate,
                   std::unique_ptr<VerifiedProposalAndErrors>(
                       const shared_model::interface::Proposal &,
                       ametsuchi::TemporaryWsv &));
    };

  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_MOCK_STATEFUL_VALIDATOR_HPP
