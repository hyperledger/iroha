/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_MOCKS_HPP
#define IROHA_VALIDATION_MOCKS_HPP

#include <gmock/gmock.h>

#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "module/irohad/validation/mock_stateful_validator.hpp"
#include "validation/chain_validator.hpp"

namespace iroha {
  namespace validation {

    class MockChainValidator : public ChainValidator {
     public:
      MOCK_CONST_METHOD2(
          validateAndApply,
          bool(std::shared_ptr<const shared_model::interface::Block>,
               ametsuchi::MutableStorage &));
    };
  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_VALIDATION_MOCKS_HPP
