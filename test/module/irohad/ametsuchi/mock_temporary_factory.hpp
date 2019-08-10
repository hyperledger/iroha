/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_TEMPORARY_FACTORY_HPP
#define IROHA_MOCK_TEMPORARY_FACTORY_HPP

#include "ametsuchi/temporary_factory.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockTemporaryFactory : public TemporaryFactory {
     public:
      MOCK_METHOD1(
          createTemporaryWsv,
          std::unique_ptr<TemporaryWsv>(std::shared_ptr<CommandExecutor>));
      MOCK_METHOD1(prepareBlock_, void(std::unique_ptr<TemporaryWsv> &));

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override {
        // gmock workaround for non-copyable parameters
        prepareBlock_(wsv);
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_TEMPORARY_FACTORY_HPP
