/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_MUTABLE_FACTORY_HPP
#define IROHA_MOCK_MUTABLE_FACTORY_HPP

#include "ametsuchi/mutable_factory.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockMutableFactory : public MutableFactory {
     public:
      MOCK_METHOD0(
          createMutableStorage,
          expected::Result<std::unique_ptr<MutableStorage>, std::string>(void));

      CommitResult commit(
          std::unique_ptr<MutableStorage> mutableStorage) override {
        // gmock workaround for non-copyable parameters
        return commit_(mutableStorage);
      }

      MOCK_CONST_METHOD0(preparedCommitEnabled, bool());
      MOCK_METHOD1(
          commitPrepared,
          CommitResult(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD1(commit_, CommitResult(std::unique_ptr<MutableStorage> &));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_MUTABLE_FACTORY_HPP
