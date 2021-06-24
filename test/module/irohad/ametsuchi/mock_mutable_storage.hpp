/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_MUTABLE_STORAGE_HPP
#define IROHA_MOCK_MUTABLE_STORAGE_HPP

#include "ametsuchi/mutable_storage.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockMutableStorage : public MutableStorage {
     public:
      MOCK_METHOD(bool,
                  applyIf,
                  (std::shared_ptr<const shared_model::interface::Block>,
                        MutableStorage::MutableStoragePredicate,
                        bool),
                  (override));
      MOCK_METHOD(bool,
                  apply,
                  (std::shared_ptr<const shared_model::interface::Block>),
                  (override));
      MOCK_METHOD(bool,
                  applyPrepared,
                  (std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD1(do_commit,
                   expected::Result<MutableStorage::CommitResult, std::string>(
                       BlockStorage &));

      expected::Result<MutableStorage::CommitResult, std::string> commit(
          BlockStorage &block_storage)
          && override {
        return do_commit(block_storage);
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_MUTABLE_STORAGE_HPP
