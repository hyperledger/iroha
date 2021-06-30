/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_MUTABLE_STORAGE_HPP
#define IROHA_MOCK_MUTABLE_STORAGE_HPP

#include "ametsuchi/mutable_storage.hpp"

#include <gmock/gmock.h>
#include <rxcpp/rx-lite.hpp>

namespace iroha {
  namespace ametsuchi {

    class MockMutableStorage : public MutableStorage {
     public:
      MOCK_METHOD(
          bool,
          applyIf,
          (rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>,
           std::function<
               bool(std::shared_ptr<const shared_model::interface::Block>,
                    const iroha::LedgerState &)>,
           unsigned reindex_blocks_flush_cache_size_in_blocks),
          (override));
      MOCK_METHOD(bool,
                  applyBlock,
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
