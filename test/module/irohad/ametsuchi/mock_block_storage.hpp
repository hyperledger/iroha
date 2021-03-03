/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_BLOCK_STORAGE_HPP
#define IROHA_MOCK_BLOCK_STORAGE_HPP

#include <gmock/gmock.h>

#include "ametsuchi/block_storage.hpp"

namespace iroha {
  namespace ametsuchi {
    class MockBlockStorage : public BlockStorage {
     public:
      MOCK_METHOD1(insert,
                   bool(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_CONST_METHOD1(
          fetch,
          boost::optional<std::unique_ptr<shared_model::interface::Block>>(
              shared_model::interface::types::HeightType));
      MOCK_CONST_METHOD0(size, size_t());
      MOCK_METHOD0(reload, void());
      MOCK_METHOD0(clear, void());
      MOCK_CONST_METHOD1(forEach,
                         expected::Result<void, std::string>(FunctionType));
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_STORAGE_HPP
