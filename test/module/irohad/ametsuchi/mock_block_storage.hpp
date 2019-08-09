/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_BLOCK_STORAGE_HPP
#define IROHA_MOCK_BLOCK_STORAGE_HPP

#include "ametsuchi/block_storage.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {
    class MockBlockStorage : public BlockStorage {
     public:
      MOCK_METHOD1(insert,
                   bool(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_CONST_METHOD1(
          fetch,
          boost::optional<
              std::shared_ptr<const shared_model::interface::Block>>(
              shared_model::interface::types::HeightType));
      MOCK_CONST_METHOD0(size, size_t(void));
      MOCK_METHOD0(clear, void(void));
      MOCK_CONST_METHOD1(forEach, void(FunctionType));
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_STORAGE_HPP
