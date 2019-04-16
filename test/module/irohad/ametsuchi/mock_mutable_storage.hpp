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
      MOCK_METHOD2(
          apply,
          bool(rxcpp::observable<
                   std::shared_ptr<shared_model::interface::Block>>,
               std::function<
                   bool(std::shared_ptr<const shared_model::interface::Block>,
                        PeerQuery &,
                        const shared_model::interface::types::HashType &)>));
      MOCK_METHOD1(apply,
                   bool(std::shared_ptr<const shared_model::interface::Block>));
      MOCK_METHOD1(applyPrepared,
                   bool(std::shared_ptr<const shared_model::interface::Block>));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_MUTABLE_STORAGE_HPP
