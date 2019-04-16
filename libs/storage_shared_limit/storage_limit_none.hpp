/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_STORAGE_LIMIT_NONE_HPP
#define IROHA_LIBS_STORAGE_LIMIT_NONE_HPP

#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {

  template <typename Item>
  struct StorageLimitNone : public StorageLimit<Item> {
    bool addIfAllowed(const Item &item) override {
      return true;
    }
    void remove(const Item &item) override {}
  };

}  // namespace iroha

#endif  // IROHA_LIBS_STORAGE_LIMIT_NONE_HPP
