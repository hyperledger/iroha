/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_LIMITABLE_STORAGE_HPP
#define IROHA_LIBS_LIMITABLE_STORAGE_HPP

namespace iroha {

  template <typename Item>
  struct LimitableStorage {
    using ItemType = Item;

    virtual ~LimitableStorage() = default;
    virtual bool insert(Item item) = 0;
  };

}  // namespace iroha

#endif  // IROHA_LIBS_LIMITABLE_STORAGE_HPP
