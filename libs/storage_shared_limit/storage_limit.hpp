/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_STORAGE_LIMIT_HPP
#define IROHA_LIBS_STORAGE_LIMIT_HPP

namespace iroha {

  template <typename Item>
  struct StorageLimit {
    virtual ~StorageLimit() = default;

    virtual bool addIfAllowed(const Item &item) = 0;

    virtual void remove(const Item &item) = 0;
  };

}  // namespace iroha

#endif  // IROHA_LIBS_STORAGE_LIMIT_HPP
