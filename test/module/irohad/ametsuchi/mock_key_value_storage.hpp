/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_KEY_VALUE_STORAGE_HPP
#define IROHA_MOCK_KEY_VALUE_STORAGE_HPP

#include "ametsuchi/key_value_storage.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockKeyValueStorage : public KeyValueStorage {
     public:
      MOCK_METHOD2(add, bool(Identifier, const Bytes &));
      MOCK_CONST_METHOD1(get, boost::optional<Bytes>(Identifier));
      MOCK_CONST_METHOD0(directory, std::string(void));
      MOCK_CONST_METHOD0(last_id, Identifier(void));
      MOCK_METHOD0(dropAll, void(void));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_KEY_VALUE_STORAGE_HPP
