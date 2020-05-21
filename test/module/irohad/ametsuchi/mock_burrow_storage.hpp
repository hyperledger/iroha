/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_READER_WRITER_HPP
#define IROHA_MOCK_READER_WRITER_HPP

#include "ametsuchi/burrow_storage.hpp"

#include <gmock/gmock.h>
#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    class MockReaderWriter : public BurrowStorage {
     public:
      MOCK_METHOD((expected::Result<std::optional<std::string>, std::string>),
                  getAccount,
                  (std::string_view),
                  (override));
      MOCK_METHOD((expected::Result<void, std::string>),
                  updateAccount,
                  (std::string_view, std::string_view),
                  (override));
      MOCK_METHOD((expected::Result<void, std::string>),
                  removeAccount,
                  (std::string_view),
                  (override));
      MOCK_METHOD((expected::Result<std::optional<std::string>, std::string>),
                  getStorage,
                  (std::string_view, std::string_view),
                  (override));
      MOCK_METHOD((expected::Result<void, std::string>),
                  setStorage,
                  (std::string_view, std::string_view, std::string_view),
                  (override));
      MOCK_METHOD((expected::Result<void, std::string>),
                  storeLog,
                  (std::string_view address,
                   std::string_view data,
                   std::vector<std::string_view> topics),
                  (override));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_READER_WRITER_HPP
