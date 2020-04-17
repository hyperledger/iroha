/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_READER_WRITER_HPP
#define IROHA_MOCK_READER_WRITER_HPP

#include "ametsuchi/reader_writer.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockReaderWriter : public ReaderWriter {
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
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_READER_WRITER_HPP
