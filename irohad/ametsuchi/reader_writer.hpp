/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_READER_WRITER_HPP
#define IROHA_AMETSUCHI_READER_WRITER_HPP

#include <optional>
#include <string>
#include <string_view>

#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    class ReaderWriter {
     public:
      virtual ~ReaderWriter() = default;

      virtual expected::Result<std::optional<std::string>, std::string>
      getAccount(std::string_view address) = 0;

      virtual expected::Result<void, std::string> updateAccount(
          std::string_view address, std::string_view account) = 0;

      virtual expected::Result<void, std::string> removeAccount(
          std::string_view address) = 0;

      virtual expected::Result<std::optional<std::string>, std::string>
      getStorage(std::string_view address, std::string_view key) = 0;

      virtual expected::Result<void, std::string> setStorage(
          std::string_view address,
          std::string_view key,
          std::string_view value) = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_READER_WRITER_HPP
