/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_READER_WRITER_HPP
#define IROHA_POSTGRES_READER_WRITER_HPP

#include "ametsuchi/reader_writer.hpp"

namespace soci {
  class session;
}

namespace iroha::ametsuchi {
  class PostgresReaderWriter : public ReaderWriter {
   public:
    PostgresReaderWriter(soci::session &sql);

    expected::Result<std::optional<std::string>, std::string> getAccount(
        std::string_view address) override;

    expected::Result<void, std::string> updateAccount(
        std::string_view address, std::string_view account) override;

    expected::Result<void, std::string> removeAccount(
        std::string_view address) override;

    expected::Result<std::optional<std::string>, std::string> getStorage(
        std::string_view address, std::string_view key) override;

    expected::Result<void, std::string> setStorage(
        std::string_view address,
        std::string_view key,
        std::string_view value) override;

   private:
    soci::session &sql_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_READER_WRITER_HPP
