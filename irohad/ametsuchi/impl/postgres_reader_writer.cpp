/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_reader_writer.hpp"

#include <soci/soci.h>

using namespace iroha::ametsuchi;

PostgresReaderWriter::PostgresReaderWriter(soci::session &sql) {}

expected::Result<std::optional<std::string>, std::string>
PostgresReaderWriter::getAccount(std::string_view address) {}

expected::Result<void, std::string> PostgresReaderWriter::updateAccount(
    std::string_view address, std::string_view account) {}

expected::Result<void, std::string> PostgresReaderWriter::removeAccount(
    std::string_view address) {}

expected::Result<std::optional<std::string>, std::string>
PostgresReaderWriter::getStorage(std::string_view address,
                                 std::string_view key) {}

expected::Result<void, std::string> PostgresReaderWriter::setStorage(
    std::string_view address, std::string_view key, std::string_view value) {}
