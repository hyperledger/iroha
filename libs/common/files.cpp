/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/files.hpp"

#include <ciso646>
#include <fstream>

#include <fmt/core.h>
#include <boost/filesystem.hpp>
#include "common/result.hpp"
#include "logger/logger.hpp"

namespace {
  template <typename T>
  iroha::expected::Result<T, std::string> readFile(
      const boost::filesystem::path &path, std::ios_base::openmode mode) {
    std::ifstream file(path.string(), mode);
    if (!file) {
      return iroha::expected::makeError(
          fmt::format("File '{}' could not be read.", path.string()));
    }

    T contents((std::istreambuf_iterator<char>(file)),
               std::istreambuf_iterator<char>());
    return iroha::expected::makeValue(std::move(contents));
  }
}  // namespace

void iroha::remove_dir_contents(const boost::filesystem::path &dir,
                                const logger::LoggerPtr &log) {
  boost::system::error_code error_code;

  bool exists = boost::filesystem::exists(dir, error_code);
  if (error_code != boost::system::errc::success) {
    log->error("{}", error_code.message());
    return;
  }
  if (not exists) {
    log->error("Directory does not exist '{}'", dir.string());
    return;
  }

  bool is_dir = boost::filesystem::is_directory(dir, error_code);
  if (error_code != boost::system::errc::success) {
    log->error("{}", error_code.message());
    return;
  }
  if (not is_dir) {
    log->error("'{}' is not a directory", dir.string());
    return;
  }

  for (auto entry : boost::filesystem::directory_iterator(dir)) {
    boost::filesystem::remove_all(entry.path(), error_code);
    if (error_code != boost::system::errc::success)
      log->error("{}", error_code.message());
  }
}

iroha::expected::Result<std::string, std::string> iroha::readTextFile(
    const boost::filesystem::path &path) {
  return readFile<std::string>(path, std::ios_base::in);
}

iroha::expected::Result<std::vector<uint8_t>, std::string>
iroha::readBinaryFile(const boost::filesystem::path &path) {
  return readFile<std::vector<uint8_t>>(
      path, std::ios_base::binary | std::ios_base::in);
}
