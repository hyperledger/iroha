/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/files.hpp"

#include <ciso646>
#include <fstream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include "logger/logger.hpp"

namespace {
  auto makeCannotReadFileError(const std::string &path) {
    return iroha::expected::makeError(
        (boost::format("File '%1%' could not be read") % path).str());
  }
}  // namespace

void iroha::remove_dir_contents(const std::string &dir,
                                const logger::LoggerPtr &log) {
  boost::system::error_code error_code;

  bool exists = boost::filesystem::exists(dir, error_code);
  if (error_code != boost::system::errc::success) {
    log->error("{}", error_code.message());
    return;
  }
  if (not exists) {
    log->error("Directory does not exist {}", dir);
    return;
  }

  bool is_dir = boost::filesystem::is_directory(dir, error_code);
  if (error_code != boost::system::errc::success) {
    log->error("{}", error_code.message());
    return;
  }
  if (not is_dir) {
    log->error("{} is not a directory", dir);
    return;
  }

  for (auto entry : boost::filesystem::directory_iterator(dir)) {
    boost::filesystem::remove_all(entry.path(), error_code);
    if (error_code != boost::system::errc::success)
      log->error("{}", error_code.message());
  }
}

iroha::expected::Result<std::string, std::string> iroha::readFile(
    const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    return makeCannotReadFileError(path);
  }

  std::stringstream ss;
  ss << file.rdbuf();
  if (!ss) {
    return makeCannotReadFileError(path);
  }
  return iroha::expected::makeValue(ss.str());
}
