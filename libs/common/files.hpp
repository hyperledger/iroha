/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FILES_HPP
#define IROHA_FILES_HPP

#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>
#include "common/result_fwd.hpp"
#include "logger/logger_fwd.hpp"

/**
 * This source file contains common methods related to files
 */
namespace iroha {

  /**
   * Remove all files and directories inside a folder.
   * Keeps the target folder.
   * @param dir - target folder
   * @param log - a log for local messages
   */
  void remove_dir_contents(const boost::filesystem::path &dir,
                           const logger::LoggerPtr &log);

  /**
   * Read file in text mode, and either return its contents as a string
   * or return the error as a string
   * @param path - path to the file
   */
  iroha::expected::Result<std::string, std::string> readTextFile(
      const boost::filesystem::path &path);

  /**
   * Read file in binary mode, and either return its contents as a byte vector
   * or return the error as a string
   * @param path - path to the file
   */
  iroha::expected::Result<std::vector<uint8_t>, std::string> readBinaryFile(
      const boost::filesystem::path &path);
}  // namespace iroha
#endif  // IROHA_FILES_HPP
