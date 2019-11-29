/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/flat_file/flat_file.hpp"

#include <ciso646>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include "common/files.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;
using Identifier = FlatFile::Identifier;
using BlockIdCollectionType = FlatFile::BlockIdCollectionType;

// ----------| public API |----------

std::string FlatFile::id_to_name(Identifier id) {
  std::ostringstream os;
  os << std::setw(FlatFile::DIGIT_CAPACITY) << std::setfill('0') << id;
  return os.str();
}

boost::optional<Identifier> FlatFile::name_to_id(const std::string &name) {
  if (name.size() != FlatFile::DIGIT_CAPACITY) {
    return boost::none;
  }
  try {
    Identifier id = std::stoul(name);
    return boost::make_optional(id);
  } catch (const std::exception &e) {
    return boost::none;
  }
}

boost::optional<std::unique_ptr<FlatFile>> FlatFile::create(
    const std::string &path, logger::LoggerPtr log) {
  boost::system::error_code err;
  if (not boost::filesystem::is_directory(path, err)
      and not boost::filesystem::create_directory(path, err)) {
    log->error("Cannot create storage dir: {}\n{}", path, err.message());
    return boost::none;
  }

  BlockIdCollectionType files_found;
  for (auto it = boost::filesystem::directory_iterator{path};
       it != boost::filesystem::directory_iterator{};
       ++it) {
    if (auto id = FlatFile::name_to_id(it->path().filename().string())) {
      files_found.insert(*id);
    } else {
      boost::filesystem::remove(it->path());
    }
  }

  return std::make_unique<FlatFile>(
      path, std::move(files_found), private_tag{}, std::move(log));
}

bool FlatFile::add(Identifier id, const Bytes &block) {
  // TODO(x3medima17): Change bool to generic Result return type

  const auto file_name = boost::filesystem::path{dump_dir_} / id_to_name(id);

  // Write block to binary file
  if (boost::filesystem::exists(file_name)) {
    // File already exist
    log_->warn("insertion for {} failed, because file already exists", id);
    return false;
  }
  // New file will be created
  boost::filesystem::ofstream file(file_name.native(), std::ofstream::binary);
  if (not file.is_open()) {
    log_->warn("Cannot open file by index {} for writing", id);
    return false;
  }

  auto val_size =
      sizeof(std::remove_reference<decltype(block)>::type::value_type);

  file.write(reinterpret_cast<const char *>(block.data()),
             block.size() * val_size);

  available_blocks_.insert(id);
  return true;
}

boost::optional<FlatFile::Bytes> FlatFile::get(Identifier id) const {
  const auto filename =
      boost::filesystem::path{dump_dir_} / FlatFile::id_to_name(id);
  if (not boost::filesystem::exists(filename)) {
    log_->info("get({}) file not found", id);
    return boost::none;
  }
  return iroha::expected::resultToOptionalValue(
      iroha::readBinaryFile(filename.string()));
}

std::string FlatFile::directory() const {
  return dump_dir_;
}

Identifier FlatFile::last_id() const {
  return (available_blocks_.empty()) ? 0 : *available_blocks_.rbegin();
}

void FlatFile::dropAll() {
  iroha::remove_dir_contents(dump_dir_, log_);
  available_blocks_.clear();
}

const BlockIdCollectionType &FlatFile::blockIdentifiers() const {
  return available_blocks_;
}

// ----------| private API |----------

FlatFile::FlatFile(std::string path,
                   BlockIdCollectionType existing_files,
                   FlatFile::private_tag,
                   logger::LoggerPtr log)
    : dump_dir_(std::move(path)),
      available_blocks_(std::move(existing_files)),
      log_{std::move(log)} {}
