/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/flat_file/flat_file.hpp"

#include <boost/filesystem.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <ciso646>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "common/files.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"

#ifdef _WIN32
// We skip format here because of strong including order
// clang-format off
#include <windows.h>
#include <fileapi.h>
// clang-format on
#endif

using namespace iroha::ametsuchi;
using Identifier = FlatFile::Identifier;
using BlockIdCollectionType = FlatFile::BlockIdCollectionType;

const std::string FlatFile::kTempFileExtension = ".tmp";
const std::regex FlatFile::kBlockFilenameRegex = std::regex("[0-9]{16}");

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

iroha::expected::Result<std::unique_ptr<FlatFile>, std::string>
FlatFile::create(const std::string &path, logger::LoggerPtr log) {
  boost::system::error_code err;
  if (not boost::filesystem::is_directory(path, err)
      and not boost::filesystem::create_directory(path, err)) {
    return fmt::format(
        "Cannot create storage dir '{}': {}", path, err.message());
  }

  return std::make_unique<FlatFile>(path, private_tag{}, std::move(log));
}

bool FlatFile::add(Identifier id, const Bytes &block) {
  // TODO(x3medima17): Change bool to generic Result return type

  const auto tmp_file_name = boost::filesystem::path{dump_dir_}
      / (id_to_name(id) + kTempFileExtension);
  const auto file_name = boost::filesystem::path{dump_dir_} / id_to_name(id);

  // Write block to binary file
  if (boost::filesystem::exists(tmp_file_name)
      || boost::filesystem::exists(file_name)) {
    // File already exist
    log_->warn("insertion for {} failed, because file already exists", id);
    return false;
  }
  // New file will be created
  boost::iostreams::stream<boost::iostreams::file_descriptor_sink> file;
  try {
    file.open(tmp_file_name, std::ofstream::binary);
  } catch (std::ios_base::failure const &e) {
    log_->warn("Cannot open file by index {} for writing: {}", id, e.what());
    return false;
  }
  if (not file.is_open()) {
    log_->warn("Cannot open file by index {} for writing", id);
    return false;
  }

  auto val_size =
      sizeof(std::remove_reference<decltype(block)>::type::value_type);

  if (not file.write(reinterpret_cast<const char *>(block.data()),
                     block.size() * val_size)) {
    log_->warn("Cannot write file by index {}", id);
    return false;
  }

  if (not file.flush()) {
    log_->warn("Cannot flush file by index {}", id);
    return false;
  }

#ifdef _WIN32
  if (not FlushFileBuffers(file->handle())) {
#else
  if (fsync(file->handle())) {
#endif
    log_->warn("Cannot fsync file by index {}", id);
    return false;
  }

  file->close();

  boost::system::error_code error_code;
  boost::filesystem::rename(tmp_file_name, file_name, error_code);
  if (error_code != boost::system::errc::success) {
    log_->error(
        "insertion for {} failed, because {}", id, error_code.message());
    return false;
  }

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

void FlatFile::reload() {
  available_blocks_.clear();
  for (auto it = boost::filesystem::directory_iterator{dump_dir_};
       it != boost::filesystem::directory_iterator{};
       ++it) {
    // skip non-block files
    if (!std::regex_match(it->path().filename().string(),
                          kBlockFilenameRegex)) {
      continue;
    }
    if (auto id = FlatFile::name_to_id(it->path().filename().string())) {
      available_blocks_.insert(*id);
    } else {
      boost::filesystem::remove(it->path());
    }
  }
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
                   FlatFile::private_tag,
                   logger::LoggerPtr log)
    : dump_dir_(std::move(path)), log_{std::move(log)} {
  reload();
}
