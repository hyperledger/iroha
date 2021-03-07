/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FLAT_FILE_HPP
#define IROHA_FLAT_FILE_HPP

#include <memory>
#include <regex>
#include <set>

#include "ametsuchi/key_value_storage.hpp"
#include "common/result_fwd.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Solid storage based on raw files
     */
    class FlatFile : public KeyValueStorage {
      /**
       * Private tag used to construct unique and shared pointers
       * without new operator
       */
      struct private_tag {};

     public:
      // ----------| public API |----------

      using BlockIdCollectionType = std::set<Identifier>;

      static const uint32_t DIGIT_CAPACITY = 16;

      static const std::string kTempFileExtension;

      static const std::regex kBlockFilenameRegex;

      /**
       * Convert id to a string representation. The string representation is
       * always DIGIT_CAPACITY-character width regardless of the value of `id`.
       * If the length of the string representation of `id` is less than
       * DIGIT_CAPACITY, then the returned value is filled with leading zeros.
       *
       * For example, if str_rep(`id`) is "123", then the returned value is
       * "0000000000000123".
       *
       * @param id - for conversion
       * @return string repr of identifier
       */
      static std::string id_to_name(Identifier id);

      /**
       * Converts aligned string (see above) to number.
       * @param name - name to convert
       * @return id or boost::none
       */
      static boost::optional<Identifier> name_to_id(const std::string &name);

      /**
       * Create storage in paths
       * @param path - target path for creating
       * @param log - logger
       * @return created storage
       */
      static iroha::expected::Result<std::unique_ptr<FlatFile>, std::string>
      create(const std::string &path, logger::LoggerPtr log);

      bool add(Identifier id, const Bytes &blob) override;

      boost::optional<Bytes> get(Identifier id) const override;

      std::string directory() const override;

      Identifier last_id() const override;

      void reload() override;

      void dropAll() override;

      /**
       * @return collection of available block ids
       */
      const BlockIdCollectionType &blockIdentifiers() const;

      // ----------| modify operations |----------

      FlatFile(const FlatFile &rhs) = delete;

      FlatFile(FlatFile &&rhs) = delete;

      FlatFile &operator=(const FlatFile &rhs) = delete;

      FlatFile &operator=(FlatFile &&rhs) = delete;

      // ----------| private API |----------

      /**
       * Create storage in path
       * @param path - folder of storage
       * @param log to print progress
       */
      FlatFile(std::string path,
               FlatFile::private_tag,
               logger::LoggerPtr log);

     private:
      /**
       * Folder of storage
       */
      const std::string dump_dir_;

      /**
       * Blocks in storage, can be modified externally
       */
      BlockIdCollectionType available_blocks_;

      logger::LoggerPtr log_;

     public:
      ~FlatFile() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_FLAT_FILE_HPP
