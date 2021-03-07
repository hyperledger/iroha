/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FLAT_FILE_BLOCK_STORAGE_HPP
#define IROHA_FLAT_FILE_BLOCK_STORAGE_HPP

#include "ametsuchi/block_storage.hpp"

#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "interfaces/iroha_internal/block_json_converter.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class FlatFileBlockStorage : public BlockStorage {
     public:
      FlatFileBlockStorage(
          std::unique_ptr<FlatFile> flat_file,
          std::shared_ptr<shared_model::interface::BlockJsonConverter>
              json_converter,
          logger::LoggerPtr log);

      bool insert(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      boost::optional<std::unique_ptr<shared_model::interface::Block>> fetch(
          shared_model::interface::types::HeightType height) const override;

      size_t size() const override;

      void reload() override;

      void clear() override;

      expected::Result<void, std::string> forEach(
          FunctionType function) const override;

     private:
      std::unique_ptr<FlatFile> flat_file_storage_;
      std::shared_ptr<shared_model::interface::BlockJsonConverter>
          json_converter_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_FLAT_FILE_BLOCK_STORAGE_HPP
