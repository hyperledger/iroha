/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ROCKSDB_BLOCK_STORAGE_HPP
#define ROCKSDB_BLOCK_STORAGE_HPP

#include <rocksdb/db.h>
#include <string>
#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include "ametsuchi/block_storage.hpp"
#include "common/bind.hpp"
#include "backend/protobuf/block.hpp"
#include "ametsuchi/block_storage_factory.hpp"
#include "backend/protobuf/proto_block_factory.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger.hpp"

using iroha::operator|;

namespace iroha {
  namespace ametsuchi {
class RocksdbBlockStorage : public BlockStorage {

	public:
		bool insert(std::shared_ptr<const shared_model::interface::Block> block) override;

		boost::optional<std::unique_ptr<shared_model::interface::Block>> fetch(
				shared_model::interface::types::HeightType height) const override;

		size_t size() const override;

		void clear() override;

		void forEach(FunctionType function) const override;

	private:
		std::string const name = (boost::filesystem::temp_directory_path()
				/ boost::filesystem::unique_path())
			.string();

		rocksdb::DB *db;

	// RocksDB Block Constructor constructor
	public:
		RocksdbBlockStorage() {
			rocksdb::Options options;
			options.create_if_missing = true;
			options.error_if_exists = true;
			// open a database with a name which corresponds to a file system directory
			rocksdb::Status status = rocksdb::DB::Open(options, name, &db);
		}
};
  }  // namespace ametsuchi
}  // namespace iroha

#endif
