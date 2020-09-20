#include <rocksdb/db.h>
#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include "ametsuchi/block_storage.hpp"

#ifndef ROCKDB_BLOCK_STORAGE_HPP
#define ROCKDB_BLOCK_STORAGE_HPP

class RockdbBlockStorage : public iroha::ametsuchi::BlockStorage {

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
		rocksdb::Options options;
		rocksdb::Status status;

	// RocksDB Block Constructor constructor
	public:
		RockdbBlockStorage() {
			options.create_if_missing = true;
			options.error_if_exists = true;
			// open a database with a name which corresponds to a file system directory
			status = rocksdb::DB::Open(options, name, &db);
		}
};

#endif
