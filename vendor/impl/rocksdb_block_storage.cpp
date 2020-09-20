#include <string>
#include "rocksdb_block_storage.hpp"

/**
 * Append block, if the storage doesn't already contain the same block
 * @return true if inserted successfully, false otherwise
 */
bool RockdbBlockStorage::insert(std::shared_ptr<const shared_model::interface::Block> block) {
	auto height = std::to_string(block->height());
	auto b = block->blob().hex();
	rocksdb::Status s = db->Put(rocksdb::WriteOptions(), height, b);
	return s.ok();
}

boost::optional<std::unique_ptr<shared_model::interface::Block>> RockdbBlockStorage::fetch(
		shared_model::interface::types::HeightType height) const {
	std::string block_data;
	rocksdb::Status s = db->Get(rocksdb::ReadOptions(), std::to_string(height), &block_data);
	return iroha::hexstringToBytestring(block_data) |
          [&, this](auto byte_block) {
            iroha::protocol::Block_v1 b1;
            b1.ParseFromString(byte_block);
            iroha::protocol::Block block;
            *block.mutable_block_v1() = b1;
            return block_factory_->createBlock(std::move(block))
                .match(
                    [&](auto &&v) {
                      return boost::make_optional(
                          std::unique_ptr<shared_model::interface::Block>(
                              std::move(v.value)));
                    },
                    [&](const auto &e)
                        -> boost::optional<
                            std::unique_ptr<shared_model::interface::Block>> {
                      log_->error("Could not build block at height {}: {}",
                                  height,
                                  e.error);
                      return boost::none;
                    });
          };
}

size_t RockdbBlockStorage::size() const {
	size_t count = 0;
	rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		count += 1;
	}
	return count;
}


void RockdbBlockStorage::clear() {
	rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		db->Delete(rocksdb::WriteOptions(), it->key());
	}
}


/**
 * Iterates through all the stored blocks
 */
void RockdbBlockStorage::forEach(FunctionType function) const {
	rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		//convert Srting block to BLock data-type. Need to change this.
		function(std::move(RockdbBlockStorage::fetch(std::stoi(it->key().ToString())).get()));
	}
}
