add_library(rockdb_block_storage
	impl/rockdb_block_storage.cpp
	)

target_link_libraries(rockdb_block_storage
	Boost::filesystem
	RocksDB::rocksdb )
