add_library(rocksdb_block_storage
	impl/rocksdb_block_storage.cpp
	)

target_link_libraries(rocksdb_block_storage
	Boost::filesystem
	RocksDB::rocksdb )
