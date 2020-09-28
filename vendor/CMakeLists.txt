add_library(rocksdb_block_storage
	impl/rocksdb_block_storage.cpp
	)

target_link_libraries(rocksdb_block_storage
	common
	Boost::filesystem
	RocksDB::rocksdb )
