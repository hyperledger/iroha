add_library(rocksdb_block_storage
	impl/rocksdb_block_storage.cpp
	)

target_link_libraries(rocksdb_block_storage
	shared_model_proto_backend
	common
	logger
	Boost::filesystem
	RocksDB::rocksdb )
