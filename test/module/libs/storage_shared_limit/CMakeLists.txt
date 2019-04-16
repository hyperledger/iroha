AddTest(storage_shared_limit_test storage_shared_limit_test.cpp)
target_link_libraries(storage_shared_limit_test
    schema
    shared_model_interfaces_factories
    shared_model_proto_backend
    test_logger
    )

