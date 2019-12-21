# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(backend_proto)
add_subdirectory(converters)
add_subdirectory(builders)
add_subdirectory(interface)
add_subdirectory(validators)
add_subdirectory(cryptography)

AddTest(reference_holder_test
    reference_holder_test.cpp
    )
target_link_libraries(reference_holder_test
    Boost::boost
    )

AddTest(interface_test
    interface_test.cpp
    )
target_link_libraries(interface_test
    shared_model_default_builders
    test_logger
    )

add_library(commands_mocks_factory
    mock_objects_factories/mock_command_factory.cpp
    )
target_link_libraries(commands_mocks_factory
    shared_model_interfaces
    shared_model_proto_backend
    logger
    GTest::gtest
    GTest::gmock
    )
# avoid compilation error due to missing operator<< in Command variant types
target_compile_definitions(commands_mocks_factory
    PUBLIC BOOST_NO_IOSTREAM
    )

add_library(query_mocks_factory
    mock_objects_factories/mock_query_factory.cpp
    )
target_link_libraries(query_mocks_factory
    shared_model_interfaces
    GTest::gtest
    GTest::gmock
    )
# avoid compilation error due to missing operator<< in Query variant types
target_compile_definitions(query_mocks_factory
    PUBLIC BOOST_NO_IOSTREAM
    )
