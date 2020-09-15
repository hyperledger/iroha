# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(acceptance)
add_subdirectory(consensus)
add_subdirectory(executor)
add_subdirectory(pipeline)
add_subdirectory(validation)

if (USE_BTF)
  add_subdirectory(binary)
endif()


addtest(grpc_retry_test grpc_retry_test.cpp)
target_link_libraries(grpc_retry_test
    endpoint
    grpc_channel_factory
    server_runner
    test_client_factory
    test_logger
    )
