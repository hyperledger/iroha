#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(irohad_utility_status_notifier status_notifier.cpp)

add_library(irohad_utility_proto_status_tools proto_status_tools.cpp)
target_link_libraries(irohad_utility_proto_status_tools
    utility_endpoint
    )

add_library(irohad_utility_service utility_service.cpp)
target_link_libraries(irohad_utility_service
    irohad_utility_proto_status_tools
    irohad_utility_status_notifier
    logger
    rxcpp
    utility_endpoint
    )

add_library(irohad_utility_client utility_client.cpp)
target_link_libraries(irohad_utility_client
    grpc_channel_factory
    irohad_utility_proto_status_tools
    logger
    utility_endpoint
    )

add_executable(shepherd shepherd.cpp)
target_link_libraries(shepherd
    gflags
    iroha_conf_loader
    irohad_utility_client
    irohad_utility_proto_status_tools
    irohad_version
    logger
    logger_manager
    )

install(TARGETS shepherd
    RUNTIME DESTINATION bin
    CONFIGURATIONS ${CMAKE_BUILD_TYPE}
    COMPONENT iroha_shepherd)
