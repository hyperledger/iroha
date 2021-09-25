#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD 20)
add_executable(iroha_migrate iroha_migrate.cpp ../main/impl/storage_init.cpp)
#target_compile_features(iroha_migrate PUBLIC cxx_std_20)
# target_compile_options(iroha_migrate PUBLIC -Werror
#         -Wno-error=unused-variable -Wno-error=comment -Wno-error=uninitialized
#         -Wno-error=maybe-uninitialized -Wno-error=unknown-warning-option)
target_link_libraries(iroha_migrate PRIVATE
        gflags
        logger_manager
        ametsuchi
        chain_validator
        generator
        yac_transport
        )

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(iroha_migrate PRIVATE nlohmann_json nlohmann_json::nlohmann_json)

add_install_step_for_bin(iroha_migrate)
