#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD 20)
add_executable(iroha_wsv_diff iroha_wsv_diff.cpp)
#target_compile_features(iroha_wsv_diff PUBLIC cxx_std_20)
#target_compile_options(iroha_wsv_diff PUBLIC -Werror -Wno-error=unused-variable)
target_link_libraries(iroha_wsv_diff PRIVATE
        gflags
        logger_manager
        ametsuchi
        )

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(iroha_wsv_diff PRIVATE nlohmann_json nlohmann_json::nlohmann_json)

add_install_step_for_bin(iroha_wsv_diff)
