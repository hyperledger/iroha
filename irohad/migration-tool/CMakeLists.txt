#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

set(CMAKE_CXX_STANDARD 20)
add_executable(migration-tool migration-tool.cpp)
#target_compile_features(migration-tool PUBLIC cxx_std_20)
#target_compile_options(migration-tool PUBLIC -Werror -Wno-error=unused-variable)
target_link_libraries(migration-tool PRIVATE
        gflags
        logger_manager
        ametsuchi
        )

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(migration-tool PRIVATE nlohmann_json nlohmann_json::nlohmann_json)
