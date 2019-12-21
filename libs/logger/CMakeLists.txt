#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(logger
    logger.cpp
    logger_spdlog.cpp
)
target_link_libraries(logger
    fmt::fmt
    spdlog::spdlog
    Boost::boost
)

add_library(logger_manager logger_manager.cpp)
target_link_libraries(logger_manager
    logger
)
