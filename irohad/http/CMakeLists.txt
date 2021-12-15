#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(iroha_http_server http_server.cpp)
target_link_libraries(iroha_http_server
        civetweb::civetweb
        )
