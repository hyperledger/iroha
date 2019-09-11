#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Interactive Client
add_library(interactive_cli
    impl/interactive_cli.cpp
    impl/interactive_common_cli.cpp
    impl/interactive_query_cli.cpp
    impl/interactive_transaction_cli.cpp
    impl/interactive_status_cli.cpp
    )
target_link_libraries(interactive_cli
    model
    parser
    client
    )
target_include_directories(interactive_cli PUBLIC
    ${PROJECT_SOURCE_DIR}/iroha-cli
    )
