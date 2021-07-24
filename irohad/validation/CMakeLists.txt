#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(stateful_validator
    impl/stateful_validator_impl.cpp
    )
target_link_libraries(stateful_validator
    ametsuchi
    shared_model_interfaces
    Boost::boost
    common
    logger
    )

add_library(chain_validator
    impl/chain_validator_impl.cpp
    )
target_link_libraries(chain_validator
    shared_model_interfaces
    logger
    supermajority_checker
    )
