#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(pipeline_test pipeline_test.cpp)
target_link_libraries(pipeline_test
    acceptance_fixture
    integration_framework
    )

addtest(batch_pipeline_test batch_pipeline_test.cpp)
target_link_libraries(batch_pipeline_test
    acceptance_fixture
    integration_framework
    )

addtest(multisig_tx_pipeline_test multisig_tx_pipeline_test.cpp)
target_link_libraries(multisig_tx_pipeline_test
    acceptance_fixture
    integration_framework
    )
