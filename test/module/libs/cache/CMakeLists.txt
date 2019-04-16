#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(cache_test
    cache_test.cpp
    )
target_link_libraries(cache_test
    torii_service
    )

addtest(single_pointer_cache_test
	single_pointer_cache_test.cpp
    )

addtest(transaction_cache_test
    transaction_cache_test.cpp
    )
