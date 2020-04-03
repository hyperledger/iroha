#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

if(USE_LIBURSA)
	add_library(ursa_cryptography
	    crypto_provider.cpp
	    )
	target_link_libraries(ursa_cryptography
		ursa
		multihash
		)
else()
	add_library(ursa_cryptography
	    crypto_provider_stub.cpp
	    )
endif()

target_link_libraries(ursa_cryptography
    shared_model_cryptography_model
    common
    )
