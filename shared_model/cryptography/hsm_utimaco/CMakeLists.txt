#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(cxi SHARED IMPORTED)
set_target_properties(cxi PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${HSM_UTIMACO_CXI_PATH}/include"
  IMPORTED_LOCATION ${HSM_UTIMACO_CXI_PATH}/lib/libcxi_m.a
  )

add_library(hsm_utimaco
  init.cpp
  signer.cpp
  verifier.cpp
  )
target_link_libraries(hsm_utimaco
  common
  cxi
  shared_model_cryptography_model
  )

target_compile_definitions(hsm_utimaco
  PUBLIC
    USE_HSM_UTIMACO
  )
