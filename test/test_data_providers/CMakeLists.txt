# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(PythonInterp 3.5 REQUIRED)

#### configurable variables ####

set(NUM_TEST_P2P_TLS_CREDS 3)
set(NUM_TEST_KEYS 3)


#### dependency libs to get test data ####

add_library(test_keys test_keys.cpp)
target_link_libraries(test_keys
  libs_files
  )

add_library(test_p2p_tls_creds test_p2p_tls_creds.cpp)
target_link_libraries(test_p2p_tls_creds
  libs_files
  )


#### intestines go below this line ####

function(generate_test_keys privkey_path pubkey_path)
  add_custom_command(
      OUTPUT
        ${privkey_path}
        ${pubkey_path}
      DEPENDS
        ${CMAKE_SOURCE_DIR}/utils/keys_helper.py
      COMMAND
        ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/utils/keys_helper.py
          --priv-out-path ${privkey_path}
          --pub-out-path ${pubkey_path}
  )
endfunction()

target_compile_definitions(test_keys PRIVATE -DNUM_TEST_KEYS=${NUM_TEST_KEYS})
foreach(peer RANGE 1 ${NUM_TEST_KEYS})
  set(PEER${peer}_PRIVKEY ${GENERATED_TEST_DATA_DIR}/peer${peer}.priv)
  set(PEER${peer}_PUBKEY ${GENERATED_TEST_DATA_DIR}/peer${peer}.pub)
  generate_test_keys(${PEER${peer}_PRIVKEY} ${PEER${peer}_PUBKEY})
  # weird, but seems "right" https://cmake.org/pipermail/cmake/2010-March/035621.html
  add_custom_target(generate_peer${peer}_privkey DEPENDS ${PEER${peer}_PRIVKEY})
  add_custom_target(generate_peer${peer}_pubkey DEPENDS ${PEER${peer}_PUBKEY})
  add_dependencies(test_keys generate_peer${peer}_privkey generate_peer${peer}_pubkey)
  target_compile_definitions(test_keys
      PRIVATE
        -DPEER${peer}_PRIVKEY="${PEER${peer}_PRIVKEY}"
        -DPEER${peer}_PUBKEY="${PEER${peer}_PUBKEY}"
      )
endforeach()

function(generate_p2p_tls_creds_self_signed pubkey_path tls_key_out tls_cert_out)
  add_custom_command(
      OUTPUT
        ${tls_key_out}
        ${tls_cert_out}
      DEPENDS
        ${pubkey_path}
        ${CMAKE_SOURCE_DIR}/utils/p2p_cert_helper.py
      COMMAND
        ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/utils/p2p_cert_helper.py
          --iroha-pubkey-path ${pubkey_path}
          --create-and-store-tls-key ${tls_key_out}
          -O ${tls_cert_out}
          gen_self_signed_cert
  )
  SET_SOURCE_FILES_PROPERTIES(${tls_key_out} PROPERTIES GENERATED TRUE)
  SET_SOURCE_FILES_PROPERTIES(${tls_cert_out} PROPERTIES GENERATED TRUE)
endfunction()

target_compile_definitions(test_p2p_tls_creds
    PRIVATE -DNUM_TEST_P2P_TLS_CREDS=${NUM_TEST_P2P_TLS_CREDS})
foreach(peer RANGE 1 ${NUM_TEST_P2P_TLS_CREDS})
  set(PEER${peer}_P2P_TLS_KEY ${TEST_P2P_TLS_DATA_DIR}/peer${peer}.key)
  set(PEER${peer}_P2P_TLS_CERT ${TEST_P2P_TLS_DATA_DIR}/peer${peer}.cert)
  generate_p2p_tls_creds_self_signed(
      ${PEER${peer}_PUBKEY} ${PEER${peer}_P2P_TLS_KEY} ${PEER${peer}_P2P_TLS_CERT})
  add_custom_target(generate_peer${peer}_p2p_tls_key DEPENDS ${PEER${peer}_P2P_TLS_KEY})
  add_custom_target(generate_peer${peer}_p2p_tls_cert DEPENDS ${PEER${peer}_P2P_TLS_CERT})
  add_dependencies(test_p2p_tls_creds
      generate_peer${peer}_p2p_tls_key generate_peer${peer}_p2p_tls_cert)
  target_compile_definitions(test_p2p_tls_creds
      PRIVATE
        -DPEER${peer}_P2P_TLS_KEY="${PEER${peer}_P2P_TLS_KEY}"
        -DPEER${peer}_P2P_TLS_CERT="${PEER${peer}_P2P_TLS_CERT}"
      )
endforeach()
