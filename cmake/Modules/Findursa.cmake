if (TARGET ursa)
  return()
endif()

set(URSA_LIBRARY_FILE_NAME "libursa.a")

set(URSA_LIB  ${EP_PREFIX}/lib)
set(URSA_LIBRARY "${URSA_LIB}/${URSA_LIBRARY_FILE_NAME}")

set(URSA_INCL ${EP_PREFIX}/include/ursa)
set(URSA_HEADERS "")
list(APPEND URSA_HEADERS "${URSA_INCL}/ursa_crypto_ed25519.h")
list(APPEND URSA_HEADERS "${URSA_INCL}/ursa_crypto.h")

add_library(ursa STATIC IMPORTED)

set_target_properties(ursa PROPERTIES
    IMPORTED_LOCATION ${URSA_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${URSA_INCL}
    INTERFACE_LINK_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto;dl;pthread"
)

if(APPLE)
  find_library(SECURITY_LIBRARY Security)
  target_link_libraries(ursa INTERFACE ${SECURITY_LIBRARY})
endif()

if(NOT TARGET hyperledger_ursa_build)
  find_package(OpenSSL REQUIRED)
  find_program(CARGO_BIN cargo PATHS /opt/rust/bin DOC "cargo executable for rust" REQUIRED)

  get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)

  file(MAKE_DIRECTORY ${URSA_LIB})
  file(MAKE_DIRECTORY ${URSA_INCL})

  externalproject_add(hyperledger_ursa_build
    GIT_REPOSITORY    "https://github.com/hyperledger/ursa/"
    GIT_TAG           "d425dc2f721659f6bdec50a91d3cb9a1d21ec3f3"
    BUILD_IN_SOURCE   1
    BUILD_COMMAND     ${CMAKE_COMMAND} -E
      env OPENSSL_DIR=${OPENSSL_ROOT_DIR}
      ${CARGO_BIN} build --release
    CONFIGURE_COMMAND "" # remove configure step
    UPDATE_COMMAND    "" # remove update step
    INSTALL_COMMAND   "" # remove install step
  )

endif()

ExternalProject_Get_Property(hyperledger_ursa_build BINARY_DIR)
set(URSA_SRC_LIB  "${BINARY_DIR}/target/release")
set(URSA_SRC_INCL "${BINARY_DIR}/libursa/include")

function(make_copy_command SRC_DIR DEST_PATH)
  get_filename_component(FILE_NAME "${DEST_PATH}" NAME)
  set(DEPENDER_TARGET "ursa_generated_${FILE_NAME}_depender")
  set(SRC_PATH "${SRC_DIR}/${FILE_NAME}")
  add_custom_command(
    OUTPUT "${DEST_PATH}"
    DEPENDS hyperledger_ursa_build
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SRC_PATH}" "${DEST_PATH}"
  )
  if(NOT TARGET ${DEPENDER_TARGET})
    add_custom_target(${DEPENDER_TARGET} DEPENDS "${DEST_PATH}")
  endif()
  add_dependencies(ursa ${DEPENDER_TARGET})
endfunction()

make_copy_command("${URSA_SRC_LIB}" "${URSA_LIBRARY}")
foreach(URSA_HEADER ${URSA_HEADERS})
  make_copy_command("${URSA_SRC_INCL}" "${URSA_HEADER}")
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ursa DEFAULT_MSG)
