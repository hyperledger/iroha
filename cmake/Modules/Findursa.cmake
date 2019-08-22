add_library(ursa UNKNOWN IMPORTED)
find_package(OpenSSL REQUIRED)

set(URL     "https://github.com/hyperledger/ursa/")
set(VERSION "d425dc2f721659f6bdec50a91d3cb9a1d21ec3f3")

set(URSA_SRC_LIB  ${EP_PREFIX}/src/hyperledger_ursa/target/release/libursa.a)
set(URSA_SRC_INCL ${EP_PREFIX}/src/hyperledger_ursa/libursa/include)

set(URSA_LIB  ${EP_PREFIX}/lib)
set(URSA_INCL ${EP_PREFIX}/include/ursa)

file(MAKE_DIRECTORY ${URSA_LIB})
file(MAKE_DIRECTORY ${URSA_INCL})

externalproject_add(hyperledger_ursa
  GIT_REPOSITORY    ${URL}
  GIT_TAG           ${VERSION}
  BUILD_IN_SOURCE   1
  BUILD_COMMAND     cargo build --release --no-default-features --features="ffi"
  CONFIGURE_COMMAND "" # remove configure step
  UPDATE_COMMAND    "" # remove update step
  INSTALL_COMMAND   "" # remove install step
)

add_custom_command(TARGET hyperledger_ursa POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${URSA_SRC_LIB} ${URSA_LIB}
  COMMAND ${CMAKE_COMMAND} -E copy ${URSA_SRC_INCL}/ursa_crypto_ed25519.h ${URSA_INCL}
  COMMAND ${CMAKE_COMMAND} -E copy ${URSA_SRC_INCL}/ursa_crypto.h ${URSA_INCL}
)

add_dependencies(ursa hyperledger_ursa)

set_target_properties(ursa PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${URSA_INCL}
    IMPORTED_LOCATION ${URSA_LIB}/libursa.a
    INTERFACE_LINK_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto;dl;pthread"
)
