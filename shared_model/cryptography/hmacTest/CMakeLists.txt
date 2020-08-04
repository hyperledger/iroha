#Temprorary test executable. It will be removed later

if(NOT PKG_CONFIG_FOUND)
  find_package(PkgConfig REQUIRED)
endif()

pkg_check_modules(BOTAN botan-2)

include_directories(${BOTAN_INCLUDE_DIRS})
link_directories(${BOTAN_LIBRARY_DIRS})

message("Botan Includes: ${BOTAN_INCLUDE_DIRS}")
message("Botan Lib dirs: ${BOTAN_LIBRARY_DIRS}")
message("Botan Libraries: ${BOTAN_LIBRARIES}")

add_executable(HMAC_TEST hmain.cpp)

target_link_libraries(HMAC_TEST
  ${BOTAN_LIBRARIES}
  gost3410_cryptography
  sha3_cryptography
)
