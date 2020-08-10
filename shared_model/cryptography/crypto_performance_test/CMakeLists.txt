find_package(Botan REQUIRED)

include_directories(${BOTAN_INCLUDE_DIRS})

add_executable(crypto_performance_test cpt_main.cpp)

target_link_libraries(crypto_performance_test
  ${BOTAN_LIBRARIES}
  gost3410_cryptography
  sha3_cryptography
)
