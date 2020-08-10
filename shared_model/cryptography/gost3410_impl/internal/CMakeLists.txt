add_library(gost3410_crypto
  gost_impl.hpp
  gost_impl.cpp
)
target_link_libraries(gost3410_crypto
  gost3410_cryptography
  sha3_cryptography
)
