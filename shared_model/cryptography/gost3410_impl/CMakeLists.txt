add_subdirectory(internal)

add_library(gost3410_cryptography
  crypto_provider.cpp
  signer.cpp
  verifier.cpp
)

target_link_libraries(gost3410_cryptography
  gost3410_crypto
  shared_model_cryptography_model
  common
)
