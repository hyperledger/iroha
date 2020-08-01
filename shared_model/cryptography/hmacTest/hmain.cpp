#include <iostream>
#include "cryptography/gost3410_impl/crypto_provider.hpp"

//Temprorary test executable. It will be removed later.

using cryptoProvider = shared_model::crypto::CryptoProviderGOST3410;

int main(){
  auto kp = cryptoProvider::generateKeypair();

  shared_model::crypto::Blob blob("My message!?");
  auto sign = cryptoProvider::sign(blob, kp);

  //std::cout << "Sign: " << sign << std::endl;
  
  auto byteRange = shared_model::interface::types::makeByteRange(sign);
  auto signByteRange = shared_model::interface::types::SignatureByteRangeView(byteRange);
  
  // auto pk = kp.publicKey();
  // std::string_view stv;
  // stv.data();
  auto kpbytes = shared_model::interface::types::makeByteRange(kp.publicKey().t);
  auto kpbrange = shared_model::interface::types::PublicKeyByteRangeView(kpbytes);

  auto res = cryptoProvider::verify(signByteRange, blob, kpbrange);
  std::cout << (res ? "Good" : "Bad") << std::endl;

  auto m2 = shared_model::crypto::Blob("Not the same");
  res = cryptoProvider::verify(signByteRange, m2, kpbrange);
  std::cout << (!res ? "Good" : "Bad") << std::endl;
  return 0;
}
