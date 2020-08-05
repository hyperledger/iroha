#include <iostream>
#include "cryptography/gost3410_impl/crypto_provider.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include <chrono>

//Temprorary test executable. It will be removed later.

using gostCryptoProvider = shared_model::crypto::CryptoProviderGOST3410;
using edCryptoProvider = shared_model::crypto::CryptoProviderEd25519Sha3;

void gostTest(){
  auto kp = gostCryptoProvider::generateKeypair();

  shared_model::crypto::Blob m1("My message!?");
  auto sign = gostCryptoProvider::sign(m1, kp);

  std::cout << "Sign:\n" << sign << std::endl;
  
  auto byteRange = shared_model::interface::types::makeByteRange(sign);
  auto signByteRange = shared_model::interface::types::SignatureByteRangeView(byteRange);
  //from hex string

  auto kpbytes = shared_model::interface::types::makeByteRange(kp.publicKey().t);
  auto kpbrange = shared_model::interface::types::PublicKeyByteRangeView(kpbytes);

  std::cout << "GOST 34.10:" << std::endl;
  auto res = gostCryptoProvider::verify(signByteRange, m1, kpbrange);
  std::cout << (res ? "Good" : "Bad") << std::endl;

  auto m2 = shared_model::crypto::Blob("Not the same");
  res = gostCryptoProvider::verify(signByteRange, m2, kpbrange);
  std::cout << (!res ? "Good" : "Bad") << std::endl;
}

void edTest(){
  std::cout << "Ed 25519:" << std::endl;
  auto kp = edCryptoProvider::generateKeypair();
  
  auto m1 = shared_model::crypto::Blob("My message!?");
  auto sign = edCryptoProvider::sign(m1, kp);

  std::cout << "Sign:\n" << sign << std::endl;

  // signature convertations
  auto blobsign = shared_model::crypto::Blob::fromHexString(sign);
  //auto byteRange = shared_model::interface::types::makeByteRange(blobsign.blob());
  auto signByteRange = shared_model::interface::types::SignatureByteRangeView(blobsign.range());
  // signature convertations END

  // public key convertations
  auto pubstr = std::string(kp.publicKey().t.data(), kp.publicKey().t.size());
  auto pubblob = shared_model::crypto::Blob::fromHexString(pubstr);
  auto kpbytes = shared_model::interface::types::makeByteRange(pubblob.blob());
  auto kpbrange = shared_model::interface::types::PublicKeyByteRangeView(kpbytes);
  // public key convertations END

  auto res = edCryptoProvider::verify(signByteRange, m1, kpbrange);
  std::cout << (res ? "Good" : "Bad") << std::endl;

  auto m2 = shared_model::crypto::Blob("Not the same");
  res = edCryptoProvider::verify(signByteRange, m2, kpbrange);
  std::cout << (!res ? "Good" : "Bad") << std::endl;
}

int main(){
 /*
  * GOST 34.10 test
  */
  auto gost_start = std::chrono::steady_clock::now();
  gostTest();
  auto gost_end = std::chrono::steady_clock::now();
 /*
  * GOST 34.10 test end
  */

 /*
  * ED 25519 test
  */
  auto ed_start = std::chrono::steady_clock::now();
  edTest();
  auto ed_end = std::chrono::steady_clock::now();
 /*
  * ED 25519 test end
  */

  std::cout << std::endl << "Time elapsed: " << std::endl;
  std::cout << "GOST: " << std::chrono::duration<double>(gost_end - gost_start).count() << " [ms]" << std::endl;
  std::cout << "ED  : " << std::chrono::duration<double>(ed_end - ed_start).count() << " [ms]" << std::endl;

  return 0;
}
