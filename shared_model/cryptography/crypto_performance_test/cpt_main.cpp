#include <iostream>
#include <chrono>
#include "cryptography/gost3410_impl/crypto_provider.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "common/hexutils.hpp"

using gostCryptoProvider = shared_model::crypto::CryptoProviderGOST3410;
using edCryptoProvider = shared_model::crypto::CryptoProviderEd25519Sha3;

const unsigned numOfTests         = 1000;
const unsigned generateKeypairNum = numOfTests;
const unsigned signNum            = numOfTests;
const unsigned verifyNum          = numOfTests;

const std::string blobMsg     = "Sign and verify test message";
const std::string blobWrgMsg  = "Wrong test message";


template<class CryptoProvider>
auto generateKeypairTest(unsigned numOfRuns){
  auto start = std::chrono::steady_clock::now();
  for(unsigned i = 0; i < numOfRuns; ++i)
    CryptoProvider::generateKeypair();
  auto end = std::chrono::steady_clock::now();

  auto total = std::chrono::duration<double>(end - start).count();
  return total;
}

template<class CryptoProvider>
auto signTest(unsigned numOfRuns){
  auto kp = CryptoProvider::generateKeypair();
  auto blob = shared_model::crypto::Blob(blobMsg);

  auto start = std::chrono::steady_clock::now();
  for(unsigned i=0; i < numOfRuns; ++i)
    CryptoProvider::sign(blob, kp);
  auto end = std::chrono::steady_clock::now();
  
  auto total = std::chrono::duration<double>(end - start).count();
  return total;
}

template<class CryptoProvider>
auto verifyTest(unsigned numOfRuns){
  auto kp = CryptoProvider::generateKeypair();
  auto blob = shared_model::crypto::Blob(blobMsg);
  auto sign = CryptoProvider::sign(blob, kp);

  auto blobSign = shared_model::crypto::Blob::fromHexString(sign);
  auto signByteRange = shared_model::interface::types::SignatureByteRangeView(blobSign.range());

  auto pubstr = std::string(kp.publicKey().t.data(), kp.publicKey().t.size());
  auto pubblob = shared_model::crypto::Blob::fromHexString(pubstr);
  auto kpbrange = shared_model::interface::types::PublicKeyByteRangeView(pubblob.range());

  auto start = std::chrono::steady_clock::now();
  for(unsigned i = 0; i < numOfRuns; ++i)
    CryptoProvider::verify(signByteRange, blob, kpbrange);
  auto end = std::chrono::steady_clock::now();

  auto total = std::chrono::duration<double>(end - start).count();
  return total;
}

template<class CryptoProvider>
auto integrityTest(){
  auto kp = CryptoProvider::generateKeypair();

  auto message = shared_model::crypto::Blob(blobMsg);
  auto wrongMessage = shared_model::crypto::Blob(blobWrgMsg);

  auto sign = CryptoProvider::sign(message, kp);
  
  // signature convertations
  auto blobSign = shared_model::crypto::Blob::fromHexString(sign);
  auto signByteRange = shared_model::interface::types::SignatureByteRangeView(blobSign.range());
  // signature convertations END

  // public key convertations
  auto pubstr = std::string(kp.publicKey().t.data(), kp.publicKey().t.size());
  auto pubblob = shared_model::crypto::Blob::fromHexString(pubstr);
  auto kpbrange = shared_model::interface::types::PublicKeyByteRangeView(pubblob.range());
  // public key convertations END

  auto res1 = CryptoProvider::verify(signByteRange, message, kpbrange);
  auto res2 = CryptoProvider::verify(signByteRange, wrongMessage, kpbrange);

  return std::make_pair(res1, !res2);
}

template<class CryptoProvider>
void test(const std::string& algName){
  std::cout << algName << std::endl;

  auto intgRes = integrityTest<CryptoProvider>();
  auto prfRes = std::make_tuple(
    generateKeypairTest<CryptoProvider>(generateKeypairNum)/generateKeypairNum,
    signTest<CryptoProvider>(signNum)/signNum,
    verifyTest<CryptoProvider>(verifyNum)/verifyNum
  );
  
  std::cout << "  Right signature test: " << (intgRes.first ? "Passed" : "Failed") << std::endl;
  std::cout << "  Wrong signature test: " << (intgRes.second ? "Passed" : "Failed") << std::endl;
  std::cout << "  Performance test (seconds):" << std::endl;
  std::cout << "  Keypair test\t\tSign test\t\tVerify test" << std::endl;
  std::cout.precision(10);
  std::cout << "  " << std::fixed << 
      std::get<0>(prfRes) << "\t\t" <<
      std::get<1>(prfRes) << "\t\t" <<
      std::get<2>(prfRes) << std::endl;
}


int main(){
  test<gostCryptoProvider>("GOST 34.10");
  std::cout << std::endl;
  test<edCryptoProvider>("Ed25519");

  return 0;
}
