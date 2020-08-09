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


void inline printResults(unsigned numberOfRuns, double totalTime){
  std::cout << "  number of runs: " << numberOfRuns << std::endl;
  std::cout << "  total: " << totalTime << " [ms]" << std::endl;  
  std::cout << "  avg: " << (numberOfRuns ? (totalTime / numberOfRuns) : 0) << " [ms]" << std::endl;
}

template<class CryptoProvider>
auto generateKeypairTest(unsigned numOfRuns){
  std::cout << "generate keypair test:" << std::endl;
  auto start = std::chrono::steady_clock::now();
  for(unsigned i = 0; i < numOfRuns; ++i)
    CryptoProvider::generateKeypair();
  auto end = std::chrono::steady_clock::now();

  auto total = std::chrono::duration<double>(end - start).count();
  printResults(numOfRuns, total);
  return total;
}

template<class CryptoProvider>
auto signTest(unsigned numOfRuns){
  std::cout << "sign test:" << std::endl;
  auto kp = CryptoProvider::generateKeypair();
  auto blob = shared_model::crypto::Blob(blobMsg);

  auto start = std::chrono::steady_clock::now();
  for(unsigned i=0; i < numOfRuns; ++i)
    CryptoProvider::sign(blob, kp);
  auto end = std::chrono::steady_clock::now();
  
  auto total = std::chrono::duration<double>(end - start).count();
  printResults(numOfRuns, total);
  return total;
}

template<class CryptoProvider>
auto verifyTest(unsigned numOfRuns){
  std::cout << "verify test:" << std::endl;
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
  printResults(numOfRuns, total);
  return total;
}

void PerfTest(){
  auto gostResults = std::make_tuple(
    generateKeypairTest<gostCryptoProvider>(generateKeypairNum),
    signTest<gostCryptoProvider>(signNum),
    verifyTest<gostCryptoProvider>(verifyNum));
  auto edResults = std::make_tuple(
    generateKeypairTest<edCryptoProvider>(generateKeypairNum),
    signTest<edCryptoProvider>(signNum),
    verifyTest<edCryptoProvider>(verifyNum));

  std::cout << "=== Test Results ===" << std::endl;
  std::cout << "Alg\t\tkeypair test\t\tsign test\t\tverify test" << std::endl;
  std::cout << "GOST3410\t\t" << 
      std::get<0>(gostResults) / generateKeypairNum << "\t\t" <<
      std::get<1>(gostResults) / signNum << "\t\t" <<
      std::get<2>(gostResults) / verifyNum << std::endl;
  std::cout << "ED25519 \t\t" <<
      std::get<0>(edResults) / generateKeypairNum << "\t\t" <<
      std::get<1>(edResults) / signNum << "\t\t" <<
      std::get<2>(edResults) / verifyNum << std::endl;
}

template<class CryptoProvider>
bool integrityTest(){
  auto kp = CryptoProvider::generateKeypair();

  auto message = shared_model::crypto::Blob(blobMsg);
  auto wrongMessage = shared_model::crypto::Blob(blobWrgMsg);

  auto sign = CryptoProvider::sign(message, kp);

  std::cout << "PBK:\n" << kp.publicKey().t << std::endl;
  std::cout << "Sign:\n" << sign << std::endl;
  
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

  std::cout << (res1 ? "Good" : "Bad") << std::endl;
  std::cout << (!res2 ? "Good" : "Bad") << std::endl;

  return res1 && !res2;
}

int main(){
  std::cout << "GOST 34.10:" << std::endl;
  auto gost_start = std::chrono::steady_clock::now();
  auto gostIntRes = integrityTest<gostCryptoProvider>();
  auto gost_end = std::chrono::steady_clock::now();

  std::cout << std::endl;

  std::cout << "Ed 25519:" << std::endl;
  auto ed_start = std::chrono::steady_clock::now();
  auto edIntRes = integrityTest<edCryptoProvider>();
  auto ed_end = std::chrono::steady_clock::now();

  std::cout << std::endl << "Time elapsed: " << std::endl;
  std::cout << "GOST: " << std::chrono::duration<double>(gost_end - gost_start).count() << " [ms]" << std::endl;
  std::cout << "ED  : " << std::chrono::duration<double>(ed_end - ed_start).count() << " [ms]" << std::endl;

  std::cout << std::endl << "Performance test: " << std::endl;
  PerfTest();
  
  std::cout << std::endl;
  std::cout << "GOST3410: " << (gostIntRes?"GOOD":"BAD") << std::endl;
  std::cout << "ED25519: " << (edIntRes?"GOOD":"BAD") << std::endl;

  return 0;
}
