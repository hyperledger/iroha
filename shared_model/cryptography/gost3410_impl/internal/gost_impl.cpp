#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

#include <botan/auto_rng.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <botan/data_src.h>
#include <botan/base64.h>
#include <iostream>

using shared_model::interface::types::PublicKeyByteRangeView;
using shared_model::interface::types::SignatureByteRangeView;

static const auto ECGName = std::string("gost_256A");
static const auto EMSA = std::string("EMSA1(SHA-512)");

namespace iroha {
  sig_t sign(const uint8_t *msg,
             size_t msgsize,
             const pubkey_t &pub,
             const privkey_t &priv) {
    sig_t sig;

    auto ds = Botan::DataSource_Memory(priv.data(), priv.size());
    auto key = Botan::PKCS8::load_key(ds);

    Botan::AutoSeeded_RNG rng;
    Botan::PK_Signer signer(*key.get(), rng, EMSA);
    signer.update(msg, msgsize);
    std::vector<uint8_t> signature = signer.signature(rng);
    
    assert(signature.size() == iroha::sig_t::size());
    std::copy_n(sig.begin(), signature.size(), signature.begin());
    

    return sig;
  }

  sig_t sign(std::string_view msg, const pubkey_t &pub, const privkey_t &priv) {
    return sign(
        reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), pub, priv);
  }


  bool verify(const uint8_t *msg,
              size_t msgsize,
              PublicKeyByteRangeView public_key,
              SignatureByteRangeView signature) {
    const shared_model::interface::types::ByteRange &pub = public_key;
    const shared_model::interface::types::ByteRange &sig = signature;

    auto ds = Botan::DataSource_Memory(reinterpret_cast<const uint8_t*>(pub.data()), pub.size());
    auto key = Botan::X509::load_key(ds);

    Botan::PK_Verifier verifier(*key, EMSA);
    verifier.update(msg, msgsize);
    auto sigt = std::string(reinterpret_cast<const char*>(signature.t.data()), signature.t.size());
    std::cout << "Sign in verify: \n" << sigt << std::endl;
    auto res = verifier.check_signature(
      //reinterpret_cast<const uint8_t*>(sig.data()), sig.size()
      Botan::base64_decode(sigt)
      );
    delete key;
    return res;
  }

  bool verify(std::string_view msg,
              PublicKeyByteRangeView public_key,
              SignatureByteRangeView signature) {
    return verify(reinterpret_cast<const uint8_t *>(msg.data()),
                  msg.size(),
                  public_key,
                  signature);
  }

  blob_t<32> create_seed(){
    throw std::logic_error("Not implemented");
  }

  blob_t<32> create_seed(std::string passphrase){
    throw std::logic_error("Not implemented");
  }

  Keypair create_keypair(blob_t<32> seed){
    throw std::logic_error("Not implemented");
  }

  Keypair create_keypair() {
    Botan::AutoSeeded_RNG rng;
    auto key = Botan::GOST_3410_PrivateKey(rng, Botan::EC_Group(ECGName));

    auto pvkey = Botan::PKCS8::BER_encode(key);
    auto pbkey = Botan::X509::BER_encode(key);
    auto pbkey2 = Botan::X509::PEM_encode(key);

    auto blob = shared_model::crypto::Blob(std::vector<uint8_t>(pvkey.begin(), pvkey.end()));
    auto pvk = shared_model::crypto::PrivateKey(blob);
    auto str = std::string(pbkey.begin(), pbkey.end());
    auto pbk = shared_model::interface::types::PublicKeyHexStringView(pbkey2);//(str);

    Keypair kp = Keypair(pbk, pvk);
    // kp.privkey = std::vector<uint8_t>(pvkey.begin(), pvkey.end()).data();
    // kp.pubkey = reinterpret_cast<const blob*>(pbkey.data());

    return kp;
  }
  
    std::vector<uint8_t> sign(const uint8_t *msg,
                    size_t msgsize,
                    const uint8_t* priv, size_t privLen){
      
      auto ds = Botan::DataSource_Memory(priv, privLen);
      auto key = Botan::PKCS8::load_key(ds);

      Botan::AutoSeeded_RNG rng;
      Botan::PK_Signer signer(*key.get(), rng, EMSA);
      signer.update(msg, msgsize);
      std::vector<uint8_t> signature = signer.signature(rng);
      
      //assert(signature.size() == iroha::sig_t::size());
      //std::copy_n(sig.begin(), signature.size(), signature.begin());
      return signature;
    }

    std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen){
      auto sig = sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                        priv, privLen);
      return Botan::base64_encode(sig.data(), sig.size());
    }
}

// class keypair{
// public:
//     std::vector<uint8_t> pubKey;
//     std::vector<uint8_t> privKey;
// };
 
// keypair makeKeypair(){
//     AutoSeeded_RNG rng;
//     auto key = GOST_3410_PrivateKey(rng, EC_Group(ECGName));

//     // auto aig = AlgorithmIdentifier(ECGName);
//     // std:: cout << 

//     std::cout << "Key length: " << key.key_length() << std::endl;

//     auto prvbits = PKCS8::BER_encode(key); //key.private_key_bits();
//     auto pbkbits = X509::BER_encode(key);//key.public_key_bits();

//     std::cout << "pvkSize: " << prvbits.size() << std::endl;
//     std::cout << "pbkSize: " << pbkbits.size() << std::endl;

//     keypair kpair;

//     kpair.privKey = std::vector<uint8_t>(prvbits.begin(), prvbits.end());
//     kpair.pubKey = std::vector<uint8_t>(pbkbits.begin(), pbkbits.end());

//     std::cout << "kpair.priv size: " << kpair.privKey.size() << std::endl;
//     std::cout << "kpair.pub size: " << kpair.pubKey.size() << std::endl;

//     return kpair;
// }

// // template<size_t size_>
// // class blob_t : public std::array<uint8_t, size_> {

// // };


// std::vector<uint8_t> sign(const uint8_t *msg,
//             size_t msgsize,
//             const pubkey_t &pub,
//             const privkey_t &priv) {
    
//     auto ds = Botan::DataSource_Memory(priv.data(), priv.size());
//     auto key = PKCS8::load_key(ds);

//     AutoSeeded_RNG rng;
//     PK_Signer signer(*key.get(), rng, "EMSA1(SHA-512)");
//     signer.update(msg, msgsize);
//     std::vector<uint8_t> signature = signer.signature(rng);
    
//     std::cout << "Signature: " << std::endl << hex_encode(signature) << std::endl;

//     return signature;
// }

// bool verify(const uint8_t *msg, size_t msgsize, const pubkey_t &pub, const std::vector<uint8_t> signature){

//     auto ds = Botan::DataSource_Memory(pub.data(), pub.size());
//     auto key = X509::load_key(ds);

//     PK_Verifier verifier(*key, "EMSA1(SHA-512)");
//     verifier.update(msg, msgsize);
//     //std::cout << "is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;
//     return verifier.check_signature(signature);
// }



// int main(int, char**) {
//     std::cout << "Hello, world!\n";

//     //rsaStuff();
//     // gostStuff();
//     // return 0;

//     std::string msg = "Hello there?!";
//     auto keyPair = makeKeypair();
//     auto signature 
//         = sign(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), keyPair.pubKey, keyPair.privKey);
//     std::cout << "Signature size: " << signature.size() << std::endl;
//     auto res = verify(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), keyPair.pubKey, signature);
//     std::cout << (res?"Good":"Bad") << std::endl;

//     return 0;
// }
