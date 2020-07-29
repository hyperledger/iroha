#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

#include <botan/auto_rng.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <botan/data_src.h>

static const auto ECGName = std::string("gost_256A");
static const auto EMSA = std::string("EMSA1(SHA-512)");

namespace iroha {

  bool verify(const uint8_t *msg,
              size_t msgsize,
              const uint8_t* pub_key,
              size_t pub_key_size,
              const uint8_t* signature,
              size_t signature_size) {

    auto ds = Botan::DataSource_Memory(pub_key, pub_key_size);
    auto key = Botan::X509::load_key(ds);

    Botan::PK_Verifier verifier(*key, EMSA);
    verifier.update(msg, msgsize);

    auto res = verifier.check_signature(
      signature, signature_size
      );
    delete key;
    return res;
  }

  bool verify(std::string_view msg,
              const std::vector<uint8_t>& public_key,
              const std::vector<uint8_t>& signature) {
    return verify(reinterpret_cast<const uint8_t *>(msg.data()),
                  msg.size(),
                  public_key.data(), public_key.size(),
                  signature.data(), signature.size()
                  );
  }

  std::pair<std::string, std::vector<uint8_t>> create_keypair() {
    Botan::AutoSeeded_RNG rng;
    auto key = Botan::GOST_3410_PrivateKey(rng, Botan::EC_Group(ECGName));

    auto pvkey = Botan::PKCS8::BER_encode(key);
    auto pbkey = Botan::X509::PEM_encode(key);

    auto pair = std::make_pair(std::move(pbkey), std::vector<uint8_t>(pvkey.begin(), pvkey.end()));
    
    return pair;
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
    
    return signature;
  }

  std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen){
    auto sig = sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                      priv, privLen);
    return std::string(reinterpret_cast<const char*>(sig.data()), sig.size());
  }
}
