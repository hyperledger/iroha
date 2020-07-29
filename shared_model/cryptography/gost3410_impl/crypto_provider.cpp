#include "cryptography/gost3410_impl/crypto_provider.hpp"

#include "cryptography/gost3410_impl/signer.hpp"
#include "cryptography/gost3410_impl/verifier.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

using namespace shared_model::interface::types;

namespace shared_model{
  namespace crypto{
    std::string CryptoProviderGOST3410::sign(const Blob &blob,
                                             const Keypair &keypair){
      return Signer::sign(blob, keypair);
    }
    
    bool CryptoProviderGOST3410::verify(SignatureByteRangeView signature,
                                           const Blob &orig,
                                           PublicKeyByteRangeView public_key) {
      return gost3410_sha512::Verifier::verifyGost3410Sha512(signature, orig.range(), public_key);
    }

    Keypair CryptoProviderGOST3410::generateKeypair() {
      auto key_pair = iroha::create_keypair();
      auto pbk = shared_model::interface::types::PublicKeyHexStringView(key_pair.first);
      auto pvk = shared_model::crypto::PrivateKey(shared_model::crypto::Blob(key_pair.second));

      return Keypair(pbk, pvk);
    }

    constexpr size_t CryptoProviderGOST3410::kHashLength;
    constexpr size_t CryptoProviderGOST3410::kPublicKeyLength;
    constexpr size_t CryptoProviderGOST3410::kPrivateKeyLength;
    constexpr size_t CryptoProviderGOST3410::kSignatureLength;
    constexpr size_t CryptoProviderGOST3410::kSeedLength;

    const char *CryptoProviderGOST3410::kName = "Gost3410 with SHA512";
  }  // namespace crypto
}  // namespace shared_model