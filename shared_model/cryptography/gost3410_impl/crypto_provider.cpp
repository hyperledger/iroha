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
      return Verifier::verify(signature, orig, public_key);
    }

Seed CryptoProviderGOST3410::generateSeed() {
      return Seed(iroha::create_seed().to_string());
    }

    Seed CryptoProviderGOST3410::generateSeed(
        const std::string &passphrase) {
      return Seed(iroha::create_seed(passphrase).to_string());
    }

    Keypair CryptoProviderGOST3410::generateKeypair() {
      auto keypair = iroha::create_keypair();
      return Keypair(PublicKeyHexStringView{keypair.pubkey.to_hexstring()},
                     PrivateKey(keypair.privkey.to_string()));
    }

    Keypair CryptoProviderGOST3410::generateKeypair(const Seed &seed) {
      assert(seed.size() == kSeedLength);
      auto keypair = iroha::create_keypair(
          iroha::blob_t<kSeedLength>::from_raw(seed.blob().data()));

      return Keypair(PublicKeyHexStringView{keypair.pubkey.to_hexstring()},
                     PrivateKey(keypair.privkey.to_string()));
    }

    constexpr size_t CryptoProviderGOST3410::kHashLength;
    constexpr size_t CryptoProviderGOST3410::kPublicKeyLength;
    constexpr size_t CryptoProviderGOST3410::kPrivateKeyLength;
    constexpr size_t CryptoProviderGOST3410::kSignatureLength;
    constexpr size_t CryptoProviderGOST3410::kSeedLength;

    const char *CryptoProviderGOST3410::kName = "Gost3410 with SHA512";
  }  // namespace crypto
}  // namespace shared_model