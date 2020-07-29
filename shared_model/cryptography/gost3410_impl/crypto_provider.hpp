#ifndef GOST_CRYPTO_PROVIDER_HPP
#define GOST_CRYPTO_PROVIDER_HPP

#include "cryptography/keypair.hpp"
#include "cryptography/seed.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {
  namespace crypto {

    class CryptoProviderGOST3410{
    public:

      static std::string sign(const Blob &blob, const Keypair &keypair);

      static bool verify(
          shared_model::interface::types::SignatureByteRangeView signature,
          const Blob &orig,
          shared_model::interface::types::PublicKeyByteRangeView public_key);
    
      static Keypair generateKeypair();

      static const char *kName;
      static constexpr size_t kHashLength = 256 / 8;
      static constexpr size_t kPublicKeyLength = 256 / 8;
      static constexpr size_t kPrivateKeyLength = 256 / 8;
      static constexpr size_t kSignatureLength = 512 / 8;
      static constexpr size_t kSeedLength = 256 / 8;
    };
  } // namespace crypto
} // namespace shared_model

#endif //GOST_CRYPTO_PROVIDER_HPP