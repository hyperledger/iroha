#ifndef GOST_CRYPTO_VERIFIER_HPP
#define GOST_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"

namespace shared_model {
  namespace crypto {
    class Verifier : public shared_model::crypto::CryptoVerifierMultihash{
      public:
      ~Verifier() override;

      iroha::expected::Result<void, std::string> verify(
          iroha::multihash::Type type,
          shared_model::interface::types::SignatureByteRangeView signature,
          shared_model::interface::types::ByteRange source,
          shared_model::interface::types::PublicKeyByteRangeView public_key)
          const override;

      static bool verifyEd25519Sha3(
          shared_model::interface::types::SignatureByteRangeView signature,
          shared_model::interface::types::ByteRange source,
          shared_model::interface::types::PublicKeyByteRangeView public_key);

      std::vector<iroha::multihash::Type> getSupportedTypes() const override;
    

      // static bool verify(
      //     shared_model::interface::types::SignatureByteRangeView signature,
      //     const Blob &orig,
      //     shared_model::interface::types::PublicKeyByteRangeView public_key);
    };
    
  } // namespace crypto
} // namespace shared_model

#endif //GOST_CRYPTO_VERIFIER_HPP