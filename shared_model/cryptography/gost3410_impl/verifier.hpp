#ifndef GOST_CRYPTO_VERIFIER_HPP
#define GOST_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier_multihash.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "cryptography/keypair.hpp"
#include "crypto/keypair.hpp"

namespace shared_model::crypto::gost3410_sha512 {
    class Verifier : public shared_model::crypto::CryptoVerifierMultihash {
      public:
      ~Verifier() override;

      iroha::expected::Result<void, std::string> verify(
          iroha::multihash::Type type,
          shared_model::interface::types::SignatureByteRangeView signature,
          shared_model::interface::types::ByteRange source,
          shared_model::interface::types::PublicKeyByteRangeView public_key)
          const override;

      static bool verifyGost3410Sha512(
          shared_model::interface::types::SignatureByteRangeView signature,
          shared_model::interface::types::ByteRange source,
          shared_model::interface::types::PublicKeyByteRangeView public_key);

      std::vector<iroha::multihash::Type> getSupportedTypes() const override;
    };
  } // namespace shared_model::crypto::gost3410_sha512

#endif //GOST_CRYPTO_VERIFIER_HPP
