#include "cryptography/gost3410_impl/verifier.hpp"

#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

using shared_model::interface::types::PublicKeyByteRangeView;
using shared_model::interface::types::SignatureByteRangeView;

namespace shared_model {
  namespace crypto {
    // bool Verifier::verify(SignatureByteRangeView signature,
    //                       const Blob &orig,
    //                       PublicKeyByteRangeView public_key) {
    //   auto& blob = orig.blob();
    //   return iroha::verify(blob.data(), blob.size(), public_key, signature);
    // }

    std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
      return {iroha::multihash::Type::kEd25519Sha3_256};
}
  } // namespace crypto
} // namespace shared_model
