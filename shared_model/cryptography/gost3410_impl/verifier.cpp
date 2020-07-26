#include "cryptography/gost3410_impl/verifier.hpp"

#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

using namespace shared_model::crypto::gost3410_sha512;
using namespace shared_model::interface::types;

iroha::expected::Result<void, std::string> Verifier::verify(
    iroha::multihash::Type type,
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange source,
    shared_model::interface::types::PublicKeyByteRangeView public_key) const{
  assert(type == iroha::multihash::Type::kGost3410Sha_512);
  if(verifyGost3410Sha512(signature, source, public_key)){
    return iroha::expected::Value<void>{};
  }  
  return iroha::expected::makeError("Bad signature.");
}

bool Verifier::verifyGost3410Sha512(
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange source,
    shared_model::interface::types::PublicKeyByteRangeView public_key){
  return iroha::verify(reinterpret_cast<const uint8_t*>(source.data()), source.size(), public_key, signature);
}


std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  return {iroha::multihash::Type::kGost3410Sha_512};
}

// using shared_model::interface::types::PublicKeyByteRangeView;
// using shared_model::interface::types::SignatureByteRangeView;

// namespace shared_model {
//   namespace crypto {
    // bool Verifier::verify(SignatureByteRangeView signature,
    //                       const Blob &orig,
    //                       PublicKeyByteRangeView public_key) {
    //   auto& blob = orig.blob();
    //   return iroha::verify(blob.data(), blob.size(), public_key, signature);
    // }
//   } // namespace crypto
// } // namespace shared_model
