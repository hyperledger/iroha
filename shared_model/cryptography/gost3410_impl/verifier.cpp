#include "cryptography/gost3410_impl/verifier.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

using namespace shared_model::crypto::gost3410;
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
  const shared_model::interface::types::ByteRange &pub = public_key;
  const shared_model::interface::types::ByteRange &sig = signature;
  return gost3410::verify(
    reinterpret_cast<const uint8_t*>(source.data()), source.size(),
    reinterpret_cast<const uint8_t*>(pub.data()), pub.size(),
    reinterpret_cast<const uint8_t*>(sig.data()), sig.size()
    );
}

std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  return {iroha::multihash::Type::kGost3410Sha_512};
}
