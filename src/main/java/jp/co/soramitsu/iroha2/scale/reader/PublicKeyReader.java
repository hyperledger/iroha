package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.PublicKey;

public class PublicKeyReader implements ScaleReader<PublicKey> {

  @Override
  public PublicKey read(ScaleCodecReader reader) {
    return new PublicKey(reader.readString(), reader.readByteArray());
  }
}
