package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.PeerId;

public class PeerIdReader implements ScaleReader<PeerId> {

  private static final PublicKeyReader PUBLIC_KEY_READER = new PublicKeyReader();

  @Override
  public PeerId read(ScaleCodecReader reader) {
    return new PeerId(reader.readString(), PUBLIC_KEY_READER.read(reader));
  }
}
