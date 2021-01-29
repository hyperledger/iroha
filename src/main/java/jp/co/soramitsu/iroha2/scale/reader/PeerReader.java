package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Peer;

public class PeerReader implements ScaleReader<Peer> {

  private static final PeerIdReader PEER_ID_READER = new PeerIdReader();

  @Override
  public Peer read(ScaleCodecReader reader) {
    return new Peer(reader.read(PEER_ID_READER));
  }
}
