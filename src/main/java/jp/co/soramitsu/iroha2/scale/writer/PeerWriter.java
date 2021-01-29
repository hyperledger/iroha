package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Peer;

public class PeerWriter implements ScaleWriter<Peer> {

  private static final PeerIdWriter PEER_ID_WRITER = new PeerIdWriter();

  public void write(ScaleCodecWriter writer, Peer value) throws IOException {
    writer.write(PEER_ID_WRITER, value.getPeerId());
  }
}
