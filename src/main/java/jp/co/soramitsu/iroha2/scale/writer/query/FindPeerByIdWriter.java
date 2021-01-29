package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindPeerById;
import jp.co.soramitsu.iroha2.scale.writer.PeerIdWriter;

class FindPeerByIdWriter implements ScaleWriter<FindPeerById> {

  private static PeerIdWriter PEER_ID_WRITER = new PeerIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindPeerById value) throws IOException {
    writer.write(PEER_ID_WRITER, value.getPeerId());
  }
}
