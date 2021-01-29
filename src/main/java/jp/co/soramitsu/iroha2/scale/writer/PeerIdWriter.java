package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.PeerId;

public class PeerIdWriter implements ScaleWriter<PeerId> {

  private static final PublicKeyWriter PUBLIC_KEY_WRITER = new PublicKeyWriter();

  public void write(ScaleCodecWriter writer, PeerId value) throws IOException {
    writer.writeAsList(value.getAddress().getBytes());
    writer.write(PUBLIC_KEY_WRITER, value.getPublicKey());
  }
}
