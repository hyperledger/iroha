package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Signature;


public class SignatureWriter implements ScaleWriter<Signature> {

  private static final PublicKeyWriter PUBLIC_KEY_WRITER = new PublicKeyWriter();

  @Override
  public void write(ScaleCodecWriter writer, Signature value) throws IOException {
    writer.write(PUBLIC_KEY_WRITER, value.getPublicKey());
    writer.writeAsList(value.getSignature());
  }

}
