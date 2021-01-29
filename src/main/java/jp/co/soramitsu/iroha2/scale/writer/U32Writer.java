package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.U32;

public class U32Writer implements ScaleWriter<U32> {

  @Override
  public void write(ScaleCodecWriter writer, U32 value) throws IOException {
    writer.writeUint32(value.getValue());
  }
}
