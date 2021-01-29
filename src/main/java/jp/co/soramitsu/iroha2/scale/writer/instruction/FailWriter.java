package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.instruction.Fail;

public class FailWriter implements ScaleWriter<Fail> {

  @Override
  public void write(ScaleCodecWriter writer, Fail value) throws IOException {
    writer.writeAsList(value.getMessage().getBytes());
  }
}
