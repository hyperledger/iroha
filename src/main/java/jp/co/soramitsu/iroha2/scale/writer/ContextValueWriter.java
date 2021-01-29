package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.ContextValue;

public class ContextValueWriter implements ScaleWriter<ContextValue> {

  @Override
  public void write(ScaleCodecWriter writer, ContextValue value) throws IOException {
    writer.writeAsList(value.getValueName().getBytes());
  }

}
