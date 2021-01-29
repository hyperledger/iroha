package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Value;

public class ValueWriter implements ScaleWriter<Value> {

  private static final ValueBoxWriter VALUE_BOX_WRITER = new ValueBoxWriter();

  @Override
  public void write(ScaleCodecWriter writer, Value value) throws IOException {
    writer.write(VALUE_BOX_WRITER, value.getValue());
  }

}
