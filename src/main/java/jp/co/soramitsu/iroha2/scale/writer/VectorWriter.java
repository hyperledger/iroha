package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Value;
import jp.co.soramitsu.iroha2.model.Vector;

public class VectorWriter implements ScaleWriter<Vector> {

  private static final ListWriter<Value> LIST_WRITER = new ListWriter<>(
      new ValueWriter());

  @Override
  public void write(ScaleCodecWriter writer, Vector value) throws IOException {
    writer.write(LIST_WRITER, value.getVector());
  }
}
