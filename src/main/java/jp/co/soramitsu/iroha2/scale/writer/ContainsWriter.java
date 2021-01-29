package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Contains;

public class ContainsWriter implements ScaleWriter<Contains> {

  private static final ExpressionWriter EXPRESSION_WRITER = new ExpressionWriter();

  @Override
  public void write(ScaleCodecWriter writer, Contains value) throws IOException {
    writer.write(EXPRESSION_WRITER, value.getCollection());
    writer.write(EXPRESSION_WRITER, value.getElement());
  }

}
