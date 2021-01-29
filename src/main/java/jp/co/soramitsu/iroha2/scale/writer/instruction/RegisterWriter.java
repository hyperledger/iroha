package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.instruction.Register;
import jp.co.soramitsu.iroha2.scale.writer.ExpressionWriter;

public class RegisterWriter implements ScaleWriter<Register> {

  private static final ExpressionWriter EXPRESSION_WRITER_WRITER = new ExpressionWriter();

  @Override
  public void write(ScaleCodecWriter writer, Register value) throws IOException {
    writer.write(EXPRESSION_WRITER_WRITER, value.getObject());
    writer.write(EXPRESSION_WRITER_WRITER, value.getDestinationId());
  }
}
