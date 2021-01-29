package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.instruction.Pair;

public class PairWriter implements ScaleWriter<Pair> {

  private static InstructionWriter INSTRUCTION_WRITER = new InstructionWriter();

  @Override
  public void write(ScaleCodecWriter writer, Pair value) throws IOException {
    writer.write(INSTRUCTION_WRITER, value.getLeft());
    writer.write(INSTRUCTION_WRITER, value.getRight());
  }
}
