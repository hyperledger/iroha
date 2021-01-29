package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import java.math.BigInteger;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.model.Payload;
import jp.co.soramitsu.iroha2.scale.writer.AccountIdWriter;

public class PayloadWtriter implements ScaleWriter<Payload> {

  private static final AccountIdWriter ACCOUNT_ID_WRITER = new AccountIdWriter();
  private static final ListWriter<Instruction> INSTRUCTIONS_WRITER = new ListWriter<>(
      new InstructionWriter());

  // TODO replace after io.emeraldpay.polkaj.scale adds support of UInt64
  static public class UInt64Writer implements ScaleWriter<BigInteger> {

    public UInt64Writer() {
    }

    public void write(ScaleCodecWriter wrt, BigInteger value) throws IOException {
      if (value.compareTo(BigInteger.ZERO) < 0) {
        throw new IllegalArgumentException("Negative values are not supported: " + value);
      } else {
        wrt.directWrite(value.and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(8).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(16).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(24).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(32).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(40).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(48).and(BigInteger.valueOf(255)).intValue());
        wrt.directWrite(value.shiftRight(56).and(BigInteger.valueOf(255)).intValue());
      }
    }

  }

  @Override
  public void write(ScaleCodecWriter writer, Payload value) throws IOException {
    writer.write(ACCOUNT_ID_WRITER, value.getAccountId());
    writer.write(INSTRUCTIONS_WRITER, value.getInstructions());
    writer.write(new UInt64Writer(), value.getCreationTime());
    writer.write(new UInt64Writer(), value.getTimeToLiveMs());
  }

}
