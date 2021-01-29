package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Signature;
import jp.co.soramitsu.iroha2.model.instruction.Transaction;
import jp.co.soramitsu.iroha2.scale.writer.SignatureWriter;

public class TransactionWriter implements ScaleWriter<Transaction> {

  private static final PayloadWtriter PAYLOAD_WRITER = new PayloadWtriter();
  private static final ListWriter<Signature> SIGNATURES_WRITER = new ListWriter<>(
      new SignatureWriter());

  @Override
  public void write(ScaleCodecWriter writer, Transaction value) throws IOException {
    writer.write(PAYLOAD_WRITER, value.getPayload());
    writer.write(SIGNATURES_WRITER, value.getSignatures());
  }
}
