package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.TransactionReceiptTime;

public class TransactionReceiptTimeWriter implements ScaleWriter<TransactionReceiptTime> {

  private static final U128Writer U_128_WRITER = new U128Writer();

  @Override
  public void write(ScaleCodecWriter writer, TransactionReceiptTime value) throws IOException {
    writer.write(U_128_WRITER, value.getValue());
  }
}
