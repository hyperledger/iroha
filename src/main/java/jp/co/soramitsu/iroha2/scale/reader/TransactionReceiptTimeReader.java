package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.TransactionReceiptTime;

public class TransactionReceiptTimeReader implements ScaleReader<TransactionReceiptTime> {

  private static final U128Reader U_128_READER = new U128Reader();

  @Override
  public TransactionReceiptTime read(ScaleCodecReader reader) {
    return new TransactionReceiptTime(reader.read(U_128_READER));
  }

}
