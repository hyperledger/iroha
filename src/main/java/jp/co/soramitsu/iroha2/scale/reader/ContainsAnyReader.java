package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.ContainsAny;

public class ContainsAnyReader implements ScaleReader<ContainsAny> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public ContainsAny read(ScaleCodecReader reader) {
    return new ContainsAny(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
