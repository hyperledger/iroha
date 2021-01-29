package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.ContainsAll;

public class ContainsAllReader implements ScaleReader<ContainsAll> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public ContainsAll read(ScaleCodecReader reader) {
    return new ContainsAll(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
