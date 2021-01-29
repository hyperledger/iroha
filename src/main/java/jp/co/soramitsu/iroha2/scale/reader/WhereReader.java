package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Expression;
import jp.co.soramitsu.iroha2.model.Where;

public class WhereReader implements ScaleReader<Where> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();
  private static final MapReader<String, Expression> VALUES_READER = new MapReader<>(
      new StringReader(),
      EXPRESSION_READER);

  @Override
  public Where read(ScaleCodecReader reader) {
    return new Where(reader.read(EXPRESSION_READER), reader.read(VALUES_READER));
  }
}
