package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.And;
import jp.co.soramitsu.iroha2.model.Equal;
import jp.co.soramitsu.iroha2.model.Expression;
import jp.co.soramitsu.iroha2.model.Or;

public class ExpressionReader implements ScaleReader<Expression> {

  private static final UnionReader<Expression> EXPRESSION_UNION_READER = new UnionReader<>(
      new AddReader(), // 0 - Add
      new SubtractReader(), // 1 - Subtract
      new GreaterReader(), // 2 - Greater
      new LessReader(), // 3 - Less
      new EqualReader(), // 4 - Equal
      new NotReader(), // 5 - Not
      new AndReader(), // 6 - And
      new OrReader(), // 7 - Or
      new IfReader(), // 8 - If
      new RawReader(), // 9 - Raw
      new QueryReader(), // 10 - Query
      new ContainsReader(), // 11 - Contains
      new ContainsAllReader(), // 12 - ContainsAll
      new ContainsAnyReader(), // 13 - ContainsAny
      new WhereReader(), // 14 - Where
      new ContextValueReader() // 15 - ContextValue
  );

  @Override
  public Expression read(ScaleCodecReader reader) {
    return reader.read(EXPRESSION_UNION_READER).getValue();
  }

}

