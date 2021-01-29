package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.UnionWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Expression;

public class ExpressionWriter implements ScaleWriter<Expression> {

  private static final UnionWriter<Expression> EXPRESSION_WRITER = new UnionWriter<>(
      new AddWriter(), // 0 - Add
      new SubtractWriter(), // 1 - Subtract
      new GreaterWriter(), // 2 - Greater
      new LessWriter(), // 3 - Less
      new EqualWriter(), // 4 - Equal
      new NotWriter(), // 5 - Not
      new AndWriter(), // 6 - And
      new OrWriter(), // 7 - Or
      new IfWriter(), // 8 - If
      new RawWriter(), // 9 - Raw
      new QueryWriter(), // 10 - Query
      new ContainsWriter(), // 11 - Contains
      new ContainsAllWriter(), // 12 - ContainsAll
      new WhereWriter(), // 13 - Where
      new ContextValueWriter() // 14 - ContextValue
  );

  @Override
  public void write(ScaleCodecWriter writer, Expression value) throws IOException {
    writer.write(EXPRESSION_WRITER, new EnumerationUnionValue<>(value));
  }

}
