package jp.co.soramitsu.iroha2.model;

import java.util.Map;
import lombok.Data;
import lombok.NonNull;

@Data
public class Where implements Expression {

  // Expression, which should evaluate to `Value`.
  @NonNull
  private Expression expression;
  
  @NonNull
  private Map<String, Expression> values;


  @Override
  public int getIndex() {
    return 13;
  }
}
