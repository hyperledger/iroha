package jp.co.soramitsu.iroha2.model.query;

import jp.co.soramitsu.iroha2.model.Signature;
import lombok.Data;

/**
 * Data model class for query request
 */
@Data
public class SignedQueryRequest {

  private String timestamp;
  private Signature signature;
  private Query query;
}
