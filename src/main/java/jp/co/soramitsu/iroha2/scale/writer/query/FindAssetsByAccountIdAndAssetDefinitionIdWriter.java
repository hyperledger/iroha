package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByAccountIdAndAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.writer.AccountIdWriter;
import jp.co.soramitsu.iroha2.scale.writer.DefinitionIdWriter;

class FindAssetsByAccountIdAndAssetDefinitionIdWriter implements
    ScaleWriter<FindAssetsByAccountIdAndAssetDefinitionId> {

  private static final AccountIdWriter ACCOUNT_ID_WRITER = new AccountIdWriter();
  private static final DefinitionIdWriter DEFINITION_ID_WRITER = new DefinitionIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindAssetsByAccountIdAndAssetDefinitionId value)
      throws IOException {
    ACCOUNT_ID_WRITER.write(writer, value.getAccountId());
    DEFINITION_ID_WRITER.write(writer, value.getAssetDefinitionId());
  }
}
