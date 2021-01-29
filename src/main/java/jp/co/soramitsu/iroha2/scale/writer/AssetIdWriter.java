package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.AssetId;

public class AssetIdWriter implements ScaleWriter<AssetId> {

  private static final DefinitionIdWriter DEFINITION_ID_WRITER = new DefinitionIdWriter();
  private static final AccountIdWriter ACCOUNT_ID_WRITER = new AccountIdWriter();

  public void write(ScaleCodecWriter writer, AssetId value) throws IOException {
    writer.write(DEFINITION_ID_WRITER, value.getDefinitionId());
    writer.write(ACCOUNT_ID_WRITER, value.getAccountId());
  }
}
