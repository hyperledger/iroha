package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByDomainNameAndAssetDefinitionId;
import jp.co.soramitsu.iroha2.scale.writer.DefinitionIdWriter;

class FindAssetsByDomainNameAndAssetDefinitionIdWriter implements
    ScaleWriter<FindAssetsByDomainNameAndAssetDefinitionId> {

  private static final DefinitionIdWriter DEFINITION_ID_WRITER = new DefinitionIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindAssetsByDomainNameAndAssetDefinitionId value)
      throws IOException {
    writer.writeAsList(value.getDomainName().getBytes());
    DEFINITION_ID_WRITER.write(writer, value.getAssetDefinitionId());
  }
}
