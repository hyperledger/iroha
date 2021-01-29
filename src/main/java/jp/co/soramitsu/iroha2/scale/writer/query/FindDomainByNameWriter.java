package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindDomainByName;

class FindDomainByNameWriter implements ScaleWriter<FindDomainByName> {

  @Override
  public void write(ScaleCodecWriter writer, FindDomainByName value) throws IOException {
    writer.writeAsList(value.getName().getBytes());
  }
}
