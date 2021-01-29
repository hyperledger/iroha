package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.AccountId;

/**
 * Scale writer that writes nothing.
 */
public class AccountIdWriter implements ScaleWriter<AccountId> {

  @Override
  public void write(ScaleCodecWriter writer, AccountId value) throws IOException {
    writer.writeAsList(value.getName().getBytes());
    writer.writeAsList(value.getDomainName().getBytes());
  }
}
