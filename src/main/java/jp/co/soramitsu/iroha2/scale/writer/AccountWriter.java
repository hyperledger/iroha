package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.Account;
import jp.co.soramitsu.iroha2.model.Asset;
import jp.co.soramitsu.iroha2.model.AssetId;
import jp.co.soramitsu.iroha2.model.PermissionRaw;
import jp.co.soramitsu.iroha2.model.PublicKey;

/**
 * Scale writer that writes nothing.
 */
public class AccountWriter implements ScaleWriter<Account> {

  private static final AccountIdWriter ACCOUNT_ID_WRITER = new AccountIdWriter();
  private static final MapWriter<AssetId, Asset> MAP_WRITER = new MapWriter<>(new AssetIdWriter(),
      new AssetWriter());
  private static final ListWriter<PublicKey> PUBLIC_KEY_LIST_WRITER = new ListWriter<>(
      new PublicKeyWriter());
  private static final ListWriter<PermissionRaw> PERMISSION_RAW_LIST_WRITER = new ListWriter<>(
      new PermissionRawWriter());

  @Override
  public void write(ScaleCodecWriter writer, Account value) throws IOException {
    ACCOUNT_ID_WRITER.write(writer, value.getId());
    MAP_WRITER.write(writer, value.getAssets());
    PUBLIC_KEY_LIST_WRITER.write(writer, value.getSignatories());
    PERMISSION_RAW_LIST_WRITER.write(writer, value.getPermissions());
  }
}
