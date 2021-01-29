package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;

/**
 * Scale writer that writes nothing. Is used for empty classes.
 */
public class NopWriter<T> implements ScaleWriter<T> {

  @Override
  public void write(ScaleCodecWriter writer, T value) {
  }
}
