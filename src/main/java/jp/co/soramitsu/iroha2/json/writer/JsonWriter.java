package jp.co.soramitsu.iroha2.json.writer;

public interface JsonWriter<T> {

  String write(T value);
}

