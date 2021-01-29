package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;
import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.AssetId;
import jp.co.soramitsu.iroha2.model.Bool;
import jp.co.soramitsu.iroha2.model.DefinitionId;
import jp.co.soramitsu.iroha2.model.Domain;
import jp.co.soramitsu.iroha2.model.Id;
import jp.co.soramitsu.iroha2.model.Identifiable;
import jp.co.soramitsu.iroha2.model.Payload;
import jp.co.soramitsu.iroha2.model.Raw;
import jp.co.soramitsu.iroha2.model.U128;
import jp.co.soramitsu.iroha2.model.U32;
import jp.co.soramitsu.iroha2.model.Value;
import jp.co.soramitsu.iroha2.model.ValueBox;
import jp.co.soramitsu.iroha2.model.WorldId;
import jp.co.soramitsu.iroha2.model.instruction.Burn;
import jp.co.soramitsu.iroha2.model.instruction.Fail;
import jp.co.soramitsu.iroha2.model.instruction.If;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.model.instruction.Mint;
import jp.co.soramitsu.iroha2.model.instruction.Pair;
import jp.co.soramitsu.iroha2.model.instruction.Register;
import jp.co.soramitsu.iroha2.model.instruction.Sequence;
import jp.co.soramitsu.iroha2.model.instruction.Transfer;
import jp.co.soramitsu.iroha2.model.instruction.Unregister;
import jp.co.soramitsu.iroha2.scale.writer.ScaleWriterFixture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests SCALE serialization of Payload with all possible instructions.
 */
public class PayloadWriterTest extends ScaleWriterFixture {

  private byte[] scale(Payload payload) {
    return Assertions.assertDoesNotThrow(() -> {
      ByteArrayOutputStream encoded = new ByteArrayOutputStream();
      ScaleCodecWriter codec = new ScaleCodecWriter(encoded);
      codec.write(new PayloadWtriter(), payload);
      return encoded.toByteArray();
    });
  }

  /**
   * Compares scale serialization of register command with generated in rust one:
   * <pre>
   * {@code
   * let domain_name = "Soramitsu";
   * let create_domain = RegisterBox::new(
   *  IdentifiableBox::from(Domain::new(domain_name)),
   *  IdBox::from(WorldId),
   * );
   * }
   * </pre>
   */
  @Test
  public void testRegisterInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611662666185");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Register register = new Register(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));

    payload.setInstructions(List.of(register));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,0,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,201,169,148,62,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of unregister command with generated in rust one:
   * <pre>
   * {@code
   * let domain_name = "Soramitsu";
   * let create_domain = UnregisterBox::new(
   *  IdentifiableBox::from(Domain::new(domain_name)),
   *  IdBox::from(WorldId),
   * );
   * }
   * </pre>
   */
  @Test
  public void testUnregisterInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611669634230");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Unregister unregister = new Unregister(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));

    payload.setInstructions(List.of(unregister));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,1,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,182,252,254,62,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of mint command with generated in rust one:
   * <pre>
   * {@code
   *     let account_id: AccountId = AccountId::new("root", "global");
   *     let quantity: u32 = 100;
   *     let mint_asset = MintBox::new(
   *         Value::U32(quantity),
   *         IdBox::AssetId(AssetId::new(
   *             AssetDefinitionId::new("XOR", "Soramitsu"),
   *             account_id,
   *         )),
   *     );
   * }
   * </pre>
   */
  @Test
  public void testMintInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611671487198");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Raw expression = new Raw(new Value(new U32(100)));
    DefinitionId definitionId = new DefinitionId("XOR", "Soramitsu");
    AssetId assetId = new AssetId(definitionId, accountId);
    Raw expression_id = new Raw(new Value(new Id(assetId)));
    Mint mint = new Mint(expression, expression_id);

    payload.setInstructions(List.of(mint));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,2,9,0,100,0,0,0,9,3,1,12,88,79,82,36,83,111,114,97,109,105,116,115,117,16,114,111,111,116,24,103,108,111,98,97,108,222,66,27,63,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of burn command with generated in rust one:
   * <pre>
   * {@code
   *     let account_id: AccountId = AccountId::new("root", "global");
   *     let quantity: u32 = 100;
   *     let burn_asset = BurnBox::new(
   *         Value::U32(quantity),
   *         IdBox::AssetId(AssetId::new(
   *             AssetDefinitionId::new("XOR", "Soramitsu"),
   *             account_id,
   *         )),
   *     );
   * }
   * </pre>
   */
  @Test
  public void testBurnInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611672005134");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Raw expression = new Raw(new Value(new U32(100)));
    DefinitionId definitionId = new DefinitionId("XOR", "Soramitsu");
    AssetId assetId = new AssetId(definitionId, accountId);
    Raw expression_id = new Raw(new Value(new Id(assetId)));
    Burn burn = new Burn(expression, expression_id);

    payload.setInstructions(List.of(burn));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,3,9,0,100,0,0,0,9,3,1,12,88,79,82,36,83,111,114,97,109,105,116,115,117,16,114,111,111,116,24,103,108,111,98,97,108,14,42,35,63,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of transfer command with generated in rust one:
   * <pre>
   * {@code
   *     let account_id = AccountId::new("root", "global");
   *     let asset_definition_id = AssetDefinitionId { name: "XOR".to_string(), domain_name: "Soramitsu".to_string() };
   *
   *     let domain_name = "Soramitsu";
   *     let transfer_asset = TransferBox::new(
   *         IdBox::AssetId(AssetId::new(
   *             asset_definition_id.clone(),
   *             account_id.clone(),
   *         )),
   *         Value::U32(100),
   *         IdBox::AssetId(AssetId::new(
   *             asset_definition_id,
   *             account_id,
   *         )),
   *     );
   * }
   * </pre>
   */
  @Test
  public void testTransferInstruction() {
    BigInteger creationTime = new BigInteger("1611673151703");
    BigInteger timeToLiveMs = BigInteger.ZERO;
    AccountId accountId = new AccountId("root", "global");

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    DefinitionId assetDefinitionId = new DefinitionId("XOR", "Soramitsu");
    Raw amount = new Raw(new Value(new U32(100)));
    AssetId assetId = new AssetId(assetDefinitionId, accountId);
    Transfer transfer = new Transfer(new Raw(new Value(new Id(assetId))), amount,
        new Raw(new Value(new Id(assetId))));

    payload.setInstructions(List.of(transfer));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,4,9,3,1,12,88,79,82,36,83,111,114,97,109,105,116,115,117,16,114,111,111,116,24,103,108,111,98,97,108,9,0,100,0,0,0,9,3,1,12,88,79,82,36,83,111,114,97,109,105,116,115,117,16,114,111,111,116,24,103,108,111,98,97,108,215,168,52,63,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of if instruction with generated in rust one:
   * <pre>
   * {@code
   *     let domain_name = "Soramitsu";
   *     let create_domain = RegisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let if_instruction = If::new(true, create_domain);
   * </pre>
   */
  @Test
  public void testIfInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611730695426");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Register register = new Register(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Raw condition = new Raw(new Value(new Bool(true)));
    If ifInstruction = new If(condition, register);

    payload.setInstructions(List.of(ifInstruction));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,5,9,1,1,0,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,0,2,181,162,66,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of if instruction with generated in rust one:
   * <pre>
   * {@code
   *     let domain_name = "Soramitsu";
   *     let create_domain = RegisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let remove_domain = UnregisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let if_instruction: Instruction = If::with_otherwise(true, create_domain, remove_domain).into();
   * </pre>
   */
  @Test
  public void testIfElseInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611731064806");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Register register = new Register(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Unregister removeDomain = new Unregister(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Raw condition = new Raw(new Value(new Bool(true)));
    If ifInstruction = new If(condition, register, removeDomain);

    payload.setInstructions(List.of(ifInstruction));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,5,9,1,1,0,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,1,1,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,230,87,168,66,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of Pair instruction with generated in rust one:
   * <pre>
   * {@code
   *     let domain_name = "Soramitsu";
   *     let create_domain = RegisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let remove_domain = UnregisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let instruction = Pair::new(create_domain, remove_domain);
   * </pre>
   */
  @Test
  public void testPairInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611732257095");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Register register = new Register(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Unregister removeDomain = new Unregister(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Instruction instruction = new Pair(register, removeDomain);

    payload.setInstructions(List.of(instruction));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,6,0,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,1,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,71,137,186,66,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of Sequence instruction with generated in rust one:
   * <pre>
   * {@code
   *     let domain_name = "Soramitsu";
   *     let create_domain = RegisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let remove_domain = UnregisterBox::new(
   *         IdentifiableBox::from(Domain::new(domain_name)),
   *         IdBox::from(WorldId),
   *     );
   *     let instructions: Vec<Instruction> = vec![create_domain.into(), remove_domain.into()];
   *     let instruction = Sequence::new(instructions);
   * </pre>
   */
  @Test
  public void testSequenceInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611732666904");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Domain domain = new Domain("Soramitsu");
    Register register = new Register(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Unregister removeDomain = new Unregister(new Raw(new Value(new Identifiable(domain))),
        new Raw(new Value(new Id(new WorldId()))));
    Instruction instruction = new Sequence(List.of(register, removeDomain));

    payload.setInstructions(List.of(instruction));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,7,8,0,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,1,9,4,3,36,83,111,114,97,109,105,116,115,117,0,0,9,3,5,24,202,192,66,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

  /**
   * Compares scale serialization of Fail instruction with generated in rust one:
   * <pre>
   * {@code
   *     let instruction = Fail::new("Fail");
   * </pre>
   */
  @Test
  public void testFailInstruction() {
    AccountId accountId = new AccountId("root", "global");
    BigInteger creationTime = new BigInteger("1611733302477");
    BigInteger timeToLiveMs = BigInteger.ZERO;

    Payload payload = new Payload(accountId, creationTime, timeToLiveMs);

    Instruction instruction = new Fail("Fail");

    payload.setInstructions(List.of(instruction));

    String expected = "[16,114,111,111,116,24,103,108,111,98,97,108,4,8,16,70,97,105,108,205,124,202,66,119,1,0,0,0,0,0,0,0,0,0,0]";
    Assertions.assertEquals(expected, bytesToJsonString(scale(payload)));
  }

}
