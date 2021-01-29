package jp.co.soramitsu.iroha2;

import java.security.KeyPair;
import java.util.concurrent.Future;
import jp.co.soramitsu.iroha2.TransactionTerminalStatusWebSocketListener.TerminalStatus;
import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.AssetId;
import jp.co.soramitsu.iroha2.model.Bool;
import jp.co.soramitsu.iroha2.model.DefinitionId;
import jp.co.soramitsu.iroha2.model.Domain;
import jp.co.soramitsu.iroha2.model.Expression;
import jp.co.soramitsu.iroha2.model.Id;
import jp.co.soramitsu.iroha2.model.Identifiable;
import jp.co.soramitsu.iroha2.model.IdentifiableBox;
import jp.co.soramitsu.iroha2.model.Value;
import jp.co.soramitsu.iroha2.model.WorldId;
import jp.co.soramitsu.iroha2.model.instruction.Burn;
import jp.co.soramitsu.iroha2.model.instruction.Fail;
import jp.co.soramitsu.iroha2.model.instruction.If;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.model.instruction.Mint;
import jp.co.soramitsu.iroha2.model.Raw;
import jp.co.soramitsu.iroha2.model.instruction.Register;
import jp.co.soramitsu.iroha2.model.instruction.Sequence;
import jp.co.soramitsu.iroha2.model.instruction.Transaction;
import jp.co.soramitsu.iroha2.model.U32;
import jp.co.soramitsu.iroha2.model.instruction.Transfer;
import jp.co.soramitsu.iroha2.model.instruction.Unregister;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class InstructionTest {

  // root account keys:
  // priv: 9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e
  // pub:  7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0
  String privateKeyHex = "9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e";
  KeyPair keyPair = Utils.EdDSAKeyPairFromHexPrivateKey(privateKeyHex);
  Iroha2Api api = new Iroha2Api("localhost:8080");

  /**
   * Asserts that transaction with instruction was successfully committed
   */
  private void assertInstructionCommitted(Instruction instruction) {
    Assertions.assertDoesNotThrow(() -> {
      Transaction transaction = new TransactionBuilder()
          .setCreator("root", "global")
          .addInstruction(instruction)
          .build()
          .sign(keyPair)
          .build();

      Future<TerminalStatus> result = api.instructionAsync(transaction);
      Assertions.assertTrue(result.get().isCommitted(), result.get().getMessage());
    });
  }

  /**
   * Asserts that transaction with instruction was rejected
   */
  private void assertInstructionRejected(Instruction instruction, String reason) {
    Assertions.assertDoesNotThrow(() -> {
      Transaction transaction = new TransactionBuilder()
          .setCreator("root", "global")
          .addInstruction(instruction)
          .build()
          .sign(keyPair)
          .build();

      Future<TerminalStatus> result = api.instructionAsync(transaction);
      Assertions.assertFalse(result.get().isCommitted());
      Assertions.assertTrue(result.get().getMessage().contains(reason));
    });
  }


  // Test register/unregister instruction
  @Test
  public void testRegister() {
    Expression object = new Raw(new Value(new Identifiable(new Domain("new test domain"))));
    Expression destination = new Raw(new Value(new Id(new WorldId())));

    Instruction register = new Register(object, destination);
    assertInstructionCommitted(register);

    Instruction unregister = new Unregister(object, destination);
    assertInstructionCommitted(unregister);
  }

  /**
   * Test mint, transfer and burn is committed, balance changed
   */
  @Test
  public void testMint() {
    Expression amount = new Raw(new Value(new U32(100)));
    Expression destination = new Raw(new Value(new Id(
        new AssetId(new DefinitionId("rose", "wonderland"), new AccountId("root", "global")))));

    Mint mint = new Mint(amount, destination);
    assertInstructionCommitted(mint);

    Transfer transfer = new Transfer(destination, amount, destination);
    assertInstructionCommitted(transfer);

    Burn burn = new Burn(amount, destination);
    assertInstructionCommitted(burn);
  }

  /**
   * Test fail instruction
   */
  @Test
  public void testFail() {
    String reason = "test fail reason";
    Fail fail = new Fail(reason);
    assertInstructionRejected(fail, reason);
  }

  /**
   * Test if instruction with false condition and empty else
   */
  @Test
  public void testIf() {
    String reason = "test fail reason";
    Fail fail = new Fail(reason);
    If ifInstruction = new If(new Raw(new Value(new Bool(false))), fail);
    assertInstructionCommitted(ifInstruction);
  }

  /**
   * Test if instruction with false condition and empty else
   */
  @Test
  public void testIfEmptyElse() {
    String reason = "test fail reason";
    Fail fail = new Fail(reason);
    Sequence emptySequence = new Sequence();
    If ifInstruction = new If(new Raw(new Value(new Bool(false))), fail, emptySequence);
    assertInstructionCommitted(ifInstruction);
  }
}
