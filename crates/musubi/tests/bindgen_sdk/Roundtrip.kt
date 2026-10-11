// Compile next to the Sample.kt emitted by bindgen::tests with the actual Kotlin SDK.
import java.math.BigInteger
import org.hyperledger.iroha.sdk.numeric.NumericV1Codec
fun main() {
    val wide = BigInteger.ONE.shiftLeft(200).toString()
    val integer = NumericV1Codec.decodeIntJson(wide)
    val payload = ksampleBindings.T1_kPayload(integer, NumericV1Codec.decodeDecimalJson("1.25"), NumericV1Codec.decodeQuantityJson("2.5"), true, "東京", "0x00ff", mapOf("valid" to true), BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE), ksampleBindings.OptionValue.Some(ksampleBindings.OptionValue.None), ksampleBindings.ResultValue.Err(ksampleBindings.T13_kFailure.v0_kInvalid), listOf(integer), ksampleBindings.T15_kStatus.v1_kComplete, ksampleBindings.T16_kValue(integer, false), "0x00")
    val view = ksampleBindings.entry2_kinspect(ksampleBindings.entry2_kinspectArgs(payload))
    val call = ksampleBindings.entry3_kupdate(ksampleBindings.entry3_kupdateArgs(payload))
    check(view.kind == "View" && call.kind == "Kotoage")
    check(ksampleBindings.entry0_khajimari(ksampleBindings.entry0_khajimariArgs()).kind == "Hajimari")
    check(ksampleBindings.entry1_kkaizen(ksampleBindings.entry1_kkaizenArgs()).kind == "Kaizen")
    val wire = view.payload.getValue("input") as Map<*, *>
    check(wire["amount"] == wide && wire["price"] == "1.25" && wire["total"] == "2.5")
    val decoded = view.decodeResult(wire)
    check(decoded == payload)
    check(ksampleBindings.entry2_kinspect(ksampleBindings.entry2_kinspectArgs(decoded)).payload == view.payload)
    fun reject(value: Any?) { check(runCatching { view.decodeResult(value) }.isFailure) }
    for ((key, value) in listOf("amount" to 1, "amount" to "01", "amount" to BigInteger.ONE.shiftLeft(511).toString(), "status" to "Invented", "pair" to listOf("1"), "items" to listOf("1", "2", "3", "4", "5"), "optional" to mapOf("some" to mapOf("none" to true), "none" to true), "note" to "\uD800", "data" to "0xAA")) reject(wire + (key to value))
    reject(wire + ("extra" to true)); reject(wire.filterKeys { it != "amount" })
    check(runCatching { ksampleBindings.entry2_kinspect(ksampleBindings.entry2_kinspectArgs(payload.copy(f4_knote = "\uD800"))) }.isFailure)
    println("Kotlin generated bindings: wide numerics, nested sums, enums, strict decoding, and kind separation passed")
}
