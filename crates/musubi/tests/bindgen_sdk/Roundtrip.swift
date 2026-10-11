// Compile next to the Sample.swift emitted by bindgen::tests with the actual Swift SDK.
import Foundation
import IrohaSwift
@main struct BindingRoundtrip {
 static func main() throws {
  typealias B = ksampleBindings
  let wide = "1606938044258990275541962092341162602522202993782792835301376"
  let integer = try KotodamaInt(wide)
  let payload = B.T1_kPayload(f0_kamount: integer, f1_kprice: try KotodamaDecimal("1.25"), f2_ktotal: try KotodamaQuantity("2.5"), f3_kenabled: true, f4_knote: "東京", f5_kdata: "0x00ff", f6_kmetadata: .object(["valid": .bool(true)]), f7_kspace: UInt64.max, f8_koptional: .some(.none), f9_koutcome: .err(.v0_kInvalid), f10_kitems: [integer], f11_kstatus: .v1_kComplete, f12_kpair: B.T16_kValue(item0: integer, item1: false), f13_kcursor: "0x00")
  let view = try B.entry2_kinspect(.init(f0_kinput: payload))
  let call = try B.entry3_kupdate(.init(f0_kinput: payload))
  precondition(view.kind == "View" && call.kind == "Kotoage")
  let activation = try B.entry0_khajimari(.init())
  precondition(activation.kind == "Hajimari")
  let upgrade = try B.entry1_kkaizen(.init())
  precondition(upgrade.kind == "Kaizen")
  guard case let .object(args) = view.payload, case let .object(wire)? = args["input"] else { fatalError("payload") }
  precondition(wire["amount"] == .string(wide) && wire["price"] == .string("1.25") && wire["total"] == .string("2.5"))
  let decoded = try view.decodeResult(.object(wire))
  precondition(decoded.f0_kamount == integer && decoded.f7_kspace == UInt64.max && decoded.f11_kstatus == .v1_kComplete)
  guard case .some(.none) = decoded.f8_koptional else { fatalError("nested Option") }
  let roundtrip = try B.entry2_kinspect(.init(f0_kinput: decoded))
  precondition(roundtrip.payload == view.payload)
  func reject(_ value: ToriiJSONValue) { do { _ = try view.decodeResult(value); fatalError("accepted malformed result") } catch {} }
  for (key, value): (String, ToriiJSONValue) in [("amount", .integer("1")), ("amount", .string("01")), ("status", .string("Invented")), ("pair", .array([.string("1")])), ("items", .array(Array(repeating: .string("1"), count: 5))), ("optional", .object(["some": .object(["none": .bool(true)]), "none": .bool(true)])), ("data", .string("0xAA"))] {
   var invalid = wire; invalid[key] = value; reject(.object(invalid))
  }
  var extra = wire; extra["extra"] = .bool(true); reject(.object(extra))
  var missing = wire; missing.removeValue(forKey: "amount"); reject(.object(missing))
  print("Swift generated bindings: wide numerics, nested sums, enums, strict decoding, and kind separation passed")
 }
}
