// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import XCTest

final class KagemushaQRRendererTests: XCTestCase {
  func testExactAskTextRendersWithActualMDescriptor() throws {
    let text = "IAK1:" + String(repeating: "A", count: 84) + ":"
    let rendered = try KagemushaQRRenderer.render(text)
    XCTAssertEqual(rendered.text, text)
    XCTAssertTrue((1...17).contains(rendered.version))
    XCTAssertGreaterThan(rendered.image.width, 0)
  }
  func testAnimatedShardTextFitsActualSystemRenderer() throws {
    // A full IRQR data/parity frame carries 256 bytes plus 36 framing bytes.
    let text = "IQR1:" + String(repeating: "A", count: 438) + ":"
    let rendered = try KagemushaQRRenderer.render(text)
    XCTAssertTrue((1...17).contains(rendered.version))
  }
  func testStaticCharacterCapNeverOverridesActualRendererCapacity() throws {
    let text = "IQR1:" + String(repeating: "A", count: 694) + ":"
    do { XCTAssertLessThanOrEqual(try KagemushaQRRenderer.render(text).version, 17) }
    catch KagemushaQRRenderer.Failure.capacity { /* Caller selects canonical animated frames. */ }
  }
  func testUnsupportedOrOversizedTextIsRefused() {
    for text in ["", "other:", "IQR1:lowercase:", "IQR1:\n:", "IQR1:" + String(repeating: "A", count: 695) + ":"] {
      XCTAssertThrowsError(try KagemushaQRRenderer.render(text))
    }
  }
}
