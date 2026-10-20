// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import Foundation
import CoreImage
import CoreImage.CIFilterBuiltins

/// A rendered symbol, checked against its actual decoded version/ECC and exact text.
struct KagemushaQRRenderedFrame {
  let text: String
  let image: CGImage
  let version: Int
}

/// System-only optical adapter. IRQR framing and monetary authority remain in their owners.
enum KagemushaQRRenderer {
  enum Failure: Error { case text, encoding, roundTrip, capacity }
  static func render(_ text: String) throws -> KagemushaQRRenderedFrame {
    guard (text.hasPrefix("IQR1:") || text.hasPrefix("IAK1:")), text.hasSuffix(":"),
      !text.isEmpty, text.utf8.count <= 700,
      text.utf8.allSatisfy({ (32...90).contains($0) }) else { throw Failure.text }
    let context = CIContext()
    let filter = CIFilter.qrCodeGenerator()
    filter.message = Data(text.utf8)
    filter.correctionLevel = "M"
    guard let symbol = filter.outputImage else { throw Failure.encoding }
    // CoreImage's symbol includes its own border. Add an explicit four-module white margin,
    // then scale by whole modules; display must never interpolate or crop the quiet zone.
    let bounds = symbol.extent.integral.insetBy(dx: -4, dy: -4)
    let white = CIImage(color: CIColor(red: 1, green: 1, blue: 1)).cropped(to: bounds)
    let output = symbol.composited(over: white).transformed(by: CGAffineTransform(scaleX: 6, y: 6))
    guard let image = context.createCGImage(output, from: output.extent),
      let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: context,
        options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else { throw Failure.encoding }
    let features = detector.features(in: CIImage(cgImage: image)).compactMap { $0 as? CIQRCodeFeature }
    guard features.count == 1, features[0].messageString == text,
      let descriptor = features[0].symbolDescriptor,
      descriptor.errorCorrectionLevel == .levelM else { throw Failure.roundTrip }
    guard (1...17).contains(descriptor.symbolVersion) else { throw Failure.capacity }
    return .init(text: text, image: image, version: descriptor.symbolVersion)
  }
}
