import Foundation
import XCTest

@testable import IrohaSwift

final class ToriiUnsignedResponseHardCutTests: XCTestCase {
  func testMultisigResponseHardCutRejectsAliasesAndPhaseSubstitutions() throws {
    let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    let otherAccount = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
    let hash = String(repeating: "a", count: 64)
    let payload = try CanonicalUnsignedTransactionTestSupport.genericPayload(
      authority: account
    )
    let signingMessage = IrohaHash.hash(payload)
    let unsigned: [String: Any] = [
      "ok": true,
      "resolved_multisig_account_id": account,
      "submitted": false,
      "proposal_id": String(repeating: "b", count: 64),
      "instructions_hash": hash,
      "creation_time_ms": 123,
      "fee_payment": authorityFeePaymentObject(),
      "transaction_payload_b64": payload.base64EncodedString(),
      "signing_message_b64": signingMessage.base64EncodedString(),
    ]

    XCTAssertNoThrow(try decodeMultisigResponse(unsigned))
    let unsignedMutations: [(inout [String: Any]) throws -> Void] = [
      { $0["transaction_scaffold_b64"] = "AQ==" },
      { $0["signed_transaction_b64"] = "AQ==" },
      { $0["signing_payload"] = ["payload_base64": "AQ=="] },
      { $0["tx_hash_hex"] = hash },
      { $0.removeValue(forKey: "transaction_payload_b64") },
      { $0.removeValue(forKey: "signing_message_b64") },
      { $0["signing_message_b64"] = Data(repeating: 7, count: 32).base64EncodedString() },
      { $0["transaction_payload_b64"] = "AQI" },
      {
        var trailing = payload
        trailing.append(0)
        $0["transaction_payload_b64"] = trailing.base64EncodedString()
        $0["signing_message_b64"] = IrohaHash.hash(trailing).base64EncodedString()
      },
    ]
    for (index, mutation) in unsignedMutations.enumerated() {
      var candidate = unsigned
      try mutation(&candidate)
      XCTAssertThrowsError(
        try decodeMultisigResponse(candidate),
        "unsigned multisig mutation \(index) must fail"
      )
    }
    let alternateSignerPayload = try CanonicalUnsignedTransactionTestSupport.genericPayload(
      authority: otherAccount
    )
    var alternateSigner = unsigned
    alternateSigner["transaction_payload_b64"] = alternateSignerPayload.base64EncodedString()
    alternateSigner["signing_message_b64"] = IrohaHash.hash(alternateSignerPayload).base64EncodedString()
    XCTAssertNoThrow(try decodeMultisigResponse(alternateSigner))

    let submitted: [String: Any] = [
      "ok": true,
      "resolved_multisig_account_id": account,
      "submitted": true,
      "proposal_id": String(repeating: "b", count: 64),
      "instructions_hash": hash,
      "tx_hash_hex": hash,
      "fee_payment": authorityFeePaymentObject(),
    ]
    XCTAssertNoThrow(try decodeMultisigResponse(submitted))
    for field in ["transaction_payload_b64", "signing_message_b64"] {
      var candidate = submitted
      candidate[field] =
        field == "transaction_payload_b64"
        ? payload.base64EncodedString()
        : signingMessage.base64EncodedString()
      XCTAssertThrowsError(try decodeMultisigResponse(candidate))
    }
    var missingHash = submitted
    missingHash.removeValue(forKey: "tx_hash_hex")
    XCTAssertThrowsError(try decodeMultisigResponse(missingHash))

    var missingFeePayment = unsigned
    missingFeePayment.removeValue(forKey: "fee_payment")
    XCTAssertThrowsError(try decodeMultisigResponse(missingFeePayment))

    var changedFeePayment = unsigned
    changedFeePayment["fee_payment"] = authorityFeePaymentObject(gasLimit: 1)
    XCTAssertThrowsError(try decodeMultisigResponse(changedFeePayment))
  }

  func testMultisigDraftBindsTheSignerRatherThanTheResolvedMultisigAccount() throws {
    let multisigAccount = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    let signerAccount = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
    let hash = String(repeating: "a", count: 64)
    let executable = CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([1])])
    let payload = try CanonicalUnsignedTransactionTestSupport.transactionPayload(
      networkId: TestNetworkIds.canonical,
      authority: signerAccount,
      creationTimeMs: 123,
      executable: executable,
      timeToLiveMs: ToriiMultisigUnsignedTransactionIntent.transactionTtlMs,
      feePayment: .authority(chargeLimits: [], gasLimit: nil)
    )
    let intent = try ToriiMultisigUnsignedTransactionIntent(
      networkId: TestNetworkIds.canonical,
      resolvedMultisigAccountId: multisigAccount,
      proposalId: String(repeating: "b", count: 64),
      instructionsHash: hash,
      executable: executable,
      metadata: [:]
    )
    let response = try decodeMultisigResponse([
      "ok": true,
      "resolved_multisig_account_id": multisigAccount,
      "submitted": false,
      "proposal_id": String(repeating: "b", count: 64),
      "instructions_hash": hash,
      "creation_time_ms": 123,
      "fee_payment": authorityFeePaymentObject(),
      "transaction_payload_b64": payload.base64EncodedString(),
      "signing_message_b64": IrohaHash.hash(payload).base64EncodedString(),
    ])

    XCTAssertNoThrow(
      try response.validatingRequestBindings(
        signerAccountId: signerAccount,
        selector: ToriiMultisigAccountSelector(multisigAccountId: multisigAccount),
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: .authority(chargeLimits: [], gasLimit: nil),
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: intent,
        clientNetworkId: TestNetworkIds.canonical
      )
    )
    XCTAssertThrowsError(
      try response.validatingRequestBindings(
        signerAccountId: multisigAccount,
        selector: ToriiMultisigAccountSelector(multisigAccountId: multisigAccount),
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: .authority(chargeLimits: [], gasLimit: nil),
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: intent,
        clientNetworkId: TestNetworkIds.canonical
      )
    )
  }

  func testMultisigDraftRejectsRehashedIntentSubstitutions() throws {
    let multisigAccount = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    let signerAccount = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
    let hash = String(repeating: "b", count: 64)
    let executable = CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([1])])
    let metadata = ["memo": ToriiJSONValue.string("approved intent")]
    let feePayment = FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
    let intent = try ToriiMultisigUnsignedTransactionIntent(
      networkId: TestNetworkIds.canonical,
      resolvedMultisigAccountId: multisigAccount,
      proposalId: String(repeating: "b", count: 64),
      instructionsHash: hash,
      executable: executable,
      metadata: metadata
    )
    let selector = ToriiMultisigAccountSelector(multisigAccountId: multisigAccount)

    func response(
      networkId: NetworkId? = nil,
      authority: String? = nil,
      executable actualExecutable: Data? = nil,
      timeToLiveMs: UInt64? = ToriiMultisigUnsignedTransactionIntent.transactionTtlMs,
      nonce: UInt32? = nil,
      metadata actualMetadata: [String: ToriiJSONValue]? = nil,
      feePayment actualFeePayment: FeePaymentIntent? = nil,
      instructionsHash actualInstructionsHash: String? = nil,
      retiredAdmissionTag: UInt32? = nil
    ) throws -> ToriiMultisigContractCallResponse {
      let responseFeePayment = actualFeePayment ?? feePayment
      let responseInstructionsHash = actualInstructionsHash ?? hash
      let payload = try CanonicalUnsignedTransactionTestSupport.transactionPayload(
        networkId: networkId ?? TestNetworkIds.canonical,
        authority: authority ?? signerAccount,
        creationTimeMs: 123,
        executable: actualExecutable ?? executable,
        timeToLiveMs: timeToLiveMs,
        nonce: nonce,
        feePayment: responseFeePayment,
        retiredAdmissionTag: retiredAdmissionTag,
        metadata: actualMetadata ?? metadata
      )
      return try decodeMultisigResponse([
        "ok": true,
        "resolved_multisig_account_id": multisigAccount,
        "submitted": false,
        "proposal_id": String(repeating: "b", count: 64),
        "instructions_hash": responseInstructionsHash,
        "creation_time_ms": 123,
        "fee_payment": try feePaymentObject(responseFeePayment),
        "transaction_payload_b64": payload.base64EncodedString(),
        "signing_message_b64": IrohaHash.hash(payload).base64EncodedString(),
      ])
    }

    func validate(_ response: ToriiMultisigContractCallResponse) throws {
      _ = try response.validatingRequestBindings(
        signerAccountId: signerAccount,
        selector: selector,
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: feePayment,
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: intent,
        clientNetworkId: TestNetworkIds.canonical
      )
    }

    XCTAssertNoThrow(try validate(response()))
    let enrichedFeePayment = FeePaymentIntent.authority(
      chargeLimits: [
        try FeeChargeLimit(
          kind: .nexus,
          assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
          maxAmount: "1"
        )
      ],
      gasLimit: nil
    )
    XCTAssertNoThrow(try validate(response(feePayment: enrichedFeePayment)))
    let substitutions = try [
      response(networkId: TestNetworkIds.other),
      response(authority: multisigAccount),
      response(
        executable: CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([2])])
      ),
      response(timeToLiveMs: 99_999),
      response(nonce: 1),
      response(metadata: ["memo": .string("changed")]),
      response(metadata: metadata.merging(["extra": .bool(true)]) { _, new in new }),
      response(feePayment: .authority(chargeLimits: [], gasLimit: 1)),
      response(instructionsHash: String(repeating: "c", count: 64)),
    ]
    for (index, substitution) in substitutions.enumerated() {
      XCTAssertThrowsError(
        try validate(substitution),
        "rehash substitution \(index) must not reach a signer"
      )
    }
    for tag: UInt32 in [0, 1, 2] {
      XCTAssertThrowsError(try response(retiredAdmissionTag: tag))
    }
    XCTAssertThrowsError(
      try response().validatingRequestBindings(
        signerAccountId: signerAccount,
        selector: selector,
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: feePayment,
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: nil,
        clientNetworkId: TestNetworkIds.canonical
      )
    )
    XCTAssertThrowsError(
      try response().validatingRequestBindings(
        signerAccountId: signerAccount,
        selector: selector,
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: feePayment,
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: intent,
        clientNetworkId: TestNetworkIds.other
      )
    )
    XCTAssertThrowsError(
      try response().validatingRequestBindings(
        signerAccountId: signerAccount,
        selector: selector,
        requestedProposalId: String(repeating: "b", count: 64),
        requestedFeePayment: feePayment,
        requestedCreationTimeMs: 123,
        unsignedTransactionIntent: intent,
        clientNetworkId: nil
      )
    )
  }

  func testMultisigResponsesRejectNonExactResolvedAccountIds() {
    let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    let paddedAccountId = "\(accountId) "
    let proposalId = String(repeating: "f", count: 64)
    func data(_ body: String) -> Data {
      body.data(using: .utf8)!
    }

    XCTAssertThrowsError(
      try JSONDecoder().decode(
        ToriiMultisigContractCallResponse.self,
        from: data(#"{"ok":true,"resolved_multisig_account_id":"\#(paddedAccountId)"}"#)
      )
    )
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        ToriiMultisigSpecResponse.self,
        from: data(#"{"resolved_multisig_account_id":"\#(paddedAccountId)","spec":{"quorum":2}}"#)
      )
    )
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        ToriiMultisigProposalsQueryResponse.self,
        from: data(#"{"resolved_multisig_account_id":"\#(paddedAccountId)","proposals":[]}"#)
      )
    )
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        ToriiMultisigProposalResolveResponse.self,
        from: data(
          #"{"resolved_multisig_account_id":"\#(paddedAccountId)","proposal_id":"\#(proposalId)","instructions_hash":"\#(proposalId)","proposal":{"approvals":[]}}"#
        )
      )
    )
  }

  private func decodeMultisigResponse(
    _ object: [String: Any]
  ) throws -> ToriiMultisigContractCallResponse {
    try JSONDecoder().decode(
      ToriiMultisigContractCallResponse.self,
      from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    )
  }

  private func authorityFeePaymentObject(gasLimit: UInt64? = nil) -> [String: Any] {
    [
      "payer": "authority",
      "value": [
        "charge_limits": [],
        "gas_limit": gasLimit.map { NSNumber(value: $0) } ?? NSNull(),
      ],
    ]
  }

  private func feePaymentObject(_ feePayment: FeePaymentIntent) throws -> [String: Any] {
    try XCTUnwrap(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(feePayment)) as? [String: Any]
    )
  }
}
