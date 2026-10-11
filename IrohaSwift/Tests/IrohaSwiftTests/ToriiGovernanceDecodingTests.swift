import CryptoKit
import XCTest
@testable import IrohaSwift

final class ToriiGovernanceDecodingTests: XCTestCase {
    private static let governanceOwner =
        "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    private static let payoutAccounts = [
        "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
        "sorauﾛ1PULｦnUPﾀZ7ﾘﾕｻ2oｿSTfKｷﾋﾌﾀnTwEZヱVﾏｱﾐLZﾒZｾNVE5DS",
        "sorauﾛ1Prﾇuﾉﾉ4ﾒdﾛﾑｲﾄn5tﾆﾒrsR9ﾋ2Gｷ7gWeFzyﾁﾋﾁAHﾌTJQQ4L",
        "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY",
        "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7",
    ]
    private static let contractAddress =
        "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
    private static let canonicalCustodyJSON = """
    {"escrowed":true,"asset_definition_id":"5dHF5UNffENuEg9mhjYwY1jcZ1K5","bond_escrow_account":"bond-escrow-account","slash_receiver_account":"slash-receiver-account"}
    """

    private func governanceLockJSON(
        amountJSON: String = "\"1\"",
        slashedJSON: String = "\"0\"",
        custodyJSON: String? = "null"
    ) -> Data {
        let custodyField = custodyJSON.map { ",\"custody\":\($0)" } ?? ""
        return Data(
            """
            {"owner":"\(Self.governanceOwner)","amount":\(amountJSON),"slashed":\(slashedJSON),"expiry_height":10,"direction":1,"duration_blocks":5\(custodyField)}
            """.utf8
        )
    }

    private func fixedBytes(_ value: UInt8, count: Int = 32) -> String {
        "[" + Array(repeating: String(value), count: count).joined(separator: ",") + "]"
    }

    private func ed25519Signer(_ seed: UInt8) throws -> String {
        let key = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: seed, count: 32)
        ).publicKey.rawRepresentation
        return CanonicalNorito.publicKeyMultihash(algorithm: .ed25519, payload: key)
    }

    private func proposalKindJSON(kind: String, payload: String) -> Data {
        Data("{\"kind\":\"\(kind)\",\"payload\":\(payload)}".utf8)
    }

    private func sccpGovernanceProposalJSON() -> String {
        """
        {"network_id":"\(TestNetworkIds.canonical.literal)","base_revisions":[{"subject":{"subject":"route","key":{"network":"bsc_mainnet","profile":null}},"revision":1}],"actions":[{"action":"remove_staged","payload":{"network":{"network":"bsc_mainnet","profile":null},"revision":1}}]}
        """
    }

    private func payoutBindingJSON() -> String {
        let providers=Self.payoutAccounts.map { "\"\($0)\"" }.joined(separator:",")
        return """
        {"contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating:"AB",count:32))","entrypoint":"autonomous_validation_fee_tick","treasury_account_id":"\(Self.governanceOwner)","ds_asset_id":"5dHF5UNffENuEg9mhjYwY1jcZ1K5","xor_asset_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","pool_contract_address":"\(Self.contractAddress)","pool_code_hash":"\(String(repeating:"CD",count:32))","pool_vault_account_id":"\(Self.payoutAccounts[0])","reward_pool_account_id":"\(Self.payoutAccounts[1])","reference_feed_id":["sbd_xor"],"reference_feed_config_version":1,"reference_provider_accounts":[\(providers)],"max_sbd_per_attempt_minor":1000,"max_sbd_per_day_minor":100000,"min_interval_ms":60000,"max_source_age_ms":300000,"max_slippage_bps":100,"validator_lane_id":1,"min_reward_claim_xor_minor":1}
        """
    }

    func testGovernanceLockRecordAcceptsCanonicalFractionAboveUInt64() throws {
        let json = governanceLockJSON(
            amountJSON: "\"18446744073709551616.25\"",
            slashedJSON: "\"0.25\"",
            custodyJSON: Self.canonicalCustodyJSON
        )
        let record = try JSONDecoder().decode(ToriiGovernanceLockRecord.self, from: json)
        XCTAssertEqual(record.amount, "18446744073709551616.25")
        XCTAssertEqual(record.slashed, "0.25")
        XCTAssertEqual(record.custody?.escrowed, true)
        XCTAssertEqual(record.custody?.assetDefinitionId, "5dHF5UNffENuEg9mhjYwY1jcZ1K5")
        XCTAssertEqual(record.custody?.bondEscrowAccount, "bond-escrow-account")
        XCTAssertEqual(record.custody?.slashReceiverAccount, "slash-receiver-account")
    }

    func testGovernanceLockRecordRejectsNumericJSONAmount() {
        for amount in ["1", "1.5", "-1"] {
            let json = governanceLockJSON(amountJSON: amount)

            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceLockRecord.self, from: json),
                "numeric JSON amount \(amount) must be rejected"
            )
        }
    }

    func testGovernanceLockRecordRejectsNoncanonicalQuantityStrings() {
        let overflowing = String(repeating: "9", count: 155)
        for amount in ["+1", "01", "1.0", "1.2300", " 1", "1 ", "-1", overflowing] {
            let json = governanceLockJSON(amountJSON: "\"\(amount)\"")

            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceLockRecord.self, from: json),
                "noncanonical amount \(amount) must be rejected"
            )
        }
    }

    func testGovernanceLockRecordRejectsNoncanonicalSlashedQuantity() {
        let overflowing = String(repeating: "9", count: 155)
        for encoded in [
            "1",
            "\"+1\"",
            "\"01\"",
            "\"1.0\"",
            "\" 1\"",
            "\"-1\"",
            "\"\(overflowing)\"",
        ] {
            let json = governanceLockJSON(slashedJSON: encoded)

            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceLockRecord.self, from: json)
            )
        }
    }

    func testGovernanceLockRecordAcceptsExplicitNullCustody() throws {
        let record = try JSONDecoder().decode(
            ToriiGovernanceLockRecord.self,
            from: governanceLockJSON(custodyJSON: "null")
        )
        XCTAssertNil(record.custody)
    }

    func testGovernanceLockRecordRejectsMissingCustody() {
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiGovernanceLockRecord.self,
                from: governanceLockJSON(custodyJSON: nil)
            )
        )
    }

    func testGovernanceLockRecordRejectsMissingOrExtraCustodyFields() {
        for custodyJSON in [
            """
            {"escrowed":true,"asset_definition_id":"asset","bond_escrow_account":"escrow"}
            """,
            """
            {"escrowed":true,"asset_definition_id":"asset","bond_escrow_account":"escrow","slash_receiver_account":"slash","asset_id":"retired"}
            """,
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceLockRecord.self,
                    from: governanceLockJSON(custodyJSON: custodyJSON)
                )
            )
        }
    }

    func testGovernanceLockRecordRejectsWrongCustodyFieldTypes() {
        for custodyJSON in [
            """
            {"escrowed":"true","asset_definition_id":"asset","bond_escrow_account":"escrow","slash_receiver_account":"slash"}
            """,
            """
            {"escrowed":true,"asset_definition_id":1,"bond_escrow_account":"escrow","slash_receiver_account":"slash"}
            """,
            """
            {"escrowed":true,"asset_definition_id":"asset","bond_escrow_account":false,"slash_receiver_account":"slash"}
            """,
            """
            {"escrowed":true,"asset_definition_id":"asset","bond_escrow_account":"escrow","slash_receiver_account":[]}
            """,
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceLockRecord.self,
                    from: governanceLockJSON(custodyJSON: custodyJSON)
                )
            )
        }
    }

    func testGovernanceTallyRejectsFloatFields() {
        let json = """
        {"referendum_id":"ref-1","approve":1.5,"reject":"2","abstain":"3"}
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(ToriiGovernanceTallyResponse.self, from: json))
    }

    func testGovernanceProposalKindRejectsRetiredKagemushaVariants() {
        for kind in [
            "KagemushaVerifierPolicyInstall",
            "KagemushaVerifierReleaseInstall",
            "KagemushaVerifierReleaseActivate",
            "KagemushaVerifierReleaseRetire",
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(
                ToriiGovernanceProposalKind.self,
                from: proposalKindJSON(kind: kind, payload: "{}")
            ))
        }
    }

    func testGovernanceProposalKindDecodesExistingV1Variants() throws {
        let deploy = proposalKindJSON(
            kind: "DeployContract",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}
            """
        )
        guard case .deployContract(let deployPayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: deploy
        ) else { return XCTFail("expected DeployContract") }
        XCTAssertEqual(deployPayload.proposalOperator, Self.governanceOwner)
        XCTAssertEqual(deployPayload.codeHash, Data(repeating: 0x11, count: 32))

        let runtime = proposalKindJSON(
            kind: "RuntimeUpgrade",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","manifest":{"name":"runtime-v1","description":"upgrade","abi_version":1,"abi_hash":\(fixedBytes(3)),"added_syscalls":[],"added_pointer_types":[],"start_height":10,"end_height":20,"sbom_digests":[],"slsa_attestation":"","provenance":[]}}
            """
        )
        guard case .runtimeUpgrade(let runtimePayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: runtime
        ) else { return XCTFail("expected RuntimeUpgrade") }
        XCTAssertEqual(runtimePayload.proposalOperator, Self.governanceOwner)
        XCTAssertEqual(runtimePayload.manifest.endHeight, 20)

        let sccp = proposalKindJSON(
            kind: "SccpRouteGovernance",
            payload: "{\"proposal\":\(sccpGovernanceProposalJSON())}"
        )
        guard case .sccpRouteGovernance(let sccpPayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: sccp
        ), case .object(let sccpProposal) = sccpPayload.proposal else {
            return XCTFail("expected SccpRouteGovernance proposal")
        }
        XCTAssertEqual(sccpProposal["network_id"], .string(TestNetworkIds.canonical.literal))

        let policy = proposalKindJSON(
            kind: "ValidationFeePolicy",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","policy":{"schema_version":1,"network_id":"\(TestNetworkIds.canonical.literal)","policy_version":"1","previous_policy_hash":null,"ds_asset_id":"5dHF5UNffENuEg9mhjYwY1jcZ1K5","ds_scale":2,"retail_schedule":{"included_payments":50,"overage_minor":10,"maintenance_tiers":[{"minimum_average_balance_minor":0,"monthly_fee_minor":100},{"minimum_average_balance_minor":50000,"monthly_fee_minor":200}]},"effective_from_ms":1788181200000,"notice_published_at_ms":1785502800000,"fee":"0.1","treasury_account_id":"\(Self.governanceOwner)","charging_mode":{"charging_mode":"RETAIL_MONTHLY_ALLOWANCE","value":null},"exemption_classes":["TREASURY_PAYOUT"],"reward_custody":{"contract_address":"\(Self.contractAddress)","treasury_account_id":"\(Self.governanceOwner)","ds_asset_id":"5dHF5UNffENuEg9mhjYwY1jcZ1K5","xor_asset_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","reward_pool_account_id":"\(Self.payoutAccounts[1])","validator_lane_id":1}}}
            """
        )
        guard case .validationFeePolicy(let policyPayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: policy
        ) else { return XCTFail("expected ValidationFeePolicy") }
        XCTAssertEqual(policyPayload.policy.fee, "0.1")
        XCTAssertEqual(policyPayload.policy.retailSchedule.includedPayments, 50)

        let lifecycle = proposalKindJSON(
            kind: "ValidationFeePayoutLifecycle",
            payload: "{\"proposal_operator\":\"\(Self.governanceOwner)\",\"payout_binding\":\(payoutBindingJSON())}"
        )
        guard case .validationFeePayoutLifecycle(let lifecyclePayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: lifecycle
        ) else { return XCTFail("expected ValidationFeePayoutLifecycle") }
        XCTAssertEqual(lifecyclePayload.payoutBinding.referenceProviderAccounts.count, 5)

        let musubi = proposalKindJSON(
            kind: "MusubiRegistryGovernance",
            payload: """
            {"kind":"RetargetAlias","value":{"alias":["demo"],"target":{"home_dataspace":1,"scope":{"kind":"DataspaceRoot","value":null},"name":["demo-package"]},"expected_revision":1}}
            """
        )
        guard case .musubiRegistryGovernance(let musubiPayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: musubi
        ), case .retargetAlias(let action) = musubiPayload else {
            return XCTFail("expected Musubi RetargetAlias")
        }
        XCTAssertEqual(action.alias.value, "demo")

        let sorafs = proposalKindJSON(
            kind: "SorafsProviderGovernance",
            payload: """
            {"action":{"action":"establish","value":{"provider_id":[\(fixedBytes(9))],"owner":"\(Self.governanceOwner)"}}}
            """
        )
        guard case .sorafsProviderGovernance(let sorafsPayload) = try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: sorafs
        ), case .establish(let action) = sorafsPayload.action else {
            return XCTFail("expected SoraFS establish")
        }
        XCTAssertEqual(action.providerId.bytes, Data(repeating: 9, count: 32))

        let contractLifecycle = proposalKindJSON(
            kind: "ContractLifecycleGovernance",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","contract_address":"\(Self.contractAddress)","expected_revision":1,"action":{"action":"CompleteEmergencyHoldRetrospective","payload":{"hold_proposal_content_id":\(fixedBytes(17)),"hold_governance_attempt_id":\(fixedBytes(34)),"incident_digest":\(fixedBytes(51)),"retrospective_finding_root":\(fixedBytes(68))}}}
            """
        )
        guard case .contractLifecycleGovernance(let contractLifecyclePayload) =
            try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: contractLifecycle),
            case .completeEmergencyHoldRetrospective(let retrospective) =
                contractLifecyclePayload.action else {
            return XCTFail("expected contract emergency-hold retrospective")
        }
        XCTAssertEqual(contractLifecyclePayload.proposalOperator, Self.governanceOwner)
        XCTAssertEqual(retrospective.holdProposalContentId, Data(repeating: 17, count: 32))
        XCTAssertEqual(retrospective.holdGovernanceAttemptId, Data(repeating: 34, count: 32))
        XCTAssertEqual(retrospective.incidentDigest, Data(repeating: 51, count: 32))
        XCTAssertEqual(retrospective.retrospectiveFindingRoot, Data(repeating: 68, count: 32))

        let emergencyHold = proposalKindJSON(
            kind: "ContractEmergencyHold",
            payload: """
            {"contract_address":"\(Self.contractAddress)","expected_revision":2,"expected_code_hash":"\(String(repeating: "ab", count: 32))","incident_digest":\(fixedBytes(85)),"reason":"contain compromised entrypoint","duration_blocks":3600}
            """
        )
        guard case .contractEmergencyHold(let emergencyHoldPayload) =
            try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: emergencyHold) else {
            return XCTFail("expected ContractEmergencyHold")
        }
        XCTAssertEqual(emergencyHoldPayload.expectedRevision, 2)
        XCTAssertEqual(emergencyHoldPayload.expectedCodeHash, Data(repeating: 0xab, count: 32))
        XCTAssertEqual(emergencyHoldPayload.incidentDigest, Data(repeating: 85, count: 32))
        XCTAssertEqual(emergencyHoldPayload.durationBlocks, 3_600)

        let triggerPermission = proposalKindJSON(
            kind: "GlobalDataTriggerPermissionGovernance",
            payload: """
            {"authority":"\(Self.governanceOwner)","action":{"action":"grant","value":null}}
            """
        )
        guard case .globalDataTriggerPermissionGovernance(let triggerPermissionPayload) =
            try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: triggerPermission) else {
            return XCTFail("expected GlobalDataTriggerPermissionGovernance")
        }
        XCTAssertEqual(triggerPermissionPayload.authority, Self.governanceOwner)
        XCTAssertEqual(triggerPermissionPayload.action, .grant)
    }

    func testGovernancePublicKeyOrderAcceptsOnlyCanonicalMultihashes() throws {
        let first = try ed25519Signer(1)
        let second = try ed25519Signer(2)
        let firstOrder = try governancePublicKeyOrderV1(first, codingPath: [])
        let secondOrder = try governancePublicKeyOrderV1(second, codingPath: [])
        XCTAssertEqual(firstOrder, try governancePublicKeyOrderV1(first, codingPath: []))
        XCTAssertNotEqual(firstOrder, secondOrder)
        XCTAssertEqual(firstOrder < secondOrder, first < second)

        for malformed in [
            first.lowercased(),
            "ed25519:\(first)",
            "ed0120" + String(repeating: "00", count: 32),
            "ed0121" + String(repeating: "11", count: 32),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .secp256k1, payload: Data(repeating: 1, count: 32)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .blsNormal, payload: Data(repeating: 1, count: 47)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .blsSmall, payload: Data(repeating: 1, count: 95)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .mlDsa, payload: Data(repeating: 1, count: 1_951)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .gost2012_256A, payload: Data(repeating: 1, count: 63)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .sm2, payload: Data(repeating: 1, count: 64)
            ),
            CanonicalNorito.publicKeyMultihash(
                algorithm: .sm2, payload: Data([0x04] + Array(repeating: 1, count: 64))
            ),
        ] {
            XCTAssertThrowsError(try governancePublicKeyOrderV1(malformed, codingPath: []), malformed)
        }
    }

    func testGlobalDataTriggerPermissionRequiresCanonicalAccountAndClosedUnitAction() throws {
        for action in ["grant", "revoke"] {
            let proposal = proposalKindJSON(
                kind: "GlobalDataTriggerPermissionGovernance",
                payload: """
                {"authority":"\(Self.governanceOwner)","action":{"action":"\(action)","value":null}}
                """
            )
            XCTAssertNoThrow(
                try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: proposal)
            )
        }

        for payload in [
            "{\"authority\":\"\(Self.governanceOwner)\",\"action\":{\"action\":\"grant\"}}",
            "{\"authority\":\"\(Self.governanceOwner)\",\"action\":{\"action\":\"grant\",\"value\":{}}}",
            "{\"authority\":\"\(Self.governanceOwner)\",\"action\":{\"action\":\"delegate\",\"value\":null}}",
            "{\"authority\":\"alice@wonderland\",\"action\":{\"action\":\"grant\",\"value\":null}}",
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceProposalKind.self,
                    from: proposalKindJSON(
                        kind: "GlobalDataTriggerPermissionGovernance",
                        payload: payload
                    )
                )
            )
        }
    }

    func testContractLifecycleActionInventoryUsesCanonicalPayloadShapes() throws {
        let actionPayloads = [
            """
            {"action":"Activate","payload":{"code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}}
            """,
            """
            {"action":"Deactivate","payload":{"expected_code_hash":"\(String(repeating: "33", count: 32))","reason":null}}
            """,
            """
            {"action":"OfferOwnership","payload":{"new_owner":"\(Self.governanceOwner)"}}
            """,
            "{\"action\":\"CancelOwnershipOffer\",\"payload\":null}",
            "{\"action\":\"AcceptParliamentOwnership\",\"payload\":null}",
            """
            {"action":"CompleteEmergencyHoldRetrospective","payload":{"hold_proposal_content_id":\(fixedBytes(17)),"hold_governance_attempt_id":\(fixedBytes(34)),"incident_digest":\(fixedBytes(51)),"retrospective_finding_root":\(fixedBytes(68))}}
            """,
        ]
        let actionTags = try actionPayloads.map { payload in
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any]
            )
            return try XCTUnwrap(object["action"] as? String)
        }
        XCTAssertEqual(actionTags, ToriiParliamentAPIV1.contractLifecycleActions)
        for payload in actionPayloads {
            XCTAssertNoThrow(
                try JSONDecoder().decode(
                    ToriiGovernanceContractLifecycleActionV1.self,
                    from: Data(payload.utf8)
                )
            )
        }

        let zeroRoot = fixedBytes(0)
        let invalidActions = [
            "{\"action\":\"CancelOwnershipOffer\"}",
            "{\"action\":\"AcceptParliamentOwnership\",\"payload\":{}}",
            "{\"action\":\"LegacyActivate\",\"payload\":null}",
            """
            {"action":"Activate","payload":{"code_hash":"\(String(repeating: "AA", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}}
            """,
            """
            {"action":"CompleteEmergencyHoldRetrospective","payload":{"hold_proposal_content_id":\(fixedBytes(17)),"hold_governance_attempt_id":\(fixedBytes(34)),"incident_digest":\(fixedBytes(51)),"retrospective_finding_root":\(zeroRoot)}}
            """,
        ]
        for payload in invalidActions {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceContractLifecycleActionV1.self,
                    from: Data(payload.utf8)
                )
            )
        }
    }

    func testContractEmergencyHoldRejectsInvalidContainmentFields() {
        let validPrefix =
            "{\"kind\":\"ContractEmergencyHold\",\"payload\":{\"contract_address\":\"\(Self.contractAddress)\",\"expected_revision\":1,\"expected_code_hash\":\"\(String(repeating: "11", count: 32))\",\"incident_digest\":\(fixedBytes(7)),"
        for suffix in [
            "\"reason\":\"   \",\"duration_blocks\":1}}",
            "\"reason\":\"containment\",\"duration_blocks\":0}}",
            "\"reason\":\"containment\",\"duration_blocks\":3601}}",
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceProposalKind.self,
                    from: Data((validPrefix + suffix).utf8)
                )
            )
        }
    }

    func testSccpRouteGovernancePayloadIsAnExactProposalWrapper() throws {
        let proposal = sccpGovernanceProposalJSON()
        XCTAssertNoThrow(
            try ToriiParliamentProposalV1(
                validating: proposalKindJSON(
                    kind: "SccpRouteGovernance",
                    payload: "{\"proposal\":\(proposal)}"
                )
            )
        )
        for payload in [
            "{}",
            "{\"proposal\":\(proposal),\"network_id\":\"\(TestNetworkIds.canonical.literal)\"}",
            "{\"anchor\":\(proposal)}",
            "{\"proposal\":[\(proposal)]}",
            "{\"proposal\":null}",
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceProposalKind.self,
                    from: proposalKindJSON(kind: "SccpRouteGovernance", payload: payload)
                ),
                payload
            )
        }
    }

    private static let sccpBscRouteSubject =
        #"{"subject":"route","key":{"network":"bsc_mainnet","profile":null}}"#
    private static let sccpRemoveStagedAction =
        #"{"action":"remove_staged","payload":{"network":{"network":"bsc_mainnet","profile":null},"revision":1}}"#

    /// One `SccpGovernanceProposalV1` body with a single base revision unless overridden.
    private func sccpProposalBody(
        networkId: String? = nil,
        subject: String = ToriiGovernanceDecodingTests.sccpBscRouteSubject,
        revision: String = "1",
        baseRevisions: String? = nil,
        actions: String? = nil,
        extra: String = ""
    ) -> String {
        let network = networkId ?? "\"\(TestNetworkIds.canonical.literal)\""
        let base = baseRevisions ?? "[{\"subject\":\(subject),\"revision\":\(revision)}]"
        let actionList = actions ?? "[\(Self.sccpRemoveStagedAction)]"
        return "{\"network_id\":\(network),\"base_revisions\":\(base),\"actions\":\(actionList)\(extra)}"
    }

    private func decodeSccpRouteProposal(_ proposal: String) throws -> ToriiGovernanceProposalKind {
        try JSONDecoder().decode(
            ToriiGovernanceProposalKind.self,
            from: proposalKindJSON(
                kind: "SccpRouteGovernance",
                payload: "{\"proposal\":\(proposal)}"
            )
        )
    }

    func testSccpRouteGovernanceChecksTheClosedProposalEnvelope() throws {
        let bscRoute = Self.sccpBscRouteSubject
        let removeStaged = Self.sccpRemoveStagedAction
        let blsValidator = "ea0130" + String(repeating: "A1", count: 48)

        // Only the envelope is checked here; whether `base_revisions` lists exactly the
        // subjects the actions touch stays with Torii until typed action decoding lands.
        for accepted in [
            sccpProposalBody(),
            sccpProposalBody(subject: #"{"subject":"route_control","key":{"network":"ethereum_mainnet","profile":null}}"#),
            sccpProposalBody(subject: #"{"subject":"light_client","key":{"network":"ton_mainnet","profile":null}}"#),
            sccpProposalBody(subject: #"{"subject":"parameters","key":null}"#, revision: "0"),
            sccpProposalBody(subject: "{\"subject\":\"bridge_key_fault\",\"key\":\"\(blsValidator)\"}"),
            sccpProposalBody(actions: "[" + Array(repeating: removeStaged, count: 16).joined(separator: ",") + "]"),
        ] {
            XCTAssertNoThrow(try decodeSccpRouteProposal(accepted), accepted)
        }
        let tronLightClient = sccpProposalBody(
            subject: #"{"subject":"light_client","key":{"network":"tron_mainnet","profile":null}}"#
        )
        XCTAssertNoThrow(
            try ToriiParliamentProposalV1(
                validating: proposalKindJSON(
                    kind: "SccpRouteGovernance",
                    payload: "{\"proposal\":\(tronLightClient)}"
                )
            )
        )

        for rejected in [
            "{}",
            sccpProposalBody(extra: ",\"memo\":null"),
            sccpProposalBody(networkId: "\"sora\""),
            sccpProposalBody(networkId: "1"),
            sccpProposalBody(baseRevisions: "[]"),
            sccpProposalBody(baseRevisions: "[" + Array(repeating: "{\"subject\":\(bscRoute),\"revision\":1}", count: 17)
                .joined(separator: ",") + "]"),
            sccpProposalBody(baseRevisions: "[{\"subject\":\(bscRoute),\"revision\":1,\"extra\":0}]"),
            sccpProposalBody(revision: "\"1\""),
            sccpProposalBody(revision: "9007199254740992"),
            sccpProposalBody(subject: #"{"subject":"unknown","key":null}"#),
            sccpProposalBody(subject: #"{"subject":"parameters","key":{"network":"bsc_mainnet","profile":null}}"#),
            sccpProposalBody(subject: #"{"subject":"route","key":{"network":"sora","profile":null}}"#),
            sccpProposalBody(subject: #"{"subject":"route","key":{"network":"solana_mainnet","profile":null}}"#),
            sccpProposalBody(subject: #"{"subject":"route","key":{"network":"bsc_mainnet","profile":"default"}}"#),
            sccpProposalBody(subject: #"{"subject":"route","key":{"network":"bsc_mainnet"}}"#),
            sccpProposalBody(subject: #"{"subject":"route","key":null}"#),
            sccpProposalBody(subject: "{\"subject\":\"bridge_key_fault\",\"key\":\"\(blsValidator.lowercased())\"}"),
            sccpProposalBody(subject: #"{"subject":"bridge_key_fault","key":"ea0130"}"#),
            sccpProposalBody(actions: "[]"),
            sccpProposalBody(actions: "[" + Array(repeating: removeStaged, count: 17).joined(separator: ",") + "]"),
            sccpProposalBody(actions: #"[{"action":"unknown","payload":{}}]"#),
            sccpProposalBody(actions: #"[{"action":"remove_staged","payload":[]}]"#),
            sccpProposalBody(actions: #"[{"action":"remove_staged","payload":{},"memo":null}]"#),
        ] {
            XCTAssertThrowsError(try decodeSccpRouteProposal(rejected), rejected)
        }
    }

    func testGovernanceProposalKindRejectsUnknownAndRetiredShapes() {
        let unknown = proposalKindJSON(kind: "EnactReferendum", payload: "{}")
        let oldSingleKey = Data(
            "{\"DeployContract\":{\"contract_address\":\"\(Self.contractAddress)\"}}".utf8
        )
        let legacyDeploy = proposalKindJSON(
            kind: "DeployContract",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","contract_address":"\(Self.contractAddress)","code_hash_hex":"\(String(repeating: "11", count: 32))","abi_hash_hex":"\(String(repeating: "22", count: 32))","abi_version":"1","manifest_provenance":null}
            """
        )
        let missingProvenance = proposalKindJSON(
            kind: "DeployContract",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1}
            """
        )
        let missingOperator = proposalKindJSON(
            kind: "DeployContract",
            payload: """
            {"contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}
            """
        )
        let malformedOperator = proposalKindJSON(
            kind: "ContractLifecycleGovernance",
            payload: """
            {"proposal_operator":"not-an-account","contract_address":"\(Self.contractAddress)","expected_revision":1,"action":{"action":"AcceptParliamentOwnership","payload":null}}
            """
        )
        let runtimeWithImplicitDefaults = proposalKindJSON(
            kind: "RuntimeUpgrade",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","manifest":{"name":"runtime-v1","description":"upgrade","abi_version":1,"abi_hash":\(fixedBytes(3)),"added_syscalls":[],"added_pointer_types":[],"start_height":10,"end_height":20}}
            """
        )
        let runtimeBeyondExactJSON = proposalKindJSON(
            kind: "RuntimeUpgrade",
            payload: """
            {"proposal_operator":"\(Self.governanceOwner)","manifest":{"name":"runtime-v1","description":"upgrade","abi_version":1,"abi_hash":\(fixedBytes(3)),"added_syscalls":[],"added_pointer_types":[],"start_height":9007199254740992,"end_height":9007199254740993,"sbom_digests":[],"slsa_attestation":"","provenance":[]}}
            """
        )
        for json in [
            unknown,
            oldSingleKey,
            legacyDeploy,
            missingProvenance,
            missingOperator,
            malformedOperator,
            runtimeWithImplicitDefaults,
            runtimeBeyondExactJSON,
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: json)
            )
        }
    }

    func testGovernanceProposalNestedActionsRejectUnknownTags() {
        let musubi = proposalKindJSON(
            kind: "MusubiRegistryGovernance",
            payload: "{\"kind\":\"Unknown\",\"value\":{}}"
        )
        let sorafs = proposalKindJSON(
            kind: "SorafsProviderGovernance",
            payload: "{\"action\":{\"action\":\"replace\",\"value\":{}}}"
        )
        for json in [musubi, sorafs] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceProposalKind.self, from: json)
            )
        }
    }

    func testGovernanceProposalRecordIsExactAndStatusesAreClosed() throws {
        let kind = """
        {"kind":"DeployContract","payload":{"proposal_operator":"\(Self.governanceOwner)","contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}}
        """
        for status in ["Proposed", "Rejected", "Enacted", "Superseded", "ExecutionFailed"] {
            let data = Data(
                "{\"proposer\":\"\(Self.governanceOwner)\",\"kind\":\(kind),\"created_height\":1,\"status\":\"\(status)\"}".utf8
            )
            XCTAssertNoThrow(
                try JSONDecoder().decode(ToriiGovernanceProposalRecord.self, from: data)
            )
        }
        for retired in [
            "{\"proposer\":\"\(Self.governanceOwner)\",\"kind\":\(kind),\"created_height\":1,\"status\":\"Approved\"}",
            "{\"proposer\":\"\(Self.governanceOwner)\",\"kind\":\(kind),\"created_height\":1}",
            "{\"proposer\":\"\(Self.governanceOwner)\",\"kind\":\(kind),\"created_height\":1,\"status\":\"Proposed\",\"pipeline\":{}}",
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiGovernanceProposalRecord.self,
                    from: Data(retired.utf8)
                )
            )
        }
        let inexactHeight = Data(
            "{\"proposer\":\"\(Self.governanceOwner)\",\"kind\":\(kind),\"created_height\":9007199254740992,\"status\":\"Proposed\"}".utf8
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiGovernanceProposalRecord.self, from: inexactHeight)
        )
    }
}
