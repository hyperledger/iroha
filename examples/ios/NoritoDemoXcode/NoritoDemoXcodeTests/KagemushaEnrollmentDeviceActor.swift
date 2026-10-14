// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
import CryptoKit
import Darwin
import Foundation

@testable import IrohaSwift

#if os(iOS) && !targetEnvironment(macCatalyst)
  /// This is test orchestration only; Native owns all installation/enrollment authority.
  /// There is deliberately no issuer, account signer, fallback evidence or proof implementation.
  actor KagemushaEnrollmentDeviceActor {
    struct Command: @unchecked Sendable {
      let action: String
      let inputs: [String: EnrollmentProbePin]
      init(_ row: [String: Any]) throws {
        guard Set(row.keys) == ["action", "inputs"], let action = row["action"] as? String,
          let inputs = row["inputs"] as? [String: Any],
          [
            "install", "begin", "permit", "authorize", "collect-evidence", "retain-request",
            "accept-result", "inspect", "start-enrollment", "renew-session", "stop",
          ].contains(action) || KagemushaMonetaryProbeManifest.actions.contains(action)
        else { throw EnrollmentProbeFailure.input }
        self.action = action
        self.inputs = try inputs.mapValues(EnrollmentProbePin.init)
      }
    }
    struct Configuration: @unchecked Sendable {
      let files: EnrollmentProbeFiles
      let actorPath: String
      let invocation: String
      let account: Data
      let requestID: Data
      let session: KagemushaWalletEnrollmentSessionOriginalsV1?
      let group: String
      let catalogPins: [String: EnrollmentProbePin]
      let identity: Data
      let requiredStage: String
      init(
        files: EnrollmentProbeFiles, row: [String: Any], role: String, invocation: String,
        independentGenesis: String, appIDPrefix: String, bundleID: String
      ) throws {
        guard Set(row.keys) == ["version", "actors", "catalog", "session", "requiredStage"],
          row["version"] as? Int == 1,
          let requiredStage = row["requiredStage"] as? String,
          [
            "installed", "dispatch", "e5", "e6", "opened", "activated", "loaded", "received",
            "sent", "unloaded",
          ].contains(requiredStage),
          ["A", "B", "C"].contains(role), let actors = row["actors"] as? [String: [String: Any]],
          Set(actors.keys) == ["A", "B", "C"], let sessionPins = row["session"] as? [String: Any],
          sessionPins.isEmpty
            || Set(sessionPins.keys) == ["access-token", "dpop-proof", "attestation-root"],
          let catalog = row["catalog"] as? [Any]
        else { throw EnrollmentProbeFailure.input }
        var ids = Set<String>()
        var accountDigests = Set<String>()
        var selected: (String, Data)?
        for name in ["A", "B", "C"] {
          let actor = actors[name]!
          guard Set(actor.keys) == ["id", "account"], let literal = actor["id"] as? String,
            let id = UUID(uuidString: literal)?.uuidString, id == literal,
            ids.insert(id).inserted
          else { throw EnrollmentProbeFailure.input }
          let account = try files.pinned(EnrollmentProbePin(actor["account"]!), maximum: 4096)
          guard !account.isEmpty,
            accountDigests.insert(EnrollmentProbeFiles.digest(account)).inserted
          else { throw EnrollmentProbeFailure.input }
          if name == role { selected = (id, account) }
        }
        guard let (actorID, account) = selected else { throw EnrollmentProbeFailure.input }
        var byPath: [String: EnrollmentProbePin] = [:]
        for row in catalog {
          let pin = try EnrollmentProbePin(row)
          guard pin.path.hasPrefix("catalog/"), byPath.updateValue(pin, forKey: pin.path) == nil
          else { throw EnrollmentProbeFailure.input }
        }
        let required = [
          "app-manifest.bin", "envelope.bin", "wallet-runtime.bin", "verifier-pack.bin",
          "producer-inventory.bin", "signed-genesis.bin", "registration-source.bin",
        ]
        guard required.allSatisfy({ byPath["catalog/" + $0] != nil }),
          byPath["catalog/verifier-pack.bin"]!.size > 0,
          byPath["catalog/producer-inventory.bin"]!.size > 0,
          EnrollmentProbeFiles.isDigest(independentGenesis),
          byPath["catalog/signed-genesis.bin"]!.sha256 == independentGenesis
        else { throw EnrollmentProbeFailure.input }
        self.requiredStage = requiredStage
        self.files = files
        self.actorPath = "actors/" + actorID
        self.invocation = invocation
        self.account = account
        self.requestID = Data(
          SHA256.hash(
            data: Data(
              ("kagemusha-device-enrollment:" + actorID + ":" + EnrollmentProbeFiles.digest(account))
                .utf8)))
        self.catalogPins = byPath
        self.group = try KagemushaWalletApplePlatformV1.keychainAccessGroup(
          applicationIdentifierPrefix: appIDPrefix, bundleIdentifier: bundleID)
        func secret(_ name: String, _ limit: Int) throws -> Data {
          let pin = try EnrollmentProbePin(sessionPins[name]!)
          guard pin.path.hasPrefix("inbox/" + invocation + "/") else {
            throw EnrollmentProbeFailure.input
          }
          return try files.pinned(pin, maximum: limit)
        }
        self.session =
          sessionPins.isEmpty
          ? nil
          : try KagemushaWalletEnrollmentSessionOriginalsV1(
            accessToken: secret("access-token", 16_384), dpopProof: secret("dpop-proof", 4096),
            attestationRootDER: secret("attestation-root", 16_384))
        // No live-session identity is frozen here: a later process needs a fresh authenticated session.
        let catalogIdentity = byPath.keys.sorted().map { key in key + ":" + byPath[key]!.sha256 }
          .joined(separator: "\n")
        self.identity = Data(
          ([
            role, actorID, EnrollmentProbeFiles.digest(account),
            EnrollmentProbeFiles.digest(requestID),
            EnrollmentProbeFiles.digest(Data(catalogIdentity.utf8)), bundleID, group,
          ].joined(separator: "\n") + "\n").utf8)
      }
      func verifyCatalog() throws {
        // Reject unlisted files and symlink directories, not merely the required entry points.
        let directory = try files.url("catalog")
        try EnrollmentProbeFiles.requireDirectory(directory)
        var found = Set<String>()
        func walk(_ current: URL, _ relative: String) throws {
          for child in try FileManager.default.contentsOfDirectory(
            at: current, includingPropertiesForKeys: nil)
          {
            var info = stat()
            guard lstat(child.path, &info) == 0 else { throw EnrollmentProbeFailure.custody }
            let path = relative + "/" + child.lastPathComponent
            if info.st_mode & S_IFMT == S_IFDIR {
              try EnrollmentProbeFiles.requireDirectory(child)
              try walk(child, path)
            } else {
              guard let pin = catalogPins[path] else { throw EnrollmentProbeFailure.input }
              try files.verifyLarge(pin)
              found.insert(path)
            }
          }
        }
        try walk(directory, "catalog")
        guard found == Set(catalogPins.keys) else { throw EnrollmentProbeFailure.input }
        try EnrollmentProbeFiles.requireDirectory(files.url("catalog/originals"))
        // Empty registration bytes are allowed only when Native authenticates a fixed adapter.
        if catalogPins["catalog/registration-source.bin"]!.size > 0 {
          try EnrollmentProbeFiles.requireDirectory(files.url("catalog/registration"))
        }
      }
      func originals() throws -> KagemushaWalletRuntimeOriginalsV1 {
        func value(_ name: String, _ maximum: Int) throws -> Data {
          try files.pinned(catalogPins["catalog/" + name]!, maximum: maximum)
        }
        let registration = try value("registration-source.bin", 8192)
        let relocated =
          registration.isEmpty
          ? registration
          : try KagemushaWalletRuntimeOriginalsV1.relocateRegistrationSource(
            registration, to: files.url("catalog/registration").path)
        return try KagemushaWalletRuntimeOriginalsV1(
          appManifest: value("app-manifest.bin", 8_388_608),
          envelope: value("envelope.bin", 2048),
          walletRuntime: value("wallet-runtime.bin", 131_072),
          verifierPack: value("verifier-pack.bin", 16_842_752),
          producerInventory: value("producer-inventory.bin", 16_777_216),
          signedGenesis: value("signed-genesis.bin", 67_108_864),
          originalsRoot: files.url("catalog/originals").path,
          registrationSource: relocated)
      }
    }

    let config: Configuration
    private let platform: KagemushaWalletApplePlatformV1
    private var attempt: KagemushaWalletInstallationAttemptV1?
    var installed: KagemushaWalletInstalledRuntimeV1?
    var enrollment: KagemushaWalletEnrollmentV1?
    private var dispatch: Data?
    var closed = false
    var wallet: KagemushaWalletV1?
    var pendingReview: KagemushaProbePendingReview?
    var timeExchange: KagemushaWalletTimeExchangeV1?
    init(configuration: Configuration) throws {
      config = configuration
      let support = try config.files.url(config.actorPath + "/custody")
      var system = KagemushaWalletAppleSystemV1.live
      // Test namespace only: every Security, clock, passcode and protected-file operation is live.
      system.applicationSupportDirectory = { .success(support) }
      platform = KagemushaWalletApplePlatformV1(
        appAttest: KagemushaWalletAppleAppAttestServiceV1(),
        accessGroup: config.group, system: system)
    }
    private func owner() throws -> KagemushaWalletEnrollmentV1 {
      guard !closed, let enrollment else { throw EnrollmentProbeFailure.lifecycle }
      return enrollment
    }
    /// Public originals are separate from private input copies, runtime credentials and custody.
    func output(_ name: String, _ bytes: Data, sequence: Int) throws {
      try config.files.publish(
        config.actorPath + "/public/" + config.invocation + "/" + String(format: "%04d", sequence)
          + "-" + name, bytes: bytes)
    }
    private func request(_ bytes: Data, sequence: Int) throws {
      try output("e5.norito", bytes, sequence: sequence)
      guard let dispatch else { throw EnrollmentProbeFailure.lifecycle }
      let frame = try ToriiKagemushaEnrollmentRequestV1(
        action: .evidence, dispatchOriginal: dispatch, evidenceOriginal: bytes)
      try output("service-evidence.norito", frame.canonicalOriginal, sequence: sequence)
    }
    func execute(_ command: Command, sequence: Int) async throws -> String {
      guard !closed else { throw EnrollmentProbeFailure.lifecycle }
      if KagemushaMonetaryProbeManifest.actions.contains(command.action) {
        return try await executeMonetary(command, sequence: sequence)
      }
      func input(_ name: String, _ maximum: Int) throws -> Data {
        guard let pin = command.inputs[name], pin.path.hasPrefix("inbox/" + config.invocation + "/")
        else { throw EnrollmentProbeFailure.input }
        let bytes = try config.files.pinned(pin, maximum: maximum)
        // Retain exact producer input before the effect. These files are never attached/exported.
        try config.files.publish(
          config.actorPath + "/private/" + config.invocation + "/"
            + String(format: "%04d", sequence) + "-" + name, bytes: bytes)
        return bytes
      }
      let names: Set<String>
      switch command.action {
      case "permit", "accept-result": names = ["response"]
      case "authorize", "retain-request": names = ["signature"]
      case "start-enrollment", "renew-session":
        names = ["access-token", "dpop-proof", "attestation-root"]
      case "install", "begin", "collect-evidence", "inspect", "stop": names = []
      default: throw EnrollmentProbeFailure.input
      }
      guard Set(command.inputs.keys) == names else { throw EnrollmentProbeFailure.input }
      switch command.action {
      case "install":
        guard enrollment == nil, wallet == nil else { throw EnrollmentProbeFailure.lifecycle }
        if installed != nil { return "installed-owner-retained" }
        if attempt == nil {
          try config.verifyCatalog()
          attempt = try KagemushaWalletInstalledRuntimeV1.install(
            platform: platform, originals: config.originals())
        }
        // A refusal retains this exact attempt; the next explicit install retries register only.
        installed = try attempt!.register()
        attempt = nil
        return "native-installation-registered"
      case "start-enrollment", "renew-session":
        let session = try KagemushaWalletEnrollmentSessionOriginalsV1(
          accessToken: input("access-token", 16_384), dpopProof: input("dpop-proof", 4096),
          attestationRootDER: input("attestation-root", 16_384))
        if command.action == "start-enrollment" {
          guard wallet == nil, enrollment == nil, let installed else {
            throw EnrollmentProbeFailure.lifecycle
          }
          enrollment = try installed.startEnrollment(session: session)
          self.installed = nil
          return "native-enrollment-session-started"
        }
        try owner().renewSession(session: session)
        dispatch = nil
        return "native-enrollment-session-renewed-begin-required"
      case "begin":
        if enrollment == nil {
          guard wallet == nil, let runtime = installed, let session = config.session else {
            throw EnrollmentProbeFailure.lifecycle
          }
          enrollment = try runtime.startEnrollment(session: session)
          installed = nil
        }
        let original = try owner().begin(requestID: config.requestID, account: config.account)
        dispatch = original
        try output("dispatch.norito", original, sequence: sequence)
        try output(
          "service-prekey.norito",
          ToriiKagemushaEnrollmentRequestV1(action: .preKey, dispatchOriginal: original)
            .canonicalOriginal, sequence: sequence)
        return "live-dispatch-exported"
      case "permit":
        let response = try input("response", ToriiKagemushaEnrollmentResponseV1.maximumBytes)
        guard
          case .permit(let original) = try ToriiKagemushaEnrollmentResponseV1(
            canonicalOriginal: response
          ).outcome
        else { throw EnrollmentProbeFailure.input }
        let challenge = try owner().acceptPermit(originalPermit: original)
        try output("verified-permit.norito", original, sequence: sequence)
        try output("account-challenge.bin", challenge, sequence: sequence)
        return "native-permit-accepted"
      case "authorize":
        let signature = try input("signature", 64)
        guard signature.count == 64 else { throw EnrollmentProbeFailure.input }
        switch try owner().authorize(accountSignature: signature) {
        case .evidence: return "native-payment-key-evidence-ready"
        case .pending: return "native-pending"
        case .abandoned: return "native-abandoned"
        case .bootstrapSelected: return "native-bootstrap-selected"
        }
      case "collect-evidence":
        let enrollment = try owner()
        if let retained = try enrollment.retainedRequest() {
          try request(retained, sequence: sequence)
          return "retained-e5-exported"
        }
        guard case .evidence(let target) = try enrollment.progress() else {
          throw EnrollmentProbeFailure.lifecycle
        }
        let evidence = try await enrollment.collectAppleEvidence(
          platform: platform, target: target,
          requireCurrent: { try Task.checkCancellation() })
        guard let keyID = Data(base64Encoded: evidence.appAttestKeyID), keyID.count == 32
        else { throw EnrollmentProbeFailure.input }
        switch try enrollment.prepareRequest(
          keyID: keyID, attestation: evidence.attestation,
          keyBindingAssertion: evidence.keyBindingAssertion)
        {
        case .accountChallenge(let challenge):
          try output("e5-account-challenge.bin", challenge, sequence: sequence)
          return "native-e5-account-challenge-exported"
        case .retained(let bytes):
          try request(bytes, sequence: sequence)
          return "retained-e5-exported"
        }
      case "retain-request":
        let signature = try input("signature", 64)
        guard signature.count == 64 else { throw EnrollmentProbeFailure.input }
        try request(owner().retainRequest(accountSignature: signature), sequence: sequence)
        return "native-durable-e5-exported"
      case "accept-result":
        let response = try input("response", ToriiKagemushaEnrollmentResponseV1.maximumBytes)
        guard
          case .credential(let original) = try ToriiKagemushaEnrollmentResponseV1(
            canonicalOriginal: response
          ).outcome
        else { throw EnrollmentProbeFailure.input }
        let retained = try owner().acceptCredential(issuerResult: original)
        guard retained == original else { throw EnrollmentProbeFailure.collision }
        try output("e6.norito", retained, sequence: sequence)
        return "native-durable-e6-exported-not-activated"
      case "inspect":
        let owner = try owner()
        var status = "native-retained-originals-inspected"
        if let bytes = try owner.retainedRequest() {
          try request(bytes, sequence: sequence)
          status = "retained-e5-exported"
        }
        if let bytes = try owner.retainedResult() {
          try output("e6.norito", bytes, sequence: sequence)
          status = "retained-e6-exported"
        }
        return status
      case "stop":
        try close()
        return "closed-with-custody-retained"
      default: throw EnrollmentProbeFailure.input
      }
    }
    /// Release is explicit and awaited; no abandonment, key deletion, replacement or bootstrap.
    func close() throws {
      if closed { return }
      try releaseWallet()
      if let enrollment {
        try enrollment.close()
        self.enrollment = nil
      }
      if let installed {
        try installed.close()
        self.installed = nil
      }
      if let attempt {
        try attempt.close()
        self.attempt = nil
      }
      closed = true
    }
  }
#endif
