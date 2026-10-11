import Foundation

/// Typed consumer views of the first-release validator and staking Norito records.
public enum ValidatorStakingNoritoV1 {
    /// Immutable ordered BLS validator generation, independent of scheduling epochs.
    public struct ValidatorGeneration: Sendable {
        private let record: Record
        public let networkID: NetworkId
        public let generation: UInt64
        public let validators: [PeerID]

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 3)
            self.record = record
            networkID = try NetworkId(bytes: record.fixed(0, count: 32))
            generation = try record.u64(1)
            validators = try record.vector(2, limit: 31, PeerID.init(noritoPayload:))
            guard validators.count >= 4, (validators.count - 1) % 3 == 0,
                  validators.allSatisfy({ $0.algorithm == .blsNormal }) else {
                throw CanonicalNoritoDecodingError.invalidField("invalid validator-generation roster")
            }
            for index in 1..<validators.count {
                guard validators[index - 1].publicKey.lexicographicallyPrecedes(validators[index].publicKey) else {
                    throw CanonicalNoritoDecodingError.invalidField("validator keys must be strictly ordered and unique")
                }
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact installed beacon session and public transcript commitment.
    public struct InstalledBeacon: Sendable {
        private let record: Record
        public let sessionID: Data
        public let transcriptHash: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            self.record = record
            sessionID = try record.fixed(0, count: 32)
            transcriptHash = try record.fixed(1, count: 32)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// One certified scheduling epoch under an explicit signing generation.
    public struct EpochAuthorization: Sendable {
        public enum Decision: UInt32, Sendable {
            case genesis = 0
            case activate = 1
            case retain = 2
            case retainAndCancel = 3
        }

        private let record: Record
        public let version: UInt16
        public let networkID: NetworkId
        public let epoch: UInt64
        public let firstHeight: UInt64
        public let lastHeight: UInt64
        public let authorityGeneration: UInt64
        public let authorityID: Data
        public let beacon: InstalledBeacon?
        public let previousAuthorizationID: Data
        public let transitionID: Data
        public let decision: Decision

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 11)
            self.record = record
            version = try record.u16(0)
            networkID = try NetworkId(bytes: record.fixed(1, count: 32))
            epoch = try record.u64(2)
            firstHeight = try record.u64(3)
            lastHeight = try record.u64(4)
            authorityGeneration = try record.u64(5)
            authorityID = try record.fixed(6, count: 32)
            let binding = try record.variant(7)
            switch binding.tag {
            case 0:
                guard record.field(7).count == 4 else {
                    throw CanonicalNoritoDecodingError.invalidField("bootstrap beacon must be a unit variant")
                }
                beacon = nil
            case 1:
                beacon = try InstalledBeacon(noritoPayload: binding.value)
            default:
                throw CanonicalNoritoDecodingError.invalidField("unknown beacon epoch binding")
            }
            previousAuthorizationID = try record.fixed(8, count: 32)
            transitionID = try record.fixed(9, count: 32)
            let disposition = try record.variant(10)
            guard record.field(10).count == 4,
                  let decision = Decision(rawValue: disposition.tag),
                  version == 1, firstHeight > 0, lastHeight >= firstHeight else {
                throw CanonicalNoritoDecodingError.invalidField("invalid epoch authorization")
            }
            self.decision = decision
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Frozen DKG attempt, signing generation and exclusive ceremony cutoffs.
    public struct DkgSession: Sendable {
        private let record: Record
        public let version: UInt16
        public let networkID: NetworkId
        public let sessionID: Data
        public let attemptID: Data
        public let authorityGeneration: UInt64
        public let rosterHash: Data
        public let committeeSize: UInt16
        public let threshold: UInt16
        public let startHeight: UInt64
        public let commitmentsEndHeight: UInt64
        public let deliveriesEndHeight: UInt64
        public let acceptancesEndHeight: UInt64

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 12)
            self.record = record
            version = try record.u16(0)
            networkID = try NetworkId(bytes: record.fixed(1, count: 32))
            sessionID = try record.fixed(2, count: 32)
            attemptID = try record.fixed(3, count: 32)
            authorityGeneration = try record.u64(4)
            rosterHash = try record.fixed(5, count: 32)
            committeeSize = try record.u16(6)
            threshold = try record.u16(7)
            startHeight = try record.u64(8)
            commitmentsEndHeight = try record.u64(9)
            deliveriesEndHeight = try record.u64(10)
            acceptancesEndHeight = try record.u64(11)
            guard version == 1, (4...31).contains(committeeSize), (committeeSize - 1) % 3 == 0,
                  threshold == (committeeSize - 1) / 3 + 1,
                  startHeight > 0, startHeight < commitmentsEndHeight,
                  commitmentsEndHeight < deliveriesEndHeight,
                  deliveriesEndHeight < acceptancesEndHeight else {
                throw CanonicalNoritoDecodingError.invalidField("invalid DKG session geometry or cutoffs")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Dealer-signed public coefficient commitments and constant-term proof.
    public struct DkgDealerCommitment: Sendable {
        private let record: Record
        public let dealerIndex: UInt16
        public let coefficientCommitments: [Data]
        public let constantProofCommitment: Data
        public let constantProofResponse: Data
        public let signature: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 4)
            self.record = record
            dealerIndex = try record.u16(0)
            coefficientCommitments = try record.vector(1, limit: 32) {
                try Record.fixedByteArray($0, count: 96)
            }
            let proof = try Record(record.field(2), fields: 2)
            constantProofCommitment = try proof.fixed(0, count: 96)
            constantProofResponse = try proof.fixed(1, count: 32)
            signature = record.field(3)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Attempt-bound hybrid recipient key signed by its consensus seat.
    public struct DkgRecipientKey: Sendable {
        private let record: Record
        public let recipientIndex: UInt16
        public let validator: Data
        public let x25519PublicKey: Data
        public let mlkem768PublicKey: Data
        public let signature: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 5)
            self.record = record
            recipientIndex = try record.u16(0)
            validator = record.field(1)
            x25519PublicKey = try record.fixed(2, count: 32)
            mlkem768PublicKey = try Record.byteVector(record.field(3))
            signature = record.field(4)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Dealer-signed encrypted private share for one exact recipient.
    public struct DkgEncryptedShare: Sendable {
        private let record: Record
        public let dealerIndex: UInt16
        public let recipientIndex: UInt16
        public let dealerCommitmentHash: Data
        public let recipientKeyHash: Data
        public let deliveryHeight: UInt64
        public let ephemeralX25519PublicKey: Data
        public let mlkem768Ciphertext: Data
        public let encryptedShare: Data
        public let signature: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 9)
            self.record = record
            dealerIndex = try record.u16(0)
            recipientIndex = try record.u16(1)
            dealerCommitmentHash = try record.fixed(2, count: 32)
            recipientKeyHash = try record.fixed(3, count: 32)
            deliveryHeight = try record.u64(4)
            ephemeralX25519PublicKey = try record.fixed(5, count: 32)
            mlkem768Ciphertext = try Record.byteVector(record.field(6))
            encryptedShare = try Record.byteVector(record.field(7))
            signature = record.field(8)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Recipient-signed acceptance of a specific encrypted edge.
    public struct DkgShareAcceptance: Sendable {
        private let record: Record
        public let dealerIndex: UInt16
        public let recipientIndex: UInt16
        public let dealerCommitmentHash: Data
        public let encryptedShareHash: Data
        public let acceptedHeight: UInt64
        public let signature: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 6)
            self.record = record
            dealerIndex = try record.u16(0)
            recipientIndex = try record.u16(1)
            dealerCommitmentHash = try record.fixed(2, count: 32)
            encryptedShareHash = try record.fixed(3, count: 32)
            acceptedHeight = try record.u64(4)
            signature = record.field(5)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Complete public all-edge DKG transcript; private scalars are absent.
    public struct DkgTranscript: Sendable {
        private let record: Record
        public let session: DkgSession
        public let generatorH: Data
        public let generatorV: Data
        public let dealerCommitments: [DkgDealerCommitment]
        public let recipientKeys: [DkgRecipientKey]
        public let encryptedShares: [DkgEncryptedShare]
        public let shareAcceptances: [DkgShareAcceptance]
        public let qualifiedDealers: [UInt16]
        public let eventHash: Data
        public let finalizedAtHeight: UInt64

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 10)
            self.record = record
            session = try DkgSession(noritoPayload: record.field(0))
            generatorH = try record.fixed(1, count: 96)
            generatorV = try record.fixed(2, count: 96)
            dealerCommitments = try record.vector(3, limit: 31, DkgDealerCommitment.init(noritoPayload:))
            recipientKeys = try record.vector(4, limit: 31, DkgRecipientKey.init(noritoPayload:))
            encryptedShares = try record.vector(5, limit: 31 * 31, DkgEncryptedShare.init(noritoPayload:))
            shareAcceptances = try record.vector(6, limit: 31 * 31, DkgShareAcceptance.init(noritoPayload:))
            qualifiedDealers = try record.vector(7, limit: 31, Record.decodeU16)
            eventHash = try record.fixed(8, count: 32)
            finalizedAtHeight = try record.u64(9)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Frozen monetary and scheduling eligibility; network authority is checked by finality.
    public struct ElectionPolicy: Sendable {
        public enum AssetScope: Sendable, Equatable { case global }

        private let record: Record
        public let xorAssetDefinitionID: Data
        public let assetScope: AssetScope
        public let assetScale: UInt32
        public let minSelfBond: Quantity
        public let minNominationBond: Quantity
        public let maxValidators: UInt32
        public let epochLengthBlocks: UInt64

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 7)
            self.record = record
            xorAssetDefinitionID = try Record.fixedByteArray(record.field(0), count: 16)
            guard record.field(1) == Data([0, 0, 0, 0]) else {
                throw CanonicalNoritoDecodingError.invalidField("validator election custody requires Global scope")
            }
            assetScope = .global
            assetScale = try record.u32(2)
            minSelfBond = try Quantity(noritoPayload: record.field(3))
            minNominationBond = try Quantity(noritoPayload: record.field(4))
            maxValidators = try record.u32(5)
            epochLengthBlocks = try record.u64(6)
            // Rust AssetDefinitionId::derive_from_components("nexus.universal", "xor").
            // This is a rejected identity, never an accepted network XOR default.
            let syntheticXor = Data([
                0x5e, 0xcd, 0x1e, 0x80, 0xac, 0x7d, 0x4d, 0x18,
                0xb2, 0x27, 0x72, 0x09, 0x1a, 0x73, 0xfc, 0x13,
            ])
            guard (xorAssetDefinitionID[6] & 0xf0) == 0x40,
                  (xorAssetDefinitionID[8] & 0xc0) == 0x80,
                  xorAssetDefinitionID != syntheticXor,
                  assetScale == 9, !minSelfBond.mantissaLittleEndian.isEmpty,
                  !minNominationBond.mantissaLittleEndian.isEmpty,
                  minSelfBond.scale <= assetScale, minNominationBond.scale <= assetScale,
                  maxValidators >= 4, maxValidators <= 31, (maxValidators - 1) % 3 == 0,
                  epochLengthBlocks >= 3 else {
                throw CanonicalNoritoDecodingError.invalidField("invalid frozen validator election policy")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Original BLS identity and possession proof. Decoding checks shape, not the pairing.
    public struct CommitteeMember: Sendable {
        private let record: Record
        public let validator: Data
        public let blsPublicKey: Data
        public let proofOfPossession: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            self.record = record
            validator = record.field(0)
            // PeerId wraps PublicKey's sequence of algorithm byte followed by compressed key.
            let peer = try Record(validator, fields: 1)
            let key: [UInt8] = try peer.vector(0, limit: 49) { field in
                guard field.count == 1 else {
                    throw CanonicalNoritoDecodingError.invalidField("non-canonical public-key byte")
                }
                return field.first!
            }
            proofOfPossession = try Record.byteVector(record.field(1))
            guard key.count == 49, key.first == 2, proofOfPossession.count == 96 else {
                throw CanonicalNoritoDecodingError.invalidField("committee member requires BLS-normal key and possession proof")
            }
            blsPublicKey = Data(key.dropFirst())
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Immutable E+2 election selected at the end of epoch E.
    public struct CommitteePreparation: Sendable {
        private let record: Record
        public let version: UInt16
        public let networkID: NetworkId
        public let selectionEpoch: UInt64
        public let selectionHeight: UInt64
        public let selectionAnchor: Data
        public let targetEpoch: UInt64
        public let firstHeight: UInt64
        public let lastHeight: UInt64
        public let authorityGeneration: UInt64
        public let preparingAuthorizationID: Data
        public let electionSeed: Data
        public let eligibility: ElectionPolicy
        public let committee: [CommitteeMember]

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 13)
            self.record = record
            version = try record.u16(0)
            networkID = try NetworkId(bytes: record.fixed(1, count: 32))
            selectionEpoch = try record.u64(2)
            selectionHeight = try record.u64(3)
            selectionAnchor = try record.fixed(4, count: 32)
            targetEpoch = try record.u64(5)
            firstHeight = try record.u64(6)
            lastHeight = try record.u64(7)
            authorityGeneration = try record.u64(8)
            preparingAuthorizationID = try record.fixed(9, count: 32)
            electionSeed = try record.fixed(10, count: 32)
            eligibility = try ElectionPolicy(noritoPayload: record.field(11))
            committee = try record.vector(12, limit: 31, CommitteeMember.init(noritoPayload:))
            let target = selectionEpoch.addingReportingOverflow(2)
            let preparingFirst = selectionHeight.addingReportingOverflow(1)
            let distance = lastHeight.subtractingReportingOverflow(firstHeight)
            let length = distance.partialValue.addingReportingOverflow(1)
            guard version == 1, record.field(1).contains(where: { $0 != 0 }),
                  selectionAnchor.contains(where: { $0 != 0 }), selectionHeight > 0,
                  authorityGeneration > 0, !target.overflow, targetEpoch == target.partialValue,
                  !preparingFirst.overflow, firstHeight > preparingFirst.partialValue,
                  !distance.overflow, !length.overflow, length.partialValue == eligibility.epochLengthBlocks,
                  preparingAuthorizationID.contains(where: { $0 != 0 }),
                  electionSeed.contains(where: { $0 != 0 }),
                  committee.count >= 4, (committee.count - 1) % 3 == 0,
                  committee.count <= Int(eligibility.maxValidators) else {
                throw CanonicalNoritoDecodingError.invalidField("invalid frozen committee preparation")
            }
            for index in 1..<committee.count {
                guard committee[index - 1].blsPublicKey.lexicographicallyPrecedes(committee[index].blsPublicKey) else {
                    throw CanonicalNoritoDecodingError.invalidField("committee keys must be strictly ordered and unique")
                }
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact finalized beacon transcript retained for the prepared committee.
    public struct CommitteeCredentials: Sendable {
        private let record: Record
        public let beacon: InstalledBeacon

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 1)
            self.record = record
            beacon = try InstalledBeacon(noritoPayload: record.field(0))
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact target seat and its retained threshold beacon-share possession proof.
    public struct SeatReadiness: Sendable {
        private let record: Record
        public let validatorIndex: UInt32
        public let beaconPossession: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            self.record = record
            validatorIndex = try record.u32(0)
            beaconPossession = record.field(1)
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Prepared credentials, seat evidence and certified terminal outcome.
    public struct CommitteeTransition: Sendable {
        private let record: Record
        public let preparation: CommitteePreparation
        public let credentials: CommitteeCredentials?
        public let readiness: [SeatReadiness]
        public let outcome: EpochAuthorization?

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 4)
            self.record = record
            preparation = try CommitteePreparation(noritoPayload: record.field(0))
            credentials = try record.option(1, CommitteeCredentials.init(noritoPayload:))
            readiness = try record.vector(2, limit: 31, SeatReadiness.init(noritoPayload:))
            outcome = try record.option(3, EpochAuthorization.init(noritoPayload:))
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Asset owner, real definition identity and exact dataspace scope.
    public struct AssetID: Sendable {
        private let record: Record
        public let account: Data
        public let definition: Data
        public let scopeDataspace: UInt64?

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 3)
            self.record = record
            account = record.field(0)
            definition = try Record.fixedByteArray(record.field(1), count: 16)
            let scope = try record.variant(2)
            switch scope.tag {
            case 0:
                guard record.field(2).count == 4 else {
                    throw CanonicalNoritoDecodingError.invalidField("global asset scope must be a unit variant")
                }
                scopeDataspace = nil
            case 1:
                scopeDataspace = try Record.decodeU64(scope.value)
            default:
                throw CanonicalNoritoDecodingError.invalidField("unknown asset balance scope")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Canonical nonnegative fixed-point amount.
    public struct Quantity: Sendable {
        private let record: Record
        public let mantissaLittleEndian: Data
        public let scale: UInt32

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            self.record = record
            var reader = CanonicalNoritoReader(data: record.field(0))
            let count = try reader.readUInt32LE()
            guard count <= 64 else {
                throw CanonicalNoritoDecodingError.invalidField("quantity mantissa exceeds 512 bits")
            }
            let mantissa = try reader.readBytes(Int(count))
            let canonicalPositive = mantissa.isEmpty ||
                ((mantissa.last! & 0x80) == 0 &&
                 (mantissa.last! != 0 ||
                  (mantissa.count > 1 && (mantissa[mantissa.count - 2] & 0x80) != 0)))
            guard reader.remaining() == 0,
                  canonicalPositive else {
                throw CanonicalNoritoDecodingError.invalidField("quantity mantissa is not canonical and nonnegative")
            }
            mantissaLittleEndian = mantissa
            scale = try record.u32(1)
            let divisibleByTen = mantissa.reversed().reduce(0) { ($0 * 256 + Int($1)) % 10 } == 0
            guard scale <= 28,
                  scale == 0 || (!mantissa.isEmpty && !divisibleByTen) else {
                throw CanonicalNoritoDecodingError.invalidField("quantity has a non-canonical decimal scale")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact peer identity bound by a bond. Key admission uses the existing SDK validator;
    /// possession and the retained validator tenure remain native execution checks.
    public struct PeerID: Sendable {
        private let record: Record
        public let algorithm: SigningAlgorithm
        public let publicKey: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 1)
            let key: [UInt8] = try record.vector(0, limit: 8_259) { byte in
                guard byte.count == 1 else {
                    throw CanonicalNoritoDecodingError.invalidField("non-canonical peer public-key byte")
                }
                return byte.first!
            }
            guard let tag = key.first, let algorithm = SigningAlgorithm(noritoDiscriminant: tag) else {
                throw CanonicalNoritoDecodingError.invalidField("unknown peer public-key algorithm")
            }
            let publicKey = Data(key.dropFirst())
            // Reuse the canonical algorithm envelope and native key admission. SM2's
            // Norito key includes the signed identifier, unlike fromAccount's SEC1 input.
            _ = try governancePublicKeyOrderV1(
                CanonicalNorito.publicKeyMultihash(algorithm: algorithm, payload: publicKey), codingPath: []
            )
            if algorithm == .sm2 {
                let length = Int(publicKey[0]) << 8 | Int(publicKey[1])
                guard let identifier = String(data: publicKey.subdata(in: 2..<(2 + length)), encoding: .utf8) else {
                    throw CanonicalNoritoDecodingError.invalidField("invalid peer SM2 identifier")
                }
                _ = try AccountAddress.fromAccount(publicKey: publicKey.subdata(in: (2 + length)..<publicKey.count),
                                                   algorithm: algorithm.wireName, distid: identifier)
            } else {
                _ = try AccountAddress.fromAccount(publicKey: publicKey, algorithm: algorithm.wireName)
            }
            self.record = record
            self.algorithm = algorithm
            self.publicKey = publicKey
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact new-validator eligibility boundary.
    public struct MonetaryRegistration: Sendable {
        private let record: Record
        public let activationHeight: UInt64

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 1)
            activationHeight = try record.u64(0)
            self.record = record
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact validator tenure and peer observed by an additional stake operation.
    public struct MonetaryBond: Sendable {
        private let record: Record
        public let activationHeight: UInt64
        public let peerID: PeerID

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            activationHeight = try record.u64(0)
            peerID = try PeerID(noritoPayload: record.field(1))
            self.record = record
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact retained withdrawal request, including Rust Hash's marked 32-byte encoding.
    public struct MonetaryUnbond: Sendable {
        private let record: Record
        public let activationHeight: UInt64
        public let requestHash: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            activationHeight = try record.u64(0)
            requestHash = try record.fixed(1, count: 32)
            guard requestHash[31] & 1 == 1 else {
                throw CanonicalNoritoDecodingError.invalidField("withdrawal request hash lacks the Iroha marker")
            }
            self.record = record
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact tenure and complete eligible custody exposure before a privileged slash.
    public struct MonetarySlash: Sendable {
        private let record: Record
        public let activationHeight: UInt64
        public let slashableExposure: Quantity

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 2)
            activationHeight = try record.u64(0)
            slashableExposure = try Quantity(noritoPayload: record.field(1))
            self.record = record
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Signed operation-specific staking precondition. Each case owns its exact Rust layout.
    public enum MonetaryPrecondition: Sendable {
        case registration(MonetaryRegistration)
        case bond(MonetaryBond)
        case unbond(MonetaryUnbond)
        case slash(MonetarySlash)

        public enum Kind: UInt32, Sendable {
            case registration = 0
            case bond = 1
            case unbond = 2
            case slash = 3
        }

        public init(noritoPayload: Data) throws {
            let variant = try Record.decodeVariant(noritoPayload)
            switch variant.tag {
            case 0: self = .registration(try MonetaryRegistration(noritoPayload: variant.value))
            case 1: self = .bond(try MonetaryBond(noritoPayload: variant.value))
            case 2: self = .unbond(try MonetaryUnbond(noritoPayload: variant.value))
            case 3: self = .slash(try MonetarySlash(noritoPayload: variant.value))
            default: throw CanonicalNoritoDecodingError.invalidField("unknown staking monetary precondition")
            }
            guard self.noritoPayload == noritoPayload else {
                throw CanonicalNoritoDecodingError.invalidField("non-canonical staking precondition length")
            }
        }

        public var kind: Kind {
            switch self {
            case .registration: return .registration
            case .bond: return .bond
            case .unbond: return .unbond
            case .slash: return .slash
            }
        }

        public var activationHeight: UInt64 {
            switch self {
            case .registration(let value): return value.activationHeight
            case .bond(let value): return value.activationHeight
            case .unbond(let value): return value.activationHeight
            case .slash(let value): return value.activationHeight
            }
        }

        public var noritoPayload: Data {
            let value: Data
            switch self {
            case .registration(let binding): value = binding.noritoPayload
            case .bond(let binding): value = binding.noritoPayload
            case .unbond(let binding): value = binding.noritoPayload
            case .slash(let binding): value = binding.noritoPayload
            }
            return Data([UInt8(kind.rawValue), 0, 0, 0]) + Record.varint(UInt64(value.count)) + value
        }
    }

    /// Exact signed source, destination, amount and custody-state plan.
    public struct MonetaryPlan: Sendable {
        private let record: Record
        public let networkScope: NetworkId?
        public let validUntilHeight: UInt64
        public let sourceAsset: AssetID
        public let destinationAsset: AssetID
        public let amount: Quantity
        public let precondition: MonetaryPrecondition

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 6)
            self.record = record
            let scope = try record.variant(0)
            switch scope.tag {
            case 0:
                guard record.field(0).count == 4 else {
                    throw CanonicalNoritoDecodingError.invalidField("genesis monetary scope must be a unit variant")
                }
                networkScope = nil
            case 1:
                networkScope = try NetworkId(bytes: scope.value)
            default:
                throw CanonicalNoritoDecodingError.invalidField("unknown staking monetary scope")
            }
            validUntilHeight = try record.u64(1)
            sourceAsset = try AssetID(noritoPayload: record.field(2))
            destinationAsset = try AssetID(noritoPayload: record.field(3))
            amount = try Quantity(noritoPayload: record.field(4))
            precondition = try MonetaryPrecondition(noritoPayload: record.field(5))
            guard validUntilHeight > 0,
                  sourceAsset.definition == destinationAsset.definition,
                  sourceAsset.scopeDataspace == destinationAsset.scopeDataspace,
                  !amount.mantissaLittleEndian.isEmpty else {
                throw CanonicalNoritoDecodingError.invalidField("invalid staking monetary plan")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Independently accrued fee reward payment, bound to its custody and receipt sequence.
    /// Authenticated beneficiary ownership and the signing recipient are verified by native execution.
    public struct FeeRewardClaim: Sendable {
        private let record: Record
        public let lifecycleSeal: Data
        public let beneficiaryID: Data
        public let beneficiaryRevision: UInt64
        public let sourceAsset: AssetID
        public let destinationAsset: AssetID
        public let amount: Quantity
        public let expectedClaimSequence: UInt64

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 7)
            self.record = record
            lifecycleSeal = try record.fixed(0, count: 32)
            beneficiaryID = record.field(1)
            beneficiaryRevision = try record.u64(2)
            sourceAsset = try AssetID(noritoPayload: record.field(3))
            destinationAsset = try AssetID(noritoPayload: record.field(4))
            amount = try Quantity(noritoPayload: record.field(5))
            expectedClaimSequence = try record.u64(6)
            guard lifecycleSeal.contains(where: { $0 != 0 }),
                  !beneficiaryID.isEmpty,
                  !amount.mantissaLittleEndian.isEmpty,
                  sourceAsset.scopeDataspace == nil, destinationAsset.scopeDataspace == nil,
                  sourceAsset.definition == destinationAsset.definition else {
                throw CanonicalNoritoDecodingError.invalidField("invalid fee reward claim custody or amount")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact authenticated claim for automatically accrued funded validator rewards.
    /// Native execution authenticates the signer, beneficiary and custody preconditions.
    public struct RewardClaimPlan: Sendable {
        private let record: Record
        public let networkScope: NetworkId?
        public let validUntilHeight: UInt64
        public let feeClaim: FeeRewardClaim

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 3)
            self.record = record
            let scope = try record.variant(0)
            switch scope.tag {
            case 0:
                guard record.field(0).count == 4 else {
                    throw CanonicalNoritoDecodingError.invalidField("genesis monetary scope must be a unit variant")
                }
                networkScope = nil
            case 1: networkScope = try NetworkId(bytes: scope.value)
            default: throw CanonicalNoritoDecodingError.invalidField("unknown staking monetary scope")
            }
            validUntilHeight = try record.u64(1)
            feeClaim = try FeeRewardClaim(noritoPayload: record.field(2))
            guard validUntilHeight > 0 else {
                throw CanonicalNoritoDecodingError.invalidField("reward plan expiry must be positive")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }

    /// Exact validator rebind with mandatory replacement-peer signature.
    public struct RebindPeer: Sendable {
        private let record: Record
        public let laneID: UInt32
        public let validator: Data
        public let peerID: Data
        public let peerSignature: Data

        public init(noritoPayload: Data) throws {
            let record = try Record(noritoPayload, fields: 4)
            self.record = record
            // LaneId is a one-field Norito newtype around the u32 lane number.
            laneID = try Record(record.field(0), fields: 1).u32(0)
            validator = record.field(1)
            peerID = record.field(2)
            peerSignature = record.field(3)
            guard !peerSignature.isEmpty else {
                throw CanonicalNoritoDecodingError.invalidField("replacement-peer consent is required")
            }
        }

        public var noritoPayload: Data { record.encode() }
    }
}

private struct Record: Sendable {
    let fields: [Data]

    init(_ payload: Data, fields count: Int) throws {
        var reader = CanonicalNoritoReader(data: payload)
        var fields = [Data]()
        fields.reserveCapacity(count)
        for _ in 0..<count {
            fields.append(try reader.readCompactField())
        }
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("Norito record has trailing fields")
        }
        self.fields = fields
        guard encode() == payload else {
            throw CanonicalNoritoDecodingError.invalidField("Norito record has non-canonical field lengths")
        }
    }

    func field(_ index: Int) -> Data { fields[index] }

    func fixed(_ index: Int, count: Int) throws -> Data {
        let payload = fields[index]
        guard payload.count == count else {
            throw CanonicalNoritoDecodingError.invalidField("fixed Norito field has wrong width")
        }
        return payload
    }

    func u16(_ index: Int) throws -> UInt16 { try Self.decodeU16(fields[index]) }
    func u32(_ index: Int) throws -> UInt32 { try Self.decodeU32(fields[index]) }
    func u64(_ index: Int) throws -> UInt64 { try Self.decodeU64(fields[index]) }
    func variant(_ index: Int) throws -> (tag: UInt32, value: Data) {
        try Self.decodeVariant(fields[index])
    }

    func vector<T>(
        _ index: Int, limit: Int, _ decode: (Data) throws -> T
    ) throws -> [T] {
        var reader = CanonicalNoritoReader(data: fields[index])
        let count = try reader.readUInt64LE()
        guard count <= UInt64(limit) else {
            throw CanonicalNoritoDecodingError.invalidField("Norito vector exceeds protocol bound")
        }
        var values = [T]()
        values.reserveCapacity(Int(count))
        for _ in 0..<Int(count) {
            values.append(try decode(reader.readCompactField()))
        }
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("Norito vector has trailing bytes")
        }
        return values
    }

    func option<T>(_ index: Int, _ decode: (Data) throws -> T) throws -> T? {
        var reader = CanonicalNoritoReader(data: fields[index])
        let tag = try reader.readUInt8()
        let value: T?
        switch tag {
        case 0: value = nil
        case 1: value = try decode(reader.readCompactField())
        default: throw CanonicalNoritoDecodingError.invalidField("unknown Norito option tag")
        }
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("Norito option has trailing bytes")
        }
        return value
    }

    func encode() -> Data {
        var output = Data()
        for field in fields {
            output.append(Self.varint(UInt64(field.count)))
            output.append(field)
        }
        return output
    }

    static func decodeU16(_ payload: Data) throws -> UInt16 {
        var reader = CanonicalNoritoReader(data: payload)
        let value = try reader.readUInt16LE()
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("u16 field has trailing bytes")
        }
        return value
    }

    static func decodeU32(_ payload: Data) throws -> UInt32 {
        var reader = CanonicalNoritoReader(data: payload)
        let value = try reader.readUInt32LE()
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("u32 field has trailing bytes")
        }
        return value
    }

    static func decodeU64(_ payload: Data) throws -> UInt64 {
        var reader = CanonicalNoritoReader(data: payload)
        let value = try reader.readUInt64LE()
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("u64 field has trailing bytes")
        }
        return value
    }

    static func decodeVariant(_ payload: Data) throws -> (tag: UInt32, value: Data) {
        var reader = CanonicalNoritoReader(data: payload)
        let tag = try reader.readUInt32LE()
        let value = reader.remaining() == 0 ? Data() : try reader.readCompactField()
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("Norito variant has trailing bytes")
        }
        return (tag, value)
    }

    static func byteVector(_ payload: Data) throws -> Data {
        var reader = CanonicalNoritoReader(data: payload)
        let length = try reader.readUInt64LE()
        guard length <= UInt64(Int.max) else {
            throw CanonicalNoritoDecodingError.invalidField("byte vector exceeds SDK bound")
        }
        let value = try reader.readBytes(Int(length))
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("byte vector has trailing bytes")
        }
        return value
    }

    static func fixedByteArray(_ payload: Data, count: Int) throws -> Data {
        var reader = CanonicalNoritoReader(data: payload)
        var value = Data()
        value.reserveCapacity(count)
        for _ in 0..<count {
            let byte = try reader.readCompactField()
            guard byte.count == 1 else {
                throw CanonicalNoritoDecodingError.invalidField("non-canonical fixed byte array")
            }
            value.append(byte)
        }
        guard reader.remaining() == 0 else {
            throw CanonicalNoritoDecodingError.invalidField("fixed byte array has trailing bytes")
        }
        return value
    }

    static func varint(_ value: UInt64) -> Data {
        var remaining = value
        var output = Data()
        while remaining >= 0x80 {
            output.append(UInt8(remaining & 0x7f) | 0x80)
            remaining >>= 7
        }
        output.append(UInt8(remaining))
        return output
    }
}
