using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Hyperledger.Iroha.SoraFs;

namespace Hyperledger.Iroha.Sdk.Tests;

public sealed class SoraFsReferenceValidatorsTests
{
    [Fact]
    public void GovernanceReferenceConstantsMatchNativeAbi()
    {
        Assert.Equal(31u, SoraFsReferenceValidators.RequiredBridgeAbiVersion);
        Assert.Equal(-114, SoraFsReferenceValidators.BridgeReferenceError);
        Assert.Equal(67_108_864, SoraFsReferenceValidators.MaxInputBytesV1);
        Assert.Equal(1_024, SoraFsReferenceValidators.MaxLabelBytesV1);
        Assert.Equal(64, SoraFsReferenceValidators.GovernanceDagMaxBlocksV1);
        Assert.Equal(32, SoraFsReferenceValidators.GovernanceDagCidBytesV1);
        Assert.Equal(64, SoraFsReferenceValidators.FixtureBundleMaxPayloadsV1);
        Assert.Equal(1, SoraFsReferenceValidators.ValidationOutcomeVersionV1);
        Assert.Equal(
            Enumerable.Range(1, 19).Select(value => (uint)value),
            Enum.GetValues<SoraFsFixtureBundlePayloadKind>().Select(value => (uint)value));
    }

    [Fact]
    public void AvailabilityRequiresAbiAndCompleteGovernanceSurface()
    {
        Assert.True(SoraFsReferenceValidators.IsAvailable(new FakeNativeBoundary()));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { Abi = 19 }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { Abi = 20 }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { Abi = 23 }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { Abi = SoraFsReferenceValidators.RequiredBridgeAbiVersion + 1 }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { SymbolsAvailable = false }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary { AppealFinanceSymbolsAvailable = false }));
        Assert.False(SoraFsReferenceValidators.IsAvailable(
            new FakeNativeBoundary
            {
                AbiError = new DllNotFoundException("bridge missing"),
            }));
    }

    [Fact]
    public void AppealFinanceAvailabilityRequiresAbiAndSymbol()
    {
        Assert.True(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary()));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary { Abi = 19 }));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary { Abi = 20 }));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary { Abi = 23 }));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary { Abi = SoraFsReferenceValidators.RequiredBridgeAbiVersion + 1 }));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary { AppealFinanceSymbolsAvailable = false }));
        Assert.False(SoraFsReferenceValidators.IsAppealFinanceAvailable(
            new FakeNativeBoundary
            {
                AbiError = new DllNotFoundException("bridge missing"),
            }));
    }

    [Fact]
    public void OrderbookPdpAvailabilityRequiresAbiAndEverySymbol()
    {
        Assert.True(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary()));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary { Abi = 19 }));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary { Abi = 20 }));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary { Abi = 23 }));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary { Abi = SoraFsReferenceValidators.RequiredBridgeAbiVersion + 1 }));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary { OrderbookPdpSymbolsAvailable = false }));
        Assert.False(SoraFsReferenceValidators.IsOrderbookPdpAvailable(
            new FakeNativeBoundary
            {
                AbiError = new DllNotFoundException("bridge missing"),
            }));
    }

    [Fact]
    public void FixtureBundleAvailabilityRequiresAbiAndSymbol()
    {
        Assert.True(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary()));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary { Abi = 19 }));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary { Abi = 20 }));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary { Abi = 23 }));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary { Abi = SoraFsReferenceValidators.RequiredBridgeAbiVersion + 1 }));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary { FixtureBundleSymbolsAvailable = false }));
        Assert.False(SoraFsReferenceValidators.IsFixtureBundleAvailable(
            new FakeNativeBoundary
            {
                AbiError = new DllNotFoundException("bridge missing"),
            }));
    }

    [Fact]
    public void OrderbookAndPdpValidationCopyInputsAndFreeOutputs()
    {
        var native = new FakeNativeBoundary();
        var order = new byte[] { 1, 2, 3 };
        var orderJson = SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.OrderRequest,
            order,
            "order.to",
            123,
            native);

        Assert.Equal(1, native.OrderbookCalls);
        Assert.Equal((uint)SoraFsOrderbookPayloadKind.OrderRequest, native.LastOrderbookKind);
        Assert.NotSame(order, native.LastOrderbookBytes);
        Assert.Equal(order, native.LastOrderbookBytes!);
        Assert.Equal("order.to", Encoding.UTF8.GetString(native.LastOrderbookLabel!));
        Assert.Contains("\"generated_at\":123", orderJson, StringComparison.Ordinal);
        Assert.Equal(1, native.FreeCalls);

        var commitment = new byte[] { 4 };
        var challenge = new byte[] { 5 };
        var proof = new byte[] { 6 };
        var bundleJson = SoraFsReferenceValidators.ValidatePdpBundleJson(
            commitment,
            challenge,
            proof,
            "commitment.to",
            "challenge.to",
            "proof.to",
            456,
            native);

        Assert.Equal(1, native.PdpBundleCalls);
        Assert.NotSame(commitment, native.LastPdpCommitment);
        Assert.NotSame(challenge, native.LastPdpChallenge);
        Assert.NotSame(proof, native.LastPdpProof);
        Assert.Equal(commitment, native.LastPdpCommitment!);
        Assert.Equal(challenge, native.LastPdpChallenge!);
        Assert.Equal(proof, native.LastPdpProof!);
        Assert.Equal(
            "commitment.to",
            Encoding.UTF8.GetString(native.LastPdpCommitmentLabel!));
        Assert.Equal(
            "challenge.to",
            Encoding.UTF8.GetString(native.LastPdpChallengeLabel!));
        Assert.Equal("proof.to", Encoding.UTF8.GetString(native.LastPdpProofLabel!));
        Assert.Contains("\"generated_at\":456", bundleJson, StringComparison.Ordinal);
        Assert.Equal(2, native.FreeCalls);

        native.LastOrderbookBytes![0] = 0x7f;
        native.LastPdpCommitment![0] = 0x7f;
        native.LastPdpChallenge![0] = 0x7f;
        native.LastPdpProof![0] = 0x7f;
        Assert.Equal(1, order[0]);
        Assert.Equal(4, commitment[0]);
        Assert.Equal(5, challenge[0]);
        Assert.Equal(6, proof[0]);
    }

    [Fact]
    public void AppealFinanceValidationCopiesInputsAndFreesOutput()
    {
        var native = new FakeNativeBoundary();
        var payload = new byte[] { 1, 2, 3 };
        var json = SoraFsReferenceValidators.ValidateAppealFinanceCancelAssetLockJson(
            payload,
            "cancel_asset_lock_v1.to",
            123,
            native);

        Assert.Equal(1, native.AppealFinanceCalls);
        Assert.NotSame(payload, native.LastAppealFinanceBytes);
        Assert.Equal(payload, native.LastAppealFinanceBytes!);
        Assert.Equal(
            "cancel_asset_lock_v1.to",
            Encoding.UTF8.GetString(native.LastAppealFinanceLabel!));
        Assert.Contains("\"generated_at\":123", json, StringComparison.Ordinal);
        Assert.Equal(1, native.FreeCalls);

        native.LastAppealFinanceBytes![0] = 0x7f;
        Assert.Equal(1, payload[0]);
    }

    [Fact]
    public void FixtureBundleValidationCopiesInputsAndFreeOutputs()
    {
        var native = new FakeNativeBoundary();
        var order = new byte[] { 1, 2, 3 };
        var proof = new byte[] { 4, 5, 6 };
        var json = SoraFsReferenceValidators.ValidateFixtureBundleJson(
            new[]
            {
                new SoraFsFixtureBundlePayloadInput(
                    SoraFsFixtureBundlePayloadKind.ReplicationOrder,
                    order,
                    "replication-order.to"),
                new SoraFsFixtureBundlePayloadInput(
                    SoraFsFixtureBundlePayloadKind.PorProof,
                    proof,
                    "por-proof.to"),
            },
            122,
            123,
            native);

        Assert.Equal(1, native.FixtureBundleCalls);
        Assert.Equal(122ul, native.LastNowUnix);
        Assert.Equal(123ul, native.LastGeneratedAt);
        var snapshots = Assert.IsType<NativeFixtureBundleInput[]>(
            native.LastFixtureBundlePayloads);
        Assert.Equal(2, snapshots.Length);
        Assert.Equal(
            (uint)SoraFsFixtureBundlePayloadKind.ReplicationOrder,
            snapshots[0].Kind);
        Assert.NotSame(order, snapshots[0].Bytes);
        Assert.NotSame(proof, snapshots[1].Bytes);
        Assert.Equal(order, snapshots[0].Bytes);
        Assert.Equal(proof, snapshots[1].Bytes);
        Assert.Equal(
            "replication-order.to",
            Encoding.UTF8.GetString(snapshots[0].LabelBytes));
        Assert.Contains("\"generated_at\":123", json, StringComparison.Ordinal);
        Assert.Equal(1, native.FreeCalls);

        snapshots[0].Bytes[0] = 0x7f;
        snapshots[1].Bytes[0] = 0x7f;
        Assert.Equal(1, order[0]);
        Assert.Equal(4, proof[0]);
    }

    [Fact]
    public void FixtureBundleValidationRejectsAliasesBoundsAndNullsBeforeNativeDispatch()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SoraFsFixtureBundlePayloadInput(
                (SoraFsFixtureBundlePayloadKind)0,
                new byte[] { 1 }));

        var native = new FakeNativeBoundary();
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateFixtureBundleJson(
                Array.Empty<SoraFsFixtureBundlePayloadInput>(),
                1,
                1,
                native));
        var item = new SoraFsFixtureBundlePayloadInput(
            SoraFsFixtureBundlePayloadKind.PorProof,
            new byte[] { 1 });
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateFixtureBundleJson(
                Enumerable.Repeat(
                    item,
                    SoraFsReferenceValidators.FixtureBundleMaxPayloadsV1 + 1)
                    .ToArray(),
                1,
                1,
                native));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SoraFsReferenceValidators.ValidateFixtureBundleJson(
                new[] { item },
                -1,
                1,
                native));
        Assert.Equal(0, native.FixtureBundleCalls);
    }

    [Fact]
    public void TypedOrderbookBuildersUseCanonicalSelectorsAndFreeOutputs()
    {
        var native = new FakeNativeBoundary();
        var owner = Encoding.UTF8.GetBytes("merchant@paynet");
        var privateKey = Enumerable.Repeat((byte)0xb7, 32).ToArray();
        var orderId = SoraFsReferenceValidators.DeriveOrderbookOrderId(owner, 7, native);
        Assert.Equal(Enumerable.Repeat((byte)7, 32), orderId);

        var order = SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
            SoraFsOrderbookSide.Bid,
            SoraFsOrderbookTier.Hot,
            "12.000000001",
            12,
            owner,
            1_700_010_000,
            7,
            25,
            30,
            privateKey,
            null,
            orderId,
            null,
            native);
        Assert.Equal(orderId, order);

        var ask = SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
            SoraFsOrderbookSide.Ask,
            SoraFsOrderbookTier.Hot,
            "1.25",
            4,
            owner,
            1_700_010_000,
            8,
            25,
            30,
            privateKey,
            null,
            null,
            Enumerable.Repeat((byte)0x72, 32).ToArray(),
            native);
        Assert.Equal(Enumerable.Repeat((byte)8, 32), ask);

        var cancel = SoraFsReferenceValidators.BuildSignedOrderbookOrderCancel(
            orderId,
            owner,
            SoraFsOrderbookCancelReason.OwnerRequested,
            8,
            privateKey,
            native);
        Assert.Equal(orderId, cancel);

        var receiptId = Enumerable.Repeat((byte)0x21, 32).ToArray();
        var receipt = SoraFsReferenceValidators.BuildSignedOrderbookSettlementReceipt(
            receiptId,
            Enumerable.Repeat((byte)0x22, 32).ToArray(),
            Enumerable.Repeat((byte)0x23, 32).ToArray(),
            0,
            4_096,
            Enumerable.Repeat((byte)0x24, 32).ToArray(),
            4_096,
            "1.000000001",
            "1",
            "0.000000001",
            1_700_000_999,
            privateKey,
            native);
        Assert.Equal(receiptId, receipt);
        Assert.Equal(4, native.FreeCalls);
        Assert.Equal(Enumerable.Repeat((byte)0xb7, 32), privateKey);
    }

    [Fact]
    public void TypedOrderbookBuildersRejectNonCanonicalInputsBeforeDispatch()
    {
        var native = new FakeNativeBoundary();
        var owner = Encoding.UTF8.GetBytes("merchant@paynet");
        var privateKey = new byte[32];

        Assert.False(Enum.IsDefined((SoraFsOrderbookPayloadKind)6));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SoraFsReferenceValidators.SignOrderbookPayload(
                (SoraFsOrderbookPayloadKind)6,
                new byte[] { 1 },
                privateKey,
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.DeriveOrderbookOrderId(Array.Empty<byte>(), 7, native));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SoraFsReferenceValidators.DeriveOrderbookOrderId(owner, 0, native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
                SoraFsOrderbookSide.Bid,
                SoraFsOrderbookTier.Hot,
                "1.0",
                1,
                owner,
                2,
                7,
                0,
                0,
                privateKey,
                null,
                null,
                null,
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
                SoraFsOrderbookSide.Bid,
                SoraFsOrderbookTier.Hot,
                "1",
                1,
                owner,
                2,
                7,
                0,
                0,
                Enumerable.Repeat((byte)0xb7, 32).ToArray(),
                null,
                null,
                Enumerable.Repeat((byte)0x72, 32).ToArray(),
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
                SoraFsOrderbookSide.Ask,
                SoraFsOrderbookTier.Hot,
                "1",
                1,
                owner,
                2,
                7,
                0,
                0,
                Enumerable.Repeat((byte)0xb7, 32).ToArray(),
                null,
                null,
                null,
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.BuildSignedOrderbookOrderCancel(
                new byte[31],
                owner,
                SoraFsOrderbookCancelReason.OwnerRequested,
                1,
                privateKey,
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.SignOrderbookPayload(
                SoraFsOrderbookPayloadKind.OrderRequest,
                new byte[] { 1 },
                new byte[31],
                native));
        Assert.Equal(0, native.FreeCalls);
    }

    [Fact]
    public void GovernanceLogNodeValidationCopiesInputsAndFreesOutput()
    {
        var native = new FakeNativeBoundary();
        var payload = new byte[] { 1, 2, 3 };
        var expectedCid = Enumerable.Repeat((byte)4, 32).ToArray();

        var json = SoraFsReferenceValidators.ValidateGovernanceLogNode(
            payload,
            expectedCid,
            "治理.to",
            123,
            native);

        Assert.Equal(1, native.LogNodeCalls);
        Assert.NotSame(payload, native.LastLogNodeBytes);
        Assert.NotSame(expectedCid, native.LastLogNodeExpectedCid);
        Assert.Equal(payload, native.LastLogNodeBytes!);
        Assert.Equal(expectedCid, native.LastLogNodeExpectedCid!);
        Assert.Equal("治理.to", Encoding.UTF8.GetString(native.LastLogNodeLabel!));
        Assert.Equal(123ul, native.LastGeneratedAt);
        Assert.Equal(1, native.FreeCalls);
        Assert.Contains("\"generated_at\":123", json, StringComparison.Ordinal);

        native.LastLogNodeBytes![0] = 0x7f;
        native.LastLogNodeExpectedCid![0] = 0x7f;
        Assert.Equal(1, payload[0]);
        Assert.Equal(4, expectedCid[0]);
    }

    [Fact]
    public void GovernanceBlockValidationCopiesInputsAndFreesOutput()
    {
        var native = new FakeNativeBoundary();
        var payload = new byte[] { 1, 2, 3 };
        var expectedCid = Enumerable.Repeat((byte)4, 32).ToArray();

        var json = SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
            payload,
            "治理-block.to",
            expectedCid,
            123,
            native);

        Assert.Equal(1, native.BlockCalls);
        Assert.NotSame(payload, native.LastBlockBytes);
        Assert.NotSame(expectedCid, native.LastExpectedCid);
        Assert.Equal(payload, native.LastBlockBytes!);
        Assert.Equal(expectedCid, native.LastExpectedCid!);
        Assert.Equal("治理-block.to", Encoding.UTF8.GetString(native.LastBlockLabel!));
        Assert.Equal(123ul, native.LastGeneratedAt);
        Assert.Equal(1, native.FreeCalls);
        Assert.Contains("\"generated_at\":123", json, StringComparison.Ordinal);

        native.LastBlockBytes![0] = 0x7f;
        native.LastExpectedCid![0] = 0x7f;
        Assert.Equal(1, payload[0]);
        Assert.Equal(4, expectedCid[0]);
    }

    [Fact]
    public void GovernanceHeadChainCopiesOrderedBlocksAndFreesOutput()
    {
        var native = new FakeNativeBoundary();
        var head = new byte[] { 9, 8 };
        var firstBytes = new byte[] { 1 };
        var secondBytes = new byte[] { 2 };
        var first = new SoraFsGovernanceDagBlockInput(firstBytes, "first.to");
        var second = new SoraFsGovernanceDagBlockInput(secondBytes, "second.to");

        _ = SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
            head,
            new[] { first, second },
            "head.to",
            456,
            native);

        Assert.Equal(1, native.HeadCalls);
        Assert.NotSame(head, native.LastHeadBytes);
        Assert.Equal(head, native.LastHeadBytes!);
        Assert.Equal("head.to", Encoding.UTF8.GetString(native.LastHeadLabel!));
        Assert.Collection(
            native.LastBlocks!,
            block =>
            {
                Assert.Equal(new byte[] { 1 }, block.Bytes);
                Assert.Equal("first.to", Encoding.UTF8.GetString(block.LabelBytes));
            },
            block =>
            {
                Assert.Equal(new byte[] { 2 }, block.Bytes);
                Assert.Equal("second.to", Encoding.UTF8.GetString(block.LabelBytes));
            });
        Assert.Equal(456ul, native.LastGeneratedAt);
        Assert.Equal(1, native.FreeCalls);

        native.LastHeadBytes![0] = 0x7f;
        native.LastBlocks![0].Bytes[0] = 0x7f;
        Assert.Equal(9, head[0]);
        Assert.Equal(1, firstBytes[0]);
    }

    [Fact]
    public void GovernanceHeadChainUsesIndexedDefaultBlockLabels()
    {
        var native = new FakeNativeBoundary();
        var blocks = new[]
        {
            new SoraFsGovernanceDagBlockInput(new byte[] { 1 }),
            new SoraFsGovernanceDagBlockInput(new byte[] { 2 }),
        };

        _ = SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
            new byte[] { 9 },
            blocks,
            null,
            456,
            native);

        Assert.Collection(
            native.LastBlocks!,
            block => Assert.Equal(
                "governance-dag-block-0.to",
                Encoding.UTF8.GetString(block.LabelBytes)),
            block => Assert.Equal(
                "governance-dag-block-1.to",
                Encoding.UTF8.GetString(block.LabelBytes)));
    }

    [Fact]
    public void GovernanceBlockInputSnapshotsConstructionAndAccess()
    {
        var source = new byte[] { 1, 2, 3 };
        var input = new SoraFsGovernanceDagBlockInput(source, "block.to");
        source[0] = 0x7f;

        var firstRead = input.NoritoBytes;
        Assert.Equal(new byte[] { 1, 2, 3 }, firstRead);
        firstRead[1] = 0x7f;
        Assert.Equal(new byte[] { 1, 2, 3 }, input.NoritoBytes);
    }

    [Fact]
    public void GeneratedAtAndAbiAreValidatedBeforeNativeDispatch()
    {
        var native = new FakeNativeBoundary();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                -1,
                native));
        Assert.Equal(0, native.BlockCalls);

        native.Abi = 20;
        var abiError = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                0,
                native));
        Assert.Contains("ABI 31", abiError.Message, StringComparison.Ordinal);
        Assert.Equal(0, native.BlockCalls);

        native.Abi = 31;
        native.SymbolsAvailable = false;
        var symbolError = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                0,
                native));
        Assert.Contains("governance reference symbols", symbolError.Message);
        Assert.Equal(0, native.BlockCalls);
    }

    [Fact]
    public void LabelsAreStrictUtf8AndBoundedBeforeNativeDispatch()
    {
        var native = new FakeNativeBoundary();
        foreach (var label in new[] { "", " ", " padded", "padded ", "bad\u0001label" })
        {
            Assert.Throws<ArgumentException>(() =>
                SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                    new byte[] { 1 },
                    label,
                    null,
                    1,
                    native));
        }
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "\ud800",
                null,
                1,
                native));
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                new string('a', SoraFsReferenceValidators.MaxLabelBytesV1 + 1),
                null,
                1,
                native));
        Assert.Equal(0, native.BlockCalls);
    }

    [Fact]
    public void HeadChainRejectsEmptyExcessAndNullBlocksBeforeNativeDispatch()
    {
        var native = new FakeNativeBoundary();
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
                new byte[] { 1 },
                Array.Empty<SoraFsGovernanceDagBlockInput>(),
                "head.to",
                1,
                native));

        var excess = Enumerable.Range(
                0,
                SoraFsReferenceValidators.GovernanceDagMaxBlocksV1 + 1)
            .Select(index => new SoraFsGovernanceDagBlockInput(
                new byte[] { (byte)index },
                $"block-{index}.to"))
            .ToArray();
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
                new byte[] { 1 },
                excess,
                "head.to",
                1,
                native));

        SoraFsGovernanceDagBlockInput[] withNull =
        [
            new SoraFsGovernanceDagBlockInput(new byte[] { 1 }),
            null!,
        ];
        Assert.Throws<ArgumentException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
                new byte[] { 1 },
                withNull,
                "head.to",
                1,
                native));
        Assert.Equal(0, native.HeadCalls);
    }

    [Fact]
    public void GovernanceBlockRejectsNonCanonicalExpectedCidLengths()
    {
        var native = new FakeNativeBoundary();
        foreach (var length in new[] { 0, 31, 33 })
        {
            var error = Assert.Throws<ArgumentException>(() =>
                SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                    new byte[] { 1 },
                    "block.to",
                    new byte[length],
                    1,
                    native));
            Assert.Contains("exactly 32 bytes", error.Message);
        }
        Assert.Equal(0, native.BlockCalls);
    }

    [Fact]
    public void GovernanceLogNodeRequiresAnExactCidBeforeNativeDispatch()
    {
        var native = new FakeNativeBoundary();
        Assert.Throws<ArgumentNullException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceLogNode(
                new byte[] { 1 },
                null!,
                "governance.to",
                1,
                native));
        foreach (var length in new[] { 0, 31, 33 })
        {
            var error = Assert.Throws<ArgumentException>(() =>
                SoraFsReferenceValidators.ValidateGovernanceLogNode(
                    new byte[] { 1 },
                    new byte[length],
                    "governance.to",
                    1,
                    native));
            Assert.Contains("exactly 32 bytes", error.Message);
        }
        Assert.Equal(0, native.LogNodeCalls);
    }

    [Fact]
    public void LinkedFixtureBundleMatchesNativeReference()
    {
        Assert.True(
            SoraFsReferenceValidators.IsFixtureBundleAvailable(),
            "ABI-31 connect_norito_bridge with fixture-bundle symbol is required.");

        var fixtureRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest");
        var json = SoraFsReferenceValidators.ValidateFixtureBundleJson(
            new[]
            {
                new SoraFsFixtureBundlePayloadInput(
                    SoraFsFixtureBundlePayloadKind.ReplicationOrder,
                    File.ReadAllBytes(
                        Path.Combine(
                            fixtureRoot,
                            "replication_order",
                            "order_v1.to")),
                    "replication-order.to"),
                new SoraFsFixtureBundlePayloadInput(
                    SoraFsFixtureBundlePayloadKind.PorProof,
                    File.ReadAllBytes(
                        Path.Combine(fixtureRoot, "por", "proof_v1.to")),
                    "por-proof.to"),
            },
            1_700_000_001,
            1_700_001_238);
        using var outcome = JsonDocument.Parse(json);
        Assert.Equal("Ok", outcome.RootElement.GetProperty("status").GetString());
        Assert.Equal("SFS-OK-000", outcome.RootElement.GetProperty("code").GetString());
        Assert.Equal(
            1_700_001_238ul,
            outcome.RootElement.GetProperty("generated_at").GetUInt64());
        Assert.Equal(
            new[] { "replication_order", "por_proof" },
            outcome.RootElement
                .GetProperty("inputs")
                .EnumerateArray()
                .Select(input => input.GetProperty("kind").GetString())
                .ToArray());
    }

    [Fact]
    public void OrderbookAndPdpFixturesMatchExactNativeReferenceOutcomes()
    {
        Assert.True(
            SoraFsReferenceValidators.IsOrderbookPdpAvailable(),
            "ABI-31 connect_norito_bridge with orderbook/PDP symbols is required.");

        var orderbookRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "orderbook");
        var orderOutcome = SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.OrderRequest,
            File.ReadAllBytes(Path.Combine(orderbookRoot, "order_request_v1.to")),
            "order_request_v1.to",
            123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    orderbookRoot,
                    "order_request_validation_outcome_v1.json"),
                Encoding.UTF8),
            orderOutcome);

        foreach (var name in new[]
        {
            "order_request_bad_signature",
            "order_request_trailing_bytes",
        })
        {
            var outcome = SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
                SoraFsOrderbookPayloadKind.OrderRequest,
                File.ReadAllBytes(
                    Path.Combine(orderbookRoot, "negative", $"{name}_v1.to")),
                $"{name}_v1.to",
                123);
            Assert.Equal(
                File.ReadAllText(
                    Path.Combine(
                        orderbookRoot,
                        "negative",
                        $"{name}_validation_outcome_v1.json"),
                    Encoding.UTF8),
                outcome);
        }

        var pdpRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "pdp");
        var commitment = File.ReadAllBytes(Path.Combine(pdpRoot, "commitment_v1.to"));
        var challenge = File.ReadAllBytes(Path.Combine(pdpRoot, "challenge_v1.to"));
        var proof = File.ReadAllBytes(Path.Combine(pdpRoot, "proof_v1.to"));
        var commitmentChallenge =
            SoraFsReferenceValidators.ValidatePdpCommitmentChallengeJson(
                commitment,
                challenge,
                "commitment_v1.to",
                "challenge_v1.to",
                123);
        using (var outcome = JsonDocument.Parse(commitmentChallenge))
        {
            Assert.Equal("Ok", outcome.RootElement.GetProperty("status").GetString());
            Assert.Equal(
                "SFS-PDP-DIAG-000",
                outcome.RootElement.GetProperty("code").GetString());
        }
        var bundle = SoraFsReferenceValidators.ValidatePdpBundleJson(
            commitment,
            challenge,
            proof,
            "commitment_v1.to",
            "challenge_v1.to",
            "proof_v1.to",
            123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(pdpRoot, "bundle_validation_outcome_v1.json"),
                Encoding.UTF8),
            bundle);

        foreach (var (name, kind) in new[]
        {
            ("duplicate_hot_leaf_challenge", SoraFsPdpPayloadKind.Challenge),
            ("missing_signature_proof", SoraFsPdpPayloadKind.Proof),
        })
        {
            var outcome = SoraFsReferenceValidators.ValidatePdpPayloadJson(
                kind,
                ReadPdpNegative(pdpRoot, name),
                $"{name}_v1.to",
                123);
            AssertPdpOutcome(pdpRoot, name, outcome);
        }

        foreach (var name in new[]
        {
            "late_proof",
            "wrong_manifest_proof",
            "wrong_provider_proof",
        })
        {
            var outcome = SoraFsReferenceValidators.ValidatePdpChallengeProofJson(
                challenge,
                ReadPdpNegative(pdpRoot, name),
                "challenge_v1.to",
                $"{name}_v1.to",
                123);
            AssertPdpOutcome(pdpRoot, name, outcome);
        }

        foreach (var name in new[]
        {
            "missing_hot_leaf_path_proof",
            "missing_segment_path_proof",
            "wrong_path_proof",
        })
        {
            var outcome = SoraFsReferenceValidators.ValidatePdpBundleJson(
                commitment,
                challenge,
                ReadPdpNegative(pdpRoot, name),
                "commitment_v1.to",
                "challenge_v1.to",
                $"{name}_v1.to",
                123);
            AssertPdpOutcome(pdpRoot, name, outcome);
        }
    }

    [Fact]
    public void AppealFinanceCancelAssetLockProfilesMatchNativeReference()
    {
        Assert.True(
            SoraFsReferenceValidators.IsAppealFinanceAvailable(),
            "ABI-31 appeal-finance reference bridge is required.");
        var fixtureRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "appeal_finance");
        var profiles = new[]
        {
            (
                Path: "cancel_asset_lock_v1.to",
                Status: "Ok",
                Code: "SFS-OK-000",
                Category: "validation"),
            (
                Path: Path.Combine(
                    "negative",
                    "cancel_asset_lock_legacy_missing_expected_v1.to"),
                Status: "Error",
                Code: "SFS-NORITO-001",
                Category: "norito"),
            (
                Path: Path.Combine(
                    "negative",
                    "cancel_asset_lock_zero_expected_v1.to"),
                Status: "Error",
                Code: "SFS-VAL-001",
                Category: "validation"),
        };

        foreach (var profile in profiles)
        {
            var outcomeJson =
                SoraFsReferenceValidators.ValidateAppealFinanceCancelAssetLockJson(
                    File.ReadAllBytes(Path.Combine(fixtureRoot, profile.Path)),
                    Path.GetFileName(profile.Path),
                    123);
            using var outcome = JsonDocument.Parse(outcomeJson);
            Assert.Equal(
                profile.Status,
                outcome.RootElement.GetProperty("status").GetString());
            Assert.Equal(
                profile.Code,
                outcome.RootElement.GetProperty("code").GetString());
            Assert.Equal(
                profile.Category,
                outcome.RootElement.GetProperty("category").GetString());
            Assert.Equal(1, outcome.RootElement.GetProperty("version").GetInt32());
            Assert.Equal(
                123ul,
                outcome.RootElement.GetProperty("generated_at").GetUInt64());
            Assert.Contains(
                "sorafs.reference.appeal_finance",
                outcome.RootElement
                    .GetProperty("telemetry_tags")
                    .EnumerateArray()
                    .Select(tag => tag.GetString()));
        }

        var referenceRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "reference_sdk");
        foreach (var profile in new[]
        {
            (
                Path: "cancel_asset_lock_v1.to",
                Expected:
                    "appeal_finance_cancel_asset_lock_positive_validation_outcome_v1.json"),
            (
                Path: Path.Combine(
                    "negative",
                    "cancel_asset_lock_zero_expected_v1.to"),
                Expected:
                    "appeal_finance_cancel_asset_lock_zero_expected_negative_validation_outcome_v1.json"),
        })
        {
            var outcome =
                SoraFsReferenceValidators.ValidateAppealFinanceCancelAssetLockJson(
                    File.ReadAllBytes(Path.Combine(fixtureRoot, profile.Path)),
                    Path.GetFileName(profile.Path),
                    123);
            Assert.Equal(
                File.ReadAllText(
                    Path.Combine(referenceRoot, profile.Expected),
                    Encoding.UTF8),
                outcome);
        }
    }

    [Fact]
    public void OrderbookBuildersProduceAcceptedPayloads()
    {
        Assert.True(
            SoraFsReferenceValidators.IsOrderbookPdpAvailable(),
            "ABI-31 connect_norito_bridge with orderbook/PDP symbols is required.");
        var privateKey = Enumerable.Repeat((byte)0xb7, 32).ToArray();
        var owner = Encoding.UTF8.GetBytes("buyer@sora");
        var orderId = SoraFsReferenceValidators.DeriveOrderbookOrderId(owner, 7);
        Assert.Equal(
            "9d91ad7700ca0c4762e031f9231aa38dd4502c6048c6ffa31d365e3c4e080b69",
            Convert.ToHexString(orderId).ToLowerInvariant());

        var order = SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
            SoraFsOrderbookSide.Bid,
            SoraFsOrderbookTier.Hot,
            "1.25",
            64,
            owner,
            1_800_000_000,
            7,
            10,
            15,
            privateKey);
        AssertOutcomeOk(SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.OrderRequest,
            order,
            null,
            123));

        var ask = SoraFsReferenceValidators.BuildSignedOrderbookOrderRequest(
            SoraFsOrderbookSide.Ask,
            SoraFsOrderbookTier.Hot,
            "1.25",
            4,
            owner,
            1_800_000_000,
            8,
            10,
            15,
            privateKey,
            providerId: Enumerable.Repeat((byte)0x72, 32).ToArray());
        AssertOutcomeOk(SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.OrderRequest,
            ask,
            null,
            123));

        var cancel = SoraFsReferenceValidators.BuildSignedOrderbookOrderCancel(
            orderId,
            owner,
            SoraFsOrderbookCancelReason.OwnerRequested,
            8,
            privateKey);
        AssertOutcomeOk(SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.OrderCancel,
            cancel,
            null,
            123));

        var receipt = SoraFsReferenceValidators.BuildSignedOrderbookSettlementReceipt(
            Enumerable.Repeat((byte)0x21, 32).ToArray(),
            Enumerable.Repeat((byte)0x22, 32).ToArray(),
            Enumerable.Repeat((byte)0x23, 32).ToArray(),
            0,
            4_096,
            Enumerable.Repeat((byte)0x24, 32).ToArray(),
            4_096,
            "1.000000001",
            "1",
            "0.000000001",
            1_700_000_999,
            privateKey);
        AssertOutcomeOk(SoraFsReferenceValidators.ValidateOrderbookPayloadJson(
            SoraFsOrderbookPayloadKind.SettlementReceipt,
            receipt,
            null,
            123));
    }

    [Fact]
    public void GovernanceLogNodeMatchesModerationGoldenByteForByte()
    {
        Assert.True(
            SoraFsReferenceValidators.IsAvailable(),
            "ABI-31 connect_norito_bridge with governance reference symbols is required.");

        var fixtureRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "moderation");
        using var node = JsonDocument.Parse(
            File.ReadAllText(
                Path.Combine(fixtureRoot, "governance_node_v1.json"),
                Encoding.UTF8));
        var expectedCid = Convert.FromHexString(
            node.RootElement.GetProperty("node_cid_hex").GetString()
            ?? throw new InvalidOperationException(
                "Moderation governance fixture is missing node_cid_hex."));

        var actual = SoraFsReferenceValidators.ValidateGovernanceLogNode(
            File.ReadAllBytes(Path.Combine(fixtureRoot, "governance_node_v1.to")),
            expectedCid,
            "moderation/governance_node_v1.to",
            1_700_001_234);

        Assert.Equal(
            File.ReadAllBytes(
                Path.Combine(
                    fixtureRoot,
                    "governance_node_validation_outcome_v1.json")),
            Encoding.UTF8.GetBytes(actual));
    }

    [Fact]
    public void GovernanceFixturesAndNegativeVectorsMatchNativeReference()
    {
        Assert.True(
            SoraFsReferenceValidators.IsAvailable(),
            "ABI-31 connect_norito_bridge with Governance DAG symbols is required.");

        var fixtureRoot = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "sorafs_manifest",
            "governance");
        var first = File.ReadAllBytes(Path.Combine(fixtureRoot, "dag_block_0_v1.to"));
        var second = File.ReadAllBytes(Path.Combine(fixtureRoot, "dag_block_1_v1.to"));
        var head = File.ReadAllBytes(Path.Combine(fixtureRoot, "dag_head_v1.to"));
        var blocks = new[]
        {
            new SoraFsGovernanceDagBlockInput(
                first,
                "dag_block_0_v1.to"),
            new SoraFsGovernanceDagBlockInput(
                second,
                "dag_block_1_v1.to"),
        };
        var expected = File.ReadAllText(
            Path.Combine(fixtureRoot, "dag_head_validation_outcome_v1.json"),
            Encoding.UTF8);

        var blockOutcome = SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
            first,
            "dag_block_0_v1.to",
            null,
            123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_block_validation_outcome_v1.json"),
                Encoding.UTF8),
            blockOutcome);

        var cidMismatch = SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
            first,
            null,
            Enumerable.Repeat((byte)0x7f, 32).ToArray(),
            123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_block_cid_mismatch_validation_outcome_v1.json"),
                Encoding.UTF8),
            cidMismatch);

        var headOutcome = SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
            head,
            blocks,
            "dag_head_v1.to",
            123);
        Assert.Equal(expected, headOutcome);

        var reordered = SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
            head,
            new[]
            {
                new SoraFsGovernanceDagBlockInput(second),
                new SoraFsGovernanceDagBlockInput(first),
            },
            null,
            123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_head_reordered_validation_outcome_v1.json"),
                Encoding.UTF8),
            reordered);

        var blockSignatureOutcome =
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                File.ReadAllBytes(
                    Path.Combine(
                        fixtureRoot,
                        "dag_block_bad_signature_v1.to")),
                "dag_block_bad_signature_v1.to",
                null,
                123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_block_bad_signature_validation_outcome_v1.json"),
                Encoding.UTF8),
            blockSignatureOutcome);

        var trailingBytesOutcome =
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                File.ReadAllBytes(
                    Path.Combine(
                        fixtureRoot,
                        "dag_block_trailing_bytes_v1.to")),
                "dag_block_trailing_bytes_v1.to",
                null,
                123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_block_trailing_bytes_validation_outcome_v1.json"),
                Encoding.UTF8),
            trailingBytesOutcome);

        var headSignatureOutcome =
            SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
                File.ReadAllBytes(
                    Path.Combine(
                        fixtureRoot,
                        "dag_head_bad_signature_v1.to")),
                blocks,
                "dag_head_bad_signature_v1.to",
                123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_head_bad_signature_validation_outcome_v1.json"),
                Encoding.UTF8),
            headSignatureOutcome);

        var predecessorOutcome =
            SoraFsReferenceValidators.ValidateGovernanceDagHeadChainJson(
                File.ReadAllBytes(
                    Path.Combine(
                        fixtureRoot,
                        "dag_head_bad_predecessor_v1.to")),
                new[]
                {
                    new SoraFsGovernanceDagBlockInput(
                        first,
                        "dag_block_0_v1.to"),
                    new SoraFsGovernanceDagBlockInput(
                        File.ReadAllBytes(
                            Path.Combine(
                                fixtureRoot,
                                "dag_block_1_bad_predecessor_v1.to")),
                        "dag_block_1_bad_predecessor_v1.to"),
                },
                "dag_head_bad_predecessor_v1.to",
                123);
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    fixtureRoot,
                    "dag_head_bad_predecessor_validation_outcome_v1.json"),
                Encoding.UTF8),
            predecessorOutcome);
    }

    [Fact]
    public void InvalidOutcomeJsonFailsClosedAndStillFreesOutput()
    {
        var native = new FakeNativeBoundary
        {
            OutputFactory = generatedAt => Encoding.UTF8.GetBytes(
                ValidOutcomeJson(generatedAt).Replace(
                    "\"generated_at\":" + generatedAt,
                    "\"generated_at\":" + generatedAt
                        + ",\"generated_at\":" + generatedAt,
                    StringComparison.Ordinal)),
        };

        var error = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                789,
                native));

        Assert.Contains("must not appear more than once", error.Message, StringComparison.Ordinal);
        Assert.Equal(1, native.FreeCalls);
    }

    [Fact]
    public void TimestampSubstitutionAndInvalidUtf8FailClosed()
    {
        var timestampNative = new FakeNativeBoundary
        {
            OutputFactory = _ => Encoding.UTF8.GetBytes(ValidOutcomeJson(999)),
        };
        var timestampError = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                1,
                timestampNative));
        Assert.Contains("generated_at", timestampError.Message, StringComparison.Ordinal);
        Assert.Equal(1, timestampNative.FreeCalls);

        var utf8Native = new FakeNativeBoundary
        {
            OutputFactory = _ => new byte[] { 0xff },
        };
        var utf8Error = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                1,
                utf8Native));
        Assert.Contains("invalid UTF-8", utf8Error.Message, StringComparison.Ordinal);
        Assert.Equal(1, utf8Native.FreeCalls);
    }

    [Fact]
    public void BridgeErrorsFreeAnyReturnedAllocation()
    {
        var native = new FakeNativeBoundary { ReturnCode = -114 };

        var error = Assert.Throws<InvalidOperationException>(() =>
            SoraFsReferenceValidators.ValidateGovernanceDagBlockJson(
                new byte[] { 1 },
                "block.to",
                null,
                1,
                native));

        Assert.Contains("-114", error.Message, StringComparison.Ordinal);
        Assert.Equal(1, native.FreeCalls);
    }

    private static byte[] ReadPdpNegative(string pdpRoot, string name)
    {
        return File.ReadAllBytes(
            Path.Combine(pdpRoot, "negative", $"{name}_v1.to"));
    }

    private static void AssertPdpOutcome(
        string pdpRoot,
        string name,
        string actual)
    {
        Assert.Equal(
            File.ReadAllText(
                Path.Combine(
                    pdpRoot,
                    "negative",
                    $"{name}_validation_outcome_v1.json"),
                Encoding.UTF8),
            actual);
    }

    private static void AssertOutcomeOk(string json)
    {
        using var outcome = JsonDocument.Parse(json);
        Assert.Equal("Ok", outcome.RootElement.GetProperty("status").GetString());
    }

    private static string ValidOutcomeJson(ulong generatedAt)
    {
        var outcome = new Dictionary<string, object?>
        {
            ["status"] = "Ok",
            ["code"] = "SFS-OK-000",
            ["category"] = "validation",
            ["message"] = "governance DAG payload accepted",
            ["action"] = null,
            ["docs_url"] = "https://docs.iroha.tech/",
            ["telemetry_tags"] = new[] { "sorafs.reference.governance_dag" },
            ["context"] = Array.Empty<object>(),
            ["inputs"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["kind"] = "governance_dag_block",
                    ["path"] = "block.to",
                },
            },
            ["version"] = 1,
            ["generated_at"] = generatedAt,
        };
        return JsonSerializer.Serialize(outcome);
    }

    private sealed class FakeNativeBoundary : ISoraFsReferenceNativeBoundary
    {
        private readonly HashSet<IntPtr> allocations = new();

        internal uint Abi { get; set; } = 31;

        internal Exception? AbiError { get; set; }

        internal bool SymbolsAvailable { get; set; } = true;

        internal bool OrderbookPdpSymbolsAvailable { get; set; } = true;

        internal bool FixtureBundleSymbolsAvailable { get; set; } = true;

        internal bool AppealFinanceSymbolsAvailable { get; set; } = true;

        internal int ReturnCode { get; set; }

        internal Func<ulong, byte[]> OutputFactory { get; set; } =
            generatedAt => Encoding.UTF8.GetBytes(ValidOutcomeJson(generatedAt));

        internal int LogNodeCalls { get; private set; }

        internal int BlockCalls { get; private set; }

        internal int HeadCalls { get; private set; }

        internal int OrderbookCalls { get; private set; }

        internal int AppealFinanceCalls { get; private set; }

        internal int PdpBundleCalls { get; private set; }

        internal int FixtureBundleCalls { get; private set; }

        internal int FreeCalls { get; private set; }

        internal uint LastOrderbookKind { get; private set; }

        internal byte[]? LastOrderbookBytes { get; private set; }

        internal byte[]? LastOrderbookLabel { get; private set; }

        internal byte[]? LastAppealFinanceBytes { get; private set; }

        internal byte[]? LastAppealFinanceLabel { get; private set; }

        internal byte[]? LastPdpCommitment { get; private set; }

        internal byte[]? LastPdpCommitmentLabel { get; private set; }

        internal byte[]? LastPdpChallenge { get; private set; }

        internal byte[]? LastPdpChallengeLabel { get; private set; }

        internal byte[]? LastPdpProof { get; private set; }

        internal byte[]? LastPdpProofLabel { get; private set; }

        internal byte[]? LastLogNodeBytes { get; private set; }

        internal byte[]? LastLogNodeLabel { get; private set; }

        internal byte[]? LastLogNodeExpectedCid { get; private set; }

        internal byte[]? LastBlockBytes { get; private set; }

        internal byte[]? LastBlockLabel { get; private set; }

        internal byte[]? LastExpectedCid { get; private set; }

        internal byte[]? LastHeadBytes { get; private set; }

        internal byte[]? LastHeadLabel { get; private set; }

        internal NativeGovernanceInput[]? LastBlocks { get; private set; }

        internal NativeFixtureBundleInput[]? LastFixtureBundlePayloads { get; private set; }

        internal ulong LastNowUnix { get; private set; }

        internal ulong LastGeneratedAt { get; private set; }

        public uint AbiVersion()
        {
            if (AbiError is not null)
            {
                throw AbiError;
            }
            return Abi;
        }

        public bool HasGovernanceDagSymbols()
        {
            return SymbolsAvailable;
        }

        public bool HasOrderbookPdpSymbols()
        {
            return OrderbookPdpSymbolsAvailable;
        }

        public bool HasFixtureBundleSymbols()
        {
            return FixtureBundleSymbolsAvailable;
        }

        public bool HasAppealFinanceSymbols()
        {
            return AppealFinanceSymbolsAvailable;
        }

        public NativeValidationResult ValidateOrderbookPayload(
            uint kind,
            byte[] bytes,
            byte[] label,
            ulong generatedAt)
        {
            OrderbookCalls++;
            LastOrderbookKind = kind;
            LastOrderbookBytes = bytes;
            LastOrderbookLabel = label;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidateAppealFinanceCancelAssetLock(
            byte[] bytes,
            byte[] label,
            ulong generatedAt)
        {
            AppealFinanceCalls++;
            LastAppealFinanceBytes = bytes;
            LastAppealFinanceLabel = label;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult SignOrderbookPayload(
            uint kind,
            byte[] bytes,
            byte[] privateKey)
        {
            return AllocateBytes(bytes.Concat(new byte[] { (byte)kind }).ToArray());
        }

        public int DeriveOrderbookOrderId(
            byte[] ownerAccount,
            ulong nonce,
            byte[] output)
        {
            Array.Fill(output, checked((byte)nonce));
            return ReturnCode;
        }

        public NativeValidationResult BuildSignedOrderbookOrderRequest(
            byte[] orderId,
            uint side,
            uint tier,
            byte[] pricePerGib,
            ulong quantityGib,
            ulong remainingGib,
            byte[] ownerAccount,
            byte[] providerId,
            ulong expiryUnix,
            ulong nonce,
            uint makerFeeBps,
            uint takerFeeBps,
            byte[] privateKey)
        {
            return AllocateBytes(orderId);
        }

        public NativeValidationResult BuildSignedOrderbookOrderCancel(
            byte[] orderId,
            byte[] ownerAccount,
            uint reason,
            ulong nonce,
            byte[] privateKey)
        {
            return AllocateBytes(orderId);
        }

        public NativeValidationResult BuildSignedOrderbookSettlementReceipt(
            byte[] receiptId,
            byte[] channelId,
            byte[] tradeId,
            ulong rangeStart,
            ulong rangeEnd,
            byte[] chunkHash,
            ulong bytesDelivered,
            byte[] xorDebited,
            byte[] providerCredit,
            byte[] feeAmount,
            ulong issuedAtUnix,
            byte[] privateKey)
        {
            return AllocateBytes(receiptId);
        }

        public NativeValidationResult ValidatePdpPayload(
            uint kind,
            byte[] bytes,
            byte[] label,
            ulong generatedAt)
        {
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidatePdpCommitmentChallenge(
            byte[] commitment,
            byte[] commitmentLabel,
            byte[] challenge,
            byte[] challengeLabel,
            ulong generatedAt)
        {
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidatePdpChallengeProof(
            byte[] challenge,
            byte[] challengeLabel,
            byte[] proof,
            byte[] proofLabel,
            ulong generatedAt)
        {
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidatePdpBundle(
            byte[] commitment,
            byte[] commitmentLabel,
            byte[] challenge,
            byte[] challengeLabel,
            byte[] proof,
            byte[] proofLabel,
            ulong generatedAt)
        {
            PdpBundleCalls++;
            LastPdpCommitment = commitment;
            LastPdpCommitmentLabel = commitmentLabel;
            LastPdpChallenge = challenge;
            LastPdpChallengeLabel = challengeLabel;
            LastPdpProof = proof;
            LastPdpProofLabel = proofLabel;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidateFixtureBundle(
            NativeFixtureBundleInput[] payloads,
            ulong nowUnix,
            ulong generatedAt)
        {
            FixtureBundleCalls++;
            LastFixtureBundlePayloads = payloads;
            LastNowUnix = nowUnix;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidateGovernanceDagBlock(
            byte[] bytes,
            byte[] label,
            byte[] expectedBlockCid,
            ulong generatedAt)
        {
            BlockCalls++;
            LastBlockBytes = bytes;
            LastBlockLabel = label;
            LastExpectedCid = expectedBlockCid;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidateGovernanceLogNode(
            byte[] bytes,
            byte[] label,
            byte[] expectedNodeCid,
            ulong generatedAt)
        {
            LogNodeCalls++;
            LastLogNodeBytes = bytes;
            LastLogNodeLabel = label;
            LastLogNodeExpectedCid = expectedNodeCid;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public NativeValidationResult ValidateGovernanceDagHeadChain(
            byte[] head,
            byte[] headLabel,
            NativeGovernanceInput[] blocks,
            ulong generatedAt)
        {
            HeadCalls++;
            LastHeadBytes = head;
            LastHeadLabel = headLabel;
            LastBlocks = blocks;
            LastGeneratedAt = generatedAt;
            return AllocateResult(generatedAt);
        }

        public void Free(IntPtr pointer)
        {
            Assert.True(allocations.Remove(pointer), "output must be freed exactly once");
            Marshal.FreeHGlobal(pointer);
            FreeCalls++;
        }

        private NativeValidationResult AllocateResult(ulong generatedAt)
        {
            return AllocateBytes(OutputFactory(generatedAt));
        }

        private NativeValidationResult AllocateBytes(byte[] output)
        {
            var pointer = Marshal.AllocHGlobal(output.Length);
            Marshal.Copy(output, 0, pointer, output.Length);
            allocations.Add(pointer);
            return new NativeValidationResult(
                ReturnCode,
                pointer,
                (UIntPtr)output.Length);
        }
    }
}
