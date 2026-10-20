using System.Collections;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using Hyperledger.Iroha.Petal;

namespace Hyperledger.Iroha.Sdk.Tests;

/// <summary>Shared camera evidence for bounded, header-checked capture averaging.</summary>
public sealed class PetalMergeTests
{
    private static PetalLuma Image(JsonElement set, JsonElement capture)
    {
        using var input = new MemoryStream(Convert.FromBase64String(capture.GetProperty("luma_zlib_base64").GetString()!));
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return new PetalLuma(set.GetProperty("width").GetInt32(), set.GetProperty("height").GetInt32(), output.ToArray());
    }

    [Theory]
    [InlineData("merges", "noisy-480p")]
    [InlineData("merges", "banded-480p")]
    [InlineData("mixed_merges", "mixed-frames-480p")]
    public void SharedCapturesRecoverOnlyTheNamedShownFrame(string group, string name)
    {
        var set = PetalTestSupport.Captures.GetProperty(group).EnumerateArray().Single(s => s.GetProperty("name").GetString() == name);
        var evidence = new List<PetalTileEvidence>();
        var session = new PetalScanSession();
        var recovered = string.Empty;
        var index = 0;
        foreach (var capture in set.GetProperty("captures").EnumerateArray())
        {
            var image = Image(set, capture);
            var decoded = PetalDecoder.Decode(image);
            Assert.True(decoded.Success);
            Assert.Equal(capture.GetProperty("reference_decoded").GetString(), decoded.Frame.Lanes);
            var item = PetalDecoder.TileEvidence(image, decoded.Frame);
            Assert.NotNull(item);
            evidence.Add(item);
            var single = PetalDecoder.MergeTiles(new[] { item });
            Assert.Equal(decoded.Frame.P, single.P);
            Assert.Equal(decoded.Frame.K, single.K);
            recovered += session.Push(image, 33L * index++).Merged;
        }
        var (p, k) = PetalDecoder.MergeTiles(evidence);
        Assert.Equal(set.GetProperty("reference_merged").GetString(), (p is null ? "" : "P") + (k is null ? "" : "K"));
        if (p is not null)
            Assert.Equal(PetalTestSupport.Hex(set, "p_data"), p.Data);
        if (k is not null)
            Assert.Equal(PetalTestSupport.Hex(set, "k_data"), k.Data);
        Assert.True(session.Stats.Merges > 0);
        foreach (var letter in set.GetProperty("must_merge").GetString()!)
            Assert.Contains(letter, recovered);
        if (group == "mixed_merges")
        {
            Assert.Empty(recovered);
            Assert.Equal(0u, session.Stats.MergedP + session.Stats.MergedK);
        }
        else
        {
            Assert.Equal((uint)recovered.Count(c => c == 'P'), session.Stats.MergedP);
            Assert.Equal((uint)recovered.Count(c => c == 'K'), session.Stats.MergedK);
        }
    }

    [Fact]
    public void EvidenceIsOwnedAndEmptyOrUnusableEvidenceCannotDecode()
    {
        Assert.Equal((null, null), PetalDecoder.MergeTiles(Array.Empty<PetalTileEvidence>()));
        var capture = PetalTestSupport.Captures.GetProperty("captures")[0];
        var image = PetalTestSupport.LumaOf(capture);
        var decoded = PetalDecoder.Decode(image).Frame!;
        var evidence = PetalDecoder.TileEvidence(image, decoded)!;
        var expected = PetalDecoder.MergeTiles(new[] { evidence });
        Array.Clear(image.Data);
        Assert.Equal(expected, PetalDecoder.MergeTiles(new[] { evidence }));
        Assert.Null(PetalDecoder.TileEvidence(new PetalLuma(8, 8), decoded));
        var invalid = new PetalDecodedFrame(decoded.Homography, 0, false, decoded.P, decoded.K, decoded.D, 4);
        Assert.Null(PetalDecoder.TileEvidence(new PetalLuma(64, 64), invalid));
    }

    private static IList Held(PetalScanSession session) =>
        (IList)typeof(PetalScanSession).GetField("held", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(session)!;

    private static void Absorb(PetalScanSession session, PetalDecodedFrame frame) =>
        typeof(PetalScanSession).GetMethod("Absorb", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(session, new object[] { frame });

    private static PetalDecodedFrame OnlyD(PetalDecodedFrame frame) =>
        new(frame.Homography, frame.Rotation, frame.Mirrored, null, null, frame.D, frame.InferredCorner);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AcceptedStreamReplacementDropsOldEvidenceAndDoneFlagsWithTheSameShortTag(bool complete)
    {
        static PetalStreamEncoder Encoder(byte value)
        {
            var payload = new byte[100];
            payload[3] = value;
            return new PetalStreamEncoder(payload, 2);
        }
        var old = Encoder(49);
        var next = Encoder(128);
        Assert.Equal((byte)61, old.Meta.Tag);
        Assert.Equal(old.Meta.Tag, next.Meta.Tag);
        Assert.NotEqual(old.Meta, next.Meta);
        var oldImage = PetalTestSupport.RenderLuma(old, 0, 512, 2);
        var nextImage = PetalTestSupport.RenderLuma(next, 0, 512, 2);
        var previous = PetalDecoder.Decode(oldImage).Frame!;
        if (!complete)
            previous = OnlyD(previous);
        var partial = OnlyD(PetalDecoder.Decode(nextImage).Frame!);
        var session = new PetalScanSession();
        Absorb(session, previous);
        session.Merge(oldImage, previous);
        Assert.NotEmpty(Held(session));
        Absorb(session, partial);
        Absorb(session, partial);
        Assert.Equal(next.Meta, session.Progress.Meta);
        Assert.Empty(Held(session));
        Assert.Empty(session.Merge(nextImage, partial));
        Assert.Equal("PK", session.Merge(nextImage, partial));
    }

    [Fact]
    public void TheFirstBeaconKeepsValidPreBeaconEvidence()
    {
        var encoder = new PetalStreamEncoder(PetalTestSupport.Payload(700, 2), 2);
        var image = PetalTestSupport.RenderLuma(encoder, 1, 512, 2);
        var partial = OnlyD(PetalDecoder.Decode(image).Frame!);
        var session = new PetalScanSession();
        Absorb(session, partial);
        session.Merge(image, partial);
        Assert.Null(session.Progress.Meta);
        var beacon = PetalTestSupport.RenderLuma(encoder, 0, 512, 2);
        Absorb(session, OnlyD(PetalDecoder.Decode(beacon).Frame!));
        Assert.Equal(encoder.Meta, session.Progress.Meta);
        Assert.Single(Held(session));
        Assert.Equal("PK", session.Merge(image, partial));
    }

    [Fact]
    public void TornAndUnkeyedFramesAreNotRetainedAndMemoryIsBoundedAndReset()
    {
        var capture = PetalTestSupport.Captures.GetProperty("captures")[0];
        var image = PetalTestSupport.LumaOf(capture);
        var original = PetalDecoder.Decode(image).Frame!;
        PetalDecodedFrame OnlyD(ushort frame)
        {
            var data = (byte[])original.D!.Data.Clone();
            data[1] = (byte)(frame >> 8);
            data[2] = (byte)frame;
            return new PetalDecodedFrame(original.Homography, original.Rotation, original.Mirrored, null, null, new PetalLaneResult(data, 0, 0), original.InferredCorner);
        }
        var session = new PetalScanSession();
        var unkeyed = new PetalDecodedFrame(original.Homography, 0, false, null, null, null, null);
        Assert.Empty(session.Merge(image, unkeyed));
        var torn = new PetalDecodedFrame(original.Homography, 0, false, original.P, null, OnlyD(100).D, null);
        Assert.Empty(session.Merge(image, torn));
        Assert.Empty(Held(session));
        for (ushort frame = 100; frame < 110; frame++)
            for (var sample = 0; sample < 6; sample++)
                Assert.Empty(session.Merge(image, OnlyD(frame)));
        Assert.Equal(PetalScanSession.MergeWindow, Held(session).Count);
        foreach (var item in Held(session))
        {
            var samples = (IList)item!.GetType().GetProperty("Evidence")!.GetValue(item)!;
            Assert.Equal(PetalScanSession.MergeCaptures, samples.Count);
        }
        var attempts = session.Stats.Merges;
        session.Reset();
        Assert.Empty(Held(session));
        Assert.Empty(session.Merge(image, OnlyD(109)));
        Assert.Equal(attempts, session.Stats.Merges);
    }
}
