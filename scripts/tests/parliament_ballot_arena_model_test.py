"""Independent allocator topology and trace-admission checks; no native builds."""

import importlib.util
from pathlib import Path
import random
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / "parliament_ballot_arena_model.py"
SPEC = importlib.util.spec_from_file_location("ballot_arena_model", PATH)
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class DenseTree:
    """Independent dense availability-tree transcription of the Rust allocator."""

    def __init__(self, blocks):
        self.blocks = blocks
        self.tree = [0] * (2 * blocks - 1)
        height = blocks.bit_length() - 1
        for depth in range(height + 1):
            for index in range((1 << depth) - 1, (1 << (depth + 1)) - 1):
                self.tree[index] = height - depth + 1

    def allocate(self, blocks):
        wanted = blocks.bit_length()
        if self.tree[0] < wanted:
            return None
        index, width, offset = 0, self.blocks, 0
        while width > blocks:
            width //= 2
            left = index * 2 + 1
            if self.tree[left] >= wanted:
                index = left
            else:
                index, offset = left + 1, offset + width
        self.tree[index] = 0
        while index:
            index = (index - 1) // 2
            self.tree[index] = max(self.tree[index * 2 + 1:index * 2 + 3])
        return offset

    def release(self, offset, blocks):
        index = (self.blocks + offset) // blocks - 1
        available = blocks.bit_length()
        self.tree[index] = available
        while index:
            index = (index - 1) // 2
            left, right = self.tree[index * 2 + 1:index * 2 + 3]
            self.tree[index] = available + 1 if left == right == available else max(left, right)
            available += 1


class BuddyTests(unittest.TestCase):
    def test_layout_validation_and_rounding(self):
        self.assertEqual(MODEL.block_bytes(1, 1), 64)
        self.assertEqual(MODEL.block_bytes(65, 8), 128)
        self.assertEqual(MODEL.block_bytes(3, 256), 256)
        for size, align in [(0, 8), (-1, 8), (True, 8), (5, 3), (5, False)]:
            with self.assertRaises(MODEL.TraceError):
                MODEL.block_bytes(size, align)
        for heap, align, limit in [(63, 8, None), (128, 0, None), (128, 8, -1)]:
            with self.assertRaises(MODEL.TraceError):
                MODEL.Buddy(heap, align, limit)

    def test_leftmost_block_is_not_smallest_available_order(self):
        buddy = MODEL.Buddy(1024, 64)
        self.assertEqual(buddy.allocate("large", 512, 8), 0)
        self.assertEqual(buddy.allocate("small", 64, 8), 512)
        buddy.release("large")
        self.assertEqual(buddy.allocate("next", 64, 8), 0)

    def test_fragmentation_can_fail_despite_half_heap_free(self):
        buddy = MODEL.Buddy(512, 64)
        for index in range(8):
            buddy.allocate(str(index), 64, 8)
        for index in range(0, 8, 2):
            buddy.release(str(index))
        before = buddy.state()
        with self.assertRaisesRegex(MODEL.TraceError, "fragmentation"):
            buddy.allocate("two", 128, 8)
        self.assertEqual(buddy.state(), before)
        for index in range(1, 8, 2):
            buddy.release(str(index))
        self.assertEqual(buddy.allocate("whole", 512, 8), 0)

    def test_spatial_bound_is_sufficient_without_claiming_necessity(self):
        self.assertTrue(MODEL.spatial_admission_bound(1024, 256, [64, 512])[
            "guaranteed_free_block"])
        self.assertFalse(MODEL.spatial_admission_bound(512, 128, [64] * 4)[
            "guaranteed_free_block"])
        # Four adjacent leaves leave a large free half, but the bound does not
        # know they share bins; it correctly declines to promise success.
        buddy = MODEL.Buddy(512, 64)
        for index in range(4):
            buddy.allocate(str(index), 64, 8)
        self.assertEqual(buddy.allocate("two", 128, 8), 256)
        with self.assertRaises(MODEL.TraceError):
            MODEL.spatial_admission_bound(512, 128, [65])

    def test_quota_alignment_ids_and_live_exit(self):
        buddy = MODEL.Buddy(512, 8, 128)
        buddy.allocate("a", 65, 8)
        for name, size, align in [("b", 1, 8), ("a", 1, 8), ("c", 1, 16)]:
            with self.assertRaises(MODEL.TraceError):
                buddy.allocate(name, size, align)
        with self.assertRaises(MODEL.TraceError):
            buddy.report()
        buddy.release("a")
        with self.assertRaises(MODEL.TraceError):
            buddy.release("a")
        self.assertEqual(buddy.report()["live_exit_block_bytes"], 0)

    def test_restoring_loop_checks_full_state_and_multiplies_counts(self):
        buddy = MODEL.Buddy(1024, 64)
        buddy.allocate("retained", 3, 8)
        before = buddy.state()
        buddy.replay([{"op": "repeat_restoring", "id": "loop", "min": 0, "max": 1000,
                       "body": [{"op": "alloc", "id": "scratch", "size": 65, "align": 8},
                                {"op": "free", "id": "scratch"}]}])
        self.assertEqual(buddy.state(), before)
        self.assertEqual(buddy.allocations, 1001)
        self.assertEqual(buddy.peak_blocks, 192)
        with self.assertRaisesRegex(MODEL.TraceError, "restore"):
            buddy.replay([{"op": "repeat_restoring", "id": "bad", "min": 1, "max": 2,
                           "body": [{"op": "free", "id": "retained"}]}])

    def test_nested_and_zero_repeats_and_unknown_events(self):
        buddy = MODEL.Buddy(1024, 64)
        unit = {"op": "repeat_restoring", "id": "inner", "min": 1, "max": 3,
                "body": [{"op": "alloc", "id": "scratch", "size": 8, "align": 8},
                         {"op": "free", "id": "scratch"}]}
        buddy.replay([{"op": "repeat_restoring", "id": "outer", "min": 2, "max": 5,
                       "body": [unit]}])
        self.assertEqual(buddy.allocations, 15)
        buddy.replay([{"op": "repeat_restoring", "min": 0, "max": 0, "body": []}])
        for event in [{"op": "lost"}, {"op": "alloc"}, None,
                      {"op": "repeat_restoring", "min": 1, "max": 0, "body": []}]:
            with self.assertRaises(MODEL.TraceError):
                buddy.replay([event])

    def test_seeded_fragmented_traces_match_dense_tree_at_each_operation(self):
        for seed in range(12):
            randomizer = random.Random(seed)
            buddy, dense = MODEL.Buddy(8192, 64), DenseTree(128)
            live = {}
            for step in range(1200):
                if live and randomizer.randrange(3) == 0:
                    name = randomizer.choice(list(live))
                    offset, blocks = live.pop(name)
                    buddy.release(name)
                    dense.release(offset // 64, blocks)
                else:
                    size = randomizer.randrange(1, 1800)
                    blocks = MODEL.block_bytes(size, 8) // 64
                    expected = dense.allocate(blocks)
                    name = str(step)
                    if expected is None:
                        with self.assertRaises(MODEL.TraceError):
                            buddy.allocate(name, size, 8)
                    else:
                        actual = buddy.allocate(name, size, 8)
                        self.assertEqual(actual, expected * 64)
                        live[name] = actual, blocks
            for name, (offset, blocks) in live.items():
                buddy.release(name)
                dense.release(offset // 64, blocks)
            self.assertEqual(buddy.state(), MODEL.Buddy(8192, 64).state())
            self.assertEqual(dense.tree, DenseTree(128).tree)


if __name__ == "__main__":
    unittest.main()
