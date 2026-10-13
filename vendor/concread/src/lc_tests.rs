//! Coordinated publication tests for the synchronous linear cell.

use crate::internals::bptree::cursor::{CursorRead, CursorWrite, SuperBlock};
use crate::internals::lincowcell::{LinCowCell, LinCowCellCapable};

struct TestStruct {
    bptree_map_a: SuperBlock<u32, u32>,
    bptree_map_b: SuperBlock<u32, u32>,
}

struct TestStructRead {
    bptree_map_a: CursorRead<u32, u32>,
    bptree_map_b: CursorRead<u32, u32>,
}

struct TestStructWrite {
    bptree_map_a: CursorWrite<u32, u32>,
    bptree_map_b: CursorWrite<u32, u32>,
}

impl LinCowCellCapable<TestStructRead, TestStructWrite> for TestStruct {
    type WriterInput = ();

    fn create_reader(&self) -> TestStructRead {
        // This sets up the first reader.
        TestStructRead {
            bptree_map_a: self.bptree_map_a.create_reader(),
            bptree_map_b: self.bptree_map_b.create_reader(),
        }
    }

    fn create_writer(&self, (): Self::WriterInput) -> TestStructWrite {
        // This sets up the first writer.
        TestStructWrite {
            bptree_map_a: self.bptree_map_a.create_writer(()),
            bptree_map_b: self.bptree_map_b.create_writer(()),
        }
    }

    fn pre_commit(&mut self, new: TestStructWrite, prev: &TestStructRead) -> TestStructRead {
        let TestStructWrite {
            bptree_map_a,
            bptree_map_b,
        } = new;

        let bptree_map_a = self
            .bptree_map_a
            .pre_commit(bptree_map_a, &prev.bptree_map_a);

        let bptree_map_b = self
            .bptree_map_b
            .pre_commit(bptree_map_b, &prev.bptree_map_b);

        TestStructRead {
            bptree_map_a,
            bptree_map_b,
        }
    }
}

#[test]
fn test_lc_basic() {
    let lcc = LinCowCell::new(TestStruct {
        bptree_map_a: unsafe { SuperBlock::new() },
        bptree_map_b: unsafe { SuperBlock::new() },
    });

    let x = lcc.write();

    x.commit();

    let _r = lcc.read();
}
