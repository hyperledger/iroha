//! Temporary before/after timing probe for interpreter, reset and construction costs.
use ivm::{IVM, Memory, MerkleTree, ProgramMetadata, encoding::wide, instruction};
use std::{hint::black_box, time::Instant};

const REPS: usize = 200_000;
const ROUNDS: usize = 7;

fn program(words: &[u32]) -> Vec<u8> {
    let mut image = ProgramMetadata::default().encode();
    for word in words {
        image.extend_from_slice(&word.to_le_bytes());
    }
    image.extend_from_slice(&wide::encode_halt().to_le_bytes());
    image
}

fn repeated(word: u32) -> Vec<u8> {
    program(&vec![word; REPS])
}

/// Median nanoseconds per instruction over `ROUNDS` fresh runs.
fn run_case(name: &str, image: &[u8], setup: impl Fn(&mut IVM)) {
    let mut samples = Vec::new();
    for round in 0..=ROUNDS {
        let mut vm = IVM::new(1_000_000_000);
        vm.load_program(image).expect("load");
        setup(&mut vm);
        let start = Instant::now();
        vm.run().expect("run");
        let elapsed = start.elapsed().as_nanos() as f64;
        if round > 0 {
            samples.push(elapsed / REPS as f64);
        }
    }
    samples.sort_by(f64::total_cmp);
    println!("{name}: median {:.2} ns/op", samples[samples.len() / 2]);
}

fn main() {
    ivm::set_banner_enabled(false);
    let add = wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2);
    run_case("ADD", &repeated(add), |vm| {
        vm.set_register(1, 123);
        vm.set_register(2, 7);
    });
    let load = wide::encode_load(instruction::wide::memory::LOAD64, 5, 4, 0);
    run_case("LOAD64", &repeated(load), |vm| {
        vm.set_register(4, Memory::HEAP_START);
    });
    let store = wide::encode_store(instruction::wide::memory::STORE64, 4, 1, 0);
    run_case("STORE64", &repeated(store), |vm| {
        vm.set_register(1, 0x55);
        vm.set_register(4, Memory::HEAP_START);
    });

    // Warm runtime reset: one tiny invocation, then restore the captured baseline.
    let tiny = program(&[wide::encode_ri(instruction::wide::arithmetic::ADDI, 7, 7, 1)]);
    let mut vm = IVM::new(1_000_000);
    vm.load_program(&tiny).expect("load");
    let template = vm.try_runtime_template().expect("template");
    let iterations = 2_000;
    let start = Instant::now();
    for _ in 0..iterations {
        vm.run().expect("run");
        vm.reset_from_runtime_template(&template).expect("reset");
    }
    println!(
        "warm run+reset: {:.2} us/iteration",
        start.elapsed().as_nanos() as f64 / iterations as f64 / 1_000.0
    );

    // Cold construction at the maximum ABI V1 stack.
    let constructions = 10;
    let start = Instant::now();
    for _ in 0..constructions {
        black_box(IVM::new(1_000_000_000));
    }
    println!(
        "cold IVM::new: {:.2} ms",
        start.elapsed().as_nanos() as f64 / constructions as f64 / 1e6
    );
    let leaves = (Memory::STACK_START + Memory::STACK_SIZE).div_ceil(32) as usize;
    let digest = [0x5a; 32];
    let start = Instant::now();
    for _ in 0..constructions {
        black_box(MerkleTree::<[u8; 32]>::try_from_repeated_hashed_leaf_sha256(leaves, digest))
            .expect("repeated tree");
    }
    println!(
        "repeated-leaf tree ({leaves} leaves): {:.2} ms",
        start.elapsed().as_nanos() as f64 / constructions as f64 / 1e6
    );
    let digests = vec![digest; leaves];
    let start = Instant::now();
    for _ in 0..constructions {
        black_box(MerkleTree::<[u8; 32]>::try_from_hashed_leaves_sha256(&digests))
            .expect("full rebuild");
    }
    println!(
        "full parent rebuild ({leaves} leaves): {:.2} ms",
        start.elapsed().as_nanos() as f64 / constructions as f64 / 1e6
    );
}
