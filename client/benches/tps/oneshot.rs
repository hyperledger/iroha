//! Single trial of the benchmark

mod lib;

use std::{fs::File, io::BufWriter};

use tracing_flame::{FlameLayer, FlushGuard};
use tracing_subscriber::prelude::*;

#[allow(clippy::expect_used, clippy::print_stdout, clippy::use_debug)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut flush_guard: Option<FlushGuard<BufWriter<File>>> = None;

    if args.len() >= 2 {
        let file = File::create(&args[1]).expect("valid path");

        let flame_layer = FlameLayer::new(BufWriter::new(file))
            .with_threads_collapsed(true)
            .with_empty_samples(true);
        flush_guard = Some(flame_layer.flush_on_drop());

        tracing_subscriber::registry().with(flame_layer).init();
        iroha_logger::disable_logger();
    }

    let config = lib::Config::from_path("benches/tps/config.json").expect("Failed to configure");
    let tps = config.measure().expect("Failed to measure");

    flush_guard.map_or_else(
        || {
            iroha_logger::info!(?config);
            iroha_logger::info!(%tps);
        },
        |guard| {
            guard.flush().expect("Flushed data without errors");
            println!("Tracing data outputted to file: {}", &args[1]);
            println!("TPS was {}", tps);
            println!("Config was {:?}", config);
        },
    )
}
