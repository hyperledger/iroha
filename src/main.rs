use std::thread;
use std::time::Duration;

mod networking;
mod cache;
mod model;

fn main() {

	println!("Hyperledgerいろは2にようこそ！");

    // Setup data structures
	let block_time_ms = 1000; //TODO: read from config file

	// move block creation to another thread
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(block_time_ms));
            println!("building block");
        }
    });

	// Initialize world state view (reads WSV if it already exists; don't worry, we will audit it
	// later in the background to make sure it hasn't been tampered with)

	// spawn auditor thread from block store to WSV
	//TODO:

	// Set up in-memory transaction caches
	let mst_cache = cache::mst_cache::MST_Cache::new();
	let pendingTxCache = cache::pending_tx_cache::PendingTxCache::new();

	println!("{}", mst_cache);
	println!("{}", pendingTxCache);

    networking::torii::start_torii(&mst_cache, &pendingTxCache);
}
