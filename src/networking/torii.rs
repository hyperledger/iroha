use crate::cache;
use std::net::TcpListener;
use std::io::prelude::*;

// Start a simple TCP server
pub fn start_torii(mut mstCache: &cache::mst_cache::MSTCache,
                   mut pendingTxCache: &cache::pending_tx_cache::PendingTxCache) {

    //TODO: make port configurable from config file
    let listener = TcpListener::bind("127.0.0.1:1337").expect("could not start server");

    // accept connections and get a TcpStream
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                //TODO: do some real stuff here
                let mut text = String::new();
                stream.read_to_string(&mut text).expect("read failed");
                println!("got '{}'", text);
            }
            Err(e) => { println!("connection failed {}", e); }
        }
    }
}
