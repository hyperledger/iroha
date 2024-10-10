//! [`fslock`]-based socket ports locking for test network peers,
//! supporting inter-process and intra-process test execution scenarios.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Write},
};

use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use derive_more::{Deref, Display};
use serde::{Deserialize, Serialize};

const DATA_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.iroha_test_network_run.json");
const LOCK_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.iroha_test_network_run.json.lock"
);

#[derive(Serialize, Deserialize, Default)]
struct LockContent {
    ports_in_use: BTreeSet<u16>,
}

impl LockContent {
    fn read() -> Result<Self> {
        let value = if std::fs::exists(DATA_FILE)? {
            OpenOptions::new()
                .read(true)
                .open(DATA_FILE)
                .wrap_err("failed to open file")
                .and_then(|mut file| {
                    let mut content = String::new();
                    file.read_to_string(&mut content)
                        .wrap_err("failed to read file")?;
                    serde_json::from_str(&content).wrap_err("failed to parse lock file contents")
                })
                .wrap_err_with(|| {
                    eyre!(
                        "Failed to read lock file at {}. Remove it manually to proceed.",
                        DATA_FILE
                    )
                })
                .unwrap()
        } else {
            Default::default()
        };
        Ok(value)
    }

    fn write(&self) -> Result<()> {
        if std::fs::exists(DATA_FILE)? {
            std::fs::remove_file(DATA_FILE)?;
        }
        if self.ports_in_use.is_empty() {
            return Ok(());
        };
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(DATA_FILE)?;
        file.write_all(serde_json::to_string(&self).unwrap().as_bytes())?;
        Ok(())
    }
}

/// Releases the port on [`Drop`].
#[derive(Debug, Deref, Display)]
pub struct AllocatedPort(u16);

impl AllocatedPort {
    pub fn new() -> Self {
        let mut lock = fslock::LockFile::open(LOCK_FILE).expect("path is valid");
        lock.lock().expect("this handle doesn't own the file yet");

        let mut value = LockContent::read().expect("should be able to read the data");

        let mut i = 0;
        let port = loop {
            let port = unique_port::get_unique_free_port().unwrap();
            if !value.ports_in_use.contains(&port) {
                break port;
            }
            i += 1;
            if i == 1000 {
                panic!("cannot find a free port")
            }
        };

        value.ports_in_use.insert(port);

        value.write().expect("should be able to write the data");
        lock.unlock().expect("this handle still holds the lock");

        // eprintln!("[unique port] allocated {port}");

        Self(port)
    }
}

impl Drop for AllocatedPort {
    fn drop(&mut self) {
        let mut lock = fslock::LockFile::open(LOCK_FILE).expect("path is valid");
        lock.lock().expect("doesn't hold it yet");
        let mut value = LockContent::read().expect("should read fine");
        value.ports_in_use.remove(&self.0);
        value.write().expect("should save the result filne");
        lock.unlock().expect("still holds it");

        // eprintln!("[unique port] released {}", self.0);
    }
}
