//! `Maintenance` module provides structures and implementation blocks related to `Iroha`
//! maintenance functions like Healthcheck, Monitoring, etc.

use crate::config::Configuration;
use async_std::task;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

/// Entry point and main entity in `maintenance` API.
/// Provides all information about the system needed for administrators and users.
#[derive(Debug)]
pub struct System {
    configuration: Configuration,
}

impl System {
    /// Default `System` constructor.
    pub fn new(configuration: &Configuration) -> Self {
        System {
            configuration: configuration.clone(),
        }
    }

    /// Scrape current system metrics.
    pub fn scrape_metrics(&self) -> Result<Metrics, String> {
        let mut metrics = Metrics::new(&self.configuration);
        metrics.calculate()?;
        Ok(metrics)
    }
}

/// `Health` enumerates different variants of Iroha `Peer` states.
/// Each variant can provide additional information if needed.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum Health {
    /// `Healthy` variant means that `Peer` has finished initial setup.
    Healthy,
    /// `Ready` variant means that `Peer` bootstrapping completed.
    Ready,
}

/// Metrics struct compose all Iroha metrics and provides an ability to export them in monitoring
/// systems.
#[derive(Clone, Debug, Default, Io, Encode, Decode)]
pub struct Metrics {
    cpu: cpu::Cpu,
    disk: disk::Disk,
    memory: memory::Memory,
}

impl Metrics {
    /// Default `Metrics` constructor.
    pub fn new(configuration: &Configuration) -> Self {
        Metrics {
            disk: disk::Disk::new(&configuration.kura_configuration),
            ..Default::default()
        }
    }

    /// Update current `Metrics` state with new data.
    pub fn calculate(&mut self) -> Result<(), String> {
        self.disk.calculate()?;
        task::block_on(async {
            self.cpu.calculate().await?;
            self.memory.calculate().await
        })?;
        Ok(())
    }
}

mod disk {
    use crate::kura::config::KuraConfiguration;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};
    use std::fs::read_dir;

    #[derive(Clone, Debug, Default, Io, Encode, Decode)]
    pub struct Disk {
        block_storage_size: u64,
        block_storage_path: String,
    }

    impl Disk {
        pub fn new(configuration: &KuraConfiguration) -> Self {
            Disk {
                block_storage_path: configuration.kura_block_store_path.clone(),
                ..Default::default()
            }
        }

        pub fn calculate(&mut self) -> Result<(), String> {
            let mut total_size: u64 = 0;
            for entry in read_dir(&self.block_storage_path)
                .map_err(|e| format!("Failed to read block storage directoru: {}", e))?
            {
                let path = entry
                    .map_err(|e| format!("Failed to retrieve entry path: {}", e))?
                    .path();
                if path.is_file() {
                    total_size += path
                        .metadata()
                        .map_err(|e| format!("Failed to get file metadata: {}", e))?
                        .len();
                }
            }
            self.block_storage_size = total_size;
            Ok(())
        }
    }
}

mod cpu {
    use heim::cpu;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};

    #[derive(Clone, Debug, Default, Io, Encode, Decode)]
    pub struct Cpu {
        load: Load,
    }

    impl Cpu {
        pub fn new() -> Self {
            Cpu::default()
        }

        pub async fn calculate(&mut self) -> Result<(), String> {
            self.load.calculate().await
        }
    }

    #[derive(Clone, Debug, Default, Io, Encode, Decode)]
    pub struct Load {
        frequency: String,
        stats: String,
        time: String,
    }

    impl Load {
        pub fn new() -> Self {
            Load::default()
        }

        pub async fn calculate(&mut self) -> Result<(), String> {
            self.frequency = format!("{:?}", cpu::frequency().await);
            self.stats = format!("{:?}", cpu::stats().await);
            self.time = format!("{:?}", cpu::time().await);
            Ok(())
        }
    }
}

mod memory {
    use heim::memory;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};

    #[derive(Clone, Debug, Default, Io, Encode, Decode)]
    pub struct Memory {
        memory: String,
        swap: String,
    }

    impl Memory {
        pub fn new() -> Self {
            Memory::default()
        }

        pub async fn calculate(&mut self) -> Result<(), String> {
            self.memory = format!("{:?}", memory::memory().await);
            self.swap = format!("{:?}", memory::swap().await);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[async_std::test]
        async fn test_calculate_memory() {
            let mut memory = Memory::default();
            memory
                .calculate()
                .await
                .expect("Failed to calculate memory.");
            assert!(!memory.memory.is_empty());
            assert!(!memory.swap.is_empty());
        }
    }
}
