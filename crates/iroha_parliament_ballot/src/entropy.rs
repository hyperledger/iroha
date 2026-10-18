//! The operating system's random source, behind a small seam the tests can script.
//!
//! Credentials, proving tapes and stamp start nonces come from [`OsEntropy`]. A failure of
//! the random source is [`EntropyUnavailableV1`]: nothing is generated or proved from a
//! partial or substituted buffer, and there is no deterministic fallback.

/// The operating system's random source failed; nothing was produced from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the operating system's random source is unavailable")]
pub struct EntropyUnavailableV1;

/// A source of uniformly random bytes.
pub trait EntropySource {
    /// Fill `dest` completely, or fail without producing anything.
    ///
    /// # Errors
    /// [`EntropyUnavailableV1`] if the source cannot supply the bytes.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailableV1>;
}

/// The operating system's cryptographic random source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailableV1> {
        getrandom::fill(dest).map_err(|_| EntropyUnavailableV1)
    }
}

/// A scripted source for tests: each call takes the next scripted chunk, which must have
/// exactly the requested length; `None` scripts a failure.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ScriptedEntropy {
    script: std::collections::VecDeque<Option<Vec<u8>>>,
    /// Number of `fill` calls so far.
    pub calls: usize,
}

#[cfg(test)]
impl ScriptedEntropy {
    /// A source that returns `chunks` in order and fails once they run out.
    pub fn new(chunks: impl IntoIterator<Item = Option<Vec<u8>>>) -> Self {
        Self {
            script: chunks.into_iter().collect(),
            calls: 0,
        }
    }
}

#[cfg(test)]
impl EntropySource for ScriptedEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailableV1> {
        self.calls += 1;
        match self.script.pop_front() {
            Some(Some(bytes)) => {
                assert_eq!(bytes.len(), dest.len(), "scripted chunk length");
                dest.copy_from_slice(&bytes);
                Ok(())
            }
            Some(None) | None => Err(EntropyUnavailableV1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_os_source_fills_the_whole_buffer() {
        let mut first = [0_u8; 64];
        let mut second = [0_u8; 64];
        OsEntropy.fill(&mut first).expect("os entropy");
        OsEntropy.fill(&mut second).expect("os entropy");
        // 512 random bits are never all zero or equal in practice.
        assert_ne!(first, [0; 64]);
        assert_ne!(first, second);
        assert!(!EntropyUnavailableV1.to_string().is_empty());
    }

    #[test]
    fn a_scripted_source_replays_and_then_fails() {
        let mut source = ScriptedEntropy::new([Some(vec![7; 4]), None]);
        let mut out = [0_u8; 4];
        assert_eq!(source.fill(&mut out), Ok(()));
        assert_eq!(out, [7; 4]);
        assert_eq!(source.fill(&mut out), Err(EntropyUnavailableV1));
        assert_eq!(source.fill(&mut out), Err(EntropyUnavailableV1));
        assert_eq!(source.calls, 3);
    }
}
