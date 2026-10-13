//! Returned-error scope probes over actual service writers and original leaves.
use norito::json::{BoundedJsonError, JsonWriteSink};

const ORIGINAL_DEPTH: usize = 5;
struct Probe {
    output: String,
    cap: usize,
    depth: usize,
    entries: usize,
    denied_entry: Option<usize>,
}
impl Probe {
    fn new(cap: usize, denied_entry: Option<usize>) -> Self {
        Self {
            output: String::new(),
            cap,
            depth: ORIGINAL_DEPTH,
            entries: 0,
            denied_entry,
        }
    }
}
impl JsonWriteSink for Probe {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        let mut bytes = [0_u8; 4];
        self.push_str(value.encode_utf8(&mut bytes))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        let length = self
            .output
            .len()
            .checked_add(value.len())
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if length > self.cap {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.output.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let ordinal = self.entries;
        self.entries += 1;
        if self.denied_entry == Some(ordinal) {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth += 1;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > ORIGINAL_DEPTH,
            "no leave of a refused or caller-owned level"
        );
        self.depth -= 1;
    }
}

/// Compare original bytes and every output-prefix/actual entry refusal at inherited depth.
pub fn audit(
    expected: &str,
    write: impl Fn(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) {
    let mut successful = Probe::new(expected.len(), None);
    write(&mut successful).expect("original supported service writer");
    assert_eq!(successful.output, expected);
    assert_eq!(
        successful.depth, ORIGINAL_DEPTH,
        "successful service inherited depth"
    );
    assert!(
        successful.entries > 0,
        "control reaches an actual owning container"
    );
    for cap in 0..expected.len() {
        let mut refused = Probe::new(cap, None);
        assert_eq!(
            write(&mut refused),
            Err(BoundedJsonError::BodyTooLarge),
            "original service byte cause at cap {cap}"
        );
        assert_eq!(
            refused.depth, ORIGINAL_DEPTH,
            "original service inherited depth at byte cap {cap}"
        );
        assert!(refused.output.len() <= cap);
        assert_eq!(
            refused.output.as_bytes(),
            &expected.as_bytes()[..refused.output.len()]
        );
        refused.output.clear();
        refused.cap = expected.len();
        refused.entries = 0;
        write(&mut refused).expect("same original caller sink retries after byte refusal");
        assert_eq!(refused.output, expected);
        assert_eq!(refused.depth, ORIGINAL_DEPTH);
    }
    for denied in 0..successful.entries {
        let mut refused = Probe::new(usize::MAX, Some(denied));
        assert_eq!(
            write(&mut refused),
            Err(BoundedJsonError::Unsupported),
            "original service entry cause at ordinal {denied}"
        );
        assert_eq!(
            refused.depth, ORIGINAL_DEPTH,
            "original service inherited depth at denied entry {denied}"
        );
        assert_eq!(
            refused.output.as_bytes(),
            &expected.as_bytes()[..refused.output.len()]
        );
        refused.output.clear();
        refused.entries = 0;
        refused.denied_entry = None;
        write(&mut refused).expect("same original caller sink retries after entry refusal");
        assert_eq!(refused.output, expected);
        assert_eq!(refused.depth, ORIGINAL_DEPTH);
    }
}
