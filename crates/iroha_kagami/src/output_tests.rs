//! Buffered command output must finish before success, without replacing command failures.

use super::{developer::PublicationExit, finish_output};
use std::io::{self, BufWriter, Write};

const RECEIPT: &[u8] = b"applied\njournal: original-journal\n";

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail_write: bool,
    fail_flush: bool,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.fail_write {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "output closed"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            return Err(io::Error::other("output flush failed"));
        }
        Ok(())
    }
}

fn buffered(output: Output) -> BufWriter<Output> {
    let mut writer = BufWriter::with_capacity(RECEIPT.len() + 1, output);
    writer
        .write_all(RECEIPT)
        .expect("receipt initially buffers");
    assert_eq!(writer.buffer(), RECEIPT);
    assert_eq!(writer.get_ref().writes, 0);
    writer
}

#[test]
fn buffered_receipt_write_failure_prevents_success() {
    let mut writer = buffered(Output {
        fail_write: true,
        ..Output::default()
    });
    let error = finish_output(&mut writer, Ok(())).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
    let (output, retained) = writer.into_parts();
    assert!(output.bytes.is_empty());
    assert_eq!(output.writes, 1);
    assert_eq!(retained.unwrap(), RECEIPT);
}

#[test]
fn underlying_flush_failure_prevents_success_after_receipt_write() {
    let mut writer = buffered(Output {
        fail_flush: true,
        ..Output::default()
    });
    let error = finish_output(&mut writer, Ok(())).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().to_string(),
        "output flush failed"
    );
    assert_eq!(writer.get_ref().bytes, RECEIPT);
    assert_eq!(writer.get_ref().writes, 1);
    assert_eq!(writer.get_ref().flushes, 1);
    assert!(writer.buffer().is_empty());
}

#[test]
fn successful_receipt_is_flushed_before_success() {
    let mut writer = buffered(Output::default());
    finish_output(&mut writer, Ok(())).unwrap();
    assert_eq!(writer.get_ref().bytes, RECEIPT);
    assert_eq!(writer.get_ref().writes, 1);
    assert_eq!(writer.get_ref().flushes, 1);
    assert!(writer.buffer().is_empty());
}

#[test]
fn original_typed_command_error_survives_buffered_write_failure() {
    let mut writer = buffered(Output {
        fail_write: true,
        ..Output::default()
    });
    let original = io::Error::new(io::ErrorKind::PermissionDenied, "original command failed");
    let error = finish_output(&mut writer, Err(original.into())).unwrap_err();
    let original = error.downcast_ref::<io::Error>().unwrap();
    assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(original.to_string(), "original command failed");
    let (output, retained) = writer.into_parts();
    assert_eq!(output.writes, 1);
    assert_eq!(retained.unwrap(), RECEIPT);
}

#[test]
fn publication_exit_survives_successful_and_failed_output_flush() {
    for fail_flush in [false, true] {
        let mut writer = buffered(Output {
            fail_flush,
            ..Output::default()
        });
        let error = finish_output(&mut writer, Err(PublicationExit(23).into())).unwrap_err();
        assert_eq!(error.downcast_ref::<PublicationExit>().unwrap().0, 23);
        assert_eq!(writer.get_ref().bytes, RECEIPT);
        assert_eq!(writer.get_ref().flushes, 1);
        assert!(writer.buffer().is_empty());
    }
}
