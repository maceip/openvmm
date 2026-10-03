// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-only packet decisions. No payload, header strings, or credentials enter this log.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

struct Sink {
    file: File,
    sequence: u64,
}
static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();

/// Reserve a fresh run log before queues start. A path supplied by the host
/// cannot overwrite an existing file or follow a symlink.
pub fn initialize() -> std::io::Result<()> {
    if SINK.get().is_some() {
        return Ok(());
    }
    let sink = if let Some(path) = std::env::var_os("NVX_FLOW_LOG") {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Some(Sink {
            file: options.open(path)?,
            sequence: 0,
        })
    } else {
        None
    };
    let _ = SINK.set(Mutex::new(sink));
    Ok(())
}

/// Record the immutable packet's policy decision immediately before transmit.
/// IPv4 transport tuples only; malformed frames and payloads are never logged.
pub fn record(frame: &[u8], allowed: bool) {
    if frame.len() < 38 || frame[12..14] != [8, 0] || frame[14] != 0x45 {
        return;
    }
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if total < 24 || total + 14 > frame.len() || frame[20] & 0x3f != 0 || frame[21] != 0 {
        return;
    }
    let proto = match frame[23] {
        6 => "tcp",
        17 => "udp",
        _ => return,
    };
    let Some(sink) = SINK.get() else { return };
    let mut guard = sink.lock().expect("host flow log mutex poisoned");
    let Some(sink) = guard.as_mut() else { return };
    if sink.sequence > 100_000 {
        return;
    }
    sink.sequence += 1;
    let line = if sink.sequence == 100_001 {
        "{\"flow_version\":1,\"truncated\":true}\n".to_owned()
    } else {
        let src = std::net::Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
        let dst = std::net::Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
        let src_port = u16::from_be_bytes([frame[34], frame[35]]);
        let dst_port = u16::from_be_bytes([frame[36], frame[37]]);
        let verdict = if allowed { "allowed" } else { "denied" };
        let time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            "{{\"flow_version\":1,\"sequence\":{},\"time_ns\":{time_ns},\"src\":\"{src}\",\"src_port\":{src_port},\"dst\":\"{dst}\",\"dst_port\":{dst_port},\"proto\":\"{proto}\",\"verdict\":\"{verdict}\",\"bytes\":{total}}}\n",
            sink.sequence
        )
    };
    // Continuing with missing audit decisions would create a misleading receipt.
    sink.file
        .write_all(line.as_bytes())
        .expect("cannot write host flow audit log");
}
