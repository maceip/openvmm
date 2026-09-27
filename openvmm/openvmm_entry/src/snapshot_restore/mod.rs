// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Snapshot restore of a VM launched from the command line, and the restore
//! steps it shares with the management RPC endpoint.
//!
//! A `--restore-snapshot` launch opens one exact snapshot generation first
//! ([`SnapshotRestore::open`]); a microVM derives its restore-time
//! configuration from that generation's manifest. Just before the VM worker
//! launches, the opened generation is validated against the VM configuration,
//! claimed if it is a single-use resume snapshot, and its RAM is mapped
//! copy-on-write ([`SnapshotRestore::prepare`]). Its open artifact handles then
//! move to the worker, which keeps the generation pinned until VM teardown.
//! The `--restore-ready-path` endpoint is connected next
//! ([`restore_ready_sink`]); the worker writes the restore readiness event to
//! it when the restored VM first starts.
//!
//! With `OPENVMM_STARTUP_PROFILE` set, these steps record the `restore` phases
//! `artifact_open`, `artifact_prepare`, and `cow_section_create`, and the
//! launch records the `startup` milestone `worker_launch`
//! ([`worker_launched`]).

mod prepare;
mod ready;

pub(crate) use prepare::prepare_snapshot_restore_for_config;
pub(crate) use ready::connect_restore_ready_sink;
pub(crate) use ready::restore_ready_sink;

use crate::Options;
use crate::microvm::MicrovmLaunch;
use anyhow::Context;
use mesh::payload::message::ProtobufMessage;
use openvmm_defs::profile::ProfileSpan;
use openvmm_defs::worker::SharedMemoryFd;
use openvmm_defs::worker::SnapshotRestoreGuards;
use openvmm_helpers::snapshot::restore::OpenedSnapshot;
use std::time::Duration;

/// The snapshot restore of a VM launched from the command line.
pub(crate) struct SnapshotRestore {
    /// The opened snapshot generation, until [`Self::prepare`] takes it.
    snapshot: Option<OpenedSnapshot>,
    /// The restore inputs of the VM worker, recorded by [`Self::prepare`].
    worker: WorkerRestore,
}

/// Restore inputs of the VM worker beyond its guest RAM and saved state.
#[derive(Default)]
pub(crate) struct WorkerRestore {
    /// Whether the restored snapshot was captured from a Linux-direct boot.
    pub(crate) linux_direct_boot: bool,
    /// Whether writes to the worker's guest RAM must remain private to this VM.
    pub(crate) shared_memory_copy_on_write: bool,
    /// Snapshot generation handles that must outlive the restored VM.
    pub(crate) guards: Option<SnapshotRestoreGuards>,
    /// Host downtime to apply before starting a restored microVM.
    pub(crate) downtime: Option<Duration>,
    /// Saved effective TSC frequency of a restored microVM.
    pub(crate) tsc_frequency_hz: Option<u64>,
    /// Saved local APIC timer frequency of a restored microVM.
    pub(crate) apic_frequency_hz: Option<u64>,
    /// Saved canonical CPU contract of a restored microVM.
    pub(crate) cpu_contract: Option<Vec<u8>>,
}

impl SnapshotRestore {
    /// Opens the `--restore-snapshot` generation, if any.
    pub(crate) fn open(opt: &Options) -> anyhow::Result<Self> {
        let artifact_open = ProfileSpan::start();
        let snapshot = opt
            .restore_snapshot
            .as_deref()
            .map(OpenedSnapshot::open)
            .transpose()?;
        if opt.restore_snapshot.is_some() {
            let counters = if openvmm_defs::profile::enabled() {
                snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.artifact_size_counters().ok())
                    .map(|(logical_bytes, allocated_bytes)| {
                        openvmm_defs::profile::ProfileCounters {
                            logical_bytes: Some(logical_bytes),
                            allocated_bytes: Some(allocated_bytes),
                            ..Default::default()
                        }
                    })
                    .unwrap_or_default()
            } else {
                Default::default()
            };
            artifact_open.complete("restore", "artifact_open", counters);
        }
        Ok(Self {
            snapshot,
            worker: WorkerRestore::default(),
        })
    }

    /// Returns the opened snapshot generation, until [`Self::prepare`] takes
    /// it.
    pub(crate) fn snapshot(&self) -> Option<&OpenedSnapshot> {
        self.snapshot.as_ref()
    }

    /// Normalizes `--memory` size for a generic (non-microVM) restore from the
    /// opened generation's manifest.
    ///
    /// A generic restore must rebuild the save-time memory layout exactly, and
    /// the layout derives from the configured size: leaving `--memory` unset
    /// would silently fall back to the 1GiB default and map guest RAM at the
    /// wrong addresses. Default an unset size from the manifest, and reject an
    /// explicit size that cannot match. microVM restores size memory through
    /// their own contract and are untouched.
    pub(crate) fn normalize_memory_size(&self, opt: &mut Options) -> anyhow::Result<()> {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return Ok(());
        };
        if opt.machine == crate::cli_args::microvm::MachineProfileCli::Microvm {
            return Ok(());
        }
        let manifest_bytes = snapshot.manifest().memory_size_bytes;
        opt.memory.size = Some(restore_memory_size(
            opt.memory.size.map(|size| size.0),
            manifest_bytes,
        )?);
        Ok(())
    }

    /// Validates the opened snapshot generation against the VM configuration
    /// and prepares it for the VM worker.
    ///
    /// Returns the worker's copy-on-write guest RAM and saved state, and
    /// records the worker's other restore inputs for [`Self::into_worker`].
    pub(crate) fn prepare(
        &mut self,
        opt: &Options,
        microvm: &MicrovmLaunch,
        expected_hypervisor: &str,
    ) -> anyhow::Result<(SharedMemoryFd, ProtobufMessage)> {
        let prepared = prepare::prepare_snapshot_restore(
            self.snapshot
                .take()
                .context("snapshot restore is missing its opened generation")?,
            opt,
            microvm,
            expected_hypervisor,
        )?;
        self.worker.shared_memory_copy_on_write = true;
        self.worker.guards = Some(prepared.guards);
        self.worker.linux_direct_boot = prepared.linux_direct_boot;
        if let Some((downtime, tsc_frequency_hz, apic_frequency_hz, cpu_contract)) =
            prepared.restore_time
        {
            self.worker.downtime = Some(downtime);
            self.worker.tsc_frequency_hz = Some(tsc_frequency_hz);
            self.worker.apic_frequency_hz = apic_frequency_hz;
            self.worker.cpu_contract = Some(cpu_contract);
        }
        Ok((prepared.shared_memory, prepared.saved_state))
    }

    /// Returns the restore inputs of the VM worker: the defaults of a VM that
    /// is not restored, or those recorded by [`Self::prepare`].
    pub(crate) fn into_worker(self) -> WorkerRestore {
        self.worker
    }
}

/// Resolves the `--memory` size for a generic restore: the manifest size when
/// unset, else the explicit size after verifying it matches the manifest.
fn restore_memory_size(
    requested: Option<u64>,
    manifest_bytes: u64,
) -> anyhow::Result<vmm_cli::MemorySize> {
    match requested {
        None => Ok(vmm_cli::MemorySize(manifest_bytes)),
        Some(size) => {
            anyhow::ensure!(
                size == manifest_bytes,
                "explicit --memory size {size} does not match the snapshot's {manifest_bytes} bytes; \
                 a generic restore must rebuild the save-time memory layout exactly"
            );
            Ok(vmm_cli::MemorySize(size))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::restore_memory_size;

    #[test]
    fn restore_memory_defaults_from_manifest() {
        let size = restore_memory_size(None, 512 << 20).unwrap();
        assert_eq!(size.0, 512 << 20);
    }

    #[test]
    fn restore_memory_accepts_matching_size() {
        let size = restore_memory_size(Some(512 << 20), 512 << 20).unwrap();
        assert_eq!(size.0, 512 << 20);
    }

    #[test]
    fn restore_memory_rejects_mismatch() {
        restore_memory_size(Some(1 << 30), 512 << 20).unwrap_err();
    }
}

/// Records the `startup/worker_launch` profile milestone once the VM worker
/// has launched.
pub(crate) fn worker_launched(worker_launch: ProfileSpan) {
    worker_launch.complete_milestone("startup", "worker_launch", Default::default());
}
