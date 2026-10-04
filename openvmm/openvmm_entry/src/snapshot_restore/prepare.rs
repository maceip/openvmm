// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation of an opened snapshot generation against the VM configuration,
//! and preparation of the private guest RAM copy and saved state it restores.

use crate::Options;
use crate::microvm;
use anyhow::Context;
use std::time::Duration;

/// An opened snapshot generation, validated against the VM configuration and
/// prepared for the VM worker.
pub(crate) struct PreparedSnapshotRestore {
    pub(crate) shared_memory: openvmm_defs::worker::SharedMemoryFd,
    pub(crate) guards: openvmm_defs::worker::SnapshotRestoreGuards,
    pub(crate) saved_state: mesh::payload::message::ProtobufMessage,
    pub(crate) restore_time: Option<(Duration, u64, Option<u64>, Vec<u8>)>,
    pub(crate) linux_direct_boot: bool,
    /// Process-private writable copy of the snapshot's RAM, mapped by the
    /// worker as its guest memory. Keeping the directory alive pins the path
    /// so a later save captures live RAM; dropping it deletes the copy.
    pub(crate) private_memory: (tempfile::TempDir, std::path::PathBuf),
}

/// Validate an opened snapshot generation against the current VM config.
/// Returns the shared memory handle, lifetime guards, and saved device state.
pub(super) fn prepare_snapshot_restore(
    snapshot: openvmm_helpers::snapshot::restore::OpenedSnapshot,
    opt: &Options,
    microvm: &microvm::MicrovmLaunch,
    expected_hypervisor: &str,
) -> anyhow::Result<PreparedSnapshotRestore> {
    let base_memory_size = snapshot.manifest().memory_size_bytes;
    let expected_microvm_contract =
        microvm.expected_restore_contract(opt, snapshot.manifest(), expected_hypervisor)?;
    prepare_snapshot_restore_for_config(
        snapshot,
        base_memory_size,
        opt.memory_size(),
        opt.processors,
        expected_microvm_contract,
    )
}

pub(crate) fn prepare_snapshot_restore_for_config(
    snapshot: openvmm_helpers::snapshot::restore::OpenedSnapshot,
    expected_memory_size: u64,
    selected_memory_size: u64,
    expected_vp_count: u32,
    expected_microvm_contract: Option<microvm::ExpectedRestoreContract<'_>>,
) -> anyhow::Result<PreparedSnapshotRestore> {
    let artifact_prepare = openvmm_defs::profile::ProfileSpan::start();
    let manifest = snapshot.manifest();
    let linux_direct_boot = manifest.linux_direct_boot;
    // Validate manifest against current VM config.
    openvmm_helpers::snapshot::validate_manifest(
        manifest,
        crate::GUEST_ARCH,
        expected_memory_size,
        expected_vp_count,
        crate::system_page_size(),
    )?;
    let mut restore_time = expected_microvm_contract
        .map(|contract| {
            microvm::validate_restore_contract(
                manifest,
                expected_memory_size,
                expected_vp_count,
                contract,
            )
        })
        .transpose()?;
    let capture_time = restore_time
        .as_ref()
        .map(|_| {
            manifest
                .machine_contract
                .as_ref()
                .context("microVM snapshot is missing its authoritative machine contract")?
                .capture_wall_clock
                .try_into()
                .context("snapshot capture wall clock is invalid")
        })
        .transpose()?;

    // The manifest and state.bin inventories describe the same machine boundary.
    // Require them to agree before worker and partition construction.
    let state_msg: mesh::payload::message::ProtobufMessage =
        mesh::payload::decode(snapshot.state_bytes())
            .context("failed to decode saved state from snapshot")?;
    if let Some(contract) = &manifest.machine_contract {
        let inventory_msg: mesh::payload::message::ProtobufMessage =
            mesh::payload::decode(snapshot.state_bytes())
                .context("failed to decode saved state inventory from snapshot")?;
        let saved_state: openvmm_defs::worker::SavedState = inventory_msg
            .parse()
            .context("failed to parse saved state inventory from snapshot")?;
        anyhow::ensure!(
            saved_state.inventory == contract.state_unit_names,
            "snapshot manifest state-unit inventory does not match state.bin"
        );
    }

    snapshot.claim_for_restore()?;

    artifact_prepare.complete(
        "restore",
        "artifact_prepare",
        openvmm_defs::profile::ProfileCounters {
            logical_bytes: Some(selected_memory_size),
            ..Default::default()
        },
    );

    // Materialize a process-private writable copy of the snapshot's RAM and
    // map that instead of the snapshot's memory.bin. A copy-on-write mapping
    // of the original would leave no file holding live RAM, making a later
    // save impossible; the private copy is mapped shared so guest writes
    // reach the file and a later save captures them. The original generation
    // stays pristine and pinned below until VM teardown, so repeated restores
    // of the same snapshot each get their own copy.
    // The duplicate validates the opened generation before the copy reads it.
    let cow_section_create = openvmm_defs::profile::ProfileSpan::start();
    let source_memory = snapshot.duplicate_memory_file_for_mapping(expected_memory_size)?;
    let (private_dir, private_path) = openvmm_helpers::snapshot::fs::copy_memory_to_private_file(
        &source_memory,
        expected_memory_size,
    )?;
    let private_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&private_path)
        .with_context(|| {
            format!(
                "failed to open private restore memory file {}",
                private_path.display()
            )
        })?;
    let shared_memory = openvmm_helpers::shared_memory::file_to_shared_memory_fd(private_file)?;
    cow_section_create.complete(
        "restore",
        "cow_section_create",
        openvmm_defs::profile::ProfileCounters {
            logical_bytes: Some(expected_memory_size),
            ..Default::default()
        },
    );
    snapshot.validate_memory_generation(expected_memory_size)?;
    // Admission calculates downtime before private RAM is materialized. Dense
    // copies can take seconds; include that work in the clock adjustment handed
    // to the worker instead of resuming the guest with the earlier sample.
    if let (Some(restore_time), Some(capture_time)) = (&mut restore_time, capture_time) {
        microvm::refresh_restore_time(restore_time, capture_time, std::time::SystemTime::now())?;
    }
    let (_, _, guards) = snapshot.into_parts();

    Ok(PreparedSnapshotRestore {
        shared_memory,
        guards,
        saved_state: state_msg,
        restore_time,
        linux_direct_boot,
        private_memory: (private_dir, private_path),
    })
}
