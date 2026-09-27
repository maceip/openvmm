// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! microVM profile of the virtio-fs resource.
//!
//! [`VirtioFsProfile`] selects the standard virtio-fs device or the microVM
//! device, which serves either an attached host folder or a dormant slot
//! backed by [`super::VirtioFsBackend::Dormant`].

use mesh::MeshPayload;

#[derive(MeshPayload)]
pub enum VirtioFsProfile {
    Standard,
    Microvm {
        stable_id: String,
        root_identity: Vec<u8>,
        read_only: bool,
        denied_paths: Vec<String>,
        owner: VirtioFsOwner,
    },
    MicrovmDormant {
        stable_id: String,
    },
}

/// Host identity that performs guest requests on a microVM HostFs attachment.
///
/// This is host execution policy, not part of the guest-visible device
/// contract or of a snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, MeshPayload, PartialEq)]
pub enum VirtioFsOwner {
    /// Perform every request as the OpenVMM process identity.
    #[default]
    Process,
    /// Perform each request as the guest caller's user and group, with guest
    /// user and group 0 mapped to the owner of the export root. Linux only.
    Caller,
}
