// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host identity that performs guest requests on the microVM HostFs attachment.

use crate::VirtioFs;
use anyhow::Context as _;
use fuse::protocol::FUSE_BATCH_FORGET;
use fuse::protocol::FUSE_FORGET;

/// Maps guest FUSE callers to the host identity that performs their requests.
///
/// Each request runs as the user and group in its FUSE header, without the
/// worker thread's supplementary groups or effective capabilities (see
/// `lxutil::FsCredentials`). Guest user and group 0 are squashed to the owner
/// of the export root, so the guest never performs host operations as root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CallerIdentity {
    squash_uid: lx::uid_t,
    squash_gid: lx::gid_t,
}

/// Thread credentials held while one request runs as its caller.
pub(crate) struct CallerCredentials {
    #[cfg(unix)]
    _credentials: lxutil::FsCredentials,
}

impl CallerIdentity {
    /// Builds the caller mapping for an opened microVM attachment.
    ///
    /// Guest root, which also performs the mount, always maps to the export
    /// owner. Verifying that mapping here turns a missing capability into a
    /// launch failure instead of a guest-visible error on every request.
    pub(crate) fn for_attachment(fs: &VirtioFs) -> anyhow::Result<Self> {
        anyhow::ensure!(
            cfg!(unix),
            "caller-owned microVM virtio-fs requests require a Linux host"
        );
        let root = fs
            .microvm_root_stat()
            .context("failed to inspect the microVM filesystem export root")?;
        anyhow::ensure!(
            root.uid != 0 && root.gid != 0,
            "caller-owned microVM virtio-fs requests require an export root owned by a non-root user and group, not {}:{}",
            root.uid,
            root.gid
        );
        let identity = Self {
            squash_uid: root.uid,
            squash_gid: root.gid,
        };
        // The returned credentials are restored at the end of the statement.
        identity.enter(0, 0).with_context(|| {
            format!(
                "cannot perform microVM virtio-fs requests as the export owner {}:{}; run OpenVMM as that user or grant it CAP_SETUID and CAP_SETGID",
                root.uid, root.gid
            )
        })?;
        Ok(identity)
    }

    /// Returns the host user and group that perform a guest caller's request.
    pub(crate) fn map(&self, uid: lx::uid_t, gid: lx::gid_t) -> (lx::uid_t, lx::gid_t) {
        (
            if uid == 0 { self.squash_uid } else { uid },
            if gid == 0 { self.squash_gid } else { gid },
        )
    }

    /// Switches the calling thread to the host identity of `request`'s caller
    /// until the returned credentials are dropped.
    ///
    /// Forget requests only release guest references, never reach the host
    /// filesystem, and cannot carry an error reply, so they keep the process
    /// identity.
    pub(crate) fn enter_request(
        &self,
        request: &fuse::Request,
    ) -> lx::Result<Option<CallerCredentials>> {
        if matches!(request.opcode(), FUSE_FORGET | FUSE_BATCH_FORGET) {
            return Ok(None);
        }
        self.enter(request.uid(), request.gid()).map(Some)
    }

    fn enter(&self, uid: lx::uid_t, gid: lx::gid_t) -> lx::Result<CallerCredentials> {
        let (uid, gid) = self.map(uid, gid);
        #[cfg(unix)]
        {
            lxutil::FsCredentials::switch(uid, gid).map(|credentials| CallerCredentials {
                _credentials: credentials,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (uid, gid);
            Err(lx::Error::ENOTSUP)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallerIdentity;
    use crate::VirtioFs;
    use crate::profile::MICROVM_ATTACHMENT_ID;
    use crate::profile::MicroVmVirtioFsProfile;
    use crate::profile::microvm_root_identity;
    use std::path::Path;

    fn microvm_fs(root: &Path) -> VirtioFs {
        let profile = MicroVmVirtioFsProfile::from_attachment(
            MICROVM_ATTACHMENT_ID.to_owned(),
            microvm_root_identity(root).unwrap(),
            false,
            Vec::new(),
        )
        .unwrap();
        VirtioFs::new_microvm(root, profile).unwrap()
    }

    #[cfg(unix)]
    fn request(opcode: u32, uid: u32, gid: u32) -> fuse::Request {
        use fuse::protocol::fuse_in_header;
        use zerocopy::IntoBytes;

        // Sixteen bytes cover the GETATTR argument and the fixed part of the
        // forget arguments.
        let argument = [0u8; 16];
        let header = fuse_in_header {
            len: (size_of::<fuse_in_header>() + argument.len()) as u32,
            opcode,
            unique: 1,
            nodeid: 1,
            uid,
            gid,
            pid: 1,
            padding: 0,
        };
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(&argument);
        fuse::Request::new(bytes.as_slice()).unwrap()
    }

    #[test]
    fn guest_root_is_squashed_to_the_export_owner() {
        let identity = CallerIdentity {
            squash_uid: 1001,
            squash_gid: 1002,
        };
        assert_eq!(identity.map(0, 0), (1001, 1002));
        assert_eq!(identity.map(1234, 0), (1234, 1002));
        assert_eq!(identity.map(0, 5678), (1001, 5678));
        assert_eq!(identity.map(1234, 5678), (1234, 5678));
    }

    #[cfg(windows)]
    #[test]
    fn caller_identity_requires_a_linux_host() {
        let root = tempfile::tempdir().unwrap();
        let error = CallerIdentity::for_attachment(&microvm_fs(root.path())).unwrap_err();
        assert!(error.to_string().contains("Linux host"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn caller_identity_rejects_a_root_owned_export() {
        // The filesystem root is owned by root on every supported host.
        let error = CallerIdentity::for_attachment(&microvm_fs(Path::new("/"))).unwrap_err();
        assert!(error.to_string().contains("non-root user"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn requests_run_as_their_caller_and_fail_closed() {
        use fuse::protocol::FUSE_BATCH_FORGET;
        use fuse::protocol::FUSE_FORGET;
        use fuse::protocol::FUSE_GETATTR;
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        // The directory is created with this thread's filesystem identity.
        let running_as_root = std::fs::metadata(root.path()).unwrap().uid() == 0;
        if running_as_root {
            std::os::unix::fs::chown(root.path(), Some(12345), Some(23456)).unwrap();
        }
        let owner = std::fs::metadata(root.path()).unwrap();
        let identity = CallerIdentity::for_attachment(&microvm_fs(root.path())).unwrap();
        assert_eq!(identity.map(0, 0), (owner.uid(), owner.gid()));

        for opcode in [FUSE_FORGET, FUSE_BATCH_FORGET] {
            assert!(
                identity
                    .enter_request(&request(opcode, 0x7fff_fff0, 0x7fff_fff0))
                    .unwrap()
                    .is_none()
            );
        }
        drop(
            identity
                .enter_request(&request(FUSE_GETATTR, 0, 0))
                .unwrap()
                .unwrap(),
        );

        let other = identity.enter_request(&request(FUSE_GETATTR, 0x7fff_fff0, 0x7fff_fff0));
        if running_as_root {
            assert!(other.unwrap().is_some());
        } else {
            assert_eq!(other.err(), Some(lx::Error::EPERM));
        }
        assert!(
            identity
                .enter_request(&request(FUSE_GETATTR, lx::UID_INVALID, 0))
                .is_err()
        );
    }
}
