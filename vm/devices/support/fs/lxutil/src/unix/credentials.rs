// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Scoped per-thread filesystem credentials.

use std::marker::PhantomData;

const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_SETGID: u32 = 6;

/// Performs filesystem operations on the calling thread as another identity.
///
/// Linux keeps the filesystem user ID, the filesystem group ID, the
/// supplementary group list, and the capability sets of each thread
/// separately, and uses them for filesystem permission checks and for the
/// ownership of new objects. While the guard is alive, the calling thread uses
/// the requested user and group with no supplementary groups and no effective
/// capabilities, so the host kernel checks every operation exactly as that
/// identity. Other threads are unaffected, and dropping the guard restores the
/// previous credentials.
///
/// Switching to an identity other than the current one requires `CAP_SETUID`
/// and `CAP_SETGID`. Every step is verified, so a missing capability fails
/// with `EPERM` instead of silently leaving the thread with its previous
/// identity. Requesting the current filesystem identity needs no capability;
/// without `CAP_SETGID`, it keeps the thread's supplementary groups.
///
/// The guard cannot leave its thread, and it must be dropped before the thread
/// runs unrelated work.
#[must_use = "the credentials are restored when the guard is dropped"]
pub struct FsCredentials {
    previous: PreviousCredentials,
    _thread_bound: PhantomData<*const ()>,
}

/// The parts of the thread credentials that a guard changed.
#[derive(Default)]
struct PreviousCredentials {
    identity: Option<(libc::uid_t, libc::gid_t)>,
    groups: Option<Vec<libc::gid_t>>,
    capabilities: Option<[CapabilityData; 2]>,
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

impl FsCredentials {
    /// Switches the calling thread's filesystem credentials to `uid` and
    /// `gid` until the returned guard is dropped.
    pub fn switch(uid: lx::uid_t, gid: lx::gid_t) -> lx::Result<Self> {
        if uid == lx::UID_INVALID || gid == lx::GID_INVALID {
            return Err(lx::Error::EINVAL);
        }
        let capabilities = thread_capabilities()?;
        let mut credentials = Self {
            previous: PreviousCredentials::default(),
            _thread_bound: PhantomData,
        };
        // Any failure below drops `credentials`, which restores every step
        // that has already completed.
        if current_fsuid() == uid && current_fsgid() == gid {
            if has_effective(&capabilities, CAP_SETGID) {
                credentials.previous.groups = clear_supplementary_groups()?;
            }
        } else {
            // SAFETY: setfsgid changes only the calling thread's filesystem
            // group and returns the previous value whether or not it
            // succeeds.
            let previous_gid = unsafe { libc::setfsgid(gid) } as libc::gid_t;
            credentials.previous.identity = Some((current_fsuid(), previous_gid));
            if current_fsgid() != gid {
                return Err(lx::Error::EPERM);
            }
            credentials.previous.groups = clear_supplementary_groups()?;
            // SAFETY: setfsuid changes only the calling thread's filesystem
            // user and returns the previous value whether or not it succeeds.
            unsafe { libc::setfsuid(uid) };
            if current_fsuid() != uid {
                return Err(lx::Error::EPERM);
            }
        }
        // Leaving the fsuid of root clears only the filesystem capabilities,
        // and other transitions clear none. Drop the rest of the effective set,
        // such as CAP_SETFCAP and CAP_SYS_ADMIN, so the new identity cannot
        // perform privileged operations. The permitted set is kept, which
        // allows restoring the effective set later.
        let mut switched = thread_capabilities()?;
        if switched.iter().any(|data| data.effective != 0) {
            credentials.previous.capabilities = Some(capabilities);
            for data in &mut switched {
                data.effective = 0;
            }
            set_thread_capabilities(&switched)?;
        }
        Ok(credentials)
    }
}

impl Drop for FsCredentials {
    fn drop(&mut self) {
        let previous = std::mem::take(&mut self.previous);
        let restore_capabilities = || {
            previous
                .capabilities
                .is_none_or(|capabilities| set_thread_capabilities(&capabilities).is_ok())
        };
        // Regain CAP_SETUID and CAP_SETGID, which restoring the identity and
        // the supplementary groups may require.
        let mut restored = restore_capabilities();
        if let Some((uid, gid)) = previous.identity {
            // SAFETY: Restores this thread's filesystem identity saved by
            // `switch`.
            unsafe {
                libc::setfsuid(uid);
                libc::setfsgid(gid);
            }
            restored &= current_fsuid() == uid && current_fsgid() == gid;
        }
        restored &= previous
            .groups
            .as_deref()
            .is_none_or(|groups| set_thread_groups(groups).is_ok());
        // Returning the fsuid to root raises the filesystem capabilities again,
        // so restore the exact effective set last.
        restored &= restore_capabilities();
        restored &= previous.capabilities.is_none_or(|capabilities| {
            thread_capabilities().is_ok_and(|current| current == capabilities)
        });
        if !restored {
            // Continuing would run unrelated work on this thread with another
            // identity's filesystem credentials.
            tracing::error!("failed to restore thread filesystem credentials");
            std::process::abort();
        }
    }
}

fn current_fsuid() -> libc::uid_t {
    // SAFETY: An invalid ID queries the current value without changing it.
    unsafe { libc::setfsuid(lx::UID_INVALID) as libc::uid_t }
}

fn current_fsgid() -> libc::gid_t {
    // SAFETY: An invalid ID queries the current value without changing it.
    unsafe { libc::setfsgid(lx::GID_INVALID) as libc::gid_t }
}

fn has_effective(capabilities: &[CapabilityData; 2], capability: u32) -> bool {
    capabilities[(capability / 32) as usize].effective & (1 << (capability % 32)) != 0
}

/// Returns the capability sets of the calling thread.
fn thread_capabilities() -> lx::Result<[CapabilityData; 2]> {
    let mut header = CapabilityHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    // SAFETY: The header selects the calling thread and version 3, whose data
    // is two `CapabilityData` entries.
    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if result != 0 {
        return Err(lx::Error::last_os_error());
    }
    Ok(data)
}

/// Replaces the capability sets of the calling thread only.
fn set_thread_capabilities(data: &[CapabilityData; 2]) -> lx::Result<()> {
    let mut header = CapabilityHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    // SAFETY: The header selects the calling thread and version 3, whose data
    // is two `CapabilityData` entries.
    let result = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) };
    if result != 0 {
        return Err(lx::Error::last_os_error());
    }
    Ok(())
}

/// Clears the calling thread's supplementary groups, returning the previous
/// list when it was not already empty.
fn clear_supplementary_groups() -> lx::Result<Option<Vec<libc::gid_t>>> {
    // SAFETY: A zero-sized query only returns the group count.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let count = usize::try_from(count).map_err(|_| lx::Error::last_os_error())?;
    if count == 0 {
        return Ok(None);
    }
    let mut groups = vec![0; count];
    // SAFETY: The buffer holds `count` group IDs.
    let written = unsafe { libc::getgroups(count as libc::c_int, groups.as_mut_ptr()) };
    let written = usize::try_from(written).map_err(|_| lx::Error::last_os_error())?;
    groups.truncate(written);
    set_thread_groups(&[])?;
    Ok(Some(groups))
}

/// Replaces the supplementary groups of the calling thread only.
///
/// The raw system call is used deliberately: the C library's `setgroups`
/// applies the change to every thread in the process.
fn set_thread_groups(groups: &[libc::gid_t]) -> lx::Result<()> {
    // SAFETY: The pointer and length describe a valid, initialized slice.
    let result = unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            groups.len() as libc::c_long,
            groups.as_ptr(),
        )
    };
    if result != 0 {
        return Err(lx::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::CAP_SETGID;
    use super::FsCredentials;
    use super::current_fsgid;
    use super::current_fsuid;
    use super::has_effective;
    use super::thread_capabilities;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    const CAP_SETUID: u32 = 7;

    fn thread_groups() -> Vec<libc::gid_t> {
        // SAFETY: A zero-sized query only returns the group count.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        let mut groups = vec![0; usize::try_from(count).unwrap()];
        // SAFETY: The buffer holds `count` group IDs.
        let written = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        groups.truncate(usize::try_from(written).unwrap());
        groups
    }

    fn has_no_effective_capabilities() -> bool {
        thread_capabilities()
            .unwrap()
            .iter()
            .all(|data| data.effective == 0)
    }

    /// Sets a file capability, which requires CAP_SETFCAP.
    fn set_file_capability(path: &std::path::Path) -> std::io::Result<()> {
        // A revision 2 `vfs_cap_data` that grants no capabilities.
        let mut value = [0u8; 20];
        value[..4].copy_from_slice(&0x0200_0000u32.to_le_bytes());
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: The path, name, and value are valid for the call.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"security.capability".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[test]
    fn switching_to_the_current_identity_restores_the_thread_credentials() {
        let (uid, gid, groups) = (current_fsuid(), current_fsgid(), thread_groups());
        let capabilities = thread_capabilities().unwrap();
        let credentials = FsCredentials::switch(uid, gid).unwrap();
        assert_eq!((current_fsuid(), current_fsgid()), (uid, gid));
        assert!(has_no_effective_capabilities());
        if has_effective(&capabilities, CAP_SETGID) {
            assert!(thread_groups().is_empty());
        } else {
            assert_eq!(thread_groups(), groups);
        }
        drop(credentials);
        assert_eq!(
            (current_fsuid(), current_fsgid(), thread_groups()),
            (uid, gid, groups)
        );
        assert_eq!(thread_capabilities().unwrap(), capabilities);
    }

    #[test]
    fn invalid_identities_are_rejected() {
        let (uid, gid) = (current_fsuid(), current_fsgid());
        assert_eq!(
            FsCredentials::switch(lx::UID_INVALID, gid).err(),
            Some(lx::Error::EINVAL)
        );
        assert_eq!(
            FsCredentials::switch(uid, lx::GID_INVALID).err(),
            Some(lx::Error::EINVAL)
        );
        assert_eq!((current_fsuid(), current_fsgid()), (uid, gid));
    }

    #[test]
    fn switching_without_capabilities_fails_closed() {
        let capabilities = thread_capabilities().unwrap();
        if has_effective(&capabilities, CAP_SETUID) || has_effective(&capabilities, CAP_SETGID) {
            return;
        }
        let (uid, gid, groups) = (current_fsuid(), current_fsgid(), thread_groups());
        for (target_uid, target_gid) in [
            (0x7fff_fff0, 0x7fff_fff0),
            (uid, 0x7fff_fff0),
            (0x7fff_fff0, gid),
        ] {
            assert_eq!(
                FsCredentials::switch(target_uid, target_gid).err(),
                Some(lx::Error::EPERM)
            );
            assert_eq!(
                (current_fsuid(), current_fsgid(), thread_groups()),
                (uid, gid, groups.clone())
            );
            assert_eq!(thread_capabilities().unwrap(), capabilities);
        }
    }

    #[test]
    fn switching_drops_privileges_and_restores_the_thread_credentials() {
        let capabilities = thread_capabilities().unwrap();
        if !has_effective(&capabilities, CAP_SETUID) || !has_effective(&capabilities, CAP_SETGID) {
            return;
        }
        let (uid, gid, groups) = (current_fsuid(), current_fsgid(), thread_groups());
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o777),
        )
        .unwrap();
        let privileged = directory.path().join("privileged");
        std::fs::write(&privileged, b"privileged").unwrap();
        let file_capabilities_supported = set_file_capability(&privileged).is_ok();
        let path = directory.path().join("created");
        {
            let _credentials = FsCredentials::switch(12345, 23456).unwrap();
            assert_eq!((current_fsuid(), current_fsgid()), (12345, 23456));
            assert!(thread_groups().is_empty());
            assert!(has_no_effective_capabilities());
            std::fs::write(&path, b"owned").unwrap();
            // Owning the file is not enough: CAP_SETFCAP must be gone too.
            if file_capabilities_supported {
                assert!(set_file_capability(&path).is_err());
            }
        }
        assert_eq!(
            (current_fsuid(), current_fsgid(), thread_groups()),
            (uid, gid, groups)
        );
        assert_eq!(thread_capabilities().unwrap(), capabilities);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (12345, 23456));
    }
}
