// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Darwin filesystem access with Linux wire flags and descriptor-pinned paths.
// UNSAFETY: POSIX descriptor APIs, with owned descriptors and checked results.
#![expect(unsafe_code)]

use crate::{LxCreateOptions, SetAttributes, SetTime};
use std::borrow::Cow;
use std::ffi::{CString, OsStr};
use std::marker::PhantomData;
use std::os::unix::prelude::*;
use std::path::{Component, Path};

pub(crate) mod path {
    use super::*;
    pub fn path_from_lx(path: &[u8]) -> lx::Result<Cow<'_, Path>> {
        Ok(Cow::Borrowed(OsStr::from_bytes(path).as_ref()))
    }
}

/// Non-root export-owner credentials; Darwin never changes process-wide IDs.
#[must_use]
pub struct FsCredentials(PhantomData<*const ()>);
impl FsCredentials {
    /// Require the identity to be the unprivileged VMM's effective identity.
    pub fn switch(uid: lx::uid_t, gid: lx::gid_t) -> lx::Result<Self> {
        // SAFETY: These queries have no preconditions or side effects.
        if unsafe { libc::geteuid() } != uid || unsafe { libc::getegid() } != gid || uid == 0 {
            return Err(lx::Error::EPERM);
        }
        Ok(Self(PhantomData))
    }
}

fn errno() -> lx::Error {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error().unwrap_or(libc::EIO) {
        libc::EPERM => lx::Error::EPERM,
        libc::ENOENT => lx::Error::ENOENT,
        libc::EIO => lx::Error::EIO,
        libc::EBADF => lx::Error::EBADF,
        libc::EACCES => lx::Error::EACCES,
        libc::EEXIST => lx::Error::EEXIST,
        libc::EXDEV => lx::Error::EXDEV,
        libc::ENOTDIR => lx::Error::ENOTDIR,
        libc::EISDIR => lx::Error::EISDIR,
        libc::EINVAL => lx::Error::EINVAL,
        libc::ENOSPC => lx::Error::ENOSPC,
        libc::EROFS => lx::Error::EROFS,
        libc::ENOTEMPTY => lx::Error::ENOTEMPTY,
        libc::ELOOP => lx::Error::ELOOP,
        libc::ENAMETOOLONG => lx::Error::ENAMETOOLONG,
        libc::ENOTSUP => lx::Error::ENOTSUP,
        _ => error.into(),
    }
}
fn checked<T: PartialOrd<T> + Default>(value: T) -> lx::Result<T> {
    if value < T::default() {
        Err(errno())
    } else {
        Ok(value)
    }
}
fn cstr(path: &Path) -> lx::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| lx::Error::EINVAL)
}
fn parent(root: &std::fs::File, path: &Path) -> lx::Result<(std::fs::File, CString)> {
    let mut directory = root.try_clone()?;
    let components: Vec<_> = path.components().collect();
    if components
        .iter()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(lx::Error::EACCES);
    }
    let mut names = components
        .iter()
        .filter_map(|part| {
            if let Component::Normal(name) = part {
                Some(*name)
            } else {
                None
            }
        })
        .peekable();
    while let Some(name) = names.next() {
        let name = CString::new(name.as_bytes()).map_err(|_| lx::Error::EINVAL)?;
        if names.peek().is_none() {
            return Ok((directory, name));
        }
        // SAFETY: name is terminated; every ancestor is pinned without following links.
        let fd = checked(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: openat returned a new owned descriptor.
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok((directory, CString::new(".").unwrap()))
}
fn open(
    root: &std::fs::File,
    path: &Path,
    flags: i32,
    mode: lx::mode_t,
) -> lx::Result<std::fs::File> {
    let (directory, name) = parent(root, path)?;
    let mut native = match flags & lx::O_ACCESS_MASK {
        lx::O_WRONLY => libc::O_WRONLY,
        lx::O_RDWR => libc::O_RDWR,
        lx::O_NOACCESS => libc::O_EVTONLY,
        _ => libc::O_RDONLY,
    };
    for (wire, host) in [
        (lx::O_CREAT, libc::O_CREAT),
        (lx::O_EXCL, libc::O_EXCL),
        (lx::O_TRUNC, libc::O_TRUNC),
        (lx::O_APPEND, libc::O_APPEND),
        (lx::O_DIRECTORY, libc::O_DIRECTORY),
    ] {
        if flags & wire != 0 {
            native |= host;
        }
    }
    // All Darwin exports forbid following the final link as well as ancestors.
    native |= libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: The descriptor and terminated name are valid; mode is used only for creation.
    let fd = checked(unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            native,
            mode as libc::c_uint,
        )
    })?;
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}
fn stat(native: libc::stat) -> lx::StatEx {
    let timestamp = |seconds: i64, nanoseconds: i64| lx::StatExTimestamp {
        seconds,
        nanoseconds: nanoseconds as u32,
        _rsvd: 0,
    };
    lx::StatEx {
        mask: lx::StatExMask::from(0xfff),
        block_size: native.st_blksize as u32,
        link_count: native.st_nlink as u32,
        uid: native.st_uid,
        gid: native.st_gid,
        mode: native.st_mode,
        inode_id: native.st_ino,
        file_size: native.st_size as u64,
        block_count: native.st_blocks as u64,
        access_time: timestamp(native.st_atime, native.st_atime_nsec),
        creation_time: timestamp(native.st_birthtime, native.st_birthtime_nsec),
        change_time: timestamp(native.st_ctime, native.st_ctime_nsec),
        write_time: timestamp(native.st_mtime, native.st_mtime_nsec),
        dev_major: libc::major(native.st_dev) as u32,
        dev_minor: libc::minor(native.st_dev) as u32,
        rdev_major: libc::major(native.st_rdev) as u32,
        rdev_minor: libc::minor(native.st_rdev) as u32,
        ..Default::default()
    }
}
fn attrs(file: &std::fs::File, attr: &SetAttributes) -> lx::Result<()> {
    // SAFETY: All calls operate on a live owned descriptor; arrays have the required lengths.
    unsafe {
        if let Some(size) = attr.size {
            checked(libc::ftruncate(file.as_raw_fd(), size))?;
        }
        if let Some(mode) = attr.mode {
            checked(libc::fchmod(file.as_raw_fd(), mode as libc::mode_t))?;
        }
        if attr.uid.is_some() || attr.gid.is_some() {
            checked(libc::fchown(
                file.as_raw_fd(),
                attr.uid.unwrap_or(lx::UID_INVALID),
                attr.gid.unwrap_or(lx::GID_INVALID),
            ))?;
        }
        if !attr.atime.is_omit() || !attr.mtime.is_omit() {
            let time = |value: &SetTime| match value {
                SetTime::Omit => libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                SetTime::Now => libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_NOW,
                },
                SetTime::Set(value) => libc::timespec {
                    tv_sec: value.as_secs() as i64,
                    tv_nsec: value.subsec_nanos() as i64,
                },
            };
            checked(libc::futimens(
                file.as_raw_fd(),
                [time(&attr.atime), time(&attr.mtime)].as_ptr(),
            ))?;
        }
    }
    Ok(())
}

pub struct LxVolume {
    root: std::fs::File,
}
impl LxVolume {
    pub fn new(path: &Path, _: &crate::LxVolumeOptions) -> lx::Result<Self> {
        let path = cstr(path)?;
        // SAFETY: Valid terminated path. The attachment validator checks all root components.
        let fd = checked(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: open returned a new owned descriptor.
        Ok(Self {
            root: unsafe { std::fs::File::from_raw_fd(fd) },
        })
    }
    pub fn supports_stable_file_id(&self) -> bool {
        true
    }
    pub fn lstat(&self, path: &Path) -> lx::Result<lx::StatEx> {
        let (directory, name) = parent(&self.root, path)?;
        // SAFETY: Output is fully initialized by a successful fstatat, without following links.
        let native = unsafe {
            let mut value = std::mem::zeroed();
            checked(libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut value,
                libc::AT_SYMLINK_NOFOLLOW,
            ))?;
            value
        };
        Ok(stat(native))
    }
    pub fn set_attr(&self, path: &Path, attr: SetAttributes) -> lx::Result<()> {
        attrs(
            &open(
                &self.root,
                path,
                if attr.size.is_some() {
                    lx::O_WRONLY
                } else {
                    lx::O_RDONLY
                },
                0,
            )?,
            &attr,
        )
    }
    pub fn set_attr_stat(&self, path: &Path, attr: SetAttributes) -> lx::Result<lx::Stat> {
        self.set_attr(path, attr)?;
        self.lstat(path).map(Into::into)
    }
    pub fn open(
        &self,
        path: &Path,
        flags: i32,
        options: Option<LxCreateOptions>,
    ) -> lx::Result<LxFile> {
        Ok(LxFile {
            fd: open(&self.root, path, flags, options.unwrap_or_default().mode)?,
            access: flags & lx::O_ACCESS_MASK,
            directory: None,
        })
    }
    pub fn mkdir(&self, path: &Path, options: LxCreateOptions) -> lx::Result<()> {
        let (directory, name) = parent(&self.root, path)?;
        // SAFETY: A pinned parent descriptor and terminated final component.
        checked(unsafe {
            libc::mkdirat(
                directory.as_raw_fd(),
                name.as_ptr(),
                options.mode as libc::mode_t,
            )
        })?;
        Ok(())
    }
    pub fn mkdir_stat(&self, path: &Path, options: LxCreateOptions) -> lx::Result<lx::Stat> {
        self.mkdir(path, options)?;
        self.lstat(path).map(Into::into)
    }
    pub fn symlink(&self, _: &Path, _: &lx::LxStr, _: LxCreateOptions) -> lx::Result<()> {
        Err(lx::Error::ENOTSUP)
    }
    pub fn symlink_stat(
        &self,
        path: &Path,
        target: &lx::LxStr,
        options: LxCreateOptions,
    ) -> lx::Result<lx::Stat> {
        self.symlink(path, target, options)?;
        self.lstat(path).map(Into::into)
    }
    pub fn read_link(&self, path: &Path) -> lx::Result<lx::LxString> {
        let (directory, name) = parent(&self.root, path)?;
        let mut buffer = [0u8; 4096];
        // SAFETY: Pinned parent and valid output buffer.
        let count = checked(unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        })?;
        Ok(lx::LxString::from_vec(buffer[..count as usize].to_vec()))
    }
    pub fn unlink(&self, path: &Path, flags: i32) -> lx::Result<()> {
        let (directory, name) = parent(&self.root, path)?;
        if flags & !lx::AT_REMOVEDIR != 0 {
            return Err(lx::Error::EINVAL);
        }
        // SAFETY: Pinned parent; unlink does not follow the final component.
        checked(unsafe {
            libc::unlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                if flags == lx::AT_REMOVEDIR {
                    libc::AT_REMOVEDIR
                } else {
                    0
                },
            )
        })?;
        Ok(())
    }
    pub fn mknod(&self, path: &Path, options: LxCreateOptions, _: lx::dev_t) -> lx::Result<()> {
        if !lx::s_isreg(options.mode) {
            return Err(lx::Error::ENOTSUP);
        }
        open(
            &self.root,
            path,
            lx::O_CREAT | lx::O_EXCL | lx::O_WRONLY,
            options.mode,
        )?;
        Ok(())
    }
    pub fn mknod_stat(
        &self,
        path: &Path,
        options: LxCreateOptions,
        device: lx::dev_t,
    ) -> lx::Result<lx::Stat> {
        self.mknod(path, options, device)?;
        self.lstat(path).map(Into::into)
    }
    pub fn rename(&self, path: &Path, destination: &Path, flags: u32) -> lx::Result<()> {
        let (source, name) = parent(&self.root, path)?;
        let (target, newname) = parent(&self.root, destination)?;
        // SAFETY: Both descriptors and terminated names are pinned. Unknown Linux flags fail closed.
        unsafe {
            if flags == 0 {
                checked(libc::renameat(
                    source.as_raw_fd(),
                    name.as_ptr(),
                    target.as_raw_fd(),
                    newname.as_ptr(),
                ))?;
            } else if flags == 1 {
                checked(libc::renameatx_np(
                    source.as_raw_fd(),
                    name.as_ptr(),
                    target.as_raw_fd(),
                    newname.as_ptr(),
                    libc::RENAME_EXCL,
                ))?;
            } else {
                return Err(lx::Error::ENOTSUP);
            }
        }
        Ok(())
    }
    pub fn link(&self, path: &Path, destination: &Path) -> lx::Result<()> {
        let (source, name) = parent(&self.root, path)?;
        let (target, newname) = parent(&self.root, destination)?;
        // SAFETY: Both descriptors and terminated names are pinned; flags do not follow symlinks.
        checked(unsafe {
            libc::linkat(
                source.as_raw_fd(),
                name.as_ptr(),
                target.as_raw_fd(),
                newname.as_ptr(),
                0,
            )
        })?;
        Ok(())
    }
    pub fn link_stat(&self, path: &Path, destination: &Path) -> lx::Result<lx::Stat> {
        self.link(path, destination)?;
        self.lstat(destination).map(Into::into)
    }
    pub fn stat_fs(&self, _: &Path) -> lx::Result<lx::StatFs> {
        // SAFETY: The root descriptor is valid and output is initialized on success.
        let value: libc::statfs = unsafe {
            let mut value = std::mem::zeroed();
            checked(libc::fstatfs(self.root.as_raw_fd(), &mut value))?;
            value
        };
        Ok(lx::StatFs {
            fs_type: value.f_type as usize,
            block_size: value.f_bsize as usize,
            block_count: value.f_blocks,
            free_block_count: value.f_bfree,
            available_block_count: value.f_bavail,
            file_count: value.f_files,
            available_file_count: value.f_ffree,
            file_system_id: [0; 8],
            maximum_file_name_length: 255,
            file_record_size: value.f_bsize as usize,
            flags: 0,
            spare: [0; 4],
        })
    }
    pub fn set_xattr(&self, _: &Path, _: &lx::LxStr, _: &[u8], _: i32) -> lx::Result<()> {
        Err(lx::Error::ENOTSUP)
    }
    pub fn get_xattr(&self, _: &Path, _: &lx::LxStr, _: Option<&mut [u8]>) -> lx::Result<usize> {
        Err(lx::Error::ENOTSUP)
    }
    pub fn list_xattr(&self, _: &Path, _: Option<&mut [u8]>) -> lx::Result<usize> {
        Ok(0)
    }
    pub fn remove_xattr(&self, _: &Path, _: &lx::LxStr) -> lx::Result<()> {
        Err(lx::Error::ENOTSUP)
    }
}

pub struct LxFile {
    fd: std::fs::File,
    access: i32,
    directory: Option<Directory>,
}
struct Directory {
    stream: std::ptr::NonNull<libc::DIR>,
    position: lx::off_t,
}
// SAFETY: Access is serialized by the enclosing mutable LxFile.
unsafe impl Send for Directory {}
// SAFETY: Shared references never call readdir; iteration requires a mutable LxFile.
unsafe impl Sync for Directory {}
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: This object owns the DIR stream.
        unsafe {
            libc::closedir(self.stream.as_ptr());
        }
    }
}
impl LxFile {
    pub fn fstat(&self) -> lx::Result<lx::StatEx> {
        // SAFETY: Output is initialized by successful fstat on a valid descriptor.
        let value = unsafe {
            let mut value = std::mem::zeroed();
            checked(libc::fstat(self.fd.as_raw_fd(), &mut value))?;
            value
        };
        Ok(stat(value))
    }
    pub fn set_attr(&self, attr: SetAttributes) -> lx::Result<()> {
        attrs(&self.fd, &attr)
    }
    pub fn pread(&self, buffer: &mut [u8], offset: lx::off_t) -> lx::Result<usize> {
        if self.access == lx::O_WRONLY || self.access == lx::O_NOACCESS {
            return Err(lx::Error::EBADF);
        }
        // SAFETY: Valid owned descriptor and output buffer.
        Ok(checked(unsafe {
            libc::pread(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset,
            )
        })? as usize)
    }
    pub fn pwrite(&self, buffer: &[u8], offset: lx::off_t, _: lx::uid_t) -> lx::Result<usize> {
        if self.access == lx::O_RDONLY || self.access == lx::O_NOACCESS {
            return Err(lx::Error::EBADF);
        }
        // SAFETY: Valid owned descriptor and input buffer.
        Ok(checked(unsafe {
            libc::pwrite(
                self.fd.as_raw_fd(),
                buffer.as_ptr().cast(),
                buffer.len(),
                offset,
            )
        })? as usize)
    }
    pub fn fsync(&self, _: bool) -> lx::Result<()> {
        // SAFETY: Valid owned descriptor.
        checked(unsafe { libc::fsync(self.fd.as_raw_fd()) })?;
        Ok(())
    }
    pub fn read_dir<F>(&mut self, offset: lx::off_t, mut callback: F) -> lx::Result<()>
    where
        F: FnMut(lx::DirEntry) -> lx::Result<bool>,
    {
        if self.access == lx::O_WRONLY || self.access == lx::O_NOACCESS {
            return Err(lx::Error::EBADF);
        }
        if offset < 0 {
            return Err(lx::Error::EINVAL);
        }
        if self.directory.is_none() {
            let fd = self.fd.try_clone()?.into_raw_fd(); // SAFETY: fdopendir takes ownership only on success.
            let stream = unsafe { libc::fdopendir(fd) };
            if let Some(stream) = std::ptr::NonNull::new(stream) {
                self.directory = Some(Directory {
                    stream,
                    position: 0,
                });
            } else {
                // SAFETY: fd remains owned after failed fdopendir.
                unsafe {
                    libc::close(fd);
                }
                return Err(errno());
            }
        }
        let directory = self.directory.as_mut().unwrap();
        let stream = directory.stream.as_ptr();
        // Darwin's telldir cookies can be zero and expire on rewind. Keep
        // ordinal wire offsets so an earlier offset remains usable afterwards.
        // SAFETY: DIR stream is owned and accessed exclusively.
        unsafe {
            if offset == 0 || offset != directory.position {
                libc::rewinddir(stream);
                directory.position = 0;
                while directory.position < offset {
                    *libc::__error() = 0;
                    if libc::readdir(stream).is_null() {
                        return if *libc::__error() == 0 {
                            Ok(())
                        } else {
                            Err(errno())
                        };
                    }
                    directory.position += 1;
                }
            }
            loop {
                *libc::__error() = 0;
                let entry = libc::readdir(stream);
                if entry.is_null() {
                    if *libc::__error() != 0 {
                        return Err(errno());
                    }
                    break;
                }
                let entry = &*entry;
                let length = entry
                    .d_name
                    .iter()
                    .position(|c| *c == 0)
                    .ok_or(lx::Error::EIO)?;
                let name = lx::LxString::from_vec(
                    entry.d_name[..length].iter().map(|c| *c as u8).collect(),
                );
                directory.position += 1;
                if !callback(lx::DirEntry {
                    name,
                    inode_nr: entry.d_ino,
                    offset: directory.position,
                    file_type: entry.d_type,
                })? {
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_pins_every_ancestor_and_refuses_final_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("link"))
            .unwrap();
        let volume = LxVolume::new(root.path(), &crate::LxVolumeOptions::new()).unwrap();
        assert!(
            volume
                .open(Path::new("escape/secret"), lx::O_RDONLY, None)
                .is_err()
        );
        assert!(volume.open(Path::new("link"), lx::O_RDONLY, None).is_err());
        assert_eq!(
            volume.mkdir(Path::new("escape/write"), LxCreateOptions::default()),
            Err(lx::Error::ENOTDIR)
        );
        assert!(volume.lstat(Path::new("../secret")).is_err());
        assert!(!outside.path().join("write").exists());
    }

    #[test]
    fn linux_flags_byte_io_and_directory_cookies_work() {
        let root = tempfile::tempdir().unwrap();
        let volume = LxVolume::new(root.path(), &crate::LxVolumeOptions::new()).unwrap();
        let file = volume
            .open(
                Path::new("data"),
                lx::O_RDWR | lx::O_CREAT | lx::O_EXCL,
                Some(LxCreateOptions {
                    mode: 0o600,
                    ..Default::default()
                }),
            )
            .unwrap();
        file.pwrite(b"\0\xffhello", 0, 65534).unwrap();
        let mut buffer = [0; 7];
        assert_eq!(file.pread(&mut buffer, 0).unwrap(), 7);
        assert_eq!(&buffer, b"\0\xffhello");
        assert_eq!(file.fstat().unwrap().file_size, 7);
        assert!(
            volume
                .open(
                    Path::new("data"),
                    lx::O_CREAT | lx::O_EXCL | lx::O_WRONLY,
                    None
                )
                .is_err()
        );
        let mut directory = volume
            .open(Path::new(""), lx::O_RDONLY | lx::O_DIRECTORY, None)
            .unwrap();
        let mut names = Vec::new();
        directory
            .read_dir(0, |entry| {
                names.push(entry.name);
                Ok(true)
            })
            .unwrap();
        assert!(names.iter().any(|name| name.as_bytes() == b"data"));
        volume
            .rename(Path::new("data"), Path::new("moved"), 0)
            .unwrap();
        assert!(root.path().join("moved").exists());
    }

    #[test]
    fn unsupported_operations_are_refused_and_unlink_preserves_the_target() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret");
        std::fs::write(&target, b"outside").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("link")).unwrap();
        let volume = LxVolume::new(root.path(), &crate::LxVolumeOptions::new()).unwrap();
        assert_eq!(
            volume.symlink(
                Path::new("new-link"),
                lx::LxStr::new("secret"),
                LxCreateOptions::default()
            ),
            Err(lx::Error::ENOTSUP)
        );
        assert_eq!(
            volume.mknod(
                Path::new("device"),
                LxCreateOptions {
                    mode: lx::S_IFCHR,
                    ..Default::default()
                },
                0
            ),
            Err(lx::Error::ENOTSUP)
        );
        assert_eq!(
            volume.set_xattr(Path::new("link"), lx::LxStr::new("user.test"), b"value", 0),
            Err(lx::Error::ENOTSUP)
        );
        assert_eq!(volume.list_xattr(Path::new(""), None), Ok(0));
        volume.unlink(Path::new("link"), 0).unwrap();
        assert!(!root.path().join("link").symlink_metadata().is_ok());
        assert_eq!(std::fs::read(target).unwrap(), b"outside");
    }

    #[test]
    fn credentials_never_impersonate_or_change_process_identity() {
        // SAFETY: Side-effect-free identity queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if uid != 0 {
            assert!(FsCredentials::switch(uid, gid).is_ok());
        }
        assert!(FsCredentials::switch(0, 0).is_err());
        assert!(FsCredentials::switch(uid.wrapping_add(1), gid).is_err());
        // SAFETY: Side-effect-free identity queries.
        assert_eq!(unsafe { (libc::geteuid(), libc::getegid()) }, (uid, gid));
    }
}
