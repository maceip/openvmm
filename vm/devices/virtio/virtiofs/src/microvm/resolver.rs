// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! microVM resource-profile resolution.

use super::profile::MICROVM_MOUNT_TAG;
use crate::virtio::VirtioFsDevice;
use virtio_resources::fs::VirtioFsBackend;
use virtio_resources::fs::VirtioFsHandle;
use virtio_resources::fs::microvm::VirtioFsProfile;
use vmcore::vm_task::VmTaskDriverSource;

pub(crate) fn resolve(
    resource: &VirtioFsHandle,
    driver_source: &VmTaskDriverSource,
) -> anyhow::Result<Option<VirtioFsDevice>> {
    let device = match &resource.profile {
        VirtioFsProfile::Standard => return Ok(None),
        VirtioFsProfile::MicrovmDormant { stable_id } => {
            anyhow::ensure!(
                resource.tag == MICROVM_MOUNT_TAG,
                "microVM virtio-fs tag must be '{}'",
                MICROVM_MOUNT_TAG
            );
            anyhow::ensure!(
                matches!(resource.fs, VirtioFsBackend::Dormant),
                "dormant microVM virtio-fs cannot have an active backend"
            );
            VirtioFsDevice::new_microvm_dormant(driver_source, stable_id.clone(), None)?
        }
        VirtioFsProfile::Microvm {
            stable_id,
            root_identity,
            read_only,
            denied_paths,
            owner,
        } => {
            anyhow::ensure!(
                resource.tag == MICROVM_MOUNT_TAG,
                "microVM virtio-fs tag must be '{}'",
                MICROVM_MOUNT_TAG
            );
            let VirtioFsBackend::HostFs {
                root_path,
                mount_options,
            } = &resource.fs
            else {
                anyhow::bail!("microVM virtio-fs requires a HostFs backend");
            };
            anyhow::ensure!(
                mount_options.is_empty(),
                "microVM virtio-fs does not accept HostFs mount options"
            );
            VirtioFsDevice::new_microvm_hostfs_with_owner(
                driver_source,
                stable_id.clone(),
                root_identity.clone(),
                *read_only,
                denied_paths.clone(),
                root_path,
                *owner,
                None,
            )?
        }
    };
    Ok(Some(device))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::MICROVM_ATTACHMENT_ID;
    use crate::profile::microvm_root_identity;
    use crate::resolver::VirtioFsResolver;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use virtio::resolve::ResolvedVirtioDevice;
    use virtio::resolve::VirtioResolveInput;
    use virtio_resources::fs::VirtioFsAggregateChild;
    use virtio_resources::fs::microvm::VirtioFsOwner;
    use vm_resource::ResolveResource;
    use vmcore::vm_task::SingleDriverBackend;

    fn resolve(
        driver: DefaultDriver,
        tag: &str,
        fs: VirtioFsBackend,
    ) -> anyhow::Result<ResolvedVirtioDevice> {
        resolve_with_owner(driver, tag, fs, VirtioFsOwner::Process)
    }

    fn resolve_with_owner(
        driver: DefaultDriver,
        tag: &str,
        fs: VirtioFsBackend,
        owner: VirtioFsOwner,
    ) -> anyhow::Result<ResolvedVirtioDevice> {
        let root_path = match &fs {
            VirtioFsBackend::HostFs { root_path, .. } => Some(root_path),
            _ => None,
        };
        let root_identity = root_path
            .map(microvm_root_identity)
            .transpose()?
            .unwrap_or_else(|| vec![1]);
        let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
        VirtioFsResolver.resolve(
            VirtioFsHandle {
                tag: tag.to_owned(),
                fs,
                profile: VirtioFsProfile::Microvm {
                    stable_id: MICROVM_ATTACHMENT_ID.to_owned(),
                    root_identity,
                    read_only: true,
                    denied_paths: Vec::new(),
                    owner,
                },
            },
            VirtioResolveInput {
                driver_source: &driver_source,
            },
        )
    }

    fn host_backend(root: &std::path::Path) -> VirtioFsBackend {
        VirtioFsBackend::HostFs {
            root_path: root.to_string_lossy().into_owned(),
            mount_options: String::new(),
        }
    }

    #[async_test]
    async fn microvm_profile_resolves_caller_owner_only_on_linux(driver: DefaultDriver) {
        let root = tempfile::tempdir().unwrap();
        let result = resolve_with_owner(
            driver,
            MICROVM_MOUNT_TAG,
            host_backend(root.path()),
            VirtioFsOwner::Caller,
        );
        if cfg!(unix) {
            // The temporary directory is owned by the test user, so the only
            // failure mode is a root-owned export when the tests run as root.
            if let Err(error) = result {
                assert!(error.to_string().contains("non-root user"), "{error:#}");
            }
        } else {
            let error = result.err().expect("caller owner resolved on Windows");
            assert!(error.to_string().contains("Linux host"), "{error:#}");
        }
    }

    #[async_test]
    async fn microvm_profile_rejects_non_fixed_tag(driver: DefaultDriver) {
        let root = tempfile::tempdir().unwrap();
        let result = resolve(
            driver,
            "other",
            VirtioFsBackend::HostFs {
                root_path: root.path().to_string_lossy().into_owned(),
                mount_options: String::new(),
            },
        );
        assert!(result.is_err());
    }

    #[async_test]
    async fn microvm_profile_rejects_mount_options(driver: DefaultDriver) {
        let root = tempfile::tempdir().unwrap();
        let result = resolve(
            driver,
            MICROVM_MOUNT_TAG,
            VirtioFsBackend::HostFs {
                root_path: root.path().to_string_lossy().into_owned(),
                mount_options: "ro".to_owned(),
            },
        );
        assert!(result.is_err());
    }

    #[async_test]
    async fn microvm_profile_rejects_non_host_backends(driver: DefaultDriver) {
        let result = resolve(
            driver,
            MICROVM_MOUNT_TAG,
            VirtioFsBackend::Aggregate {
                children: vec![VirtioFsAggregateChild {
                    name: "child".to_owned(),
                    root_path: ".".to_owned(),
                    mount_options: String::new(),
                }],
            },
        );
        assert!(result.is_err());
    }

    #[async_test]
    async fn microvm_profile_rejects_section_backend(driver: DefaultDriver) {
        let result = resolve(
            driver,
            MICROVM_MOUNT_TAG,
            VirtioFsBackend::SectionFs {
                root_path: ".".to_owned(),
            },
        );
        assert!(result.is_err());
    }
}
