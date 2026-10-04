// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native macOS Hypervisor.framework backends.

#![expect(missing_docs)]
#![cfg(all(target_os = "macos", guest_is_native))]
// UNSAFETY: Calling Hypervisor.framework and mapping guest memory.
#![expect(unsafe_code)]

#[cfg(any(guest_arch = "x86_64", test))]
mod intel;

#[cfg(guest_arch = "aarch64")]
include!("aarch64.rs");

#[cfg(guest_arch = "x86_64")]
mod x86_64;
#[cfg(guest_arch = "x86_64")]
pub use x86_64::*;
