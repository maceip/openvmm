// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Intel Hypervisor.framework ABI, as declared by the macOS SDK.

use std::ffi::c_void;

pub const INVALID_VCPU: u32 = u32::MAX;

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_create(options: u64) -> u32;
    pub fn hv_vm_destroy() -> u32;
    pub fn hv_vm_map(address: *mut c_void, gpa: u64, size: usize, flags: u64) -> u32;
    pub fn hv_vm_unmap(gpa: u64, size: usize) -> u32;
    pub fn hv_vcpu_create(vcpu: *mut u32, options: u64) -> u32;
    pub fn hv_vcpu_destroy(vcpu: u32) -> u32;
    pub fn hv_vcpu_read_register(vcpu: u32, register: u32, value: *mut u64) -> u32;
    pub fn hv_vcpu_write_register(vcpu: u32, register: u32, value: u64) -> u32;
    pub fn hv_vcpu_read_msr(vcpu: u32, msr: u32, value: *mut u64) -> u32;
    pub fn hv_vcpu_write_msr(vcpu: u32, msr: u32, value: u64) -> u32;
    pub fn hv_vcpu_enable_native_msr(vcpu: u32, msr: u32, enable: bool) -> u32;
    pub fn hv_vcpu_read_fpstate(vcpu: u32, buffer: *mut c_void, size: usize) -> u32;
    pub fn hv_vcpu_write_fpstate(vcpu: u32, buffer: *mut c_void, size: usize) -> u32;
    pub fn hv_vcpu_run_until(vcpu: u32, deadline: u64) -> u32;
    pub fn hv_vcpu_interrupt(vcpus: *mut u32, count: u32) -> u32;
    pub fn hv_vcpu_set_tsc_relative(vcpu: u32, offset: i64) -> u32;
    pub fn hv_tsc_clock() -> u64;
    pub fn hv_vmx_vcpu_read_vmcs(vcpu: u32, field: u32, value: *mut u64) -> u32;
    pub fn hv_vmx_vcpu_write_vmcs(vcpu: u32, field: u32, value: u64) -> u32;
    pub fn hv_vmx_vcpu_get_cap_write_vmcs(
        vcpu: u32,
        field: u32,
        must_be_one: *mut u64,
        allowed_one: *mut u64,
    ) -> u32;
}

#[repr(C)]
pub struct MachTimebase {
    pub numer: u32,
    pub denom: u32,
}
unsafe extern "C" {
    pub fn mach_absolute_time() -> u64;
    pub fn mach_timebase_info(info: *mut MachTimebase) -> i32;
}
