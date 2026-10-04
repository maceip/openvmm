// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Architectural state and framework policy shared by Intel HVF and its tests.

pub const INITIAL_ENTRY_CONTROLS: u64 = 1 << 15; // load EFER, maintained in VMCS
pub const EFER_MASK: u64 = (1 << 0) | (1 << 8) | (1 << 10) | (1 << 11);

/// Separate VMX's fixed hardware bits from the architectural guest value.
pub struct ControlRegisterPolicy {
    required: u64,
    allowed: u64,
    cleared: u64,
    pub mask: u64,
}

impl ControlRegisterPolicy {
    pub fn cr0(required: u64, allowed: u64) -> Self {
        // Unrestricted guests may clear PE and PG. Cache-disable bits stay
        // virtual, and trapping PG changes keeps EFER.LMA and entry mode in sync.
        let required = required & !((1 << 0) | (1 << 31));
        let cleared = (1 << 29) | (1 << 30);
        Self {
            required,
            allowed,
            cleared,
            mask: required | !allowed | cleared | (1 << 31),
        }
    }

    pub fn cr4(required: u64, allowed: u64) -> Self {
        Self {
            required,
            allowed,
            cleared: 0,
            mask: required | !allowed,
        }
    }

    pub fn hardware(&self, guest: u64) -> u64 {
        ((guest | self.required) & self.allowed) & !self.cleared
    }

    pub fn guest(&self, hardware: u64, shadow: u64) -> u64 {
        (hardware & !self.mask) | (shadow & self.mask)
    }

    pub fn supports(&self, guest: u64) -> bool {
        guest & !self.allowed == 0
    }
}

pub fn efer_for_cr0(efer: u64, cr0: u64) -> u64 {
    let long_mode = efer & (1 << 8) != 0 && cr0 & (1 << 31) != 0;
    (efer & !(1 << 10)) | (u64::from(long_mode) << 10)
}

/// LMSW changes only CR0's low four bits and cannot clear PE once set.
pub fn cr0_for_lmsw(current: u64, source: u64) -> u64 {
    (current & !0xf) | (source & 0xf) | (current & 1)
}

pub const NATIVE_MSRS: &[u32] = &[
    0xc0000081, 0xc0000082, 0xc0000083, 0xc0000084, 0xc0000100, 0xc0000101, 0xc0000102, 0x174,
    0x175, 0x176,
];

/// Guest PAT is software state: the framework exposes neither its MSR nor VMCS.
pub struct GuestPat(u64);

impl Default for GuestPat {
    fn default() -> Self {
        Self(0x0007_0406_0007_0406)
    }
}

impl GuestPat {
    pub fn get(&self) -> u64 {
        self.0
    }

    /// Invalid memory types leave the old value intact so WRMSR can inject #GP.
    pub fn set(&mut self, value: u64) -> bool {
        if !(0..8).all(|index| matches!((value >> (index * 8)) & 0xff, 0..=1 | 4..=7)) {
            return false;
        }
        self.0 = value;
        true
    }
}

/// Preserve read-only LMA and forbid changing LME while paging is enabled.
pub fn guest_efer_write(current: u64, requested: u64, paging: bool) -> Option<u64> {
    if requested & !EFER_MASK != 0 || (paging && (requested ^ current) & (1 << 8) != 0) {
        return None;
    }
    Some((requested & !(1 << 10)) | (current & (1 << 10)))
}

pub fn entry_controls_for_efer(controls: u64, efer: u64) -> u64 {
    (controls & !(1 << 9)) | (((efer >> 10) & 1) << 9)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn native_pvh_state_satisfies_fixed_bits_without_changing_guest_state() {
        let cr0 = ControlRegisterPolicy::cr0(0x80000021, 0xffffffff);
        let cr4 = ControlRegisterPolicy::cr4(0x2000, 0x3767ff);
        // Actual microVM loader state and native i7-8700B capability masks.
        assert_eq!(0x80000001u64 & 0x20, 0);
        assert_eq!(0x20 & 0x2000, 0);
        assert_eq!(cr0.hardware(0x80000001), 0x80000021);
        assert_eq!(cr4.hardware(0x20), 0x2020);
        assert_eq!(cr0.guest(cr0.hardware(0x80000001), 0x80000001), 0x80000001);
        assert_eq!(cr4.guest(cr4.hardware(0x20), 0x20), 0x20);
    }

    #[test]
    fn virtual_control_bits_round_trip_while_unmasked_bits_follow_execution() {
        let policy = ControlRegisterPolicy::cr0(0x80000021, 0xffffffff);
        for guest in [0x60000010, 1, 0x80000001, 0x80010033] {
            let hardware = policy.hardware(guest);
            assert_eq!(hardware & 0x60000000, 0);
            assert_ne!(hardware & 0x20, 0);
            let captured = policy.guest(hardware ^ 8, guest);
            assert_eq!(captured, guest ^ 8);
            assert_eq!(policy.guest(policy.hardware(captured), captured), captured);
        }
        assert!(!policy.supports(1 << 32));
    }

    #[test]
    fn paging_transitions_select_long_mode_and_preserve_other_efer_bits() {
        assert_eq!(efer_for_cr0(0x901, 0x80000001), 0xd01);
        assert_eq!(efer_for_cr0(0xd01, 1), 0x901);
        assert_eq!(efer_for_cr0(0x801, 0x80000001), 0x801);
    }

    #[test]
    fn lmsw_preserves_paging_and_cannot_leave_protected_mode() {
        assert_eq!(cr0_for_lmsw(0x80000001, 0), 0x80000001);
        assert_eq!(cr0_for_lmsw(0x60000010, 0xffff), 0x6000001f);
    }

    #[test]
    fn required_entry_controls_fit_native_framework_capabilities() {
        // Observed on the native Intel macOS runner: EFER is required, PAT
        // loading is not exposed by the framework's VM-entry API.
        let allowed = 0xb3ff;
        assert_eq!(INITIAL_ENTRY_CONTROLS & !allowed, 0);
        assert_ne!(INITIAL_ENTRY_CONTROLS & (1 << 15), 0);
    }

    #[test]
    fn native_msr_list_excludes_vmcs_and_software_state() {
        // The framework rejects native PAT and EFER MSR access. It exposes
        // EFER through the guest VMCS field and does not expose guest PAT.
        assert!(!NATIVE_MSRS.contains(&0xc0000080));
        assert!(!NATIVE_MSRS.contains(&0x277));
        assert!(NATIVE_MSRS.contains(&0xc0000081));
    }

    #[test]
    fn guest_pat_rejects_reserved_types_without_mutating_state() {
        for index in 0..8 {
            for memory_type in 0..=255u64 {
                let mut pat = GuestPat::default();
                let initial = pat.get();
                let value = (initial & !(0xff << (index * 8))) | (memory_type << (index * 8));
                let valid = matches!(memory_type, 0..=1 | 4..=7);
                assert_eq!(pat.set(value), valid);
                assert_eq!(pat.get(), if valid { value } else { initial });
            }
        }
    }

    #[test]
    fn guest_pat_survives_capture_and_restore() {
        let mut source = GuestPat::default();
        assert!(source.set(0x0104_0506_0700_0106));
        let captured = source.get();
        let mut restored = GuestPat::default();
        assert!(restored.set(captured));
        assert_eq!(restored.get(), captured);
        assert!(!restored.set(0x0204_0506_0700_0106));
        assert_eq!(restored.get(), captured);
    }

    #[test]
    fn guest_efer_preserves_lma_and_locks_lme_while_paging() {
        let current = (1 << 8) | (1 << 10);
        assert_eq!(
            guest_efer_write(current, current ^ (1 << 10), true),
            Some(current)
        );
        assert_eq!(guest_efer_write(current, current ^ (1 << 8), true), None);
        assert_eq!(guest_efer_write(0, 1 << 8, false), Some(1 << 8));
        assert_eq!(guest_efer_write(current, current | (1 << 63), true), None);
    }

    #[test]
    fn restored_efer_selects_guest_mode_without_changing_other_controls() {
        let controls = 0x91ff;
        assert_eq!(
            entry_controls_for_efer(controls, 1 << 10),
            controls | (1 << 9)
        );
        assert_eq!(entry_controls_for_efer(controls | (1 << 9), 0), controls);
    }
}
