// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Architectural state and framework policy shared by Intel HVF and its tests.

pub const INITIAL_ENTRY_CONTROLS: u64 = 1 << 15; // load EFER, maintained in VMCS
pub const EFER_MASK: u64 = (1 << 0) | (1 << 8) | (1 << 10) | (1 << 11);

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
