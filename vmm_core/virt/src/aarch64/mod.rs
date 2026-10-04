// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod gic_software_device;
pub mod gic_v2m;
pub mod vm;
pub mod vp;

use crate::IsolationType;
use crate::state::StateElement;
use aarch64defs::Vendor;
use inspect::Inspect;
use mesh_protobuf::Protobuf;
use thiserror::Error;
use vm_topology::processor::aarch64::Aarch64VpInfo;

pub use virt_support_gic::SavedDistributorState;
pub use virt_support_gic::SavedRedistributorState;

/// VP state that can be set for initial boot.
#[derive(Debug, PartialEq, Eq, Protobuf)]
pub struct Aarch64InitialRegs {
    /// Register state to be set on the BSP.
    pub registers: vp::Registers,
    /// System register state for the BSP.
    pub system_registers: vp::SystemRegisters,
}

impl Aarch64InitialRegs {
    pub fn at_reset(caps: &Aarch64PartitionCapabilities, bsp: &Aarch64VpInfo) -> Self {
        Self {
            registers: vp::Registers::at_reset(caps, bsp),
            system_registers: vp::SystemRegisters::at_reset(caps, bsp),
        }
    }
}

#[derive(Debug, Inspect)]
pub struct Aarch64PartitionCapabilities {
    /// Isolation type for the partition.
    pub isolation: IsolationType,
    /// Whether the processor supports aarch32 execution at EL0.
    pub supports_aarch32_el0: bool,
    #[inspect(display)]
    pub vendor: Vendor,
    /// Number of SPIs in the GIC distributor.
    ///
    /// This sizes the distributor save/restore vectors and gates whether GIC
    /// state participates in snapshots at all: backends whose interrupt
    /// controller state cannot be captured must set this to zero, in which
    /// case the distributor and redistributor elements are skipped on save
    /// and never present on restore.
    pub gic_max_spis: u32,
    /// Whether the per-VP virtual-timer control registers (`CNTV_CTL_EL0`,
    /// `CNTV_CVAL_EL0`) participate in snapshots. Without them a restored
    /// guest loses its timer interrupt and stops making progress.
    pub virtual_timer_save: bool,
    /// Complete backend-native state is included in the snapshot.
    pub native_state_save: bool,
    /// Whether the [`vp::ExtendedSystemRegisters`] (`SPSR_EL1`, the `TPIDR`
    /// thread registers, the `AP*KEY` pointer-authentication keys, and
    /// `FPCR`/`FPSR`) participate in snapshots. These change at runtime
    /// (per-CPU base, thread pointers, exception return state, per-boot keys)
    /// and cannot be reconstructed, so a backend that cannot capture them
    /// must leave this clear.
    pub extended_system_registers_save: bool,
}

#[derive(Error, Debug)]
pub enum Aarch64PartitionCapabilitiesError {}
