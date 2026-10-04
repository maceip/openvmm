// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::IsolationType;
use crate::aarch64::Aarch64PartitionCapabilities;
use crate::aarch64::SavedRedistributorState;
use crate::state::HvRegisterState;
use crate::state::StateElement;
use crate::state::state_trait;
use aarch64defs::Cpsr64;
use aarch64defs::SctlrEl1;
use hvdef::HvArm64RegisterName;
use hvdef::HvRegisterValue;
use inspect::Inspect;
use mesh_protobuf::Protobuf;
use vm_topology::processor::aarch64::Aarch64VpInfo;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Protobuf, Inspect)]
#[mesh(package = "virt.aarch64")]
#[inspect(hex)]
pub struct Registers {
    #[mesh(1)]
    pub x0: u64,
    #[mesh(2)]
    pub x1: u64,
    #[mesh(3)]
    pub x2: u64,
    #[mesh(4)]
    pub x3: u64,
    #[mesh(5)]
    pub x4: u64,
    #[mesh(6)]
    pub x5: u64,
    #[mesh(7)]
    pub x6: u64,
    #[mesh(8)]
    pub x7: u64,
    #[mesh(9)]
    pub x8: u64,
    #[mesh(10)]
    pub x9: u64,
    #[mesh(11)]
    pub x10: u64,
    #[mesh(12)]
    pub x11: u64,
    #[mesh(13)]
    pub x12: u64,
    #[mesh(14)]
    pub x13: u64,
    #[mesh(15)]
    pub x14: u64,
    #[mesh(16)]
    pub x15: u64,
    #[mesh(17)]
    pub x16: u64,
    #[mesh(18)]
    pub x17: u64,
    #[mesh(19)]
    pub x18: u64,
    #[mesh(20)]
    pub x19: u64,
    #[mesh(21)]
    pub x20: u64,
    #[mesh(22)]
    pub x21: u64,
    #[mesh(23)]
    pub x22: u64,
    #[mesh(24)]
    pub x23: u64,
    #[mesh(25)]
    pub x24: u64,
    #[mesh(26)]
    pub x25: u64,
    #[mesh(27)]
    pub x26: u64,
    #[mesh(28)]
    pub x27: u64,
    #[mesh(29)]
    pub x28: u64,
    #[mesh(30)]
    pub fp: u64,
    #[mesh(31)]
    pub lr: u64,
    #[mesh(32)]
    pub sp_el0: u64,
    #[mesh(33)]
    pub sp_el1: u64,
    #[mesh(34)]
    pub pc: u64,
    #[mesh(35)]
    pub cpsr: u64,
}

impl HvRegisterState<HvArm64RegisterName, 35> for Registers {
    fn names(&self) -> &'static [HvArm64RegisterName; 35] {
        &[
            HvArm64RegisterName::X0,
            HvArm64RegisterName::X1,
            HvArm64RegisterName::X2,
            HvArm64RegisterName::X3,
            HvArm64RegisterName::X4,
            HvArm64RegisterName::X5,
            HvArm64RegisterName::X6,
            HvArm64RegisterName::X7,
            HvArm64RegisterName::X8,
            HvArm64RegisterName::X9,
            HvArm64RegisterName::X10,
            HvArm64RegisterName::X11,
            HvArm64RegisterName::X12,
            HvArm64RegisterName::X13,
            HvArm64RegisterName::X14,
            HvArm64RegisterName::X15,
            HvArm64RegisterName::X16,
            HvArm64RegisterName::X17,
            HvArm64RegisterName::X18,
            HvArm64RegisterName::X19,
            HvArm64RegisterName::X20,
            HvArm64RegisterName::X21,
            HvArm64RegisterName::X22,
            HvArm64RegisterName::X23,
            HvArm64RegisterName::X24,
            HvArm64RegisterName::X25,
            HvArm64RegisterName::X26,
            HvArm64RegisterName::X27,
            HvArm64RegisterName::X28,
            HvArm64RegisterName::XFp,
            HvArm64RegisterName::XLr,
            HvArm64RegisterName::XSpEl0,
            HvArm64RegisterName::XSpElx,
            HvArm64RegisterName::XPc,
            HvArm64RegisterName::Cpsr,
        ]
    }

    fn get_values<'a>(&self, it: impl Iterator<Item = &'a mut HvRegisterValue>) {
        let &Self {
            x0,
            x1,
            x2,
            x3,
            x4,
            x5,
            x6,
            x7,
            x8,
            x9,
            x10,
            x11,
            x12,
            x13,
            x14,
            x15,
            x16,
            x17,
            x18,
            x19,
            x20,
            x21,
            x22,
            x23,
            x24,
            x25,
            x26,
            x27,
            x28,
            fp,
            lr,
            sp_el0,
            sp_el1,
            pc,
            cpsr,
        } = self;
        for (dest, src) in it.zip([
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18,
            x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, fp, lr, sp_el0, sp_el1, pc, cpsr,
        ]) {
            *dest = src.into()
        }
    }

    fn set_values(&mut self, mut it: impl Iterator<Item = HvRegisterValue>) {
        let Self {
            x0,
            x1,
            x2,
            x3,
            x4,
            x5,
            x6,
            x7,
            x8,
            x9,
            x10,
            x11,
            x12,
            x13,
            x14,
            x15,
            x16,
            x17,
            x18,
            x19,
            x20,
            x21,
            x22,
            x23,
            x24,
            x25,
            x26,
            x27,
            x28,
            fp,
            lr,
            sp_el0,
            sp_el1,
            pc,
            cpsr,
        } = self;
        for (dest, src) in [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18,
            x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, fp, lr, sp_el0, sp_el1, pc, cpsr,
        ]
        .into_iter()
        .zip(&mut it)
        {
            *dest = src.as_u64();
        }
    }
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for Registers {
    fn is_present(_caps: &Aarch64PartitionCapabilities) -> bool {
        true
    }

    fn at_reset(_caps: &Aarch64PartitionCapabilities, _vp_info: &Aarch64VpInfo) -> Self {
        Self {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            fp: 0,
            lr: 0,
            sp_el0: 0,
            sp_el1: 0,
            pc: 0,
            cpsr: Cpsr64::new()
                .with_sp(true)
                .with_el(1)
                .with_f(true)
                .with_i(true)
                .with_a(true)
                .with_d(true)
                .into(),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Protobuf, Inspect)]
#[mesh(package = "virt.aarch64")]
pub struct SystemRegisters {
    #[inspect(hex)]
    #[mesh(1)]
    pub sctlr_el1: u64,
    #[inspect(hex)]
    #[mesh(2)]
    pub ttbr0_el1: u64,
    #[inspect(hex)]
    #[mesh(3)]
    pub ttbr1_el1: u64,
    #[inspect(hex)]
    #[mesh(4)]
    pub tcr_el1: u64,
    #[inspect(hex)]
    #[mesh(5)]
    pub esr_el1: u64,
    #[inspect(hex)]
    #[mesh(6)]
    pub far_el1: u64,
    #[inspect(hex)]
    #[mesh(7)]
    pub mair_el1: u64,
    #[inspect(hex)]
    #[mesh(8)]
    pub elr_el1: u64,
    #[inspect(hex)]
    #[mesh(9)]
    pub vbar_el1: u64,
}

impl HvRegisterState<HvArm64RegisterName, 9> for SystemRegisters {
    fn names(&self) -> &'static [HvArm64RegisterName; 9] {
        &[
            HvArm64RegisterName::SctlrEl1,
            HvArm64RegisterName::Ttbr0El1,
            HvArm64RegisterName::Ttbr1El1,
            HvArm64RegisterName::TcrEl1,
            HvArm64RegisterName::EsrEl1,
            HvArm64RegisterName::FarEl1,
            HvArm64RegisterName::MairEl1,
            HvArm64RegisterName::ElrEl1,
            HvArm64RegisterName::VbarEl1,
        ]
    }

    fn get_values<'a>(&self, it: impl Iterator<Item = &'a mut HvRegisterValue>) {
        let &Self {
            sctlr_el1,
            ttbr0_el1,
            ttbr1_el1,
            tcr_el1,
            esr_el1,
            far_el1,
            mair_el1,
            elr_el1,
            vbar_el1,
        } = self;
        for (dest, src) in it.zip([
            sctlr_el1, ttbr0_el1, ttbr1_el1, tcr_el1, esr_el1, far_el1, mair_el1, elr_el1, vbar_el1,
        ]) {
            *dest = src.into();
        }
    }

    fn set_values(&mut self, it: impl Iterator<Item = HvRegisterValue>) {
        let Self {
            sctlr_el1,
            ttbr0_el1,
            ttbr1_el1,
            tcr_el1,
            esr_el1,
            far_el1,
            mair_el1,
            elr_el1,
            vbar_el1,
        } = self;
        for (src, dest) in it.zip([
            sctlr_el1, ttbr0_el1, ttbr1_el1, tcr_el1, esr_el1, far_el1, mair_el1, elr_el1, vbar_el1,
        ]) {
            *dest = src.as_u64();
        }
    }
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for SystemRegisters {
    fn is_present(_caps: &Aarch64PartitionCapabilities) -> bool {
        true
    }

    fn at_reset(caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        // ITD and SED are RES1 when aarch32 is not supported. When aarch32 is
        // supported, they reset to 0.
        let no_aarch32 = !caps.supports_aarch32_el0;
        let sctlr_el1 = match caps.isolation {
            IsolationType::Cca => u64::from(
                SctlrEl1::new()
                    .with_sa(true)
                    .with_sa0(true)
                    .with_cp15ben(true)
                    .with_n_aa(true)
                    .with_eos(true)
                    .with_n_twi(true)
                    .with_n_twe(true)
                    .with_eis(true)
                    .with_span(true),
            ),
            _ => u64::from(
                SctlrEl1::new()
                    .with_eos(true)
                    .with_tscxt(true)
                    .with_eis(true)
                    .with_span(true)
                    .with_n_tlsmd(true)
                    .with_lsmaoe(true)
                    .with_itd(no_aarch32)
                    .with_sed(no_aarch32),
            ),
        };

        Self {
            sctlr_el1,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            esr_el1: 0,
            far_el1: 0,
            mair_el1: 0,
            elr_el1: 0,
            vbar_el1: 0,
        }
    }
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for SavedRedistributorState {
    fn is_present(caps: &Aarch64PartitionCapabilities) -> bool {
        caps.gic_max_spis > 0
    }

    fn at_reset(_caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        SavedRedistributorState {
            pending: 0,
            active: 0,
            group: 0,
            enable: 0,
            ppi_cfg: 0,
            priority: [0; 8],
            sleep: false,
        }
    }
}

/// Per-VP virtual-timer control state (`CNTV_CTL_EL0`/`CNTV_CVAL_EL0`).
///
/// The timer counter itself (`CNTVCT_EL0`) is host time and is not captured;
/// a restored compare value in the past fires immediately, after which the
/// guest reprograms the timer and returns to steady state.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Protobuf, Inspect)]
#[mesh(package = "virt.aarch64")]
pub struct VirtualTimerState {
    #[mesh(1)]
    pub ctl_el0: u64,
    #[mesh(2)]
    pub cval_el0: u64,
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for VirtualTimerState {
    fn is_present(caps: &Aarch64PartitionCapabilities) -> bool {
        caps.virtual_timer_save
    }

    fn at_reset(_caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        Self::default()
    }
}

/// Per-VP system registers outside [`SystemRegisters`] that guest software
/// mutates at runtime.
///
/// `TPIDR_EL1` is the Linux per-CPU base: without it every per-CPU access
/// (including the IRQ-stack switch on exception entry) uses a stale pointer.
/// `TPIDR_EL0`/`TPIDRRO_EL0` are the user thread pointers (TLS). `SPSR_EL1`
/// is consumed by the next `ERET`. The `AP*KEY` registers hold the pointer
/// authentication keys Linux randomizes per CPU at boot; a stale key faults
/// every authenticated return. `FPCR`/`FPSR` round out the FP control state,
/// while `CPACR_EL1` gates FP traps, `CNTKCTL_EL1` gates EL0 timer access,
/// and `CONTEXTIDR_EL1` is rewritten on every task switch. None of these are
/// stable constants, so a backend that cannot capture them must leave
/// [`Aarch64PartitionCapabilities::extended_system_registers_save`] clear.
///
/// (The 128-bit SIMD vector registers are not covered: no access API for
/// them exists on any backend yet.)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Protobuf, Inspect)]
#[mesh(package = "virt.aarch64")]
pub struct ExtendedSystemRegisters {
    #[mesh(1)]
    pub spsr_el1: u64,
    #[mesh(2)]
    pub tpidr_el0: u64,
    #[mesh(3)]
    pub tpidrro_el0: u64,
    #[mesh(4)]
    pub tpidr_el1: u64,
    #[mesh(5)]
    pub apdakeylo_el1: u64,
    #[mesh(6)]
    pub apdakeyhi_el1: u64,
    #[mesh(7)]
    pub apdbkeylo_el1: u64,
    #[mesh(8)]
    pub apdbkeyhi_el1: u64,
    #[mesh(9)]
    pub apiakeylo_el1: u64,
    #[mesh(10)]
    pub apiakeyhi_el1: u64,
    #[mesh(11)]
    pub apibkeylo_el1: u64,
    #[mesh(12)]
    pub apibkeyhi_el1: u64,
    #[mesh(13)]
    pub apgakeylo_el1: u64,
    #[mesh(14)]
    pub apgakeyhi_el1: u64,
    #[mesh(15)]
    pub fpcr: u64,
    #[mesh(16)]
    pub fpsr: u64,
    #[mesh(17)]
    pub cpacr_el1: u64,
    #[mesh(18)]
    pub cntkctl_el1: u64,
    #[mesh(19)]
    pub contextidr_el1: u64,
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for ExtendedSystemRegisters {
    fn is_present(caps: &Aarch64PartitionCapabilities) -> bool {
        caps.extended_system_registers_save
    }

    fn at_reset(_caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        Self::default()
    }
}

state_trait! {
    "Per-VP state",
    AccessVpState,
    Aarch64PartitionCapabilities,
    Aarch64VpInfo,
    VpSavedState,
    "virt.aarch64",
    (1, "registers", registers, set_registers, Registers),
    (2, "system_registers", system_registers, set_system_registers, SystemRegisters),
    (3, "redistributor", redistributor, set_redistributor, SavedRedistributorState),
    (4, "virtual_timer", virtual_timer, set_virtual_timer, VirtualTimerState),
    (
        5,
        "extended_system_registers",
        extended_system_registers,
        set_extended_system_registers,
        ExtendedSystemRegisters
    ),
}

#[cfg(test)]
mod tests {
    use super::ExtendedSystemRegisters;
    use super::SavedRedistributorState;
    use super::VirtualTimerState;
    use super::VpSavedState;
    use crate::IsolationType;
    use crate::aarch64::Aarch64PartitionCapabilities;
    use crate::state::StateElement;
    use aarch64defs::Vendor;
    use vm_topology::processor::aarch64::Aarch64VpInfo;

    fn caps() -> Aarch64PartitionCapabilities {
        Aarch64PartitionCapabilities {
            isolation: IsolationType::None,
            supports_aarch32_el0: false,
            vendor: Vendor::ARM,
            gic_max_spis: 256,
            virtual_timer_save: true,
            native_state_save: false,
            extended_system_registers_save: true,
        }
    }

    #[test]
    fn new_elements_roundtrip_through_mesh() {
        let redistributor = SavedRedistributorState {
            pending: 0x80000001,
            active: 0x2,
            group: 0x4,
            enable: 0x8,
            ppi_cfg: 0x10,
            priority: [0x20; 8],
            sleep: true,
        };
        let virtual_timer = VirtualTimerState {
            ctl_el0: 1,
            cval_el0: 0x1234567890abcdef,
        };
        let extended_system_registers = ExtendedSystemRegisters {
            spsr_el1: 0x63400005,
            tpidr_el0: 0x1000,
            tpidrro_el0: 0x2000,
            tpidr_el1: 0xffff800082a1aa80,
            apdakeylo_el1: 0x1111,
            apdakeyhi_el1: 0x2222,
            apdbkeylo_el1: 0x3333,
            apdbkeyhi_el1: 0x4444,
            apiakeylo_el1: 0x5555,
            apiakeyhi_el1: 0x6666,
            apibkeylo_el1: 0x7777,
            apibkeyhi_el1: 0x8888,
            apgakeylo_el1: 0x9999,
            apgakeyhi_el1: 0xaaaa,
            fpcr: 0,
            fpsr: 0x10,
            cpacr_el1: 0x300000,
            cntkctl_el1: 0,
            contextidr_el1: 0x55,
        };
        let state = VpSavedState {
            registers: None,
            system_registers: None,
            redistributor: Some(redistributor.clone()),
            virtual_timer: Some(virtual_timer),
            extended_system_registers: Some(extended_system_registers),
        };
        let bytes = mesh_protobuf::encode(state);
        let back: VpSavedState = mesh_protobuf::decode(&bytes).unwrap();
        assert_eq!(back.redistributor, Some(redistributor));
        assert_eq!(back.virtual_timer, Some(virtual_timer));
        assert_eq!(
            back.extended_system_registers,
            Some(extended_system_registers)
        );
    }

    #[test]
    fn saved_state_without_new_elements_decodes_to_none() {
        // A snapshot captured before these elements existed carries only the
        // register fields; the new elements must decode as absent (skipped on
        // restore), not as zeroes.
        let state = VpSavedState {
            registers: Some(super::Registers::default()),
            system_registers: Some(super::SystemRegisters::default()),
            redistributor: None,
            virtual_timer: None,
            extended_system_registers: None,
        };
        let bytes = mesh_protobuf::encode(state);
        let back: VpSavedState = mesh_protobuf::decode(&bytes).unwrap();
        assert!(back.redistributor.is_none());
        assert!(back.virtual_timer.is_none());
        assert!(back.extended_system_registers.is_none());
    }

    #[test]
    fn elements_absent_without_backend_support() {
        let no_gic = Aarch64PartitionCapabilities {
            gic_max_spis: 0,
            virtual_timer_save: false,
            native_state_save: false,
            extended_system_registers_save: false,
            ..caps()
        };
        let vp = Aarch64VpInfo {
            base: vm_topology::processor::VpInfo {
                vp_index: vm_topology::processor::VpIndex::new(0),
                vnode: 0,
            },
            mpidr: aarch64defs::MpidrEl1::new(),
            gicr: None,
            pmu_gsiv: None,
        };
        assert!(!SavedRedistributorState::is_present(&no_gic));
        assert!(!VirtualTimerState::is_present(&no_gic));
        assert!(!ExtendedSystemRegisters::is_present(&no_gic));
        assert!(SavedRedistributorState::is_present(&caps()));
        // Reset values match a freshly built partition.
        assert_eq!(
            SavedRedistributorState::at_reset(&caps(), &vp),
            SavedRedistributorState {
                pending: 0,
                active: 0,
                group: 0,
                enable: 0,
                ppi_cfg: 0,
                priority: [0; 8],
                sleep: false,
            }
        );
        assert_eq!(
            VirtualTimerState::at_reset(&caps(), &vp),
            VirtualTimerState::default()
        );
        assert_eq!(
            ExtendedSystemRegisters::at_reset(&caps(), &vp),
            ExtendedSystemRegisters::default()
        );
    }
}
