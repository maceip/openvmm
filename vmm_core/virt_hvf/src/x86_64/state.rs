// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Architectural state read and write for Intel HVF.

use super::Error;
use super::HvfPartition;
use super::HvfProcessor;
use super::Vcpu;
use super::abi;
use super::check;
use virt::x86::TableRegister;
use virt::x86::X86PartitionCapabilities;
use virt::x86::vm;
use virt::x86::vp;
use x86defs::SegmentRegister;

impl Vcpu {
    pub(super) fn segment(&self, index: u32) -> Result<SegmentRegister, Error> {
        let ar = self.vmcs(0x4814 + index * 2)? as u32;
        Ok(SegmentRegister {
            selector: self.vmcs(0x800 + index * 2)? as u16,
            base: self.vmcs(0x6806 + index * 2)?,
            limit: self.vmcs(0x4800 + index * 2)? as u32,
            attributes: (ar as u16).into(),
        })
    }

    fn set_segment(&self, index: u32, value: &SegmentRegister) -> Result<(), Error> {
        let bits = u16::from(value.attributes);
        let ar = u64::from(bits) | (u64::from(!value.attributes.present()) << 16);
        self.vmcs_set(0x800 + index * 2, u64::from(value.selector))?;
        self.vmcs_set(0x6806 + index * 2, value.base)?;
        self.vmcs_set(0x4800 + index * 2, u64::from(value.limit))?;
        self.vmcs_set(0x4814 + index * 2, ar)
    }

    pub(super) fn registers(&self) -> Result<vp::Registers, Error> {
        Ok(vp::Registers {
            rip: self.reg(0)?,
            rflags: self.reg(1)?,
            rax: self.reg(2)?,
            rcx: self.reg(3)?,
            rdx: self.reg(4)?,
            rbx: self.reg(5)?,
            rsi: self.reg(6)?,
            rdi: self.reg(7)?,
            rsp: self.reg(8)?,
            rbp: self.reg(9)?,
            r8: self.reg(10)?,
            r9: self.reg(11)?,
            r10: self.reg(12)?,
            r11: self.reg(13)?,
            r12: self.reg(14)?,
            r13: self.reg(15)?,
            r14: self.reg(16)?,
            r15: self.reg(17)?,
            es: self.segment(0)?.into(),
            cs: self.segment(1)?.into(),
            ss: self.segment(2)?.into(),
            ds: self.segment(3)?.into(),
            fs: self.segment(4)?.into(),
            gs: self.segment(5)?.into(),
            ldtr: self.segment(6)?.into(),
            tr: self.segment(7)?.into(),
            gdtr: TableRegister {
                base: self.vmcs(0x6816)?,
                limit: self.vmcs(0x4810)? as u16,
            },
            idtr: TableRegister {
                base: self.vmcs(0x6818)?,
                limit: self.vmcs(0x4812)? as u16,
            },
            cr0: self.reg(36)?,
            cr2: self.reg(38)?,
            cr3: self.reg(39)?,
            cr4: self.reg(40)?,
            cr8: self.reg(49)? >> 4,
            efer: self.efer()?,
        })
    }

    pub(super) fn set_registers(&self, value: &vp::Registers) -> Result<(), Error> {
        for (index, value) in [
            value.rip,
            value.rflags,
            value.rax,
            value.rcx,
            value.rdx,
            value.rbx,
            value.rsi,
            value.rdi,
            value.rsp,
            value.rbp,
            value.r8,
            value.r9,
            value.r10,
            value.r11,
            value.r12,
            value.r13,
            value.r14,
            value.r15,
        ]
        .into_iter()
        .enumerate()
        {
            self.set_reg(index as u32, value)?;
        }
        for (index, segment) in [
            value.es, value.cs, value.ss, value.ds, value.fs, value.gs, value.ldtr, value.tr,
        ]
        .iter()
        .enumerate()
        {
            self.set_segment(index as u32, &(*segment).into())?;
        }
        self.vmcs_set(0x6816, value.gdtr.base)?;
        self.vmcs_set(0x4810, u64::from(value.gdtr.limit))?;
        self.vmcs_set(0x6818, value.idtr.base)?;
        self.vmcs_set(0x4812, u64::from(value.idtr.limit))?;
        self.set_reg(36, value.cr0)?;
        self.set_reg(38, value.cr2)?;
        self.set_reg(39, value.cr3)?;
        self.set_reg(40, value.cr4)?;
        self.set_reg(49, value.cr8 << 4)?;
        self.set_efer(value.efer)
    }
}

pub struct VmState<'a>(&'a HvfPartition);
impl virt::PartitionAccessState for HvfPartition {
    type StateAccess<'a> = VmState<'a>;
    fn access_state(&self, _vtl: hvdef::Vtl) -> VmState<'_> {
        VmState(self)
    }
}

macro_rules! unavailable {
    ($get:ident, $set:ident, $ty:ty) => {
        fn $get(&mut self) -> Result<$ty, Error> {
            Err(anyhow::anyhow!(concat!("Intel HVF does not expose ", stringify!($get))).into())
        }
        fn $set(&mut self, _value: &$ty) -> Result<(), Error> {
            Err(anyhow::anyhow!(concat!("Intel HVF does not expose ", stringify!($get))).into())
        }
    };
}

impl vm::AccessVmState for VmState<'_> {
    type Error = Error;
    fn caps(&self) -> &X86PartitionCapabilities {
        &self.0.inner.caps
    }
    fn commit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    unavailable!(hypercall, set_hypercall, vm::HypercallMsrs);
    unavailable!(reftime, set_reftime, vm::ReferenceTime);
    unavailable!(
        reference_tsc_page,
        set_reference_tsc_page,
        vm::ReferenceTscPage
    );
}

pub struct VpState<'a, 'b>(pub(super) &'a mut HvfProcessor<'b>);

const FIXED_MTRRS: [u32; 11] = [
    0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
];

pub(super) fn is_fixed_mtrr(msr: u32) -> bool {
    FIXED_MTRRS.contains(&msr)
}

#[repr(align(64))]
pub(super) struct FpState(pub(super) [u8; 576]);

impl vp::AccessVpState for VpState<'_, '_> {
    type Error = Error;
    fn caps(&self) -> &X86PartitionCapabilities {
        &self.0.partition.caps
    }
    fn commit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn registers(&mut self) -> Result<vp::Registers, Error> {
        if let Some(error) = self.0.state_error.take() {
            return Err(error);
        }
        self.0.vcpu.registers()
    }
    fn set_registers(&mut self, value: &vp::Registers) -> Result<(), Error> {
        self.0.vcpu.set_registers(value)
    }
    fn activity(&mut self) -> Result<vp::Activity, Error> {
        let shadow = self.0.vcpu.vmcs(0x4824)?;
        let event = self.0.vcpu.vmcs(0x4016)?;
        let pending_interruption = if event & (1 << 31) != 0 {
            Some(match (event >> 8) & 7 {
                0 => vp::PendingInterruption::Interrupt {
                    vector: event as u8,
                },
                2 => vp::PendingInterruption::Nmi,
                3 => vp::PendingInterruption::Exception {
                    vector: event as u8,
                    error_code: if event & (1 << 11) != 0 {
                        Some(self.0.vcpu.vmcs(0x4018)? as u32)
                    } else {
                        None
                    },
                },
                _ => return Err(anyhow::anyhow!("unsupported Intel HVF pending event type").into()),
            })
        } else {
            None
        };
        Ok(vp::Activity {
            extint_pending: self.0.extint_pending,
            mp_state: if self.0.wait_for_sipi {
                vp::MpState::WaitForSipi
            } else if self.0.halted {
                vp::MpState::Halted
            } else {
                vp::MpState::Running
            },
            nmi_pending: self.0.nmi_pending,
            nmi_masked: shadow & 8 != 0,
            interrupt_shadow: shadow & 3 != 0,
            pending_event: self.0.pending_event,
            pending_interruption,
        })
    }
    fn set_activity(&mut self, value: &vp::Activity) -> Result<(), Error> {
        if value.mp_state == vp::MpState::Idle {
            return Err(anyhow::anyhow!("Intel HVF cannot restore Hyper-V idle state").into());
        }
        self.0.halted = value.mp_state == vp::MpState::Halted;
        self.0.wait_for_sipi = value.mp_state == vp::MpState::WaitForSipi;
        self.0.extint_pending = value.extint_pending;
        self.0.pending_event = value.pending_event;
        self.0.nmi_pending = value.nmi_pending;
        self.0.vcpu.vmcs_set(
            0x4824,
            u64::from(value.interrupt_shadow) | (u64::from(value.nmi_masked) << 3),
        )?;
        self.0.vcpu.vmcs_set(0x4016, 0)?;
        if let Some(pending) = value.pending_interruption {
            match pending {
                vp::PendingInterruption::Interrupt { vector } => {
                    self.0.vcpu.inject(vector, 0, None)?
                }
                vp::PendingInterruption::Nmi => self.0.vcpu.inject(2, 2, None)?,
                vp::PendingInterruption::Exception { vector, error_code } => {
                    self.0.vcpu.inject(vector, 3, error_code)?
                }
            }
        }
        Ok(())
    }
    fn xsave(&mut self) -> Result<vp::Xsave, Error> {
        let mut data = FpState([0; 576]);
        // SAFETY: writable 64-byte-aligned legacy FXSAVE buffer of 512 bytes.
        check(
            unsafe { abi::hv_vcpu_read_fpstate(self.0.vcpu.id, data.0.as_mut_ptr().cast(), 512) },
            "read FPU",
        )?;
        data.0[512..520].copy_from_slice(&3u64.to_le_bytes());
        Ok(vp::Xsave::from_standard(&data.0, self.caps()))
    }
    fn set_xsave(&mut self, value: &vp::Xsave) -> Result<(), Error> {
        let mut data = FpState([0; 576]);
        value.write_standard(&mut data.0, self.caps());
        // SAFETY: readable 64-byte-aligned legacy FXSAVE buffer of 512 bytes.
        check(
            unsafe { abi::hv_vcpu_write_fpstate(self.0.vcpu.id, data.0.as_mut_ptr().cast(), 512) },
            "write FPU",
        )
    }
    fn apic(&mut self) -> Result<vp::Apic, Error> {
        Ok(self.0.apic.save())
    }
    fn set_apic(&mut self, value: &vp::Apic) -> Result<(), Error> {
        self.0
            .apic
            .restore(value)
            .map_err(|error| Error(error.into()))
    }
    fn xcr(&mut self) -> Result<vp::Xcr0, Error> {
        Ok(vp::Xcr0 {
            value: self.0.vcpu.reg(50)?,
        })
    }
    fn set_xcr(&mut self, value: &vp::Xcr0) -> Result<(), Error> {
        self.0.vcpu.set_reg(50, value.value)
    }
    unavailable!(xss, set_xss, vp::Xss);
    fn mtrrs(&mut self) -> Result<vp::Mtrrs, Error> {
        let mut value = vp::Mtrrs {
            msr_mtrr_def_type: *self.0.msrs.get(&0x2ff).unwrap_or(&0),
            ..Default::default()
        };
        for (slot, msr) in value.fixed.iter_mut().zip(FIXED_MTRRS) {
            *slot = *self.0.msrs.get(&msr).unwrap_or(&0);
        }
        for (index, slot) in value.variable.iter_mut().enumerate() {
            *slot = *self.0.msrs.get(&(0x200 + index as u32)).unwrap_or(&0);
        }
        Ok(value)
    }
    fn set_mtrrs(&mut self, value: &vp::Mtrrs) -> Result<(), Error> {
        self.0.msrs.insert(0x2ff, value.msr_mtrr_def_type);
        for (msr, value) in FIXED_MTRRS.into_iter().zip(value.fixed) {
            self.0.msrs.insert(msr, value);
        }
        for (index, value) in value.variable.iter().enumerate() {
            self.0.msrs.insert(0x200 + index as u32, *value);
        }
        Ok(())
    }
    fn pat(&mut self) -> Result<vp::Pat, Error> {
        Ok(vp::Pat {
            value: self.0.guest_pat.get(),
        })
    }
    fn set_pat(&mut self, value: &vp::Pat) -> Result<(), Error> {
        if !self.0.guest_pat.set(value.value) {
            return Err(anyhow::anyhow!("Intel HVF PAT contains a reserved memory type").into());
        }
        Ok(())
    }
    fn virtual_msrs(&mut self) -> Result<vp::VirtualMsrs, Error> {
        Ok(vp::VirtualMsrs {
            kernel_gs_base: self.0.vcpu.msr(0xc0000102)?,
            sysenter_cs: self.0.vcpu.msr(0x174)?,
            sysenter_eip: self.0.vcpu.msr(0x176)?,
            sysenter_esp: self.0.vcpu.msr(0x175)?,
            star: self.0.vcpu.msr(0xc0000081)?,
            lstar: self.0.vcpu.msr(0xc0000082)?,
            cstar: self.0.vcpu.msr(0xc0000083)?,
            sfmask: self.0.vcpu.msr(0xc0000084)?,
        })
    }
    fn set_virtual_msrs(&mut self, value: &vp::VirtualMsrs) -> Result<(), Error> {
        for (msr, value) in [
            (0xc0000102, value.kernel_gs_base),
            (0x174, value.sysenter_cs),
            (0x176, value.sysenter_eip),
            (0x175, value.sysenter_esp),
            (0xc0000081, value.star),
            (0xc0000082, value.lstar),
            (0xc0000083, value.cstar),
            (0xc0000084, value.sfmask),
        ] {
            self.0.vcpu.set_msr(msr, value)?;
        }
        Ok(())
    }
    fn debug_regs(&mut self) -> Result<vp::DebugRegisters, Error> {
        Ok(vp::DebugRegisters {
            dr0: self.0.vcpu.reg(41)?,
            dr1: self.0.vcpu.reg(42)?,
            dr2: self.0.vcpu.reg(43)?,
            dr3: self.0.vcpu.reg(44)?,
            dr6: self.0.vcpu.reg(47)?,
            dr7: self.0.vcpu.reg(48)?,
        })
    }
    fn set_debug_regs(&mut self, value: &vp::DebugRegisters) -> Result<(), Error> {
        for (reg, value) in [
            (41, value.dr0),
            (42, value.dr1),
            (43, value.dr2),
            (44, value.dr3),
            (47, value.dr6),
            (48, value.dr7),
        ] {
            self.0.vcpu.set_reg(reg, value)?;
        }
        Ok(())
    }
    fn tsc(&mut self) -> Result<vp::Tsc, Error> {
        Ok(vp::Tsc {
            value: self.0.vcpu.msr(0x10)?,
        })
    }
    fn set_tsc(&mut self, value: &vp::Tsc) -> Result<(), Error> {
        // SAFETY: the abstract HVF clock is valid after partition creation.
        let clock = unsafe { abi::hv_tsc_clock() };
        // SAFETY: owning thread, scalar offset modulo 2^64.
        check(
            unsafe {
                abi::hv_vcpu_set_tsc_relative(
                    self.0.vcpu.id,
                    value.value.wrapping_sub(clock) as i64,
                )
            },
            "restore TSC",
        )
    }
    unavailable!(cet, set_cet, vp::Cet);
    unavailable!(cet_ss, set_cet_ss, vp::CetSs);
    unavailable!(tsc_aux, set_tsc_aux, vp::TscAux);
    unavailable!(tsc_deadline, set_tsc_deadline, vp::TscDeadline);
    unavailable!(synic_msrs, set_synic_msrs, vp::SyntheticMsrs);
    unavailable!(
        synic_message_page,
        set_synic_message_page,
        vp::SynicMessagePage
    );
    unavailable!(
        synic_event_flags_page,
        set_synic_event_flags_page,
        vp::SynicEventFlagsPage
    );
    unavailable!(
        synic_message_queues,
        set_synic_message_queues,
        vp::SynicMessageQueues
    );
    unavailable!(synic_timers, set_synic_timers, vp::SynicTimers);
    unavailable!(nested_state, set_nested_state, vp::NestedState);
}
