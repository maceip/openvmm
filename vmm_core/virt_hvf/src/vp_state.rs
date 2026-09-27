// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VP state handling.

use crate::Error;
use crate::HvfProcessor;
use crate::abi;
use hvdef::HvArm64RegisterName;
use virt::aarch64::Aarch64PartitionCapabilities;
use virt::aarch64::vp::AccessVpState;
use virt::state::HvRegisterState;

enum Reg {
    Reg(abi::HvReg),
    SysReg(abi::HvSysReg),
}

fn hv_to_hvf(name: HvArm64RegisterName) -> Option<Reg> {
    let v = match name {
        HvArm64RegisterName::X0 => Reg::Reg(abi::HvReg::X0),
        HvArm64RegisterName::X1 => Reg::Reg(abi::HvReg::X1),
        HvArm64RegisterName::X2 => Reg::Reg(abi::HvReg::X2),
        HvArm64RegisterName::X3 => Reg::Reg(abi::HvReg::X3),
        HvArm64RegisterName::X4 => Reg::Reg(abi::HvReg::X4),
        HvArm64RegisterName::X5 => Reg::Reg(abi::HvReg::X5),
        HvArm64RegisterName::X6 => Reg::Reg(abi::HvReg::X6),
        HvArm64RegisterName::X7 => Reg::Reg(abi::HvReg::X7),
        HvArm64RegisterName::X8 => Reg::Reg(abi::HvReg::X8),
        HvArm64RegisterName::X9 => Reg::Reg(abi::HvReg::X9),
        HvArm64RegisterName::X10 => Reg::Reg(abi::HvReg::X10),
        HvArm64RegisterName::X11 => Reg::Reg(abi::HvReg::X11),
        HvArm64RegisterName::X12 => Reg::Reg(abi::HvReg::X12),
        HvArm64RegisterName::X13 => Reg::Reg(abi::HvReg::X13),
        HvArm64RegisterName::X14 => Reg::Reg(abi::HvReg::X14),
        HvArm64RegisterName::X15 => Reg::Reg(abi::HvReg::X15),
        HvArm64RegisterName::X16 => Reg::Reg(abi::HvReg::X16),
        HvArm64RegisterName::X17 => Reg::Reg(abi::HvReg::X17),
        HvArm64RegisterName::X18 => Reg::Reg(abi::HvReg::X18),
        HvArm64RegisterName::X19 => Reg::Reg(abi::HvReg::X19),
        HvArm64RegisterName::X20 => Reg::Reg(abi::HvReg::X20),
        HvArm64RegisterName::X21 => Reg::Reg(abi::HvReg::X21),
        HvArm64RegisterName::X22 => Reg::Reg(abi::HvReg::X22),
        HvArm64RegisterName::X23 => Reg::Reg(abi::HvReg::X23),
        HvArm64RegisterName::X24 => Reg::Reg(abi::HvReg::X24),
        HvArm64RegisterName::X25 => Reg::Reg(abi::HvReg::X25),
        HvArm64RegisterName::X26 => Reg::Reg(abi::HvReg::X26),
        HvArm64RegisterName::X27 => Reg::Reg(abi::HvReg::X27),
        HvArm64RegisterName::X28 => Reg::Reg(abi::HvReg::X28),
        HvArm64RegisterName::XFp => Reg::Reg(abi::HvReg::FP),
        HvArm64RegisterName::XLr => Reg::Reg(abi::HvReg::LR),
        HvArm64RegisterName::XSpEl0 => Reg::SysReg(abi::HvSysReg::SP_EL0),
        HvArm64RegisterName::XSpElx => Reg::SysReg(abi::HvSysReg::SP_EL1),
        HvArm64RegisterName::XPc => Reg::Reg(abi::HvReg::PC),
        HvArm64RegisterName::Cpsr => Reg::Reg(abi::HvReg::CPSR),
        HvArm64RegisterName::SctlrEl1 => Reg::SysReg(abi::HvSysReg::SCTLR_EL1),
        HvArm64RegisterName::Ttbr0El1 => Reg::SysReg(abi::HvSysReg::TTBR0_EL1),
        HvArm64RegisterName::Ttbr1El1 => Reg::SysReg(abi::HvSysReg::TTBR1_EL1),
        HvArm64RegisterName::TcrEl1 => Reg::SysReg(abi::HvSysReg::TCR_EL1),
        HvArm64RegisterName::EsrEl1 => Reg::SysReg(abi::HvSysReg::ESR_EL1),
        HvArm64RegisterName::FarEl1 => Reg::SysReg(abi::HvSysReg::FAR_EL1),
        HvArm64RegisterName::MairEl1 => Reg::SysReg(abi::HvSysReg::MAIR_EL1),
        HvArm64RegisterName::ElrEl1 => Reg::SysReg(abi::HvSysReg::ELR_EL1),
        HvArm64RegisterName::VbarEl1 => Reg::SysReg(abi::HvSysReg::VBAR_EL1),
        _ => {
            tracing::error!(?name, "Unsupported register name translation");
            return None;
        }
    };
    Some(v)
}

pub struct HvfVpStateAccess<'a, 'b> {
    pub(crate) processor: &'a mut HvfProcessor<'b>,
}

impl HvfVpStateAccess<'_, '_> {
    pub(crate) fn set_register_state<T, const N: usize>(&mut self, value: &T) -> Result<(), Error>
    where
        T: HvRegisterState<HvArm64RegisterName, N>,
    {
        let mut values = [0u32.into(); N];
        value.get_values(values.iter_mut());
        for (&name, value) in value.names().iter().zip(values) {
            match hv_to_hvf(name).unwrap() {
                Reg::Reg(reg) => self.processor.vcpu.set_reg(reg, value.as_u64())?,
                Reg::SysReg(reg) => self.processor.vcpu.set_sys_reg(reg, value.as_u64())?,
            }
        }

        Ok(())
    }

    pub(crate) fn get_register_state<T, const N: usize>(&mut self) -> Result<T, Error>
    where
        T: HvRegisterState<HvArm64RegisterName, N>,
    {
        let mut value = T::default();
        let mut values = [0u64; N];
        for (&name, value) in value.names().iter().zip(&mut values) {
            *value = match hv_to_hvf(name).unwrap() {
                Reg::Reg(reg) => self.processor.vcpu.reg(reg)?,
                Reg::SysReg(reg) => self.processor.vcpu.sys_reg(reg)?,
            };
        }

        value.set_values(values.into_iter().map(|v| v.into()));
        Ok(value)
    }
}

impl AccessVpState for HvfVpStateAccess<'_, '_> {
    type Error = Error;

    fn caps(&self) -> &Aarch64PartitionCapabilities {
        &self.processor.partition.caps
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn registers(&mut self) -> Result<virt::aarch64::vp::Registers, Self::Error> {
        self.get_register_state()
    }

    fn set_registers(&mut self, value: &virt::aarch64::vp::Registers) -> Result<(), Self::Error> {
        self.set_register_state(value)
    }

    fn system_registers(&mut self) -> Result<virt::vp::SystemRegisters, Self::Error> {
        self.get_register_state()
    }

    fn set_system_registers(
        &mut self,
        value: &virt::vp::SystemRegisters,
    ) -> Result<(), Self::Error> {
        self.set_register_state(value)
    }

    fn redistributor(&mut self) -> Result<virt::aarch64::SavedRedistributorState, Self::Error> {
        let vp = self.processor.inner.vp_info.base.vp_index;
        Ok(self.processor.partition.gicd.save_redistributor(vp)?)
    }

    fn set_redistributor(
        &mut self,
        value: &virt::aarch64::SavedRedistributorState,
    ) -> Result<(), Self::Error> {
        let vp = self.processor.inner.vp_info.base.vp_index;
        self.processor
            .partition
            .gicd
            .restore_redistributor(vp, value)?;
        Ok(())
    }

    fn virtual_timer(&mut self) -> Result<virt::aarch64::vp::VirtualTimerState, Self::Error> {
        Ok(virt::aarch64::vp::VirtualTimerState {
            ctl_el0: self.processor.vcpu.sys_reg(abi::HvSysReg::CNTV_CTL_EL0)?,
            cval_el0: self.processor.vcpu.sys_reg(abi::HvSysReg::CNTV_CVAL_EL0)?,
        })
    }

    fn set_virtual_timer(
        &mut self,
        value: &virt::aarch64::vp::VirtualTimerState,
    ) -> Result<(), Self::Error> {
        self.processor
            .vcpu
            .set_sys_reg(abi::HvSysReg::CNTV_CTL_EL0, value.ctl_el0)?;
        self.processor
            .vcpu
            .set_sys_reg(abi::HvSysReg::CNTV_CVAL_EL0, value.cval_el0)?;
        Ok(())
    }

    fn extended_system_registers(
        &mut self,
    ) -> Result<virt::aarch64::vp::ExtendedSystemRegisters, Self::Error> {
        let vcpu = &self.processor.vcpu;
        Ok(virt::aarch64::vp::ExtendedSystemRegisters {
            spsr_el1: vcpu.sys_reg(abi::HvSysReg::SPSR_EL1)?,
            tpidr_el0: vcpu.sys_reg(abi::HvSysReg::TPIDR_EL0)?,
            tpidrro_el0: vcpu.sys_reg(abi::HvSysReg::TPIDRRO_EL0)?,
            tpidr_el1: vcpu.sys_reg(abi::HvSysReg::TPIDR_EL1)?,
            apdakeylo_el1: vcpu.sys_reg(abi::HvSysReg::APDAKEYLO_EL1)?,
            apdakeyhi_el1: vcpu.sys_reg(abi::HvSysReg::APDAKEYHI_EL1)?,
            apdbkeylo_el1: vcpu.sys_reg(abi::HvSysReg::APDBKEYLO_EL1)?,
            apdbkeyhi_el1: vcpu.sys_reg(abi::HvSysReg::APDBKEYHI_EL1)?,
            apiakeylo_el1: vcpu.sys_reg(abi::HvSysReg::APIAKEYLO_EL1)?,
            apiakeyhi_el1: vcpu.sys_reg(abi::HvSysReg::APIAKEYHI_EL1)?,
            apibkeylo_el1: vcpu.sys_reg(abi::HvSysReg::APIBKEYLO_EL1)?,
            apibkeyhi_el1: vcpu.sys_reg(abi::HvSysReg::APIBKEYHI_EL1)?,
            apgakeylo_el1: vcpu.sys_reg(abi::HvSysReg::APGAKEYLO_EL1)?,
            apgakeyhi_el1: vcpu.sys_reg(abi::HvSysReg::APGAKEYHI_EL1)?,
            fpcr: vcpu.reg(abi::HvReg::FPCR)?,
            fpsr: vcpu.reg(abi::HvReg::FPSR)?,
            cpacr_el1: vcpu.sys_reg(abi::HvSysReg::CPACR_EL1)?,
            cntkctl_el1: vcpu.sys_reg(abi::HvSysReg::CNTKCTL_EL1)?,
            contextidr_el1: vcpu.sys_reg(abi::HvSysReg::CONTEXTIDR_EL1)?,
        })
    }

    fn set_extended_system_registers(
        &mut self,
        value: &virt::aarch64::vp::ExtendedSystemRegisters,
    ) -> Result<(), Self::Error> {
        let vcpu = &mut self.processor.vcpu;
        vcpu.set_sys_reg(abi::HvSysReg::SPSR_EL1, value.spsr_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::TPIDR_EL0, value.tpidr_el0)?;
        vcpu.set_sys_reg(abi::HvSysReg::TPIDRRO_EL0, value.tpidrro_el0)?;
        vcpu.set_sys_reg(abi::HvSysReg::TPIDR_EL1, value.tpidr_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APDAKEYLO_EL1, value.apdakeylo_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APDAKEYHI_EL1, value.apdakeyhi_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APDBKEYLO_EL1, value.apdbkeylo_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APDBKEYHI_EL1, value.apdbkeyhi_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APIAKEYLO_EL1, value.apiakeylo_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APIAKEYHI_EL1, value.apiakeyhi_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APIBKEYLO_EL1, value.apibkeylo_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APIBKEYHI_EL1, value.apibkeyhi_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APGAKEYLO_EL1, value.apgakeylo_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::APGAKEYHI_EL1, value.apgakeyhi_el1)?;
        vcpu.set_reg(abi::HvReg::FPCR, value.fpcr)?;
        vcpu.set_reg(abi::HvReg::FPSR, value.fpsr)?;
        vcpu.set_sys_reg(abi::HvSysReg::CPACR_EL1, value.cpacr_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::CNTKCTL_EL1, value.cntkctl_el1)?;
        vcpu.set_sys_reg(abi::HvSysReg::CONTEXTIDR_EL1, value.contextidr_el1)?;
        Ok(())
    }
}
