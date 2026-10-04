// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Complete native ARM KVM migration state, including SIMD and the kernel GIC.

use super::sys_reg64;
use crate::KvmError;
use crate::KvmPartitionInner;
use aarch64defs::SystemReg;
use mesh_protobuf::Protobuf;
use virt::aarch64::vm::NativeState;

#[derive(Protobuf)]
struct CpuState {
    #[mesh(1)]
    registers: Vec<(u64, Vec<u8>)>,
    #[mesh(2)]
    mp_state: u32,
    #[mesh(3)]
    serror_pending: bool,
    #[mesh(4)]
    serror_esr: Option<u64>,
    #[mesh(5)]
    external_abort: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Protobuf)]
struct DeviceRegister {
    #[mesh(1)]
    its: bool,
    #[mesh(2)]
    group: u32,
    #[mesh(3)]
    selector: u64,
    #[mesh(4)]
    wide: bool,
    #[mesh(5)]
    value: u64,
}

#[derive(Protobuf)]
struct State {
    #[mesh(1)]
    cpus: Vec<CpuState>,
    #[mesh(2)]
    devices: Vec<DeviceRegister>,
}

fn device_registers(partition: &KvmPartitionInner) -> Result<Vec<DeviceRegister>, KvmError> {
    let mut registers = Vec::new();
    let mut add = |its, group, selector, wide| {
        registers.push(DeviceRegister {
            its,
            group,
            selector,
            wide,
            value: 0,
        })
    };
    let dist = kvm::KVM_DEV_ARM_VGIC_GRP_DIST_REGS;
    add(false, dist, 0, false); // CTLR
    add(false, dist, 0x10, false); // STATUSR
    for irq in (32..partition.gic_nr_irqs).step_by(32) {
        for base in [0x80, 0x100, 0x200, 0x300, 0xd00] {
            add(false, dist, base + u64::from(irq / 32) * 4, false);
        }
        add(
            false,
            kvm::KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO,
            u64::from(irq),
            false,
        );
    }
    for irq in (32..partition.gic_nr_irqs).step_by(16) {
        add(false, dist, 0xc00 + u64::from(irq / 16) * 4, false);
    }
    for irq in (32..partition.gic_nr_irqs).step_by(4) {
        add(false, dist, 0x400 + u64::from(irq), false);
    }
    for irq in 32..partition.gic_nr_irqs {
        // The KVM migration ABI accesses 64-bit distributor registers as
        // two separate 32-bit words.
        add(false, dist, 0x6000 + u64::from(irq) * 8, false);
        add(false, dist, 0x6004 + u64::from(irq) * 8, false);
    }
    for vp in &partition.vps {
        let mpidr = u64::from(vp.vp_info.mpidr);
        let affinity = ((mpidr >> 32) << 24) | (mpidr & 0xffffff);
        let cpu = affinity << 32;
        let redist = kvm::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS;
        for offset in [
            0, 0x10, 0x14, 0x10080, 0x10100, 0x10200, 0x10300, 0x10c04, 0x10d00,
        ] {
            add(false, redist, cpu | offset, false);
        }
        for offset in (0x10400..0x10420).step_by(4) {
            add(false, redist, cpu | offset, false);
        }
        add(false, kvm::KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO, cpu, false);
        let group = kvm::KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS;
        for register in [
            SystemReg::ICC_SRE_EL1,
            SystemReg::ICC_CTLR_EL1,
            SystemReg::ICC_PMR_EL1,
            SystemReg::ICC_BPR0_EL1,
            SystemReg::ICC_BPR1_EL1,
            SystemReg::ICC_IGRPEN0_EL1,
            SystemReg::ICC_IGRPEN1_EL1,
        ] {
            add(false, group, cpu | (sys_reg64(register) & 0xffff), true);
        }
        // The number of active-priority registers is host-defined.
        // SAFETY: KVM documents CPU_SYSREGS as a u64 attribute.
        let ctl = unsafe {
            partition
                ._gic_device
                .get_device_attr::<u64>(group, cpu | (sys_reg64(SystemReg::ICC_CTLR_EL1) & 0xffff))
        }
        .map_err(kvm::Error::GetDeviceAttr)?;
        let priority_bits = ((ctl >> 8) & 7) + 1;
        let count = if priority_bits >= 7 {
            4
        } else if priority_bits >= 6 {
            2
        } else {
            1
        };
        for (bank0, bank1) in [
            SystemReg::ICC_AP0R0_EL1,
            SystemReg::ICC_AP0R1_EL1,
            SystemReg::ICC_AP0R2_EL1,
            SystemReg::ICC_AP0R3_EL1,
        ]
        .into_iter()
        .zip([
            SystemReg::ICC_AP1R0_EL1,
            SystemReg::ICC_AP1R1_EL1,
            SystemReg::ICC_AP1R2_EL1,
            SystemReg::ICC_AP1R3_EL1,
        ])
        .take(count)
        {
            add(false, group, cpu | (sys_reg64(bank0) & 0xffff), true);
            add(false, group, cpu | (sys_reg64(bank1) & 0xffff), true);
        }
        if partition._its_device.is_some() {
            for offset in [0x70, 0x74, 0x78, 0x7c] {
                add(false, redist, cpu | offset, false);
            }
        }
    }
    if partition._its_device.is_some() {
        let group = kvm::KVM_DEV_ARM_VGIC_GRP_ITS_REGS;
        add(true, group, 0, false);
        for offset in [
            0x80, 0x88, 0x90, 0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
        ] {
            add(true, group, offset, true);
        }
    }
    Ok(registers)
}

pub(super) fn save(partition: &KvmPartitionInner) -> Result<NativeState, KvmError> {
    if let Some(its) = &partition._its_device {
        // SAFETY: these control operations have no payload.
        unsafe {
            partition
                ._gic_device
                .set_device_attr::<()>(
                    kvm::KVM_DEV_ARM_VGIC_GRP_CTRL,
                    kvm::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES,
                    &(),
                    0,
                )
                .map_err(kvm::Error::SetDeviceAttr)?;
            its.set_device_attr::<()>(
                kvm::KVM_DEV_ARM_VGIC_GRP_CTRL,
                kvm::KVM_DEV_ARM_ITS_SAVE_TABLES,
                &(),
                0,
            )
            .map_err(kvm::Error::SetDeviceAttr)?;
        }
    }
    let mut devices = device_registers(partition)?;
    for register in &mut devices {
        let device = if register.its {
            partition
                ._its_device
                .as_ref()
                .ok_or(KvmError::NotSupported)?
        } else {
            &partition._gic_device
        };
        // SAFETY: descriptor widths follow the documented VGIC migration ABI.
        register.value = unsafe {
            if register.wide {
                device.get_device_attr::<u64>(register.group, register.selector)
            } else {
                device
                    .get_device_attr::<u32>(register.group, register.selector)
                    .map(u64::from)
            }
        }
        .map_err(kvm::Error::GetDeviceAttr)?;
    }
    let cpus = partition
        .vps
        .iter()
        .map(|vp| {
            let cpu = partition.kvm.vp(vp.vp_info.base.vp_index.index());
            let registers = cpu
                .register_ids()?
                .into_iter()
                .map(|id| Ok((id, cpu.register_bytes(id)?)))
                .collect::<Result<_, KvmError>>()?;
            let events = cpu.get_vcpu_events()?.exception;
            Ok(CpuState {
                registers,
                mp_state: cpu.get_mp_state()?,
                serror_pending: events.serror_pending != 0,
                serror_esr: (events.serror_has_esr != 0).then_some(events.serror_esr),
                external_abort: events.ext_dabt_pending != 0,
            })
        })
        .collect::<Result<_, KvmError>>()?;
    Ok(NativeState {
        backend: "kvm-arm64".into(),
        version: 1,
        data: mesh_protobuf::encode(State { cpus, devices }),
    })
}

pub(super) fn restore(partition: &KvmPartitionInner, value: &NativeState) -> Result<(), KvmError> {
    if value.backend != "kvm-arm64" || value.version != 1 || value.data.len() > 16 * 1024 * 1024 {
        return Err(KvmError::InvalidState("incompatible ARM KVM native state"));
    }
    let state: State = mesh_protobuf::decode(&value.data)
        .map_err(|_| KvmError::InvalidState("invalid ARM KVM native state"))?;
    let expected = device_registers(partition)?;
    if state.cpus.len() != partition.vps.len()
        || state.devices.len() != expected.len()
        || state
            .devices
            .iter()
            .zip(&expected)
            .any(|(actual, expected)| {
                actual.its != expected.its
                    || actual.group != expected.group
                    || actual.selector != expected.selector
                    || actual.wide != expected.wide
                    || (!actual.wide && actual.value > u64::from(u32::MAX))
            })
    {
        return Err(KvmError::InvalidState(
            "ARM KVM native state topology mismatch",
        ));
    }
    // Validate every register before mutating hardware state.
    for (saved, vp) in state.cpus.iter().zip(&partition.vps) {
        let cpu = partition.kvm.vp(vp.vp_info.base.vp_index.index());
        let ids = cpu.register_ids()?;
        if saved.registers.len() != ids.len()
            || saved
                .registers
                .iter()
                .zip(ids)
                .any(|((id, bytes), expected)| {
                    *id != expected
                        || bytes.len() != 1usize.checked_shl(((id >> 52) & 15) as u32).unwrap_or(0)
                })
        {
            return Err(KvmError::InvalidState(
                "ARM KVM native register contract mismatch",
            ));
        }
    }
    for (saved, vp) in state.cpus.iter().zip(&partition.vps) {
        let cpu = partition.kvm.vp(vp.vp_info.base.vp_index.index());
        for (id, bytes) in &saved.registers {
            cpu.set_register_bytes(*id, bytes)?;
        }
        cpu.set_mp_state(saved.mp_state)?;
        cpu.set_vcpu_events(&kvm::kvm_vcpu_events {
            exception: kvm::kvm_vcpu_events__bindgen_ty_1 {
                serror_pending: saved.serror_pending.into(),
                serror_has_esr: saved.serror_esr.is_some().into(),
                serror_esr: saved.serror_esr.unwrap_or(0),
                ext_dabt_pending: saved.external_abort.into(),
                ..Default::default()
            },
            ..Default::default()
        })?;
    }
    for register in &state.devices {
        let device = if register.its {
            partition
                ._its_device
                .as_ref()
                .ok_or(KvmError::NotSupported)?
        } else {
            &partition._gic_device
        };
        // Enable and active registers use W1S: clear them before restoring.
        let offset = register.selector & 0xffffffff;
        let clear = match register.group {
            kvm::KVM_DEV_ARM_VGIC_GRP_DIST_REGS
                if (0x100..0x180).contains(&offset) || (0x300..0x380).contains(&offset) =>
            {
                Some(register.selector + 0x80)
            }
            kvm::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS if offset == 0x10100 || offset == 0x10300 => {
                Some(register.selector + 0x80)
            }
            _ => None,
        };
        // SAFETY: validated descriptors use the documented attribute type.
        unsafe {
            if let Some(clear) = clear {
                device
                    .set_device_attr64(register.group, clear, &u32::MAX)
                    .map_err(kvm::Error::SetDeviceAttr)?;
            }
            if register.wide {
                device.set_device_attr64(register.group, register.selector, &register.value)
            } else {
                device.set_device_attr64(
                    register.group,
                    register.selector,
                    &(register.value as u32),
                )
            }
        }
        .map_err(kvm::Error::SetDeviceAttr)?;
    }
    if let Some(its) = &partition._its_device {
        // SAFETY: restore-tables is a payload-free control operation.
        unsafe {
            its.set_device_attr::<()>(
                kvm::KVM_DEV_ARM_VGIC_GRP_CTRL,
                kvm::KVM_DEV_ARM_ITS_RESTORE_TABLES,
                &(),
                0,
            )
        }
        .map_err(kvm::Error::SetDeviceAttr)?;
    }
    Ok(())
}
