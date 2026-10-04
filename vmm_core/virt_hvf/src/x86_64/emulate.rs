// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Instruction emulation for Intel HVF MMIO and string I/O exits.

use super::ApicAccess;
use super::Error;
use super::HvfProcessor;
use super::abi;
use super::check;
use super::state::FpState;
use guestmem::GuestMemory;
use hvdef::HvX64PendingEvent;
use virt::VpHaltReason;
use virt::VpIndex;
use virt::io::CpuIo;
use virt::x86::vp::Registers;
use virt_support_x86emu::emulate::*;
use virt_support_x86emu::translate::EncryptionMode;
use virt_support_x86emu::translate::TranslationRegisters;
use x86defs::RFlags;
use x86defs::SegmentRegister;
use x86emu::Gp;
use x86emu::Segment;

struct Emulator<'a, 'b, D> {
    vp: &'a mut HvfProcessor<'b>,
    registers: Registers,
    fp: FpState,
    fault_gpa: Option<u64>,
    pending: Option<HvX64PendingEvent>,
    dev: &'a D,
}

impl HvfProcessor<'_> {
    pub(super) async fn emulate(
        &mut self,
        dev: &impl CpuIo,
        gpa: Option<u64>,
    ) -> Result<(), VpHaltReason> {
        let registers = self
            .vcpu
            .registers()
            .map_err(|error| dev.fatal_error(error.into()))?;
        let mut fp = FpState([0; 576]);
        // SAFETY: the owning VP reads into a 64-byte-aligned FXSAVE buffer.
        check(
            unsafe { abi::hv_vcpu_read_fpstate(self.vcpu.id, fp.0.as_mut_ptr().cast(), 512) },
            "read emulation FPU",
        )
        .map_err(|error| dev.fatal_error(error.into()))?;
        let gm = self.partition.guest_memory.clone();
        let memory = EmulatorMemoryAccess {
            gm: &gm,
            kx_gm: &gm,
            ux_gm: &gm,
        };
        let mut emulator = Emulator {
            vp: self,
            registers,
            fp,
            fault_gpa: gpa,
            pending: None,
            dev,
        };
        emulate(&mut emulator, &memory, dev).await?;
        emulator
            .apply()
            .map_err(|error| dev.fatal_error(error.into()))
    }
}

impl<D: CpuIo> Emulator<'_, '_, D> {
    fn apply(&mut self) -> Result<(), Error> {
        self.vp.vcpu.set_registers(&self.registers)?;
        // SAFETY: the owning VP restores a 64-byte-aligned FXSAVE buffer.
        check(
            unsafe {
                abi::hv_vcpu_write_fpstate(self.vp.vcpu.id, self.fp.0.as_mut_ptr().cast(), 512)
            },
            "write emulation FPU",
        )?;
        if let Some(pending) = self.pending.take() {
            let exception = hvdef::HvX64PendingExceptionEvent::from(u128::from(pending.reg_0));
            if !exception.event_pending()
                || exception.event_type() != hvdef::HV_X64_PENDING_EVENT_EXCEPTION
            {
                return Err(anyhow::anyhow!("unsupported Intel HVF emulated event").into());
            }
            if exception.vector() == 14 {
                self.vp.vcpu.set_reg(38, exception.exception_parameter())?;
            }
            self.vp.vcpu.inject(
                exception.vector() as u8,
                3,
                exception
                    .deliver_error_code()
                    .then_some(exception.error_code()),
            )?;
        }
        Ok(())
    }
}

macro_rules! gp_fields {
    ($this:ident, $index:ident, $($name:ident => $field:ident),+ $(,)?) => {
        match $index { $(Gp::$name => &mut $this.registers.$field),+ }
    }
}

impl<D: CpuIo> EmulatorSupport for Emulator<'_, '_, D> {
    fn vp_index(&self) -> VpIndex {
        self.vp.vp_info.base.vp_index
    }
    fn vendor(&self) -> x86defs::cpuid::Vendor {
        self.vp.partition.caps.vendor
    }
    fn gp(&mut self, index: Gp) -> u64 {
        *gp_fields!(self,index,RAX=>rax,RCX=>rcx,RDX=>rdx,RBX=>rbx,RSP=>rsp,RBP=>rbp,RSI=>rsi,RDI=>rdi,R8=>r8,R9=>r9,R10=>r10,R11=>r11,R12=>r12,R13=>r13,R14=>r14,R15=>r15)
    }
    fn set_gp(&mut self, index: Gp, value: u64) {
        *gp_fields!(self,index,RAX=>rax,RCX=>rcx,RDX=>rdx,RBX=>rbx,RSP=>rsp,RBP=>rbp,RSI=>rsi,RDI=>rdi,R8=>r8,R9=>r9,R10=>r10,R11=>r11,R12=>r12,R13=>r13,R14=>r14,R15=>r15) =
            value;
    }
    fn rip(&mut self) -> u64 {
        self.registers.rip
    }
    fn set_rip(&mut self, value: u64) {
        self.registers.rip = value;
    }
    fn segment(&mut self, index: Segment) -> SegmentRegister {
        match index {
            Segment::ES => self.registers.es.into(),
            Segment::CS => self.registers.cs.into(),
            Segment::SS => self.registers.ss.into(),
            Segment::DS => self.registers.ds.into(),
            Segment::FS => self.registers.fs.into(),
            Segment::GS => self.registers.gs.into(),
        }
    }
    fn efer(&mut self) -> u64 {
        self.registers.efer
    }
    fn cr0(&mut self) -> u64 {
        self.registers.cr0
    }
    fn rflags(&mut self) -> RFlags {
        self.registers.rflags.into()
    }
    fn set_rflags(&mut self, value: RFlags) {
        self.registers.rflags = value.into();
    }
    fn xmm(&mut self, index: usize) -> u128 {
        let mut bytes = [0; 16];
        if let Some(value) = index.checked_mul(16).and_then(|offset| {
            offset
                .checked_add(16)
                .and_then(|end| self.fp.0[160..416].get(offset..end))
        }) {
            bytes.copy_from_slice(value);
        }
        u128::from_le_bytes(bytes)
    }
    fn set_xmm(&mut self, index: usize, value: u128) {
        if let Some(dest) = index.checked_mul(16).and_then(|offset| {
            offset
                .checked_add(16)
                .and_then(|end| self.fp.0[160..416].get_mut(offset..end))
        }) {
            dest.copy_from_slice(&value.to_le_bytes());
        }
    }
    fn flush(&mut self) {}
    fn instruction_bytes(&self) -> &[u8] {
        &[]
    }
    fn physical_address(&self) -> Option<u64> {
        self.fault_gpa
    }
    fn initial_gva_translation(&mut self) -> Option<InitialTranslation> {
        None
    }
    fn interruption_pending(&self) -> bool {
        false
    }
    fn check_vtl_access(
        &mut self,
        _gpa: u64,
        _mode: TranslateMode,
    ) -> Result<(), EmuCheckVtlAccessError> {
        Ok(())
    }
    fn translate_gva(
        &mut self,
        gva: u64,
        mode: TranslateMode,
    ) -> Result<EmuTranslateResult, EmuTranslateError> {
        emulate_translate_gva(self, gva, mode)
    }
    fn inject_pending_event(&mut self, event: HvX64PendingEvent) {
        self.pending = Some(event);
    }
    fn is_gpa_mapped(&self, gpa: u64, write: bool) -> bool {
        self.vp
            .partition
            .mappings
            .lock()
            .iter()
            .any(|(range, writable)| range.contains_addr(gpa) && (!write || *writable))
    }
    fn lapic_base_address(&self) -> Option<u64> {
        self.vp.apic.base_address()
    }
    fn lapic_read(&mut self, address: u64, data: &mut [u8]) {
        let mut cr8 = self.registers.cr8 as u32;
        let mut client = ApicAccess {
            partition: &self.vp.partition,
            dev: self.dev,
            vmtime: &self.vp.vmtime,
            cr8: &mut cr8,
        };
        self.vp.apic.access(&mut client).mmio_read(address, data);
        self.registers.cr8 = u64::from(cr8);
    }
    fn lapic_write(&mut self, address: u64, data: &[u8]) {
        let mut cr8 = self.registers.cr8 as u32;
        let mut client = ApicAccess {
            partition: &self.vp.partition,
            dev: self.dev,
            vmtime: &self.vp.vmtime,
            cr8: &mut cr8,
        };
        self.vp.apic.access(&mut client).mmio_write(address, data);
        self.registers.cr8 = u64::from(cr8);
    }
}
impl<D: CpuIo> TranslateGvaSupport for Emulator<'_, '_, D> {
    fn guest_memory(&self) -> &GuestMemory {
        &self.vp.partition.guest_memory
    }
    fn acquire_tlb_lock(&mut self) {}
    fn registers(&mut self) -> TranslationRegisters {
        TranslationRegisters {
            cr0: self.registers.cr0,
            cr4: self.registers.cr4,
            efer: self.registers.efer,
            cr3: self.registers.cr3,
            rflags: self.registers.rflags,
            ss: self.registers.ss.into(),
            encryption_mode: EncryptionMode::None,
        }
    }
}
