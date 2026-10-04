// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Intel VT-x backend. Virtual interrupt state stays in the VMM APIC emulator.

mod abi;
mod emulate;
mod state;

use anyhow::Context;
use guestmem::GuestMemory;
use hvdef::Vtl;
use inspect::Inspect;
use inspect::InspectMut;
use memory_range::MemoryRange;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::poll_fn;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::task::Waker;
use thiserror::Error;
use virt::BindProcessor;
use virt::CpuidLeaf;
use virt::CpuidLeafSet;
use virt::NeedsYield;
use virt::Processor;
use virt::StopVp;
use virt::VpHaltReason;
use virt::VpIndex;
use virt::io::CpuIo;
use virt::irqcon::IoApicRouting;
use virt::irqcon::IrqRoutes;
use virt::irqcon::MsiRequest;
use virt::x86::CpuCompatibilityContract;
use virt::x86::X86PartitionCapabilities;
use virt::x86::vp;
use virt::x86::vp::AccessVpState;
use virt_support_apic::ApicClient;
use virt_support_apic::LocalApic;
use virt_support_apic::LocalApicSet;
use vm_topology::processor::x86::ApicMode;
use vm_topology::processor::x86::X86VpInfo;
use vmcore::vmtime::VmTime;
use vmcore::vmtime::VmTimeAccess;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

fn check(status: u32, operation: &'static str) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Hypervisor.framework {operation}: {status:#x}").into())
    }
}

#[derive(Debug)]
pub struct HvfHypervisor;

fn host_cpuid(function: u32, index: u32) -> [u32; 4] {
    let value = safe_intrinsics::cpuid(function, index);
    [value.eax, value.ebx, value.ecx, value.edx]
}

fn tsc_frequency() -> Result<u64, Error> {
    let mut frequency = 0u64;
    let mut size = size_of::<u64>();
    // SAFETY: a constant NUL-terminated sysctl name and an exact-size writable
    // output; no input buffer is provided.
    let status = unsafe {
        libc::sysctlbyname(
            c"machdep.tsc.frequency".as_ptr(),
            std::ptr::from_mut(&mut frequency).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || size != size_of::<u64>() || frequency == 0 {
        return Err(anyhow::anyhow!(
            "cannot determine Intel HVF TSC frequency: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(frequency)
}

fn filtered_cpuid(function: u32, index: u32) -> [u32; 4] {
    let mut value = host_cpuid(function, index);
    match function {
        1 => {
            // Native FXSAVE preserves x87/SSE. Do not advertise AVX or state
            // components that this backend cannot save and restore.
            value[2] &= !((1 << 5) | (1 << 12) | (1 << 24) | (7 << 26) | (1 << 29) | (1 << 31));
        }
        7 | 0xd | 0x12 | 0x40000000..=0x4fffffff => value = [0; 4],
        0x80000001 => value[3] &= !(1 << 27), // RDTSCP/TSC_AUX
        _ => {}
    }
    value
}

impl virt::Hypervisor for HvfHypervisor {
    type ProtoPartition<'a> = HvfProtoPartition<'a>;
    type Partition = HvfPartition;
    type Error = Error;

    fn platform_info(&self) -> virt::PlatformInfo {
        virt::PlatformInfo::default()
    }

    fn new_partition<'a>(
        &'a mut self,
        config: virt::ProtoPartitionConfig<'a>,
    ) -> Result<Self::ProtoPartition<'a>, Error> {
        if config.isolation.is_isolated() || config.hv_config.is_some() {
            return Err(anyhow::anyhow!("Intel HVF supports unenlightened VTL0 guests").into());
        }
        Ok(HvfProtoPartition { config })
    }
}

pub struct HvfProtoPartition<'a> {
    config: virt::ProtoPartitionConfig<'a>,
}

impl virt::ProtoPartition for HvfProtoPartition<'_> {
    type Partition = HvfPartition;
    type ProcessorBinder = HvfProcessorBinder;
    type Error = Error;

    fn max_physical_address_size(&self) -> u8 {
        virt::x86::max_physical_address_size_from_cpuid(&mut filtered_cpuid)
    }

    fn build(
        self,
        config: virt::PartitionConfig<'_>,
    ) -> Result<(HvfPartition, Vec<HvfProcessorBinder>), Error> {
        let frequency = tsc_frequency()?;
        let mut leaves = Vec::new();
        for function in 0..=host_cpuid(0, 0)[0].min(0x20) {
            let indexed = matches!(function, 4 | 7 | 0xb | 0xd | 0x1f);
            let indices = if indexed { 32 } else { 1 };
            for index in 0..indices {
                let result = filtered_cpuid(function, index);
                let mut leaf = CpuidLeaf::new(function, result);
                if indexed {
                    leaf = leaf.indexed(index);
                }
                leaves.push(leaf);
                if indexed && result == [0; 4] {
                    break;
                }
            }
        }
        for function in 0x80000000..=host_cpuid(0x80000000, 0)[0].min(0x80000020) {
            leaves.push(CpuidLeaf::new(function, filtered_cpuid(function, 0)));
        }
        leaves.extend(
            config
                .cpuid
                .iter()
                .copied()
                .filter(|leaf| !matches!(leaf.function, 7 | 0xd | 0x12 | 0x40000000..=0x4fffffff)),
        );
        virt::x86::topology::topology_cpuid(
            self.config.processor_topology,
            &filtered_cpuid,
            &mut leaves,
        )
        .context("Intel HVF processor topology")?;
        let x2apic = self.config.processor_topology.apic_mode() != ApicMode::XApic;
        leaves
            .push(CpuidLeaf::new(1, [0, 0, u32::from(x2apic) << 21, 0]).masked([0, 0, 1 << 21, 0]));
        // Configuration cannot opt into unsupported architectural state.
        leaves.push(CpuidLeaf::new(1, [0; 4]).masked([
            0,
            0,
            (1 << 5) | (1 << 12) | (1 << 24) | (7 << 26) | (1 << 29) | (1 << 31),
            0,
        ]));
        // Architectural extensions cannot be re-enabled by caller overrides.
        for function in [7, 0xd, 0x12] {
            leaves.push(CpuidLeaf::new(function, [0; 4]));
        }
        leaves.push(CpuidLeaf::new(0x80000001, [0; 4]).masked([0, 0, 0, 1 << 27]));
        leaves.extend(
            virt::x86::tsc::tsc_frequency_cpuid_leaves(frequency, host_cpuid(0, 0)[0])
                .context("Intel HVF TSC CPUID")?,
        );
        let cpuid = CpuidLeafSet::new(leaves);
        let caps =
            X86PartitionCapabilities::from_cpuid(self.config.processor_topology, &mut |f, i| {
                cpuid.result(f, i, &[0; 4])
            })
            .context("Intel HVF CPU capabilities")?;
        // SAFETY: creating a process-local VM has no pointer requirements.
        check(unsafe { abi::hv_vm_create(0) }, "create VM")?;
        let apics = LocalApicSet::builder().x2apic_capable(x2apic).build();
        let inner = Arc::new(PartitionInner {
            caps,
            frequency,
            cpuid,
            guest_memory: config.guest_memory.clone(),
            apics,
            irq_routes: IrqRoutes::new(),
            mappings: Default::default(),
            vps: self
                .config
                .processor_topology
                .vps_arch()
                .map(|_| VpShared {
                    vcpu: AtomicU32::new(abi::INVALID_VCPU),
                    needs_yield: NeedsYield::new(),
                    waker: Default::default(),
                })
                .collect(),
        });
        let binders = self
            .config
            .processor_topology
            .vps_arch()
            .map(|vp_info| HvfProcessorBinder {
                partition: inner.clone(),
                vp_info,
                initial: Some((
                    inner.apics.add_apic(&vp_info, false),
                    self.config
                        .vmtime
                        .access(format!("hvf-vp{}", vp_info.base.vp_index.index())),
                )),
            })
            .collect();
        Ok((HvfPartition { inner }, binders))
    }
}

#[derive(Inspect)]
#[inspect(transparent)]
pub struct HvfPartition {
    inner: Arc<PartitionInner>,
}

#[derive(Inspect)]
struct PartitionInner {
    caps: X86PartitionCapabilities,
    frequency: u64,
    #[inspect(skip)]
    cpuid: CpuidLeafSet,
    #[inspect(skip)]
    guest_memory: GuestMemory,
    apics: LocalApicSet,
    irq_routes: IrqRoutes,
    #[inspect(skip)]
    vps: Vec<VpShared>,
    #[inspect(skip)]
    mappings: Mutex<Vec<(MemoryRange, bool)>>,
}

struct VpShared {
    vcpu: AtomicU32,
    needs_yield: NeedsYield,
    waker: Mutex<Option<Waker>>,
}

impl PartitionInner {
    fn wake(&self, index: VpIndex) {
        if let Some(vp) = self.vps.get(index.index() as usize) {
            let mut id = vp.vcpu.load(Ordering::Acquire);
            if id != abi::INVALID_VCPU {
                // SAFETY: the pointer names one initialized ID; interrupt is
                // explicitly thread-safe, including a concurrently stopped VP.
                let _ = unsafe { abi::hv_vcpu_interrupt(&mut id, 1) };
            }
            if let Some(waker) = vp.waker.lock().take() {
                waker.wake();
            }
        }
    }

    fn interrupt(&self, request: MsiRequest) {
        self.apics
            .request_interrupt(request.address, request.data, |vp| self.wake(vp));
    }
}

impl Drop for PartitionInner {
    fn drop(&mut self) {
        // SAFETY: all processors retain this Arc, so they have been destroyed.
        let status = unsafe { abi::hv_vm_destroy() };
        if status != 0 {
            tracing::error!(status, "Intel HVF VM destruction failed");
        }
    }
}

impl virt::Partition for HvfPartition {
    fn initial_vp_state_source(&self) -> virt::InitialVpStateSource {
        virt::InitialVpStateSource::Registers
    }
    fn cpu_compatibility_contract(&self) -> CpuCompatibilityContract {
        CpuCompatibilityContract::new(&self.inner.caps, &self.inner.cpuid)
    }
    fn caps(&self) -> &X86PartitionCapabilities {
        &self.inner.caps
    }
    fn tsc_frequency_hz(&self) -> Result<Option<u64>, Error> {
        Ok(Some(self.inner.frequency))
    }
    fn set_tsc_frequency_hz(&self, frequency: u64) -> Result<(), Error> {
        if frequency != self.inner.frequency {
            return Err(anyhow::anyhow!("Intel HVF cannot scale the guest TSC").into());
        }
        Ok(())
    }
    fn supports_reset(&self) -> Option<&dyn virt::ResetPartition<Error = Error>> {
        None
    }
    fn request_msi(&self, _vtl: Vtl, request: MsiRequest) {
        self.inner.interrupt(request);
    }
    fn request_yield(&self, index: VpIndex) {
        if let Some(vp) = self.inner.vps.get(index.index() as usize) {
            vp.needs_yield.request_yield();
            self.inner.wake(index);
        }
    }
    fn apic_frequency_hz(&self) -> Result<Option<u64>, Error> {
        Ok(Some(virt_support_apic::TIMER_FREQUENCY))
    }
}

impl virt::X86Partition for HvfPartition {
    fn ioapic_routing(&self) -> Arc<dyn IoApicRouting> {
        self.inner.clone()
    }
    fn pulse_lint(&self, vp: VpIndex, _vtl: Vtl, lint: u8) {
        self.inner
            .apics
            .lint(vp, usize::from(lint), |vp| self.inner.wake(vp));
    }
}

impl IoApicRouting for PartitionInner {
    fn set_irq_route(&self, irq: u8, request: Option<MsiRequest>) {
        self.irq_routes.set_irq_route(irq, request);
    }
    fn assert_irq(&self, irq: u8) {
        self.irq_routes
            .assert_irq(irq, |request| self.interrupt(request));
    }
}

impl virt::Hv1 for HvfPartition {
    type Error = Error;
    type Device = virt::UnimplementedDevice;
    fn reference_time_source(&self) -> Option<vmcore::reference_time::ReferenceTimeSource> {
        None
    }
    fn new_virtual_device(
        &self,
    ) -> Option<&dyn virt::DeviceBuilder<Device = Self::Device, Error = Error>> {
        None
    }
    fn synic(&self) -> anyhow::Result<Arc<dyn vmcore::synic::SynicPortAccess>> {
        anyhow::bail!("Intel HVF does not expose Hyper-V synthetic interrupts")
    }
}

impl virt::PartitionMemoryMapper for HvfPartition {
    fn memory_mapper(&self, _vtl: Vtl) -> Arc<dyn virt::PartitionMemoryMap> {
        self.inner.clone()
    }
}

impl virt::PartitionMemoryMap for PartitionInner {
    unsafe fn map_range(
        &self,
        data: *mut u8,
        size: usize,
        addr: u64,
        writable: bool,
        exec: bool,
    ) -> anyhow::Result<()> {
        let end = addr
            .checked_add(size as u64)
            .context("Intel HVF GPA overflow")?;
        let mut mappings = self.mappings.lock();
        // SAFETY: the caller retains the mapped allocation for this lifetime.
        check(
            unsafe {
                abi::hv_vm_map(
                    data.cast(),
                    addr,
                    size,
                    1 | (u64::from(writable) << 1) | (u64::from(exec) << 2),
                )
            },
            "map RAM",
        )?;
        mappings.push((MemoryRange::new(addr..end), writable));
        Ok(())
    }
    fn unmap_range(&self, addr: u64, size: u64) -> anyhow::Result<()> {
        let end = addr.checked_add(size).context("Intel HVF GPA overflow")?;
        let mut mappings = self.mappings.lock();
        // SAFETY: the partition memory interface owns these mappings.
        check(
            unsafe { abi::hv_vm_unmap(addr, usize::try_from(size)?) },
            "unmap RAM",
        )?;
        mappings.retain(|(range, _)| range.end() <= addr || range.start() >= end);
        Ok(())
    }
}

pub struct HvfProcessorBinder {
    partition: Arc<PartitionInner>,
    vp_info: X86VpInfo,
    initial: Option<(LocalApic, VmTimeAccess)>,
}

impl BindProcessor for HvfProcessorBinder {
    type Processor<'a> = HvfProcessor<'a>;
    type Error = Error;
    fn bind(&mut self) -> Result<Self::Processor<'_>, Error> {
        let vcpu = Vcpu::new()?;
        let (apic, vmtime) = self
            .initial
            .take()
            .context("Intel HVF VP is already bound")?;
        self.partition.vps[self.vp_info.base.vp_index.index() as usize]
            .vcpu
            .store(vcpu.id, Ordering::Release);
        Ok(HvfProcessor {
            partition: self.partition.clone(),
            vp_info: self.vp_info,
            vcpu,
            apic,
            vmtime,
            halted: false,
            wait_for_sipi: !self.vp_info.base.is_bsp(),
            pending_event: None,
            state_error: None,
            nmi_pending: false,
            extint_pending: false,
            msrs: Default::default(),
            guest_pat: Default::default(),
            _binder: PhantomData,
        })
    }
}

pub struct HvfProcessor<'a> {
    partition: Arc<PartitionInner>,
    vp_info: X86VpInfo,
    vcpu: Vcpu,
    apic: LocalApic,
    vmtime: VmTimeAccess,
    halted: bool,
    wait_for_sipi: bool,
    pending_event: Option<vp::PendingEvent>,
    state_error: Option<Error>,
    nmi_pending: bool,
    extint_pending: bool,
    msrs: std::collections::BTreeMap<u32, u64>,
    guest_pat: crate::intel::GuestPat,
    _binder: PhantomData<&'a mut HvfProcessorBinder>,
}

impl InspectMut for HvfProcessor<'_> {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("vcpu", self.vcpu.id)
            .field("apic", &self.apic)
            .field("halted", self.halted);
    }
}

impl Drop for HvfProcessor<'_> {
    fn drop(&mut self) {
        self.partition.vps[self.vp_info.base.vp_index.index() as usize]
            .vcpu
            .store(abi::INVALID_VCPU, Ordering::Release);
    }
}

struct Vcpu {
    id: u32,
    cr0: crate::intel::ControlRegisterPolicy,
    cr4: crate::intel::ControlRegisterPolicy,
    // Hypervisor.framework VP APIs must execute on the owning thread.
    _thread: PhantomData<Rc<()>>,
    quantum: u64,
}

impl Vcpu {
    fn new() -> Result<Self, Error> {
        let mut fixed = [0; 4];
        for (field, value) in (11..=14).zip(&mut fixed) {
            // SAFETY: writable result pointer; capability IDs are from hv_vmx.h.
            check(
                unsafe { abi::hv_vmx_read_capability(field, value) },
                "read VMX control-register capability",
            )?;
        }
        let mut id = abi::INVALID_VCPU;
        // SAFETY: writable ID pointer; called on the binding thread.
        check(unsafe { abi::hv_vcpu_create(&mut id, 0) }, "create VP")?;
        let mut timebase = abi::MachTimebase { numer: 0, denom: 0 };
        // SAFETY: a writable mach timebase structure.
        let status = unsafe { abi::mach_timebase_info(&mut timebase) };
        if status != 0 || timebase.numer == 0 || timebase.denom == 0 {
            // SAFETY: clean up the just-created VP on its owning thread.
            let _ = unsafe { abi::hv_vcpu_destroy(id) };
            return Err(anyhow::anyhow!("cannot determine Intel HVF timer timebase").into());
        }
        let quantum = 1_000_000u64 * u64::from(timebase.denom) / u64::from(timebase.numer);
        let cpu = Self {
            id,
            cr0: crate::intel::ControlRegisterPolicy::cr0(fixed[0], fixed[1]),
            cr4: crate::intel::ControlRegisterPolicy::cr4(fixed[2], fixed[3]),
            _thread: PhantomData,
            quantum: quantum.max(1),
        };
        cpu.control(0x4000, 1)?; // external interrupt exiting
        cpu.control(
            0x4002,
            (1 << 3) | (1 << 7) | (1 << 19) | (1 << 20) | (1 << 24) | (1 << 31),
        )?;
        cpu.control(0x401e, (1 << 1) | (1 << 7))?; // EPT + unrestricted guest
        cpu.control(0x400c, 0)?; // retain the framework's required VM-exit controls
        cpu.control(0x4012, crate::intel::INITIAL_ENTRY_CONTROLS)?;
        cpu.vmcs_set(0x4004, 0)?;
        cpu.vmcs_set(0x6000, cpu.cr0.mask)?;
        cpu.vmcs_set(0x6002, cpu.cr4.mask)?;
        for &msr in crate::intel::NATIVE_MSRS {
            // SAFETY: architectural native MSRs, retained and switched by HVF.
            check(
                unsafe { abi::hv_vcpu_enable_native_msr(id, msr, true) },
                "enable native MSR",
            )?;
        }
        Ok(cpu)
    }
    fn reg(&self, register: u32) -> Result<u64, Error> {
        if register == 36 {
            return Ok(self.cr0.guest(self.vmcs(0x6800)?, self.vmcs(0x6004)?));
        }
        if register == 40 {
            return Ok(self.cr4.guest(self.vmcs(0x6804)?, self.vmcs(0x6006)?));
        }
        let mut value = 0;
        // SAFETY: writable result pointer and owning thread.
        check(
            unsafe { abi::hv_vcpu_read_register(self.id, register, &mut value) },
            "read register",
        )?;
        Ok(value)
    }
    fn set_reg(&self, register: u32, value: u64) -> Result<(), Error> {
        let value = match register {
            36 => {
                self.vmcs_set(0x6004, value)?;
                self.cr0.hardware(value)
            }
            40 => {
                self.vmcs_set(0x6006, value)?;
                self.cr4.hardware(value)
            }
            _ => value,
        };
        // SAFETY: owning thread and scalar arguments.
        check(
            unsafe { abi::hv_vcpu_write_register(self.id, register, value) },
            "write register",
        )
    }
    fn vmcs(&self, field: u32) -> Result<u64, Error> {
        let mut value = 0;
        // SAFETY: writable result pointer and owning thread.
        check(
            unsafe { abi::hv_vmx_vcpu_read_vmcs(self.id, field, &mut value) },
            "read VMCS",
        )?;
        Ok(value)
    }
    fn vmcs_set(&self, field: u32, value: u64) -> Result<(), Error> {
        // SAFETY: owning thread and scalar arguments.
        check(
            unsafe { abi::hv_vmx_vcpu_write_vmcs(self.id, field, value) },
            "write VMCS",
        )
    }
    fn control(&self, field: u32, desired: u64) -> Result<(), Error> {
        let (mut required, mut allowed) = (0, 0);
        // SAFETY: both masks point to initialized writable u64 values.
        check(
            unsafe {
                abi::hv_vmx_vcpu_get_cap_write_vmcs(self.id, field, &mut required, &mut allowed)
            },
            "query VMCS control mask",
        )?;
        if desired & !allowed != 0 {
            return Err(anyhow::anyhow!(
                "Intel HVF lacks required VMCS control bits {:#x} for {field:#x}",
                desired & !allowed
            )
            .into());
        }
        self.vmcs_set(field, desired | required)
    }
    fn msr(&self, msr: u32) -> Result<u64, Error> {
        let mut value = 0;
        // SAFETY: writable result pointer and owning thread.
        check(
            unsafe { abi::hv_vcpu_read_msr(self.id, msr, &mut value) },
            "read MSR",
        )?;
        Ok(value)
    }
    fn set_msr(&self, msr: u32, value: u64) -> Result<(), Error> {
        // SAFETY: owning thread and scalar arguments.
        check(
            unsafe { abi::hv_vcpu_write_msr(self.id, msr, value) },
            "write MSR",
        )
    }
    fn efer(&self) -> Result<u64, Error> {
        self.vmcs(0x2806)
    }
    fn set_efer(&self, value: u64) -> Result<(), Error> {
        if value & !crate::intel::EFER_MASK != 0 {
            return Err(anyhow::anyhow!("Intel HVF EFER contains reserved bits").into());
        }
        self.vmcs_set(0x2806, value)?;
        self.vmcs_set(
            0x4012,
            crate::intel::entry_controls_for_efer(self.vmcs(0x4012)?, value),
        )
    }
    fn advance(&self) -> Result<(), Error> {
        self.set_reg(0, self.reg(0)?.wrapping_add(self.vmcs(0x440c)?))
    }
    fn guest_control_write(&self, register: u32, value: u64) -> Result<bool, Error> {
        let efer = self.efer()?;
        let valid = match register {
            36 => {
                self.cr0.supports(value)
                    && value & !0xe005003f == 0
                    && (value & (1 << 31) == 0 || value & 1 != 0)
                    && (value & (1 << 29) == 0 || value & (1 << 30) != 0)
                    && (value & (1 << 31) == 0
                        || efer & (1 << 8) == 0
                        || self.reg(40)? & (1 << 5) != 0)
            }
            40 => self.cr4.supports(value) && (efer & (1 << 10) == 0 || value & (1 << 5) != 0),
            _ => false,
        };
        if !valid {
            self.inject(13, 3, Some(0))?;
            return Ok(false);
        }
        self.set_reg(register, value)?;
        if register == 36 {
            self.set_efer(crate::intel::efer_for_cr0(efer, value))?;
        }
        // SAFETY: owning VP thread; changed paging state invalidates translations.
        check(
            unsafe { abi::hv_vcpu_invalidate_tlb(self.id) },
            "invalidate TLB",
        )?;
        Ok(true)
    }
    fn control_access(&self, q: u64) -> Result<bool, Error> {
        let cr = q & 0xf;
        let gp = [2, 3, 4, 5, 8, 9, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17][((q >> 8) & 15) as usize];
        let access = (q >> 4) & 3;
        let register = match cr {
            0 => 36,
            4 => 40,
            8 => 49,
            _ => {
                return Err(
                    anyhow::anyhow!("unexpected Intel HVF control-register exit {q:#x}").into(),
                );
            }
        };
        let value = match access {
            0 => self.reg(gp)?,
            1 => {
                let value = self.reg(register)?;
                self.set_reg(gp, if cr == 8 { value >> 4 } else { value })?;
                return Ok(true);
            }
            2 if cr == 0 => self.reg(36)? & !(1 << 3),
            3 if cr == 0 => crate::intel::cr0_for_lmsw(self.reg(36)?, q >> 16),
            _ => {
                return Err(
                    anyhow::anyhow!("invalid Intel HVF control-register access {q:#x}").into(),
                );
            }
        };
        if cr == 8 {
            if value > 15 {
                self.inject(13, 3, Some(0))?;
                return Ok(false);
            }
            self.set_reg(49, value << 4)?;
            Ok(true)
        } else {
            self.guest_control_write(register, value)
        }
    }
    fn inject(&self, vector: u8, kind: u32, error: Option<u32>) -> Result<(), Error> {
        self.vmcs_set(
            0x4016,
            (1 << 31)
                | u64::from(vector)
                | (u64::from(kind) << 8)
                | (u64::from(error.is_some()) << 11),
        )?;
        if let Some(error) = error {
            self.vmcs_set(0x4018, u64::from(error))?;
        }
        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        // SAFETY: the owning processor thread destroys its own VP.
        let status = unsafe { abi::hv_vcpu_destroy(self.id) };
        if status != 0 {
            tracing::error!(status, "Intel HVF VP destruction failed");
        }
    }
}

struct ApicAccess<'a, D> {
    partition: &'a PartitionInner,
    dev: &'a D,
    vmtime: &'a VmTimeAccess,
    cr8: &'a mut u32,
}
impl<D: CpuIo> ApicClient for ApicAccess<'_, D> {
    fn cr8(&mut self) -> u32 {
        *self.cr8
    }
    fn set_cr8(&mut self, value: u32) {
        *self.cr8 = value;
    }
    fn set_apic_base(&mut self, _value: u64) {}
    fn wake(&mut self, vp: VpIndex) {
        self.partition.wake(vp);
    }
    fn eoi(&mut self, vector: u8) {
        self.dev.handle_eoi(vector.into());
    }
    fn now(&mut self) -> VmTime {
        self.vmtime.now()
    }
    fn pull_offload(&mut self) -> ([u32; 8], [u32; 8]) {
        ([0; 8], [0; 8])
    }
}

impl HvfProcessor<'_> {
    fn apply_apic_work(
        &mut self,
        init: bool,
        sipi: Option<u8>,
        nmi: bool,
        extint: bool,
    ) -> Result<(), Error> {
        if init {
            let info = self.vp_info;
            vp::x86_init(&mut self.access_state(Vtl::Vtl0), &info).context("Intel HVF INIT")?;
            self.wait_for_sipi = !info.base.is_bsp();
            self.halted = false;
            self.nmi_pending = false;
            self.extint_pending = false;
        }
        if let Some(vector) = sipi.filter(|_| self.wait_for_sipi) {
            let mut registers = self.vcpu.registers()?;
            registers.cs.selector = u16::from(vector) << 8;
            registers.cs.base = u64::from(vector) << 12;
            registers.rip = 0;
            self.vcpu.set_registers(&registers)?;
            self.wait_for_sipi = false;
        }
        self.nmi_pending |= nmi;
        self.extint_pending |= extint;
        Ok(())
    }

    fn dispatch_msr(&mut self, dev: &impl CpuIo, write: bool) -> Result<(), Error> {
        let msr = self.vcpu.reg(3)? as u32;
        let mut cr8 = (self.vcpu.reg(49)? >> 4) as u32;
        let mut client = ApicAccess {
            partition: &self.partition,
            dev,
            vmtime: &self.vmtime,
            cr8: &mut cr8,
        };
        let apic_msr = msr == 0x1b || (0x800..=0x8ff).contains(&msr);
        if write {
            let value =
                (self.vcpu.reg(2)? as u32 as u64) | ((self.vcpu.reg(4)? as u32 as u64) << 32);
            let valid = if apic_msr {
                self.apic.access(&mut client).msr_write(msr, value).is_ok()
            } else if msr == 0x277 {
                self.guest_pat.set(value)
            } else if msr == 0xc0000080 {
                if let Some(value) = crate::intel::guest_efer_write(
                    self.vcpu.efer()?,
                    value,
                    self.vcpu.reg(36)? & (1 << 31) != 0,
                ) {
                    self.vcpu.set_efer(value)?;
                    true
                } else {
                    false
                }
            } else if msr == 0x10 {
                self.access_state(Vtl::Vtl0).set_tsc(&vp::Tsc { value })?;
                true
            } else if (0x200..=0x20f).contains(&msr)
                || state::is_fixed_mtrr(msr)
                || matches!(msr, 0x2ff | 0x1a0 | 0x3b | 0x8b)
            {
                self.msrs.insert(msr, value);
                true
            } else {
                false
            };
            if !valid {
                return self.vcpu.inject(13, 3, Some(0));
            }
        } else {
            let value = if apic_msr {
                self.apic.access(&mut client).msr_read(msr).ok()
            } else {
                match msr {
                    0x10 => Some(self.vcpu.msr(0x10)?),
                    0x277 => Some(self.guest_pat.get()),
                    0xc0000080 => Some(self.vcpu.efer()?),
                    0xfe => Some(0x508),
                    0x1a0 => Some(*self.msrs.get(&msr).unwrap_or(&((1 << 11) | (1 << 12) | 1))),
                    0x200..=0x20f
                    | 0x250
                    | 0x258
                    | 0x259
                    | 0x268..=0x26f
                    | 0x2ff
                    | 0x3b
                    | 0x8b
                    | 0x17
                    | 0xce => Some(*self.msrs.get(&msr).unwrap_or(&0)),
                    _ => None,
                }
            };
            let Some(value) = value else {
                return self.vcpu.inject(13, 3, Some(0));
            };
            self.vcpu.set_reg(2, value as u32 as u64)?;
            self.vcpu.set_reg(4, value >> 32)?;
        }
        self.vcpu.set_reg(49, u64::from(cr8) << 4)?;
        self.vcpu.advance()
    }

    async fn run(
        &mut self,
        mut stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        loop {
            let index = self.vp_info.base.vp_index;
            self.partition.vps[index.index() as usize]
                .needs_yield
                .maybe_yield()
                .await;
            stop.check()?;
            stop.until_stop(poll_fn(|cx| {
                self.partition.vps[index.index() as usize]
                    .waker
                    .lock()
                    .replace(cx.waker().clone());
                loop {
                    let work = self.apic.scan(&mut self.vmtime, true);
                    self.nmi_pending |= work.nmi;
                    self.extint_pending |= work.extint;
                    self.apply_apic_work(work.init, work.sipi, work.nmi, work.extint)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    let shadow = self
                        .vcpu
                        .vmcs(0x4824)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    let pending = self
                        .vcpu
                        .vmcs(0x4016)
                        .map_err(|error| dev.fatal_error(error.into()))?
                        & (1 << 31)
                        != 0;
                    let interruptible = self
                        .vcpu
                        .reg(1)
                        .map_err(|error| dev.fatal_error(error.into()))?
                        & (1 << 9)
                        != 0
                        && shadow & 3 == 0
                        && !pending;
                    if !pending {
                        match self.pending_event {
                            Some(vp::PendingEvent::Exception {
                                vector,
                                error_code,
                                parameter,
                            }) => {
                                if vector == 14 {
                                    self.vcpu
                                        .set_reg(38, parameter)
                                        .map_err(|error| dev.fatal_error(error.into()))?;
                                }
                                self.vcpu
                                    .inject(vector, 3, error_code)
                                    .map_err(|error| dev.fatal_error(error.into()))?;
                                self.pending_event = None;
                                self.halted = false;
                                continue;
                            }
                            Some(vp::PendingEvent::ExtInt { vector }) if interruptible => {
                                self.vcpu
                                    .inject(vector, 0, None)
                                    .map_err(|error| dev.fatal_error(error.into()))?;
                                self.pending_event = None;
                                self.halted = false;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    let cr8 = self
                        .vcpu
                        .reg(49)
                        .map_err(|error| dev.fatal_error(error.into()))?
                        >> 4;
                    let interrupt = work
                        .interrupt
                        .filter(|vector| u64::from(*vector >> 4) > cr8);
                    if self.nmi_pending && shadow & 8 == 0 && !pending {
                        self.vcpu
                            .inject(2, 2, None)
                            .map_err(|error| dev.fatal_error(error.into()))?;
                        self.nmi_pending = false;
                        self.halted = false;
                    } else if interruptible {
                        let vector = if self.extint_pending {
                            dev.acknowledge_pic_interrupt()
                        } else {
                            interrupt
                        };
                        if let Some(vector) = vector {
                            self.vcpu
                                .inject(vector, 0, None)
                                .map_err(|error| dev.fatal_error(error.into()))?;
                            if self.extint_pending {
                                self.extint_pending = false;
                            } else {
                                self.apic.acknowledge_interrupt(vector);
                            }
                            self.halted = false;
                        }
                    }
                    let mut controls = self
                        .vcpu
                        .vmcs(0x4002)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    controls = (controls & !(1 << 2))
                        | (u64::from(
                            !interruptible && (interrupt.is_some() || self.extint_pending),
                        ) << 2);
                    self.vcpu
                        .vmcs_set(0x4002, controls)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    if self.halted || self.wait_for_sipi {
                        if self.vmtime.poll_timeout(cx).is_ready() {
                            continue;
                        }
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok::<(), VpHaltReason>(()));
                }
            }))
            .await??;
            // SAFETY: the processor and the VP are bound to this thread.
            let deadline = unsafe { abi::mach_absolute_time() }.saturating_add(self.vcpu.quantum);
            // SAFETY: the VP is bound to this thread; the deadline is a scalar.
            check(
                unsafe { abi::hv_vcpu_run_until(self.vcpu.id, deadline) },
                "run VP",
            )
            .map_err(|error| dev.fatal_error(error.into()))?;
            let reason = self
                .vcpu
                .vmcs(0x4402)
                .map_err(|error| dev.fatal_error(error.into()))? as u32;
            if reason & (1 << 31) != 0 {
                return Err(dev.fatal_error(
                    anyhow::anyhow!("Intel HVF VM entry failed: {reason:#x}").into(),
                ));
            }
            match reason & 0xffff {
                1 | 7 | 8 | 52 => {}
                10 => {
                    let function = self
                        .vcpu
                        .reg(2)
                        .map_err(|error| dev.fatal_error(error.into()))?
                        as u32;
                    let index = self
                        .vcpu
                        .reg(3)
                        .map_err(|error| dev.fatal_error(error.into()))?
                        as u32;
                    let mut value = self.partition.cpuid.result(function, index, &[0; 4]);
                    if function == 1 {
                        value[1] = (value[1] & 0xffffff) | (self.vp_info.apic_id << 24);
                    }
                    if matches!(function, 0xb | 0x1f) {
                        value[3] = self.vp_info.apic_id;
                    }
                    for (reg, value) in [2, 5, 3, 4].into_iter().zip(value) {
                        self.vcpu
                            .set_reg(reg, u64::from(value))
                            .map_err(|error| dev.fatal_error(error.into()))?;
                    }
                    self.vcpu
                        .advance()
                        .map_err(|error| dev.fatal_error(error.into()))?;
                }
                12 => {
                    self.vcpu
                        .advance()
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    self.halted = true;
                }
                28 => {
                    let q = self
                        .vcpu
                        .vmcs(0x6400)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    if !self
                        .vcpu
                        .control_access(q)
                        .map_err(|error| dev.fatal_error(error.into()))?
                    {
                        continue;
                    }
                    self.vcpu
                        .advance()
                        .map_err(|error| dev.fatal_error(error.into()))?;
                }
                30 => {
                    let q = self
                        .vcpu
                        .vmcs(0x6400)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    if q & (3 << 4) != 0 {
                        self.emulate(dev, None).await?;
                    } else {
                        let length = ((q & 7) + 1) as u8;
                        if !matches!(length, 1 | 2 | 4) {
                            return Err(dev.fatal_error(
                                anyhow::anyhow!("invalid Intel HVF I/O width").into(),
                            ));
                        }
                        let mut rax = self
                            .vcpu
                            .reg(2)
                            .map_err(|error| dev.fatal_error(error.into()))?;
                        virt_support_x86emu::emulate::emulate_io(
                            index,
                            q & 8 == 0,
                            (q >> 16) as u16,
                            &mut rax,
                            length,
                            dev,
                        )
                        .await;
                        self.vcpu
                            .set_reg(2, rax)
                            .map_err(|error| dev.fatal_error(error.into()))?;
                        self.vcpu
                            .advance()
                            .map_err(|error| dev.fatal_error(error.into()))?;
                    }
                }
                31 | 32 => self
                    .dispatch_msr(dev, reason & 0xffff == 32)
                    .map_err(|error| dev.fatal_error(error.into()))?,
                48 => {
                    let gpa = self
                        .vcpu
                        .vmcs(0x2400)
                        .map_err(|error| dev.fatal_error(error.into()))?;
                    self.emulate(dev, Some(gpa)).await?;
                }
                2 => return Err(VpHaltReason::TripleFault { vtl: Vtl::Vtl0 }),
                _ => {
                    return Err(dev.fatal_error(
                        anyhow::anyhow!("unsupported Intel HVF VM exit {reason:#x}").into(),
                    ));
                }
            }
        }
    }
}

impl<'b> Processor for HvfProcessor<'b> {
    type StateAccess<'a>
        = state::VpState<'a, 'b>
    where
        Self: 'a;
    fn set_debug_state(
        &mut self,
        _vtl: Vtl,
        state: Option<&virt::x86::DebugState>,
    ) -> Result<(), Error> {
        if state.is_some() {
            return Err(anyhow::anyhow!("Intel HVF guest debugging is unsupported").into());
        }
        Ok(())
    }
    async fn run_vp(
        &mut self,
        stop: StopVp<'_>,
        dev: &impl CpuIo,
    ) -> Result<Infallible, VpHaltReason> {
        self.run(stop, dev).await
    }
    fn flush_async_requests(&mut self) {
        let work = self.apic.flush();
        if let Err(error) = self.apply_apic_work(work.init, work.sipi, work.nmi, work.extint) {
            self.state_error = Some(error);
        }
    }
    fn access_state(&mut self, _vtl: Vtl) -> Self::StateAccess<'_> {
        state::VpState(self)
    }
}
