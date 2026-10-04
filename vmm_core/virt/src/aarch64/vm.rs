// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Aarch64PartitionCapabilities;
use inspect::Inspect;
use mesh_protobuf::Protobuf;

/// Versioned backend state for hardware that exposes a native migration ABI.
/// Snapshot compatibility checks bind this state to the original backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Protobuf, Inspect)]
#[mesh(package = "virt.aarch64")]
pub struct NativeState {
    #[mesh(1)]
    pub backend: String,
    #[mesh(2)]
    pub version: u32,
    #[mesh(3)]
    #[inspect(skip)]
    pub data: Vec<u8>,
}

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for NativeState {
    fn is_present(caps: &Aarch64PartitionCapabilities) -> bool {
        caps.native_state_save
    }
    fn at_reset(_caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        Self::default()
    }
    fn can_compare(_caps: &Aarch64PartitionCapabilities) -> bool {
        false
    }
}

use super::SavedDistributorState;
use crate::state::StateElement;
use crate::state::state_trait;
use vm_topology::processor::aarch64::Aarch64VpInfo;

impl StateElement<Aarch64PartitionCapabilities, Aarch64VpInfo> for SavedDistributorState {
    fn is_present(caps: &Aarch64PartitionCapabilities) -> bool {
        caps.gic_max_spis > 0
    }

    fn at_reset(caps: &Aarch64PartitionCapabilities, _vp: &Aarch64VpInfo) -> Self {
        SavedDistributorState::at_reset(caps.gic_max_spis)
    }
}

state_trait!(
    "Access to per-VM state.",
    AccessVmState,
    Aarch64PartitionCapabilities,
    Aarch64VpInfo,
    VmSavedState,
    "virt.aarch64",
    (2, "native", native, set_native, NativeState),
    (
        1,
        "distributor",
        distributor,
        set_distributor,
        SavedDistributorState
    ),
);
