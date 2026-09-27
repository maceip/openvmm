// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Aarch64PartitionCapabilities;
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
    (
        1,
        "distributor",
        distributor,
        set_distributor,
        SavedDistributorState
    ),
);
