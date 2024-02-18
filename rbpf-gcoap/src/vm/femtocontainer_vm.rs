use riot_wrappers::gcoap::PacketBuffer;

use crate::vm::VirtualMachine;

extern "C" {
    /// Executes a femtocontainer VM where the eBPF program has access
    /// to the pointer to the CoAP packet.
    fn execute_fc_vm_on_coap_pkt(
        program: *const u8,
        program_len: usize,
        pkt: *mut PacketBuffer,
        return_value: *mut i64,
    ) -> u32;
}

pub struct FemtoContainerVm {}

impl VirtualMachine for FemtoContainerVm {
    fn execute(&self, program: &[u8], result: &mut i64) -> u32 {
        0
    }

    fn execute_on_coap_pkt(
        &self,
        program: &[u8],
        pkt: &mut PacketBuffer,
        result: &mut i64,
    ) -> u32 {
        unsafe {
            return execute_fc_vm_on_coap_pkt(
                program.as_ptr() as *const u8,
                program.len(),
                pkt as *mut PacketBuffer,
                result as *mut i64,
            );
        }
    }
}
