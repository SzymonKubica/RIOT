use crate::middleware;
use crate::vm::VirtualMachine;
use core::ops::DerefMut;
use rbpf::{helpers, without_std::Error};
use riot_sys;
use riot_wrappers::{cstr::cstr, gcoap::PacketBuffer, stdio::println, ztimer::Clock};
pub struct RbpfVm {}

extern "C" {
    /// Copies all contents of the packet under *ctx into the provided memory region.
    /// It also recalculates pointers inside of that packet struct so that they point
    /// to correct offsets in the target memory buffer. This function is needed for
    /// executing the rBPF VM on raw packet data.
    fn copy_packet(buffer: *mut PacketBuffer, mem: *mut u8);
}

impl RbpfVm {
    pub fn new() -> Self {
        RbpfVm {}
    }

    fn timed_execution(&self, execution_fn: impl Fn() -> Result<u64, Error>) -> (i64, u32) {
        // This unsafe hacking is needed as the ztimer_now call expects to get an
        // argument of type riot_sys::inline::ztimer_clock_t but the ztimer_clock_t
        // ZTIMER_USEC that we get from riot_sys has type riot_sys::ztimer_clock_t.
        let clock = unsafe { riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t };
        let start: u32 = Self::time_now(clock);
        let result = execution_fn();
        let end: u32 = Self::time_now(clock);
        let ret = if let Ok(val) = result {
            println!("Program returned: {:?} ({:#x})", val, val);
            val as i64
        } else {
            println!("Program returned: {:?}", result);
            -1
        };
        let execution_time = end - start;
        println!("Execution time: {} [us]", execution_time);
        (ret as i64, execution_time)
    }

    #[inline(always)]
    fn time_now(clock: *mut riot_sys::inline::ztimer_clock_t) -> u32 {
        unsafe { riot_sys::inline::ztimer_now(clock) }
    }
}

impl VirtualMachine for RbpfVm {
    fn execute(&self, program: &[u8], result: &mut i64) -> u32 {
        let mut vm = rbpf::EbpfVmNoData::new(Some(program)).unwrap();

        // We register a helper function that can be called by the program, into
        // the VM.
        vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf)
            .unwrap();

        middleware::register_all_vm_no_data(&mut vm);

        println!("Starting rBPf VM execution.");
        let (_, execution_time) = self.timed_execution(|| vm.execute_program());
        execution_time
    }
    fn execute_on_coap_pkt(&self, program: &[u8], pkt: &mut PacketBuffer, result: &mut i64) -> u32 {
        // Memory for the packet.
        let mut mem: [u8; 512] = [0; 512];
        unsafe { copy_packet(pkt, mem.as_mut_ptr() as *mut u8) };

        println!("Packet copy size: {}", mem.len());

        // Initialise the VM operating on a fixed memory buffer.
        //let mut vm = rbpf::EbpfVmRaw::new(Some(program)).unwrap();
        let mut vm = rbpf::EbpfVmRaw::new(Some(program)).unwrap();

        // We register a helper function that can be called by the program, into
        // the VM.
        vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf)
            .unwrap();

        middleware::register_all_raw_vm(&mut vm);
        let mutex = riot_wrappers::mutex::Mutex::new(mem);

        println!("Starting rBPf VM execution.");
        let (_, execution_time) =
            // Here we need to do some hacking with locks as closures don't like
            // capturing &mut references from environment. It does make sense.
            self.timed_execution(|| vm.execute_program(mutex.lock().deref_mut()));
        execution_time
    }
}
