// This module implements middleware layer to allow rBPF VM call into the RIOT
// host OS. It contains all of the helper functions required to make rBPF a
// drop-in replacement for the Femto-Container VM.
//
// The prototype for helpers follows the convention used by rBpF: five `u64` as arguments, and a
// `u64` as a return value. Hence some helpers have unused arguments, or return a 0 value in all
// cases, in order to respect this convention.
// Question: why do we need this convention?

use riot_wrappers::stdio::println;

/// Indices of the helper functions are defined to be exactly the same as in the
/// case of Femto-Container eBPF VM to achieve compatibility.

/* Print/debug helper functions */
pub const BPF_PRINTF_IDX: u32 = 0x01;
pub const BPF_DEBUG_PRINT_IDX: u32 = 0x03;

/* Memory copy helper functions */
pub const BPF_MEMCPY_IDX: u32 = 0x02;

/* Key/value store functions */
pub const BPF_STORE_LOCAL_IDX: u32 = 0x10;
pub const BPF_STORE_GLOBAL_IDX: u32 = 0x11;
pub const BPF_FETCH_LOCAL_IDX: u32 = 0x12;
pub const BPF_FETCH_GLOBAL_IDX: u32 = 0x13;

/* Saul functions */
pub const BPF_SAUL_REG_FIND_NTH_IDX: u32 = 0x30;
pub const BPF_SAUL_REG_FIND_TYPE_IDX: u32 = 0x31;
pub const BPF_SAUL_REG_READ_IDX: u32 = 0x32;
pub const BPF_SAUL_REG_WRITE_IDX: u32 = 0x33;

/* (g)coap functions */
pub const BPF_GCOAP_RESP_INIT_IDX: u32 = 0x40;
pub const BPF_COAP_OPT_FINISH_IDX: u32 = 0x41;
pub const BPF_COAP_ADD_FORMAT_IDX: u32 = 0x42;
pub const BPF_COAP_GET_PDU_IDX: u32 = 0x43;

pub const BPF_FMT_S16_DFP_IDX: u32 = 0x50;
pub const BPF_FMT_U32_DEC_IDX: u32 = 0x51;

/* Time(r) functions */
pub const BPF_NOW_MS_IDX: u32 = 0x20;

/* ZTIMER */
pub const BPF_ZTIMER_NOW_IDX: u32 = 0x60;
pub const BPF_ZTIMER_PERIODIC_WAKEUP_IDX: u32 = 0x61;

/* Print/debug helper functions - implementation */
/// The goal is to allow for printing arbitrary text, it isn't possible at the moment.
pub fn bpf_printf(fmt: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    // TODO: figure out how to the format string from the eBPF program so that
    // it can be loaded here. Is that even easily doable?
    //
    // For now, behaves the same way as bpf_trace_printk from rBPF but with decimal
    // formatting.
    println!("bpf_trace_printf: {a1}, {a2}, {a3}, {a4}");
    return 0;
}

/// Responsible for printing debug information. Prints a single value.
pub fn bpf_print_debug(a1: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    println!("[DEBUG]: {a1}");
    return 0;
}

/* Saul functions - implementation */

/// Find a SAUL device by its position in the registry. It returns a pointer to
/// the device which can then be used with reg_read / reg_write helpers to
/// manipulate the device.
pub fn bpf_saul_reg_find_nth(
    saul_dev_index: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    unsafe { return riot_sys::saul_reg_find_nth(saul_dev_index as i32) as u64 }
}
pub fn bpf_saul_reg_find_type(
    unused1: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    return 0;
}
pub fn bpf_saul_reg_read(
    unused1: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    return 0;
}
pub fn bpf_saul_reg_write(
    device: u64,
    payload: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    unsafe {
        let dev: *mut riot_sys::saul_reg_t = device as *mut riot_sys::saul_reg_t;
        let data: *const riot_sys::phydat_t = payload as *const riot_sys::phydat_t;
        let res = riot_sys::saul_reg_write(dev, data) as u64;
        return res;
    }
}

/// Returns the current time in milliseconds as measured by RIOT's ZTIMER.
pub fn bpf_now_ms(unused1: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    let clock = unsafe { riot_sys::ZTIMER_MSEC as *mut riot_sys::inline::ztimer_clock_t };
    let now: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
    now as u64
}

/// Returns the current time in microseconds as measured by RIOT's ZTIMER.
pub fn bpf_ztimer_now(unused1: u64, unused2: u64, unused3: u64, unused4: u64, unused5: u64) -> u64 {
    let now: u32 = unsafe {
        // An explicit cast into *mut riot_sys::inline::ztimer_clock_t is needed here
        // because the type of riot_sys::ZTIMER_USEC is riot_sys::ztimer_clock_t
        // and the compiler complains about the mismatching type.
        riot_sys::inline::ztimer_now(riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t)
    };
    now as u64
}

/// List of all helpers together with their corresponding numbers (used
/// directly as function pointers in the compiled eBPF bytecode).
pub const ALL_HELPERS: [(u32, fn(u64, u64, u64, u64, u64) -> u64); 6] = [
    // Print/debug helper functions
    (BPF_DEBUG_PRINT_IDX, bpf_print_debug),
    (BPF_PRINTF_IDX, bpf_printf),
    // Time(r) functions
    (BPF_NOW_MS_IDX, bpf_now_ms),
    (BPF_ZTIMER_NOW_IDX, bpf_ztimer_now),
    // Saul functions
    (BPF_SAUL_REG_FIND_NTH_IDX, bpf_saul_reg_find_nth),
    (BPF_SAUL_REG_WRITE_IDX, bpf_saul_reg_write),
];

pub fn register_all(vm: &mut rbpf::EbpfVmFixedMbuff) {
    for (id, helper) in ALL_HELPERS {
        vm.register_helper(id, helper);
    }
}
