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
///
/* Aux helper functions (stdlib) */
pub const BPF_PRINTF_IDX: u32 = 0x01;
pub const BPF_MEMCPY_IDX: u32 = 0x02;

/* Key/value store functions */
pub const BPF_STORE_LOCAL_IDX: u32 = 0x10;
pub const BPF_STORE_GLOBAL_IDX: u32 = 0x11;
pub const BPF_FETCH_LOCAL_IDX: u32 = 0x12;
pub const BPF_FETCH_GLOBAL_IDX: u32 = 0x13;

/* Time(r) functions */
pub const BPF_NOW_MS_IDX: u32 = 0x20;

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

/* ZTIMER */
pub const BPF_ZTIMER_NOW_IDX: u32 = 0x60;
pub const BPF_ZTIMER_PERIODIC_WAKEUP_IDX: u32 = 0x61;

///
pub fn bpf_printf(fmt: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    // TODO: figure out how to the format string from the eBPF program so that
    // it can be loaded here. Is that even easily doable?
    //
    // For now, behaves the same way as bpf_trace_printk from rBPF but with decimal
    // formatting.
    println!("bpf_trace_printf: {a1}, {a2}, {a3}, {a4}");
    return 0;
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
        riot_sys::inline::ztimer_now(riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t)
    };
    now as u64
}
