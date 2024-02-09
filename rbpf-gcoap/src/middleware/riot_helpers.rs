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

/* Format functions */
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

/* Standard library functions */

pub fn bpf_memcpy(dest_p: u64, src_p: u64, size: u64, unused4: u64, unused5: u64) -> u64 {
    let dest: *mut riot_sys::libc::c_void = dest_p as *mut riot_sys::libc::c_void;
    let src: *const riot_sys::libc::c_void = src_p as *const riot_sys::libc::c_void;
    let size = size as u32;
    unsafe {
        return riot_sys::memcpy(dest, src, size) as u64;
    }
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

/// Find the first device of the given type. The saul_dev_type needs to match
/// the list of all device classes is available here:
/// https://api.riot-os.org/group__drivers__saul.html#:~:text=category%20IDs.%20More...-,enum,-%7B%0A%C2%A0%C2%A0SAUL_ACT_ANY
pub fn bpf_saul_reg_find_type(
    saul_dev_type: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    unsafe { return riot_sys::saul_reg_find_type(saul_dev_type as u8) as u64 }
}

/// Given a pointer to the SAUL device struct, it reads from the device into the
/// provided phydat_t struct.
pub fn bpf_saul_reg_read(
    dev_ptr: u64,
    data_ptr: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    let dev: *mut riot_sys::saul_reg_t = dev_ptr as *mut riot_sys::saul_reg_t;
    let data: *mut riot_sys::phydat_t = data_ptr as *mut riot_sys::phydat_t;
    let mut res = 0;
    unsafe {
        res = riot_sys::saul_reg_read(dev, data) as u64;
    }
    res
}

/// Given a pointer to the SAUL device struct, it writes the provided phydat_t
/// struct (pointed to by data_ptr) into the device.
pub fn bpf_saul_reg_write(
    dev_ptr: u64,
    data_ptr: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    let dev: *mut riot_sys::saul_reg_t = dev_ptr as *mut riot_sys::saul_reg_t;
    let data: *const riot_sys::phydat_t = data_ptr as *const riot_sys::phydat_t;
    let mut res = 0;
    unsafe {
        res = riot_sys::saul_reg_write(dev, data) as u64;
    }
    res
}

#[repr(align(8))]
#[derive(Debug)]
/// Wrapper for struct fields that need to be aligned at the 8-bytest binary.
/// It is introduced to mimice the __attribute__((aligned(8))) that is used
/// on bpf_coap_ctx_t on the eBPF C code side.
struct Align8<T>(pub T);

#[derive(Debug)]
struct CoapContext {
    /// Opaque pointer to the coap_pkt_t struct
    pkt: Align8<*mut riot_sys::coap_pkt_t>,
    /// Packet buffer
    buf: Align8<*mut u8>,
    /// Packet buffer length
    buf_len: usize,
}

/* (g)coap functions */
/// Initializes a CoAP response packet on a buffer.
/// Initializes payload location within the buffer based on packet setup.
pub fn bpf_gcoap_resp_init(
    coap_ctx_p: u64,
    resp_code: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    let coap_ctx: *const CoapContext = coap_ctx_p as *const CoapContext;

    let resp_code = resp_code as u32;

    unsafe {
        println!("coap_ctx: {:?}", *coap_ctx);
        println!("buf_len: {:?}", (*coap_ctx).buf_len);
        println!("packet payload len: {:?}", (*(*coap_ctx).pkt.0).payload_len);
        println!("resp code: {:?}", resp_code);
        let res =  riot_sys::gcoap_resp_init(
            (*coap_ctx).pkt.0,
            (*coap_ctx).buf.0,
            (*coap_ctx).buf_len as u32,
            resp_code,
        ) as u64;
        return res;
    }
}

pub fn bpf_coap_opt_finish(
    coap_ctx_p: u64,
    flags_u: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    let coap_ctx: *const CoapContext = coap_ctx_p as *const CoapContext;
    unsafe {
        println!("coap_ctx: {:?}", *coap_ctx);
        println!("buf_len: {:?}", (*coap_ctx).buf_len);
        println!("packet payload len: {:?}", (*(*coap_ctx).pkt.0).payload_len);
        return riot_sys::coap_opt_finish((*coap_ctx).pkt.0, flags_u as u16) as u64;
    }
}

/// Append a Content-Format option to the pkt buffer.
pub fn bpf_coap_add_format(
    coap_ctx_p: u64,
    format: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
    let coap_ctx: *const CoapContext = coap_ctx_p as *const CoapContext;
    unsafe {
        println!("coap_ctx: {:?}", *coap_ctx);
        println!("buf_len: {:?}", (*coap_ctx).buf_len);
        println!("packet payload len: {:?}", (*(*coap_ctx).pkt.0).payload_len);
        // Again the type cast hacking is needed because we are using the function
        // from the inline module.
        return riot_sys::inline::coap_opt_add_format(
            (*coap_ctx).pkt.0 as *mut riot_sys::inline::coap_pkt_t,
            format as u16,
        ) as u64;
    }
}
pub fn bpf_coap_get_pdu(
    unused1: u64,
    unused2: u64,
    unused3: u64,
    unused4: u64,
    unused5: u64,
) -> u64 {
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
        // An explicit cast into *mut riot_sys::inline::ztimer_clock_t is needed here
        // because the type of riot_sys::ZTIMER_USEC is riot_sys::ztimer_clock_t
        // and the compiler complains about the mismatching type.
        riot_sys::inline::ztimer_now(riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t)
    };
    now as u64
}

/*
/* Format functions - implementation */
pub fn bpf_fmt_s16_dfp(out_: u64, val: u64, fp_digits: u64, unused4: u64, unused5: u64) -> u64 {
{
    (void)f12r;
    (void)a4;
    (void)a5;

    char *out = (char*)(intptr_t)out_p;
    size_t res = fmt_s16_dfp(out, (int16_t)val, (int)fp_digits);
    return (uint32_t)res;
}

pub fn bpf_fmt_u32_dec(f12r_t *f12r, uint32_t out_p, uint32_t val, uint32_t a3, uint32_t a4, uint32_t a5)
{
    (void)f12r;
    (void)a3;
    (void)a4;
    (void)a5;

    char *out = (char*)(intptr_t)out_p;
    size_t res = fmt_u32_dec(out, (uint32_t)val);
    return (uint32_t)res;
}
*/


/// List of all helpers together with their corresponding numbers (used
/// directly as function pointers in the compiled eBPF bytecode).
pub const ALL_HELPERS: [(u32, fn(u64, u64, u64, u64, u64) -> u64); 13] = [
    // Print/debug helper functions
    (BPF_DEBUG_PRINT_IDX, bpf_print_debug),
    (BPF_PRINTF_IDX, bpf_printf),
    (BPF_MEMCPY_IDX, bpf_memcpy),
    // Time(r) functions
    (BPF_NOW_MS_IDX, bpf_now_ms),
    (BPF_ZTIMER_NOW_IDX, bpf_ztimer_now),
    // Saul functions
    (BPF_SAUL_REG_FIND_NTH_IDX, bpf_saul_reg_find_nth),
    (BPF_SAUL_REG_FIND_TYPE_IDX, bpf_saul_reg_find_type),
    (BPF_SAUL_REG_WRITE_IDX, bpf_saul_reg_write),
    (BPF_SAUL_REG_READ_IDX, bpf_saul_reg_read),
    (BPF_GCOAP_RESP_INIT_IDX, bpf_gcoap_resp_init),
    (BPF_COAP_OPT_FINISH_IDX, bpf_coap_opt_finish),
    (BPF_COAP_ADD_FORMAT_IDX, bpf_coap_add_format),
    (BPF_COAP_GET_PDU_IDX, bpf_gcoap_resp_init),
    //(BPF_FMT_S16_DFP_IDX, bpf_fmt_s16_dfp),
    //(BPF_FMT_U32_DEC_IDX, bpf_fmt_u32_dec),
];

pub fn register_all(vm: &mut rbpf::EbpfVmFixedMbuff) {
    for (id, helper) in ALL_HELPERS {
        vm.register_helper(id, helper);
    }
}
