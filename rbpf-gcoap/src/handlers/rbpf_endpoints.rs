use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use core::fmt;
use riot_wrappers::coap_message::ResponseMessage;
use riot_wrappers::gcoap::PacketBuffer;
use riot_wrappers::{cstr::cstr, stdio::println, ztimer::Clock};
use riot_wrappers::{mutex::Mutex, thread, ztimer};

use crate::middleware;
use crate::rbpf;
use crate::rbpf::helpers;
// The riot_sys reimported through the wrappers doesn't seem to work.
use riot_sys;

static VM_THREAD_STACK: Mutex<[u8; 5120]> = Mutex::new([0; 5120]);

extern "C" {
    /// Responsible for loading the bytecode from the SUIT ram storage.
    /// The application bytes are written into the buffer.
    fn load_bytes_from_suit_storage(buffer: *mut u8, location: *const char) -> u32;
    /// Copies all contents of the packet under *ctx into the provided memory region.
    /// It also recalculates pointers inside of that packet struct so that they point
    /// to correct offsets in the target memory buffer. This function is needed for
    /// executing the rBPF VM on raw packet data.
    fn copy_packet(buffer: *mut PacketBuffer, mem: *mut u8);
}

struct RbpfCoapExecutor {
    execution_time: u32,
    result: i64,
}

impl riot_wrappers::gcoap::Handler for RbpfCoapExecutor {
    fn handle(&mut self, pkt: &mut PacketBuffer) -> isize {
        let request_data = self.extract_request_data(pkt);
        let mut lengthwrapped = ResponseMessage::new(pkt);
        self.build_response(&mut lengthwrapped, request_data);
        lengthwrapped.finish()
    }
}

impl RbpfCoapExecutor {
    fn extract_request_data(&mut self, request: &mut PacketBuffer) -> u8 {
        if request.code() as u8 != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }

        // Request payload determines from which SUIT storage slot we are
        // reading the bytecode.
        let Ok(s) = core::str::from_utf8(request.payload()) else {
            return coap_numbers::code::BAD_REQUEST;
        };

        println!("Request payload received: {}", s);

        // The SUIT ram storage for the program is 2048 bytes large so we won't
        // be able to load larger images. Hence 2048 byte buffer is sufficient
        let mut prog_buf: [u8; 2048] = [0; 2048];
        let mut length = 0;

        let mut location = format!(".ram.{s}\0");

        // Memory for the packet.
        let mut mem: [u8; 512] = [0; 512];
        unsafe { copy_packet(request, mem.as_mut_ptr() as *mut u8) };

        println!("Packet copy size: {}", mem.len());
        unsafe {
            // Make this debug information
            //println!("Packet copy address: {:?}", mem.as_ptr() as u64);
        }

        unsafe {
            let buffer_ptr = prog_buf.as_mut_ptr();
            let location_ptr = location.as_ptr() as *const char;
            length = load_bytes_from_suit_storage(buffer_ptr, location_ptr);
        };

        let program = &prog_buf[..(length as usize)];
        println!(
            "Loaded program bytecode from SUIT storage location {}, program length: {}",
            location,
            program.to_vec().len()
        );

        // Initialise the VM operating on a fixed memory buffer.
        //let mut vm = rbpf::EbpfVmRaw::new(Some(program)).unwrap();
        let mut vm = rbpf::EbpfVmRaw::new(Some(program)).unwrap();

        // We register a helper function that can be called by the program, into
        // the VM.
        vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf)
            .unwrap();

        middleware::register_all_raw_vm(&mut vm);

        let mut vm_closure = || {
            println!("Starting rBPf VM execution.");
            // This unsafe hacking is needed as the ztimer_now call expects to get an
            // argument of type riot_sys::inline::ztimer_clock_t but the ztimer_clock_t
            // ZTIMER_USEC that we get from riot_sys has type riot_sys::ztimer_clock_t.
            let clock = unsafe { riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t };
            let start: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
            let result = vm.execute_program(&mut mem);
            let end: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
            if let Ok(res) = result {
                println!("Program returned: {:?} ({:#x})", res, res);
                self.result = res as i64;
            } else {
                println!("Program returned: {:?}", result);
                self.result = -1;
            }

            println!("Execution time: {} [us]", end - start);

            self.execution_time = end - start;
        };

        let mut vmthread_stacklock = VM_THREAD_STACK.lock();

        thread::scope(|threadscope| {
            let vmthread = threadscope
                .spawn(
                    vmthread_stacklock.as_mut(),
                    &mut vm_closure,
                    cstr!("rbpf vm"),
                    (riot_sys::THREAD_PRIORITY_MAIN - 2) as _,
                    (riot_sys::THREAD_CREATE_STACKTEST) as _,
                )
                .expect("Failed to spawn second thread");

            println!(
                "rBPF VM thread spawned as {:?} ({:?}), status {:?}",
                vmthread.pid(),
                vmthread.pid().get_name(),
                vmthread.status()
            );
        });

        coap_numbers::code::CHANGED
    }

    fn estimate_length(&mut self, _request: &u8) -> usize {
        1
    }

    fn build_response(&mut self, response: &mut impl MutableWritableMessage, request: u8) {
        response.set_code(request.try_into().map_err(|_| ()).unwrap());
        let resp = format!(
            "{{\"execution_time\": {}, \"result\": {}}}",
            self.execution_time, self.result
        );
        response.set_payload(resp.as_bytes());
    }
}

pub fn execute_rbpf_on_coap_pkt() -> impl riot_wrappers::gcoap::Handler {
    RbpfCoapExecutor {
        execution_time: 0,
        result: 0,
    }
}

struct RbpfExecutionHandler {
    execution_time: u32,
    result: i64,
}

impl coap_handler::Handler for RbpfExecutionHandler {
    type RequestData = u8;

    fn extract_request_data(&mut self, request: &impl ReadableMessage) -> Self::RequestData {
        let mut perform_checksum = |checksum_message: &str, program: &[u8]| {
            let message_bytes = checksum_message.as_bytes();

            let packet = Packet {
                payload: message_bytes.to_vec(),
            };
            let mut packet_with_payload = packet.get_bytes();

            // Initialise the VM operating on a fixed memory buffer.
            let mut vm = rbpf::EbpfVmFixedMbuff::new(Some(program), 0x40, 0x50).unwrap();

            // We register a helper function, that can be called by the program, into
            // the VM.
            vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf)
                .unwrap();

            middleware::register_all(&mut vm);

            // This unsafe hacking is needed as the ztimer_now call expects to get an
            // argument of type riot_sys::inline::ztimer_clock_t but the ztimer_clock_t
            // ZTIMER_USEC that we get from riot_sys has type riot_sys::ztimer_clock_t.
            let clock = unsafe { riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t };
            let start: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
            let res = vm.execute_program(&mut packet_with_payload).unwrap();
            let end: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };

            println!("Program returned: {:?} ({:#x})", res, res);
            println!("Execution time: {} [us]", end - start);
            self.execution_time = end - start;
            self.result = res as i64;
        };

        if request.code().into() != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }

        // Request payload determines from which SUIT storage slot we are
        // reading the bytecode.
        let Ok(s) = core::str::from_utf8(request.payload()) else {
            return coap_numbers::code::BAD_REQUEST;
        };

        println!("Request payload received: {}", s);

        // The SUIT ram storage for the program is 2048 bytes large so we won't
        // be able to load larger images. Hence 2048 byte buffer is sufficient
        let mut buffer: [u8; 2048] = [0; 2048];
        let mut length = 0;

        let mut location = format!(".ram.{s}\0");

        unsafe {
            let buffer_ptr = buffer.as_mut_ptr();
            let location_ptr = location.as_ptr() as *const char;
            length = load_bytes_from_suit_storage(buffer_ptr, location_ptr);
        };

        let program = &buffer[..(length as usize)];
        println!(
            "Read program bytecode from SUIT storage location {}:\n {:?}",
            location,
            program.to_vec()
        );

        // This checksum was taken from an example in RIOT.
        let checksum_message = "abcdef\
            AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc\
            d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3\
            QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs\
            4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT\
            tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n\
            byNy4yqxu7";

        perform_checksum(checksum_message, program);

        coap_numbers::code::CHANGED
    }

    fn estimate_length(&mut self, _request: &Self::RequestData) -> usize {
        1
    }

    fn build_response(
        &mut self,
        response: &mut impl MutableWritableMessage,
        request: Self::RequestData,
    ) {
        response.set_code(request.try_into().map_err(|_| ()).unwrap());
        let resp = format!(
            "{{\"execution_time\": {}, \"result\": {}}}",
            self.execution_time, self.result
        );
        response.set_payload(resp.as_bytes());
    }
}

pub fn handle_bytecode_load() -> impl coap_handler::Handler {
    RbpfExecutionHandler {
        execution_time: 0,
        result: 0,
    }
}

struct Packet {
    payload: Vec<u8>,
}

impl Packet {
    /// Returns the packet as a byte array with its data payload appended at the
    /// end. The first byte of the payload represents the length of the data
    /// segment.
    pub fn get_bytes(self) -> Vec<u8> {
        let packet_template = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x08,
            0x00, // ethertype
            0x45, 0x00, 0x00, 0x3b, // start ip_hdr
            0xa6, 0xab, 0x40, 0x00, 0x40, 0x06, 0x96, 0x0f, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
            0x00, 0x01, 0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
            0xd1, 0xe5, 0xc4, 0x9d, 0xd4, 0x30, 0xb5, 0xd2, 0x80, 0x18, 0x01, 0x56, 0xfe, 0x2f,
            0x00, 0x00,
            // Payload starts here
        ];

        let mut packet_with_payload = packet_template.to_vec();

        // Beware: the length of to_ne_bytes vec is actually 4 and not 8
        // as the lsp suggests, it is because the ARM architecture of the
        // target is 32-bit.
        let mut length = self.payload.len().to_ne_bytes().to_vec();

        packet_with_payload.append(&mut length);
        packet_with_payload.append(&mut self.payload.to_vec());
        packet_with_payload
    }
}
