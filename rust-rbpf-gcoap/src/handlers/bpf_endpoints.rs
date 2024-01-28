use alloc::string::String;
use alloc::vec::Vec;
use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use core::fmt;
use riot_wrappers::{cstr::cstr, stdio::println, ztimer::Clock};

use crate::rbpf;
use crate::rbpf::helpers;
// The riot_sys reimported through the wrappers doesn't seem to work.
use riot_sys;

struct BpfBytecodeLoader {}

impl coap_handler::Handler for BpfBytecodeLoader {
    type RequestData = u8;

    fn extract_request_data(&mut self, request: &impl ReadableMessage) -> Self::RequestData {
        extern "C" {
            fn load_suit_bytecode(buffer: *mut u8, location: *const char) -> u32;
        }

        // The SUIT ram storage for the program is 2048 bytes large so we won't
        // be able to load larger images.
        let mut buffer: [u8; 2048] = [0; 2048];
        let mut length = 0;
        unsafe {
            length = load_suit_bytecode(buffer.as_mut_ptr(), ".ram.0\0".as_ptr() as *const char);
        };

        if request.code().into() != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }

        if let Ok(s) = core::str::from_utf8(request.payload()) {
            println!("{}", s);

            println!(
                "Received program bytecode: {:?}",
                buffer[..(length as usize)].to_vec()
            );

            let mut packet1 = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x08,
                0x00, // ethertype
                0x45, 0x00, 0x00, 0x3b, // start ip_hdr
                0xa6, 0xab, 0x40, 0x00, 0x40, 0x06, 0x96, 0x0f, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
                0x00, 0x01,
                // Program matches the next two bytes: 0x9999 returns 0xffffffff, else return 0.
                0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
                0xd1, 0xe5, 0xc4, 0x9d, 0xd4, 0x30, 0xb5, 0xd2, 0x80, 0x18, 0x01, 0x56, 0xfe, 0x2f,
                0x00, 0x00,
                // Payload starts here
            ];

            let mut packet_with_payload = packet1.to_vec();

            // This checksum was taken from an example in RIOT.
            let checksum_message = "abcdef\
            AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc\
            d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3\
            QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs\
            4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT\
            tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n\
            byNy4yqxu7";

            let message_bytes = checksum_message.as_bytes();

            println!("Message length: {}", message_bytes.len());

            packet_with_payload.push(message_bytes.len() as u8);
            packet_with_payload.append(&mut message_bytes.to_vec());

            let mut vm = rbpf::EbpfVmFixedMbuff::new(Some(&buffer[..(length as usize)]), 0x40, 0x50).unwrap();

            // We register a helper function, that can be called by the program, into
            // the VM.
            vm.register_helper(helpers::BPF_TRACE_PRINTK_IDX, helpers::bpf_trace_printf)
                .unwrap();

            let clock  = unsafe { riot_sys::ZTIMER_USEC as *mut riot_sys::inline::ztimer_clock_t};
            let start: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
            let res = vm.execute_program(&mut packet_with_payload).unwrap();
            let end: u32 = unsafe { riot_sys::inline::ztimer_now(clock) };
            println!("Program returned: {:?} ({:#x})", res, res);
            println!("Execution time: {} [us]", end - start);


            // Game plan: add endpoint functionality and an extern C function that
            // will allow for loading the rust rBPF compatible program into one
            // SUIT storage and the femto container one into the second one
            // After that benchmark the two.

            coap_numbers::code::CHANGED
        } else {
            coap_numbers::code::BAD_REQUEST
        }
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
        response.set_payload(b"Success");
    }
}

pub fn handle_bytecode_load() -> impl coap_handler::Handler {
    BpfBytecodeLoader {}
}
